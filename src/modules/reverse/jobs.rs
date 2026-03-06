use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::errors::RustpenError;

use super::adapters::adapter_for_engine;
use super::analyzer::detect_format;
use super::orchestrator::ReverseOrchestrator;

const DEFAULT_GHIDRA_AUTO_INDEX_THRESHOLD_MB: u64 = 25;
const APK_SCAN_WINDOW: usize = 4 * 1024 * 1024;

fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn reverse_deep_enabled() -> bool {
    env_flag("RSCAN_REVERSE_DEEP", false)
}

fn reverse_rust_first_enabled() -> bool {
    env_flag("RSCAN_REVERSE_RUST_FIRST", true)
}

fn ghidra_slim_enabled() -> bool {
    env_flag("RSCAN_GHIDRA_SLIM", true)
}

fn is_probable_apk(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("apk"))
        .unwrap_or(false)
    {
        return true;
    }

    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };

    let Ok(meta) = f.metadata() else {
        return false;
    };
    if meta.len() < 4 {
        return false;
    }

    let mut head = vec![0u8; APK_SCAN_WINDOW.min(meta.len() as usize)];
    if f.read_exact(&mut head).is_err() {
        return false;
    }
    if !head.starts_with(b"PK\x03\x04") {
        return false;
    }
    if matches!(detect_format(&head), super::model::BinaryFormat::Apk) {
        return true;
    }

    if meta.len() <= APK_SCAN_WINDOW as u64 {
        return false;
    }

    let tail_len = APK_SCAN_WINDOW.min(meta.len() as usize);
    if f.seek(SeekFrom::End(-(tail_len as i64))).is_err() {
        return false;
    }
    let mut tail = vec![0u8; tail_len];
    if f.read_exact(&mut tail).is_err() {
        return false;
    }

    let mut merged = head;
    merged.extend_from_slice(&tail);
    matches!(detect_format(&merged), super::model::BinaryFormat::Apk)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReverseJobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseJobMeta {
    pub id: String,
    pub kind: String,
    pub backend: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub function: Option<String>,
    pub target: PathBuf,
    pub workspace: PathBuf,
    pub status: ReverseJobStatus,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub ended_at: Option<u64>,
    pub exit_code: Option<i32>,
    pub program: String,
    pub args: Vec<String>,
    pub note: String,
    pub artifacts: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileRunReport {
    pub job: ReverseJobMeta,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileBatchReport {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub reports: Vec<DecompileRunReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPrunePolicy {
    pub keep_latest: Option<usize>,
    pub older_than_days: Option<u64>,
    pub include_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseJobHealth {
    pub id: String,
    pub status: ReverseJobStatus,
    pub healthy: bool,
    pub pseudocode_exists: bool,
    pub pseudocode_nonempty: bool,
    pub pseudocode_rows: usize,
    pub logs_exist: bool,
    pub issues: Vec<String>,
}

pub fn run_decompile_job(
    input: &Path,
    workspace: &Path,
    engine_name: &str,
    mode: super::model::DecompileMode,
    function: Option<&str>,
    timeout_secs: Option<u64>,
) -> Result<DecompileRunReport, RustpenError> {
    let fast_reverse = env_flag("RSCAN_FAST_REVERSE", false);
    let rust_first = reverse_rust_first_enabled();
    let deep = reverse_deep_enabled();
    let apk_like = is_probable_apk(input);

    // Fast path: lightweight Rust index (no Ghidra) when requested or auto for index.
    if mode == super::model::DecompileMode::Index
        && (engine_name.eq_ignore_ascii_case("rust")
            || engine_name.eq_ignore_ascii_case("rust-index")
            || (engine_name.eq_ignore_ascii_case("auto") && !apk_like && (rust_first && !deep)))
    {
        return run_rust_index_job(input, workspace);
    }
    // Optional lightweight ASM-only path (no pseudocode).
    if (mode == super::model::DecompileMode::Function || mode == super::model::DecompileMode::Full)
        && (engine_name.eq_ignore_ascii_case("rust-asm")
            || engine_name.eq_ignore_ascii_case("rust")
            || (engine_name.eq_ignore_ascii_case("auto") && !apk_like && (rust_first && !deep)))
    {
        return run_rust_asm_job(input, workspace, mode);
    }
    if fast_reverse
        && engine_name.eq_ignore_ascii_case("auto")
        && (mode == super::model::DecompileMode::Function
            || mode == super::model::DecompileMode::Full)
    {
        if let Ok(report) = run_rust_asm_job(input, workspace, mode) {
            return Ok(report);
        }
    }

    std::fs::create_dir_all(workspace)?;
    let orchestrator = ReverseOrchestrator::detect();
    let id = new_job_id();
    let jobs_root = workspace.join("jobs");
    let job_dir = jobs_root.join(&id);
    std::fs::create_dir_all(&job_dir)?;
    let out_dir = workspace.join("reverse_out").join(&id);
    std::fs::create_dir_all(&out_dir)?;

    let preferred = if engine_name.eq_ignore_ascii_case("auto") {
        if apk_like {
            Some("jadx")
        } else {
            None
        }
    } else {
        Some(engine_name)
    };
    let requested_mode = mode;
    let mut effective_mode = requested_mode;
    let mut plan = orchestrator.build_pseudocode_plan(
        input,
        &out_dir,
        preferred,
        effective_mode,
        function_arg_for_mode(effective_mode, function),
    )?;
    let mut adaptive_note: Option<String> = None;
    let force_slim_ghidra =
        requested_mode == super::model::DecompileMode::Full
            && !deep
            && ghidra_slim_enabled()
            && is_ghidra_program(&plan.program);
    if force_slim_ghidra
        || should_auto_switch_ghidra_full_to_index(
            requested_mode,
            &plan.program,
            std::fs::metadata(input).ok().map(|m| m.len()),
            ghidra_auto_index_threshold_bytes(),
        )
    {
        effective_mode = super::model::DecompileMode::Index;
        plan = orchestrator.build_pseudocode_plan(
            input,
            &out_dir,
            preferred,
            effective_mode,
            function_arg_for_mode(effective_mode, function),
        )?;
        let file_size = std::fs::metadata(input).ok().map(|m| m.len()).unwrap_or(0);
        let threshold = ghidra_auto_index_threshold_bytes()
            .unwrap_or(DEFAULT_GHIDRA_AUTO_INDEX_THRESHOLD_MB * 1024 * 1024);
        adaptive_note = if force_slim_ghidra {
            Some("ghidra_slim_mode: full->index (deep mode disabled)".to_string())
        } else {
            Some(format!(
                "adaptive_ghidra_mode: full->index (file_size={} bytes >= threshold={} bytes)",
                file_size, threshold
            ))
        };
    }
    let backend = preferred.unwrap_or("auto").to_string();
    let artifact_name = match effective_mode {
        super::model::DecompileMode::Full => "pseudocode.jsonl",
        super::model::DecompileMode::Index => "index.jsonl",
        super::model::DecompileMode::Function => "function.jsonl",
    };
    let is_jadx = is_jadx_program(&plan.program);
    if plan
        .program
        .to_ascii_lowercase()
        .contains("analyzeheadless")
        && plan.args.len() >= 2
    {
        plan.args[1] = format!("rscan_{}", id);
    }

    let mut job = ReverseJobMeta {
        id: id.clone(),
        kind: "decompile".to_string(),
        backend,
        mode: Some(format!("{:?}", effective_mode).to_ascii_lowercase()),
        function: function.map(|s| s.to_string()),
        target: input.to_path_buf(),
        workspace: workspace.to_path_buf(),
        status: ReverseJobStatus::Queued,
        created_at: now_epoch_secs(),
        started_at: None,
        ended_at: None,
        exit_code: None,
        program: plan.program.clone(),
        args: plan.args.clone(),
        note: match adaptive_note {
            Some(ref n) => format!("{}; {}", plan.note, n),
            None => plan.note.clone(),
        },
        artifacts: {
            let mut arts = vec![
                path_to_string(job_dir.join("stdout.log")),
                path_to_string(job_dir.join("stderr.log")),
            ];
            if is_jadx && effective_mode == super::model::DecompileMode::Full {
                arts.push(path_to_string(out_dir.join("sources")));
                arts.push(path_to_string(out_dir.join("resources")));
            } else {
                arts.push(path_to_string(out_dir.join(artifact_name)));
            }
            arts
        },
        error: None,
    };
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    job.status = ReverseJobStatus::Running;
    job.started_at = Some(now_epoch_secs());
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    let stdout_log = job_dir.join("stdout.log");
    let stderr_log = job_dir.join("stderr.log");
    let mut run_status = match run_with_logs_and_timeout(
        &plan.program,
        &plan.args,
        &stdout_log,
        &stderr_log,
        timeout_secs,
    ) {
        Ok(status) => status,
        Err(e) => {
            job.ended_at = Some(now_epoch_secs());
            job.exit_code = None;
            job.status = ReverseJobStatus::Failed;
            job.error = Some(e.to_string());
            save_job_meta(&job_dir.join("meta.json"), &job)?;
            return Ok(DecompileRunReport {
                job,
                stdout_log,
                stderr_log,
            });
        }
    };
    if run_status != Some(0) && is_ghidra_program(&plan.program) && stderr_has_ghidra_lock(&stderr_log) {
        let old_reuse = std::env::var("RSCAN_GHIDRA_REUSE_PROJECT").ok();
        let old_cache = std::env::var("RSCAN_GHIDRA_PROJECT_CACHE").ok();
        unsafe {
            std::env::set_var("RSCAN_GHIDRA_REUSE_PROJECT", "0");
            std::env::set_var("RSCAN_GHIDRA_PROJECT_CACHE", "0");
        }
        if let Ok(retry_plan) = orchestrator.build_pseudocode_plan(
            input,
            &out_dir,
            preferred,
            effective_mode,
            function_arg_for_mode(effective_mode, function),
        ) {
            let _ = std::fs::remove_file(&stdout_log);
            let _ = std::fs::remove_file(&stderr_log);
            if let Ok(status2) = run_with_logs_and_timeout(
                &retry_plan.program,
                &retry_plan.args,
                &stdout_log,
                &stderr_log,
                timeout_secs,
            ) {
                run_status = status2;
                job.program = retry_plan.program;
                job.args = retry_plan.args;
                job.note = format!("{}; ghidra lock retry without cache", job.note);
            }
        }
        match old_reuse {
            Some(v) => unsafe { std::env::set_var("RSCAN_GHIDRA_REUSE_PROJECT", v) },
            None => unsafe { std::env::remove_var("RSCAN_GHIDRA_REUSE_PROJECT") },
        }
        match old_cache {
            Some(v) => unsafe { std::env::set_var("RSCAN_GHIDRA_PROJECT_CACHE", v) },
            None => unsafe { std::env::remove_var("RSCAN_GHIDRA_PROJECT_CACHE") },
        }
    }

    job.ended_at = Some(now_epoch_secs());
    job.exit_code = run_status;
    let pseudo_path = out_dir.join(artifact_name);
    let pseudo_ok = path_is_nonempty_file(&pseudo_path);
    let jadx_sources_ok = path_has_any_file(&out_dir.join("sources"));
    let jadx_resources_ok = path_has_any_file(&out_dir.join("resources"));
    let jadx_output_ok = jadx_sources_ok || jadx_resources_ok;
    let success = if is_jadx && effective_mode == super::model::DecompileMode::Full {
        (run_status == Some(0) && jadx_output_ok) || (run_status != Some(0) && jadx_output_ok)
    } else {
        run_status == Some(0) && pseudo_ok
    };
    if success {
        job.status = ReverseJobStatus::Succeeded;
        if is_jadx && run_status != Some(0) {
            let warn = format!(
                "jadx finished with non-zero exit code {} but exported output exists",
                run_status
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            if job.note.trim().is_empty() {
                job.note = warn;
            } else {
                job.note = format!("{}; {}", job.note, warn);
            }
        }
        if let Ok(Some(ir_path)) = try_emit_ir_artifact(workspace, &job) {
            job.artifacts.push(path_to_string(ir_path));
        }
    } else {
        job.status = ReverseJobStatus::Failed;
        job.error = if run_status != Some(0) {
            Some(format!(
                "tool '{}' exited with status {}",
                plan.program,
                run_status
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ))
        } else if is_jadx && effective_mode == super::model::DecompileMode::Full {
            Some(format!(
                "jadx finished but output tree missing/empty: {}",
                out_dir.display()
            ))
        } else {
            Some(format!(
                "decompile finished but pseudocode artifact missing/empty: {}",
                pseudo_path.display()
            ))
        };
    }
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    Ok(DecompileRunReport {
        job,
        stdout_log,
        stderr_log,
    })
}

pub fn run_decompile_batch(
    inputs: &[PathBuf],
    workspace: &Path,
    engine_name: &str,
    mode: super::model::DecompileMode,
    function: Option<&str>,
    timeout_secs: Option<u64>,
    parallel_jobs: usize,
) -> Result<DecompileBatchReport, RustpenError> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel_jobs.max(1))
        .build()
        .map_err(|e| RustpenError::Generic(format!("failed to build thread pool: {}", e)))?;

    let reports = pool.install(|| {
        inputs
            .par_iter()
            .map(|p| run_decompile_job(p, workspace, engine_name, mode, function, timeout_secs))
            .collect::<Vec<_>>()
    });

    let mut out = Vec::new();
    let mut failed = 0usize;
    for r in reports {
        match r {
            Ok(v) => {
                if v.job.status == ReverseJobStatus::Succeeded {
                    out.push(v);
                } else {
                    failed += 1;
                    out.push(v);
                }
            }
            Err(e) => {
                failed += 1;
                let fallback = DecompileRunReport {
                    job: ReverseJobMeta {
                        id: new_job_id(),
                        kind: "decompile".to_string(),
                        backend: engine_name.to_string(),
                        mode: Some(format!("{:?}", mode).to_ascii_lowercase()),
                        function: function.map(|s| s.to_string()),
                        target: PathBuf::new(),
                        workspace: workspace.to_path_buf(),
                        status: ReverseJobStatus::Failed,
                        created_at: now_epoch_secs(),
                        started_at: None,
                        ended_at: Some(now_epoch_secs()),
                        exit_code: None,
                        program: "".to_string(),
                        args: Vec::new(),
                        note: "batch item failed before launch".to_string(),
                        artifacts: Vec::new(),
                        error: Some(e.to_string()),
                    },
                    stdout_log: PathBuf::new(),
                    stderr_log: PathBuf::new(),
                };
                out.push(fallback);
            }
        }
    }
    let succeeded = out
        .iter()
        .filter(|r| r.job.status == ReverseJobStatus::Succeeded)
        .count();
    Ok(DecompileBatchReport {
        total: out.len(),
        succeeded,
        failed,
        reports: out,
    })
}

pub fn list_jobs(workspace: &Path) -> Result<Vec<ReverseJobMeta>, RustpenError> {
    let root = workspace.join("jobs");
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut jobs = Vec::new();
    for entry in std::fs::read_dir(root).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path().join("meta.json");
        if p.is_file()
            && let Ok(job) = load_job_meta(&p)
        {
            jobs.push(job);
        }
    }
    jobs.sort_by_key(|j| std::cmp::Reverse(j.created_at));
    Ok(jobs)
}

pub fn load_job_by_id(workspace: &Path, job_id: &str) -> Result<ReverseJobMeta, RustpenError> {
    let meta = workspace.join("jobs").join(job_id).join("meta.json");
    load_job_meta(&meta)
}

pub fn load_job_logs(workspace: &Path, job_id: &str) -> Result<(String, String), RustpenError> {
    let dir = workspace.join("jobs").join(job_id);
    let out = std::fs::read_to_string(dir.join("stdout.log")).map_err(RustpenError::Io)?;
    let err = std::fs::read_to_string(dir.join("stderr.log")).map_err(RustpenError::Io)?;
    Ok((out, err))
}

pub fn load_job_pseudocode_rows(
    workspace: &Path,
    job_id: &str,
) -> Result<Vec<serde_json::Value>, RustpenError> {
    let job = load_job_by_id(workspace, job_id)?;
    let pseudo = resolve_pseudocode_path(workspace, &job);
    let pseudo_exists = pseudo.exists()
        && std::fs::metadata(&pseudo)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
    if pseudo_exists {
        return read_jsonl(&pseudo);
    }
    load_lightweight_rows(workspace, &job)
}

fn read_jsonl(path: &Path) -> Result<Vec<serde_json::Value>, RustpenError> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(RustpenError::Io)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            RustpenError::ParseError(format!("invalid jsonl at line {}: {}", idx + 1, e))
        })?;
        rows.push(v);
    }
    Ok(rows)
}

fn parse_addr_str(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        u64::from_str_radix(s, 16)
            .ok()
            .or_else(|| s.parse::<u64>().ok())
    }
}

fn value_to_addr(v: &serde_json::Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        return parse_addr_str(s);
    }
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    None
}

fn load_asm_only_rows(base: &Path) -> Result<Option<Vec<serde_json::Value>>, RustpenError> {
    let candidates = [base.join("function_asm.jsonl"), base.join("asm_full.jsonl")];
    let asm_path = candidates.iter().find(|p| p.exists());
    let Some(path) = asm_path else {
        return Ok(None);
    };
    let rows = read_jsonl(path)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut asm_lines = Vec::new();
    for r in rows.iter().take(200) {
        if let Some(text) = r.get("text").and_then(|v| v.as_str()) {
            if !text.is_empty() {
                asm_lines.push(text.to_string());
            }
        }
    }
    if asm_lines.is_empty() {
        return Ok(None);
    }
    let ea = rows
        .iter()
        .find_map(|r| r.get("ea").and_then(value_to_addr))
        .unwrap_or(0);
    let row = serde_json::json!({
        "ea": format!("0x{:x}", ea),
        "name": "<asm-only>",
        "pseudocode": "asm-only job: run ghidra for pseudocode/index, or JADX for APK source export.",
        "calls": [],
        "call_names": [],
        "xrefs": [],
        "ext_refs": [],
        "asm": asm_lines,
    });
    Ok(Some(vec![row]))
}

fn load_lightweight_rows(
    workspace: &Path,
    job: &ReverseJobMeta,
) -> Result<Vec<serde_json::Value>, RustpenError> {
    let base = workspace.join("reverse_out").join(&job.id);
    let index_path = base.join("index.jsonl");
    if !index_path.exists() {
        if let Some(rows) = load_asm_only_rows(&base)? {
            return Ok(rows);
        }
        return Err(RustpenError::ScanError(format!(
            "pseudocode artifact not found and no index available at {}",
            index_path.display()
        )));
    }
    let mut rows = read_jsonl(&index_path)?;

    // Optional enrichments
    let calls_func_path = base.join("calls_functions.jsonl");
    let xrefs_func_path = base.join("xrefs_functions.jsonl");
    let cfg_path = base.join("cfg_functions.jsonl");
    let asm_preview_path = base.join("asm_preview.jsonl");

    let mut call_map: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    if calls_func_path.exists() {
        for row in read_jsonl(&calls_func_path)? {
            let func = row
                .get("func")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut addrs = Vec::new();
            let mut names = Vec::new();
            if let Some(edges) = row.get("calls").and_then(|v| v.as_array()) {
                for e in edges {
                    let to = e
                        .get("to")
                        .and_then(value_to_addr)
                        .map(|v| format!("0x{:x}", v))
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let name = e
                        .get("symbol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    addrs.push(to);
                    names.push(name);
                }
            }
            call_map.insert(func, (addrs, names));
        }
    }

    let mut xref_map: HashMap<String, Vec<String>> = HashMap::new();
    if xrefs_func_path.exists() {
        for row in read_jsonl(&xrefs_func_path)? {
            let func = row
                .get("func")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut froms = Vec::new();
            if let Some(edges) = row.get("xrefs").and_then(|v| v.as_array()) {
                for e in edges {
                    let from = e
                        .get("from")
                        .and_then(value_to_addr)
                        .map(|v| format!("0x{:x}", v))
                        .unwrap_or_else(|| "<unknown>".to_string());
                    froms.push(from);
                }
            }
            xref_map.insert(func, froms);
        }
    }

    let mut cfg_map: HashMap<String, Vec<String>> = HashMap::new();
    if cfg_path.exists() {
        for row in read_jsonl(&cfg_path)? {
            let func = row
                .get("func")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut blocks_out = Vec::new();
            if let Some(blocks) = row.get("blocks").and_then(|v| v.as_array()) {
                for b in blocks {
                    let addr = b.get("addr").and_then(|v| v.as_str()).unwrap_or("<addr>");
                    let len = b
                        .get("len")
                        .and_then(|v| v.as_u64())
                        .map(|v| format!("len=0x{:x}", v))
                        .unwrap_or_default();
                    let flow = b.get("flow").and_then(|v| v.as_str()).unwrap_or("Next");
                    blocks_out.push(format!("{addr} {len} {flow}"));
                }
            }
            cfg_map.insert(func, blocks_out);
        }
    }

    let asm_preview = if asm_preview_path.exists() {
        read_jsonl(&asm_preview_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut asm_group: HashMap<String, Vec<String>> = HashMap::new();
    if !asm_preview.is_empty() {
        let mut func_addrs: Vec<u64> = rows
            .iter()
            .filter_map(|r| {
                r.get("ea")
                    .and_then(|v| v.as_str())
                    .and_then(parse_addr_str)
            })
            .collect();
        func_addrs.sort_unstable();
        func_addrs.dedup();
        let lookup_func = |addr: u64, funcs: &Vec<u64>| -> Option<u64> {
            funcs.iter().rev().find(|a| addr >= **a).copied()
        };
        for inst in asm_preview {
            let Some(addr) = inst.get("ea").and_then(value_to_addr) else {
                continue;
            };
            let func = lookup_func(addr, &func_addrs).unwrap_or(addr);
            let key = format!("0x{:x}", func).to_ascii_lowercase();
            let text = inst
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if text.is_empty() {
                continue;
            }
            let entry = asm_group.entry(key).or_default();
            if entry.len() < 120 {
                entry.push(text);
            }
        }
    }

    for r in &mut rows {
        let Some(obj) = r.as_object_mut() else {
            continue;
        };
        let ea = obj
            .get("ea")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let (calls, call_names) = call_map
            .get(&ea)
            .cloned()
            .unwrap_or_else(|| (Vec::new(), Vec::new()));
        let xrefs = xref_map.get(&ea).cloned().unwrap_or_default();
        let asm = asm_group.get(&ea).cloned().unwrap_or_default();
        let cfg_lines = cfg_map.get(&ea).cloned().unwrap_or_default();
        obj.insert(
            "pseudocode".to_string(),
            serde_json::Value::String(
                "rust fast path: no pseudocode. press 'd' to run ghidra for pseudocode."
                    .to_string(),
            ),
        );
        obj.insert(
            "calls".to_string(),
            serde_json::Value::Array(calls.into_iter().map(serde_json::Value::String).collect()),
        );
        obj.insert(
            "call_names".to_string(),
            serde_json::Value::Array(
                call_names
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        obj.insert(
            "xrefs".to_string(),
            serde_json::Value::Array(xrefs.into_iter().map(serde_json::Value::String).collect()),
        );
        obj.entry("ext_refs".to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        obj.insert(
            "asm".to_string(),
            serde_json::Value::Array(if asm.is_empty() {
                vec![serde_json::Value::String(
                    "<no asm preview; run rust-asm or ghidra full>".to_string(),
                )]
            } else {
                asm.into_iter()
                    .map(serde_json::Value::String)
                    .collect::<Vec<_>>()
            }),
        );
        if !cfg_lines.is_empty() {
            obj.insert(
                "cfg".to_string(),
                serde_json::Value::Array(
                    cfg_lines
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }

    Ok(rows)
}

pub fn clear_jobs(workspace: &Path, job_id: Option<&str>) -> Result<usize, RustpenError> {
    let root = workspace.join("jobs");
    if !root.exists() {
        return Ok(0);
    }
    match job_id {
        Some(id) => {
            let dir = root.join(id);
            if dir.exists() {
                std::fs::remove_dir_all(dir)?;
                Ok(1)
            } else {
                Ok(0)
            }
        }
        None => {
            let mut removed = 0usize;
            for entry in std::fs::read_dir(&root).map_err(RustpenError::Io)? {
                let entry = entry.map_err(RustpenError::Io)?;
                let p = entry.path();
                if p.is_dir() {
                    std::fs::remove_dir_all(&p)?;
                    removed += 1;
                }
            }
            Ok(removed)
        }
    }
}

pub fn prune_jobs_keep_recent(workspace: &Path, keep: usize) -> Result<usize, RustpenError> {
    prune_jobs(
        workspace,
        JobPrunePolicy {
            keep_latest: Some(keep.max(1)),
            older_than_days: None,
            include_running: false,
        },
    )
}

pub fn prune_jobs(workspace: &Path, policy: JobPrunePolicy) -> Result<usize, RustpenError> {
    let jobs = list_jobs(workspace)?;
    if jobs.is_empty() {
        return Ok(0);
    }
    let keep_latest = policy.keep_latest.map(|v| v.max(1));
    let now = now_epoch_secs();
    let older_cutoff = policy
        .older_than_days
        .map(|d| now.saturating_sub(d.saturating_mul(24 * 3600)));

    let root = workspace.join("jobs");
    let mut removed = 0usize;
    for (idx, job) in jobs.iter().enumerate() {
        if !policy.include_running && job.status == ReverseJobStatus::Running {
            continue;
        }
        let by_keep = keep_latest.is_some_and(|k| idx >= k);
        let by_age = older_cutoff.is_some_and(|c| job.created_at <= c);
        if !by_keep && !by_age {
            continue;
        }
        let dir = root.join(&job.id);
        if dir.is_dir() {
            std::fs::remove_dir_all(dir)?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn inspect_job_health(
    workspace: &Path,
    job_id: &str,
) -> Result<ReverseJobHealth, RustpenError> {
    let job = load_job_by_id(workspace, job_id)?;
    let mut issues = Vec::new();
    let pseudo_path = resolve_pseudocode_path(workspace, &job);
    let pseudocode_exists = pseudo_path.exists();
    let pseudocode_nonempty = std::fs::metadata(&pseudo_path)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !pseudocode_exists {
        issues.push(format!(
            "pseudocode artifact not found: {}",
            pseudo_path.display()
        ));
    } else if !pseudocode_nonempty {
        issues.push(format!(
            "pseudocode artifact empty: {}",
            pseudo_path.display()
        ));
    }
    let mut pseudocode_rows = 0usize;
    if pseudocode_exists && pseudocode_nonempty {
        match std::fs::read_to_string(&pseudo_path) {
            Ok(text) => {
                for (idx, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if serde_json::from_str::<serde_json::Value>(line).is_err() {
                        issues.push(format!("invalid jsonl line {}", idx + 1));
                        break;
                    }
                    pseudocode_rows += 1;
                }
                if pseudocode_rows == 0 {
                    issues.push("pseudocode has zero rows".to_string());
                }
            }
            Err(e) => issues.push(format!("failed to read pseudocode: {}", e)),
        }
    }

    let stdout_ok = workspace
        .join("jobs")
        .join(job_id)
        .join("stdout.log")
        .is_file();
    let stderr_ok = workspace
        .join("jobs")
        .join(job_id)
        .join("stderr.log")
        .is_file();
    let logs_exist = stdout_ok && stderr_ok;
    if !stdout_ok {
        issues.push("stdout.log missing".to_string());
    }
    if !stderr_ok {
        issues.push("stderr.log missing".to_string());
    }

    Ok(ReverseJobHealth {
        id: job.id,
        status: job.status,
        healthy: issues.is_empty(),
        pseudocode_exists,
        pseudocode_nonempty,
        pseudocode_rows,
        logs_exist,
        issues,
    })
}

pub fn inspect_jobs_health(
    workspace: &Path,
    limit: Option<usize>,
) -> Result<Vec<ReverseJobHealth>, RustpenError> {
    let jobs = list_jobs(workspace)?;
    let n = limit.unwrap_or(50).max(1);
    let mut out = Vec::new();
    for job in jobs.into_iter().take(n) {
        if let Ok(h) = inspect_job_health(workspace, &job.id) {
            out.push(h);
        }
    }
    Ok(out)
}

fn load_job_meta(path: &Path) -> Result<ReverseJobMeta, RustpenError> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))
}

fn save_job_meta(path: &Path, job: &ReverseJobMeta) -> Result<(), RustpenError> {
    let s =
        serde_json::to_string_pretty(job).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    std::fs::write(path, s)?;
    Ok(())
}

fn new_job_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("job-{:x}", ns)
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().to_string()
}

fn resolve_pseudocode_path(workspace: &Path, job: &ReverseJobMeta) -> PathBuf {
    let pseudo = job
        .artifacts
        .iter()
        .find(|a| {
            a.ends_with("function.jsonl")
                || a.ends_with("pseudocode.jsonl")
                || a.ends_with("index.jsonl")
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("reverse_out").join("pseudocode.jsonl"));
    if pseudo.exists() {
        return pseudo;
    }
    if pseudo.is_absolute() {
        return pseudo;
    }
    let joined = workspace.join(&pseudo);
    if joined.exists() {
        joined
    } else {
        workspace.join("reverse_out").join("pseudocode.jsonl")
    }
}

fn infer_engine_for_ir(job: &ReverseJobMeta) -> Option<super::model::DecompilerEngine> {
    let b = job.backend.to_ascii_lowercase();
    if b.contains("ghidra") || job.program.to_ascii_lowercase().contains("analyzeheadless") {
        return Some(super::model::DecompilerEngine::Ghidra);
    }
    if b.contains("jadx") || job.program.to_ascii_lowercase().contains("jadx") {
        return Some(super::model::DecompilerEngine::Jadx);
    }
    if b.contains("radare2") || b == "r2" || job.program.to_ascii_lowercase().ends_with("/r2") {
        return Some(super::model::DecompilerEngine::Radare2);
    }
    None
}

fn write_ir_jsonl(path: &Path, doc: &super::ir::ReverseIrDoc) -> Result<(), RustpenError> {
    use std::io::Write;

    let mut f = std::fs::File::create(path)?;
    let meta = serde_json::json!({
        "kind": "meta",
        "payload": doc.meta
    });
    writeln!(
        f,
        "{}",
        serde_json::to_string(&meta).map_err(|e| RustpenError::ParseError(e.to_string()))?
    )
    .map_err(RustpenError::Io)?;

    for func in &doc.functions {
        let row = serde_json::json!({
            "kind": "function",
            "payload": func
        });
        writeln!(
            f,
            "{}",
            serde_json::to_string(&row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    Ok(())
}

fn try_emit_ir_artifact(workspace: &Path, job: &ReverseJobMeta) -> Result<Option<PathBuf>, RustpenError> {
    let Some(engine) = infer_engine_for_ir(job) else {
        return Ok(None);
    };
    let Some(adapter) = adapter_for_engine(engine) else {
        return Ok(None);
    };

    let out_dir = workspace.join("reverse_out").join(&job.id);
    let pseudo_path = resolve_pseudocode_path(workspace, job);
    let pseudo_rows = if pseudo_path.exists() {
        std::fs::read_to_string(&pseudo_path)
            .ok()
            .map(|text| {
                text.lines()
                    .filter_map(|line| {
                        let s = line.trim();
                        if s.is_empty() {
                            return None;
                        }
                        serde_json::from_str::<serde_json::Value>(s).ok()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let index_path = out_dir.join("index.jsonl");
    let index_rows = if index_path.exists() {
        std::fs::read_to_string(&index_path)
            .ok()
            .map(|text| {
                text.lines()
                    .filter_map(|line| {
                        let s = line.trim();
                        if s.is_empty() {
                            return None;
                        }
                        serde_json::from_str::<serde_json::Value>(s).ok()
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let is_jadx = matches!(engine, super::model::DecompilerEngine::Jadx);
    if index_rows.is_empty() && pseudo_rows.is_empty() && !is_jadx {
        return Ok(None);
    }

    let file_size = std::fs::metadata(&job.target).ok().map(|m| m.len());
    let meta = super::ir::IrBinaryMeta {
        sample: job.target.display().to_string(),
        backend: adapter.name().to_string(),
        format: None,
        arch: None,
        entry: None,
        file_size,
    };
    let doc = adapter.build_doc_with_context(meta, &index_rows, &pseudo_rows, &out_dir, &job.target)?;
    if doc.functions.is_empty() && index_rows.is_empty() && pseudo_rows.is_empty() {
        return Ok(None);
    }
    let ir_path = out_dir.join("ir.jsonl");
    write_ir_jsonl(&ir_path, &doc)?;
    Ok(Some(ir_path))
}

fn function_arg_for_mode<'a>(
    mode: super::model::DecompileMode,
    function: Option<&'a str>,
) -> Option<&'a str> {
    if mode == super::model::DecompileMode::Function {
        function
    } else {
        None
    }
}

fn ghidra_auto_index_threshold_bytes() -> Option<u64> {
    let raw = std::env::var("RSCAN_GHIDRA_AUTO_INDEX_MB").ok();
    let mb = match raw {
        Some(v) => match v.trim().parse::<u64>() {
            Ok(0) => return None, // explicit disable
            Ok(n) => n,
            Err(_) => DEFAULT_GHIDRA_AUTO_INDEX_THRESHOLD_MB,
        },
        None => DEFAULT_GHIDRA_AUTO_INDEX_THRESHOLD_MB,
    };
    Some(mb.saturating_mul(1024 * 1024))
}

fn should_auto_switch_ghidra_full_to_index(
    requested_mode: super::model::DecompileMode,
    plan_program: &str,
    file_size_bytes: Option<u64>,
    threshold_bytes: Option<u64>,
) -> bool {
    if requested_mode != super::model::DecompileMode::Full {
        return false;
    }
    if !is_ghidra_program(plan_program) {
        return false;
    }
    let Some(limit) = threshold_bytes else {
        return false;
    };
    let Some(size) = file_size_bytes else {
        return false;
    };
    size >= limit
}

fn is_ghidra_program(program: &str) -> bool {
    let p = program.to_ascii_lowercase();
    p.contains("analyzeheadless") || p.contains("ghidra")
}

fn is_jadx_program(program: &str) -> bool {
    program.to_ascii_lowercase().contains("jadx")
}

fn path_is_nonempty_file(path: &Path) -> bool {
    path.is_file() && std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false)
}

fn path_has_any_file(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if path.is_file() {
        return std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);
    }
    let Ok(rd) = std::fs::read_dir(path) else {
        return false;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_file() {
            if std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false) {
                return true;
            }
            continue;
        }
        if p.is_dir() && path_has_any_file(&p) {
            return true;
        }
    }
    false
}

fn stderr_has_ghidra_lock(stderr_log: &Path) -> bool {
    std::fs::read_to_string(stderr_log)
        .ok()
        .map(|s| {
            let lc = s.to_ascii_lowercase();
            lc.contains("lockexception") || lc.contains("unable to lock project")
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisasmArch {
    X86_64,
    X86_32,
    Arm64,
    Arm,
    Unsupported,
}

fn detect_arch(bytes: &[u8]) -> DisasmArch {
    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::Elf(elf)) => match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => DisasmArch::X86_64,
            goblin::elf::header::EM_386 => DisasmArch::X86_32,
            goblin::elf::header::EM_AARCH64 => DisasmArch::Arm64,
            goblin::elf::header::EM_ARM => DisasmArch::Arm,
            _ => DisasmArch::Unsupported,
        },
        Ok(goblin::Object::PE(pe)) => {
            if pe.is_64 {
                DisasmArch::X86_64
            } else {
                DisasmArch::X86_32
            }
        }
        _ => DisasmArch::Unsupported,
    }
}

/// Lightweight index + asm/calls/sections/strings (Rust-only, no Ghidra).
fn run_rust_index_job(input: &Path, workspace: &Path) -> Result<DecompileRunReport, RustpenError> {
    use addr2line::Context;
    use capstone::{Capstone, arch::BuildsCapstone};
    use goblin::Object;
    use goblin::elf::sym::STT_FUNC;
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter};
    use serde_json::json;
    use std::io::Write;

    std::fs::create_dir_all(workspace)?;
    let id = new_job_id();
    let jobs_root = workspace.join("jobs");
    let job_dir = jobs_root.join(&id);
    std::fs::create_dir_all(&job_dir)?;
    let out_dir = workspace.join("reverse_out").join(&id);
    std::fs::create_dir_all(&out_dir)?;

    let index_path = out_dir.join("index.jsonl");
    let asm_path = out_dir.join("asm_preview.jsonl");
    let calls_path = out_dir.join("calls_preview.jsonl");
    let xrefs_path = out_dir.join("xrefs_preview.jsonl");
    let sections_path = out_dir.join("sections.jsonl");
    let strings_path = out_dir.join("strings_ascii.jsonl");
    let strings_utf16_path = out_dir.join("strings_utf16.jsonl");
    let stdout_log = job_dir.join("stdout.log");
    let stderr_log = job_dir.join("stderr.log");

    let bytes = std::fs::read(input)?;
    let arch = detect_arch(&bytes);

    let mut rows = Vec::new();
    let mut asm_out = Vec::new();
    let mut calls_out = Vec::new();
    let mut xrefs_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut symbol_map: HashMap<u64, String> = HashMap::new();
    let mut import_map: HashMap<u64, String> = HashMap::new();
    let mut sections_out = Vec::new();
    let mut strings_out = Vec::new();
    let mut strings_out_utf16 = Vec::new();
    let mut extra_artifacts: Vec<PathBuf> = Vec::new();
    let obj = addr2line::object::File::parse(&*bytes).ok();
    let mut dwarf_ctx: Option<
        Context<addr2line::gimli::EndianReader<addr2line::gimli::RunTimeEndian, std::rc::Rc<[u8]>>>,
    > = None;
    if let Some(ref ofile) = obj {
        if let Ok(ctx) = Context::new(ofile) {
            dwarf_ctx = Some(ctx);
        }
    }

    let demangle = |name: &str| -> Option<String> {
        let d = symbolic_demangle::demangle(name);
        match d {
            std::borrow::Cow::Owned(s) => Some(s),
            std::borrow::Cow::Borrowed(s) if s != name => Some(s.to_string()),
            _ => None,
        }
    };

    let entry_addr = match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let entry = elf.entry;
            rows.push(json!({ "ea": format!("0x{:x}", entry), "name": "entry", "signature": "", "size": 0 }));
            let strtab = elf.strtab;
            for sym in elf.syms.iter() {
                if sym.st_type() != STT_FUNC || sym.st_value == 0 {
                    continue;
                }
                if let Some(name) = strtab.get_at(sym.st_name) {
                    let mut row = json!({ "ea": format!("0x{:x}", sym.st_value), "name": name, "signature": "", "size": sym.st_size });
                    if let Some(d) = demangle(name) {
                        row["demangled"] = serde_json::Value::String(d.clone());
                        symbol_map.insert(sym.st_value, d);
                    } else {
                        symbol_map.insert(sym.st_value, name.to_string());
                    }
                    if let Some(ctx) = dwarf_ctx.as_ref() {
                        if let Ok(Some(loc)) = ctx.find_location(sym.st_value) {
                            if let (Some(file), Some(line)) = (loc.file, loc.line) {
                                row["signature"] = json!(format!("{}:{}", file, line));
                            }
                        }
                    }
                    rows.push(row);
                }
            }
            for sh in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    sections_out.push(json!({
                        "name": name,
                        "addr": format!("0x{:x}", sh.sh_addr),
                        "size": sh.sh_size,
                        "flags": sh.sh_flags,
                    }));
                }
            }
            for sym in elf.dynsyms.iter() {
                if sym.st_value == 0 {
                    continue;
                }
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    import_map.insert(sym.st_value, name.to_string());
                }
            }
            Some(entry)
        }
        Ok(Object::PE(pe)) => {
            let entry = (pe.entry as u64).saturating_add(pe.image_base as u64);
            rows.push(json!({ "ea": format!("0x{:x}", entry), "name": "entry", "signature": "", "size": 0 }));
            for exp in pe.exports.iter() {
                let va = exp.rva as u64 + pe.image_base as u64;
                if let Some(name) = exp.name {
                    let demangled = demangle(name).unwrap_or_else(|| name.to_string());
                    symbol_map.insert(va, demangled.clone());
                    rows.push(json!({ "ea": format!("0x{:x}", va), "name": name, "demangled": demangled, "signature": "", "size": 0 }));
                } else {
                    rows.push(json!({ "ea": format!("0x{:x}", va), "name": "export", "signature": "", "size": 0 }));
                }
            }
            for imp in &pe.imports {
                let dll = imp.dll;
                let name = if !imp.name.is_empty() {
                    imp.name.to_string()
                } else if imp.ordinal != 0 {
                    format!("#{}", imp.ordinal)
                } else {
                    "<ordinal>".to_string()
                };
                import_map.insert(
                    imp.rva as u64 + pe.image_base as u64,
                    format!("{}!{}", dll, name),
                );
            }
            for s in &pe.sections {
                sections_out.push(json!({
                    "name": s.name().unwrap_or("<none>"),
                    "addr": format!("0x{:x}", s.virtual_address as u64 + pe.image_base as u64),
                    "size": s.virtual_size.max(s.size_of_raw_data) as u64,
                    "characteristics": s.characteristics,
                }));
            }
            Some(entry)
        }
        _ => {
            return Err(RustpenError::ParseError(
                "unsupported binary for rust index backend (expect ELF/PE)".to_string(),
            ));
        }
    };

    // ASCII strings
    const STR_MIN: usize = 4;
    const STR_MAX: usize = 5000;
    let mut cur = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if (0x20..=0x7e).contains(b) {
            cur.push(*b);
        } else {
            if cur.len() >= STR_MIN {
                strings_out.push(json!({
                    "off": format!("0x{:x}", i + 1 - cur.len()),
                    "s": String::from_utf8_lossy(&cur),
                }));
                if strings_out.len() >= STR_MAX {
                    break;
                }
            }
            cur.clear();
        }
    }
    // UTF-16LE strings
    let mut cur16 = Vec::<u16>::new();
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let v = u16::from_le_bytes([chunk[0], chunk[1]]);
        if (0x20u16..=0x7eu16).contains(&v) {
            cur16.push(v);
        } else {
            if cur16.len() >= STR_MIN {
                let off = idx * 2 + 2 - cur16.len() * 2;
                strings_out_utf16.push(json!({
                    "off": format!("0x{:x}", off),
                    "s": String::from_utf16_lossy(&cur16),
                }));
                if strings_out_utf16.len() >= STR_MAX {
                    break;
                }
            }
            cur16.clear();
        }
    }

    // Disassembly & calls (stream all; soft cap to avoid OOM)
    const ASM_LIMIT_INDEX: usize = 400_000;
    const ASM_LIMIT_ASM: usize = 200_000;
    let asm_limit = ASM_LIMIT_INDEX;
    match arch {
        DisasmArch::X86_64 | DisasmArch::X86_32 => {
            let bitness = if matches!(arch, DisasmArch::X86_64) {
                64
            } else {
                32
            };
            let decoder = Decoder::with_ip(bitness, &bytes, 0, DecoderOptions::NONE);
            let mut decoder = decoder;
            let mut formatter = NasmFormatter::new();
            formatter.options_mut().set_first_operand_char_index(10);
            let mut instr = Instruction::default();
            let mut count = 0usize;
            let mut func_calls: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
            let mut func_xrefs: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
            let mut func_blocks: HashMap<u64, Vec<(u64, u64, FlowControl)>> = HashMap::new();
            let reloc_syms = build_reloc_symbol_map(&bytes).unwrap_or_default();

            // simple func list for grouping (use symbol_map keys)
            let mut func_addrs: Vec<u64> = symbol_map.keys().copied().collect();
            if let Some(entry) = entry_addr {
                func_addrs.push(entry);
            }
            func_addrs.sort_unstable();
            let lookup_func = |addr: u64, funcs: &Vec<u64>| -> Option<u64> {
                funcs.iter().rev().find(|a| addr >= **a).copied()
            };

            while decoder.can_decode() && count < asm_limit {
                decoder.decode_out(&mut instr);
                let mut line = String::new();
                let _ = formatter.format(&instr, &mut line);
                asm_out.push(json!({"ea": format!("0x{:x}", instr.ip()), "text": line}));

                // cfg blocks
                if let Some(func) = lookup_func(instr.ip(), &func_addrs) {
                    let bb = func_blocks.entry(func).or_default();
                    if bb
                        .last()
                        .map(|(_, _, fc)| fc != &instr.flow_control())
                        .unwrap_or(true)
                    {
                        bb.push((instr.ip(), instr.len() as u64, instr.flow_control()));
                    } else if let Some(last) = bb.last_mut() {
                        last.1 += instr.len() as u64;
                    }
                }

                if instr.is_call_near() || instr.is_call_far() {
                    if instr.op_count() > 0 {
                        let op0 = instr.op0_kind();
                        if op0 == iced_x86::OpKind::NearBranch64
                            || op0 == iced_x86::OpKind::NearBranch32
                        {
                            let from = format!("0x{:x}", instr.ip());
                            let to = instr.near_branch_target();
                            let to_str = format!("0x{:x}", to);
                            let name = symbol_map
                                .get(&to)
                                .or_else(|| import_map.get(&to))
                                .or_else(|| reloc_syms.get(&to))
                                .cloned();
                            calls_out.push(
                                json!({"from": from.clone(), "to": to_str.clone(), "symbol": name}),
                            );
                            xrefs_map.entry(to_str).or_default().push(from.clone());
                            if let Some(func) = lookup_func(instr.ip(), &func_addrs) {
                                func_calls
                                    .entry(func)
                                    .or_default()
                                    .push(json!({"from": instr.ip(), "to": to, "symbol": name}));
                            }
                            if let Some(func) = lookup_func(to, &func_addrs) {
                                func_xrefs
                                    .entry(func)
                                    .or_default()
                                    .push(json!({"from": instr.ip(), "to": to, "symbol": name}));
                            }
                        }
                    }
                }

                // tail call (jmp near)
                if instr.mnemonic() == iced_x86::Mnemonic::Jmp
                    && instr.op_count() > 0
                    && (instr.op0_kind() == iced_x86::OpKind::NearBranch64
                        || instr.op0_kind() == iced_x86::OpKind::NearBranch32)
                {
                    let to = instr.near_branch_target();
                    let to_str = format!("0x{:x}", to);
                    let name = symbol_map
                        .get(&to)
                        .or_else(|| import_map.get(&to))
                        .or_else(|| reloc_syms.get(&to))
                        .cloned();
                    xrefs_map
                        .entry(to_str.clone())
                        .or_default()
                        .push(format!("0x{:x}", instr.ip()));
                    // mark as call edge for tail call
                    calls_out.push(json!({"from": format!("0x{:x}", instr.ip()), "to": to_str, "symbol": name, "tail": true}));
                }
                count += 1;
            }

            // per-function calls/xrefs/cfg
            let calls_func_path = out_dir.join("calls_functions.jsonl");
            let xrefs_func_path = out_dir.join("xrefs_functions.jsonl");
            let cfg_path = out_dir.join("cfg_functions.jsonl");
            extra_artifacts.push(calls_func_path.clone());
            extra_artifacts.push(xrefs_func_path.clone());
            extra_artifacts.push(cfg_path.clone());
            let mut f_calls = std::fs::File::create(&calls_func_path).map_err(RustpenError::Io)?;
            for (func, edges) in &func_calls {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "calls": edges});
                writeln!(
                    f_calls,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
            let mut f_xrefs = std::fs::File::create(&xrefs_func_path).map_err(RustpenError::Io)?;
            for (func, edges) in &func_xrefs {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "xrefs": edges});
                writeln!(
                    f_xrefs,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
            let mut f_cfg = std::fs::File::create(&cfg_path).map_err(RustpenError::Io)?;
            for (func, blocks) in &func_blocks {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let bbs: Vec<_> = blocks
                    .iter()
                    .map(|(a, len, fc)| json!({ "addr": format!("0x{:x}", a), "len": len, "flow": format!("{:?}", fc) }))
                    .collect();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "blocks": bbs});
                writeln!(
                    f_cfg,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
        }
        DisasmArch::Arm | DisasmArch::Arm64 => {
            let cs = if matches!(arch, DisasmArch::Arm64) {
                Capstone::new()
                    .arm64()
                    .mode(capstone::arch::arm64::ArchMode::Arm)
                    .detail(false)
                    .build()
            } else {
                Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Arm)
                    .detail(false)
                    .build()
            }
            .map_err(|e| RustpenError::ParseError(format!("capstone init: {}", e)))?;

            let insns = cs
                .disasm_all(&bytes, 0)
                .map_err(|e| RustpenError::ParseError(format!("capstone disasm: {}", e)))?;
            let mut func_calls: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
            let mut func_xrefs: HashMap<u64, Vec<serde_json::Value>> = HashMap::new();
            let mut func_blocks: HashMap<u64, Vec<(u64, u64, String, Vec<String>)>> =
                HashMap::new();
            let mut func_addrs: Vec<u64> = symbol_map.keys().copied().collect();
            if let Some(entry) = entry_addr {
                func_addrs.push(entry);
            }
            func_addrs.sort_unstable();
            func_addrs.dedup();
            let lookup_func = |addr: u64, funcs: &Vec<u64>| -> Option<u64> {
                funcs.iter().rev().find(|a| addr >= **a).copied()
            };

            for ins in insns.iter().take(asm_limit) {
                asm_out
                    .push(json!({"ea": format!("0x{:x}", ins.address()), "text": ins.to_string()}));
                let mnemonic = ins.mnemonic().unwrap_or("").to_ascii_lowercase();
                if let Some(func) = lookup_func(ins.address(), &func_addrs) {
                    let flow = if mnemonic.starts_with("ret") || mnemonic == "bx" {
                        "Return"
                    } else if mnemonic.starts_with('b') {
                        "Branch"
                    } else {
                        "Next"
                    };
                    let blocks = func_blocks.entry(func).or_default();
                    let mut targets = Vec::new();
                    if flow == "Branch" {
                        if let Some(op) = ins.op_str() {
                            if let Some(hex) = op.trim().strip_prefix("0x") {
                                if let Ok(t) = u64::from_str_radix(hex, 16) {
                                    targets.push(format!("0x{:x}", t));
                                }
                            }
                        }
                    }
                    if blocks
                        .last()
                        .map(|(_, _, last_flow, _)| last_flow != flow)
                        .unwrap_or(true)
                    {
                        blocks.push((
                            ins.address(),
                            ins.bytes().len() as u64,
                            flow.to_string(),
                            targets,
                        ));
                    } else if let Some(last) = blocks.last_mut() {
                        last.1 += ins.bytes().len() as u64;
                        last.3.extend(targets);
                    }
                }
                if mnemonic.starts_with("bl") {
                    if let Some(op) = ins.op_str() {
                        if let Some(stripped) = op.trim().strip_prefix("0x") {
                            if let Ok(to) = u64::from_str_radix(stripped, 16) {
                                let from = format!("0x{:x}", ins.address());
                                let to_str = format!("0x{:x}", to);
                                let name =
                                    symbol_map.get(&to).or_else(|| import_map.get(&to)).cloned();
                                calls_out.push(json!({"from": from.clone(), "to": to_str.clone(), "symbol": name}));
                                xrefs_map.entry(to_str).or_default().push(from);
                                if let Some(func) = lookup_func(ins.address(), &func_addrs) {
                                    func_calls
                                        .entry(func)
                                        .or_default()
                                        .push(json!({"from": ins.address(), "to": to, "symbol": name.clone()}));
                                }
                                if let Some(func) = lookup_func(to, &func_addrs) {
                                    func_xrefs.entry(func).or_default().push(
                                        json!({"from": ins.address(), "to": to, "symbol": name}),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            // per-function outputs for ARM/ARM64
            let calls_func_path = out_dir.join("calls_functions.jsonl");
            let xrefs_func_path = out_dir.join("xrefs_functions.jsonl");
            let cfg_path = out_dir.join("cfg_functions.jsonl");
            extra_artifacts.push(calls_func_path.clone());
            extra_artifacts.push(xrefs_func_path.clone());
            extra_artifacts.push(cfg_path.clone());
            let mut f_calls = std::fs::File::create(&calls_func_path).map_err(RustpenError::Io)?;
            for (func, edges) in &func_calls {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "calls": edges});
                writeln!(
                    f_calls,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
            let mut f_xrefs = std::fs::File::create(&xrefs_func_path).map_err(RustpenError::Io)?;
            for (func, edges) in &func_xrefs {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "xrefs": edges});
                writeln!(
                    f_xrefs,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
            let mut f_cfg = std::fs::File::create(&cfg_path).map_err(RustpenError::Io)?;
            for (func, blocks) in &func_blocks {
                let name = symbol_map.get(func).cloned().unwrap_or_default();
                let bbs: Vec<_> = blocks
                    .iter()
                    .map(|(a, len, flow, tgt)| {
                        json!({ "addr": format!("0x{:x}", a), "len": len, "flow": flow, "targets": tgt })
                    })
                    .collect();
                let row = json!({"func": format!("0x{:x}", func), "name": name, "blocks": bbs});
                writeln!(
                    f_cfg,
                    "{}",
                    serde_json::to_string(&row)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                )
                .map_err(RustpenError::Io)?;
            }
        }
        DisasmArch::Unsupported => { /* leave empty; will still output index/sections/strings */ }
    }

    // Write outputs
    let mut f = std::fs::File::create(&index_path).map_err(RustpenError::Io)?;
    for row in &rows {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&asm_path).map_err(RustpenError::Io)?;
    for row in &asm_out {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&calls_path).map_err(RustpenError::Io)?;
    for row in &calls_out {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&xrefs_path).map_err(RustpenError::Io)?;
    for (to, froms) in &xrefs_map {
        let row = json!({ "to": to, "froms": froms });
        writeln!(
            f,
            "{}",
            serde_json::to_string(&row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&sections_path).map_err(RustpenError::Io)?;
    for row in &sections_out {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&strings_path).map_err(RustpenError::Io)?;
    for row in &strings_out {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let mut f = std::fs::File::create(&strings_utf16_path).map_err(RustpenError::Io)?;
    for row in &strings_out_utf16 {
        writeln!(
            f,
            "{}",
            serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?
        )
        .map_err(RustpenError::Io)?;
    }
    let ir_path = out_dir.join("ir.jsonl");
    let mut ir_doc = super::ir::ReverseIrDoc {
        meta: super::ir::IrBinaryMeta {
            sample: input.display().to_string(),
            backend: "rust-index".to_string(),
            format: None,
            arch: Some(format!("{arch:?}")),
            entry: entry_addr.map(|v| format!("0x{:x}", v)),
            file_size: std::fs::metadata(input).ok().map(|m| m.len()),
        },
        ..Default::default()
    };
    for row in &rows {
        let ea = row
            .get("ea")
            .and_then(|v| v.as_str())
            .unwrap_or("0x0")
            .to_string();
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let signature = row
            .get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let demangled = row
            .get("demangled")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let size = row.get("size").and_then(|v| v.as_u64());
        ir_doc.functions.push(super::ir::IrFunction {
            ea,
            name,
            demangled,
            signature,
            size,
            pseudocode: None,
            asm_preview: None,
            tags: Vec::new(),
        });
    }
    write_ir_jsonl(&ir_path, &ir_doc)?;

    std::fs::write(
        &stdout_log,
        format!(
            "rust index arch={:?} rows={} asm={} calls={} xrefs={} strings16={}\n",
            arch,
            rows.len(),
            asm_out.len(),
            calls_out.len(),
            xrefs_map.len(),
            strings_out_utf16.len()
        ),
    )?;
    std::fs::write(&stderr_log, "")?;

    let job = ReverseJobMeta {
        id,
        kind: "decompile".to_string(),
        backend: "rust-index".to_string(),
        mode: Some("index".to_string()),
        function: None,
        target: input.to_path_buf(),
        workspace: workspace.to_path_buf(),
        status: ReverseJobStatus::Succeeded,
        created_at: now_epoch_secs(),
        started_at: Some(now_epoch_secs()),
        ended_at: Some(now_epoch_secs()),
        exit_code: Some(0),
        program: "rust-index".to_string(),
        args: Vec::new(),
        note: "rust index backend (no Ghidra)".to_string(),
        artifacts: {
            let mut arts = vec![
                path_to_string(index_path),
                path_to_string(asm_path),
                path_to_string(calls_path),
                path_to_string(xrefs_path),
                path_to_string(sections_path),
                path_to_string(strings_path),
                path_to_string(strings_utf16_path),
                path_to_string(ir_path),
            ];
            arts.extend(extra_artifacts.into_iter().map(path_to_string));
            arts
        },
        error: None,
    };
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    Ok(DecompileRunReport {
        job,
        stdout_log,
        stderr_log,
    })
}

/// Lightweight ASM-only export (no pseudocode), supports x86/x86_64 and ARM/ARM64.
fn run_rust_asm_job(
    input: &Path,
    workspace: &Path,
    mode: super::model::DecompileMode,
) -> Result<DecompileRunReport, RustpenError> {
    use capstone::{Capstone, arch::BuildsCapstone};
    use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
    use serde_json::json;
    use std::io::Write;

    std::fs::create_dir_all(workspace)?;
    let id = new_job_id();
    let jobs_root = workspace.join("jobs");
    let job_dir = jobs_root.join(&id);
    std::fs::create_dir_all(&job_dir)?;
    let out_dir = workspace.join("reverse_out").join(&id);
    std::fs::create_dir_all(&out_dir)?;

    let asm_path = out_dir.join(match mode {
        super::model::DecompileMode::Function => "function_asm.jsonl",
        _ => "asm_full.jsonl",
    });
    let calls_path = out_dir.join(match mode {
        super::model::DecompileMode::Function => "function_calls.jsonl",
        _ => "calls.jsonl",
    });
    let xrefs_path = out_dir.join(match mode {
        super::model::DecompileMode::Function => "function_xrefs.jsonl",
        _ => "xrefs.jsonl",
    });
    let stdout_log = job_dir.join("stdout.log");
    let stderr_log = job_dir.join("stderr.log");

    let bytes = std::fs::read(input)?;
    let arch = detect_arch(&bytes);

    let mut asm_out = Vec::new();
    let mut calls_out = Vec::new();
    let mut xrefs_map: HashMap<String, Vec<String>> = HashMap::new();

    match arch {
        DisasmArch::X86_64 | DisasmArch::X86_32 => {
            let bitness = if matches!(arch, DisasmArch::X86_64) {
                64
            } else {
                32
            };
            let mut decoder = Decoder::with_ip(bitness, &bytes, 0, DecoderOptions::NONE);
            let mut formatter = NasmFormatter::new();
            formatter.options_mut().set_first_operand_char_index(10);
            let mut instr = Instruction::default();
            let mut count = 0usize;
            while decoder.can_decode() && count < 20_000 {
                decoder.decode_out(&mut instr);
                let mut line = String::new();
                let _ = formatter.format(&instr, &mut line);
                asm_out.push(json!({"ea": format!("0x{:x}", instr.ip()), "text": line}));
                if instr.is_call_near() || instr.is_call_far() {
                    if instr.op_count() > 0 {
                        let op0 = instr.op0_kind();
                        if op0 == iced_x86::OpKind::NearBranch64
                            || op0 == iced_x86::OpKind::NearBranch32
                        {
                            let from = format!("0x{:x}", instr.ip());
                            let to = format!("0x{:x}", instr.near_branch_target());
                            calls_out.push(json!({ "from": from.clone(), "to": to.clone() }));
                            xrefs_map.entry(to).or_default().push(from);
                        }
                    }
                }
                count += 1;
            }
        }
        DisasmArch::Arm | DisasmArch::Arm64 => {
            let cs = if matches!(arch, DisasmArch::Arm64) {
                Capstone::new()
                    .arm64()
                    .mode(capstone::arch::arm64::ArchMode::Arm)
                    .detail(false)
                    .build()
            } else {
                Capstone::new()
                    .arm()
                    .mode(capstone::arch::arm::ArchMode::Arm)
                    .detail(false)
                    .build()
            }
            .map_err(|e| RustpenError::ParseError(format!("capstone init: {}", e)))?;

            let insns = cs
                .disasm_all(&bytes, 0)
                .map_err(|e| RustpenError::ParseError(format!("capstone disasm: {}", e)))?;
            for ins in insns.iter().take(20_000) {
                asm_out
                    .push(json!({"ea": format!("0x{:x}", ins.address()), "text": ins.to_string()}));
                let mnem = ins.mnemonic().unwrap_or("").to_ascii_lowercase();
                if mnem.starts_with("bl") {
                    if let Some(op) = ins.op_str() {
                        if let Some(hex) = op.trim().strip_prefix("0x") {
                            if let Ok(to_u64) = u64::from_str_radix(hex, 16) {
                                let from = format!("0x{:x}", ins.address());
                                let to = format!("0x{:x}", to_u64);
                                calls_out.push(json!({ "from": from.clone(), "to": to.clone() }));
                                xrefs_map.entry(to).or_default().push(from);
                            }
                        }
                    }
                }
            }
        }
        DisasmArch::Unsupported => { /* leave empty */ }
    }

    // write outputs
    {
        let mut f = std::fs::File::create(&asm_path).map_err(RustpenError::Io)?;
        for row in &asm_out {
            let line =
                serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?;
            writeln!(f, "{line}").map_err(RustpenError::Io)?;
        }
    }
    {
        let mut f = std::fs::File::create(&calls_path).map_err(RustpenError::Io)?;
        for row in &calls_out {
            let line =
                serde_json::to_string(row).map_err(|e| RustpenError::ParseError(e.to_string()))?;
            writeln!(f, "{line}").map_err(RustpenError::Io)?;
        }
    }
    {
        let mut f = std::fs::File::create(&xrefs_path).map_err(RustpenError::Io)?;
        for (to, froms) in &xrefs_map {
            let row = json!({ "to": to, "froms": froms });
            let line =
                serde_json::to_string(&row).map_err(|e| RustpenError::ParseError(e.to_string()))?;
            writeln!(f, "{line}").map_err(RustpenError::Io)?;
        }
    }

    std::fs::write(
        &stdout_log,
        format!(
            "rust asm backend arch={:?} asm={} calls={} xrefs={}\n",
            arch,
            asm_out.len(),
            calls_out.len(),
            xrefs_map.len()
        ),
    )?;
    std::fs::write(&stderr_log, "")?;

    let job = ReverseJobMeta {
        id,
        kind: "decompile".to_string(),
        backend: "rust-asm".to_string(),
        mode: Some(format!("{:?}", mode).to_ascii_lowercase()),
        function: None,
        target: input.to_path_buf(),
        workspace: workspace.to_path_buf(),
        status: ReverseJobStatus::Succeeded,
        created_at: now_epoch_secs(),
        started_at: Some(now_epoch_secs()),
        ended_at: Some(now_epoch_secs()),
        exit_code: Some(0),
        program: "rust-asm".to_string(),
        args: Vec::new(),
        note: "rust asm-only backend (no pseudocode)".to_string(),
        artifacts: vec![
            path_to_string(asm_path),
            path_to_string(calls_path),
            path_to_string(xrefs_path),
            path_to_string(stdout_log.clone()),
            path_to_string(stderr_log.clone()),
        ],
        error: None,
    };
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    Ok(DecompileRunReport {
        job,
        stdout_log,
        stderr_log,
    })
}
fn run_with_logs_and_timeout(
    program: &str,
    args: &[String],
    stdout_log: &Path,
    stderr_log: &Path,
    timeout_secs: Option<u64>,
) -> Result<Option<i32>, RustpenError> {
    let stdout = std::fs::File::create(stdout_log)?;
    let stderr = std::fs::File::create(stderr_log)?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|e| RustpenError::ScanError(format!("failed to launch {}: {}", program, e)))?;

    let Some(timeout_secs) = timeout_secs else {
        let status = child
            .wait()
            .map_err(|e| RustpenError::ScanError(format!("wait failed for {}: {}", program, e)))?;
        return Ok(status.code());
    };

    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs.max(1));
    loop {
        match child
            .try_wait()
            .map_err(|e| RustpenError::ScanError(format!("try_wait failed: {}", e)))?
        {
            Some(status) => return Ok(status.code()),
            None => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RustpenError::ScanError(format!(
                        "decompile job timeout after {}s",
                        timeout_secs
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ReverseJobMeta, ReverseJobStatus, is_ghidra_program, is_jadx_program, is_probable_apk,
        path_has_any_file,
        should_auto_switch_ghidra_full_to_index, try_emit_ir_artifact,
    };
    #[test]
    fn ghidra_program_detection_works() {
        assert!(is_ghidra_program("analyzeHeadless"));
        assert!(is_ghidra_program("/opt/ghidra/support/analyzeHeadless"));
        assert!(!is_ghidra_program("jadx"));
    }

    #[test]
    fn jadx_program_detection_works() {
        assert!(is_jadx_program("jadx"));
        assert!(is_jadx_program("/usr/bin/jadx"));
        assert!(!is_jadx_program("analyzeHeadless"));
    }

    #[test]
    fn path_has_any_file_detects_nested_tree() {
        let root = std::env::temp_dir().join(format!("rscan_any_file_{}", super::new_job_id()));
        let nested = root.join("sources").join("com").join("demo");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(!path_has_any_file(&root));
        std::fs::write(nested.join("A.java"), "class A {}\n").unwrap();
        assert!(path_has_any_file(&root));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn auto_switch_only_for_full_and_large_ghidra_jobs() {
        let full = crate::modules::reverse::model::DecompileMode::Full;
        let index = crate::modules::reverse::model::DecompileMode::Index;
        assert!(should_auto_switch_ghidra_full_to_index(
            full,
            "analyzeHeadless",
            Some(30 * 1024 * 1024),
            Some(25 * 1024 * 1024)
        ));
        assert!(!should_auto_switch_ghidra_full_to_index(
            full,
            "jadx",
            Some(30 * 1024 * 1024),
            Some(25 * 1024 * 1024)
        ));
        assert!(!should_auto_switch_ghidra_full_to_index(
            index,
            "analyzeHeadless",
            Some(30 * 1024 * 1024),
            Some(25 * 1024 * 1024)
        ));
        assert!(!should_auto_switch_ghidra_full_to_index(
            full,
            "analyzeHeadless",
            Some(10 * 1024 * 1024),
            Some(25 * 1024 * 1024)
        ));
    }

    #[test]
    fn emit_ir_artifact_from_ghidra_index_rows() {
        let ws = std::env::temp_dir().join(format!("rscan_ir_emit_{}", super::new_job_id()));
        let out_dir = ws.join("reverse_out").join("job-test");
        std::fs::create_dir_all(&out_dir).unwrap();
        let index_path = out_dir.join("index.jsonl");
        std::fs::write(
            &index_path,
            "{\"ea\":\"0x401000\",\"name\":\"main\",\"size\":64}\n",
        )
        .unwrap();
        let target = ws.join("sample.bin");
        std::fs::write(&target, b"\x7fELF").unwrap();
        let job = ReverseJobMeta {
            id: "job-test".to_string(),
            kind: "decompile".to_string(),
            backend: "ghidra".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: target.clone(),
            workspace: ws.clone(),
            status: ReverseJobStatus::Succeeded,
            created_at: 0,
            started_at: None,
            ended_at: None,
            exit_code: Some(0),
            program: "analyzeHeadless".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: vec![index_path.to_string_lossy().to_string()],
            error: None,
        };
        let ir = try_emit_ir_artifact(&ws, &job).unwrap();
        assert!(ir.is_some());
        let ir_path = ir.unwrap();
        let text = std::fs::read_to_string(&ir_path).unwrap();
        assert!(text.contains("\"kind\":\"meta\""));
        assert!(text.contains("\"kind\":\"function\""));

        let _ = std::fs::remove_file(index_path);
        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(ir_path);
        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn apk_detection_uses_magic_and_markers() {
        let p = std::env::temp_dir().join(format!("rscan_apk_probe_{}.zip", super::new_job_id()));
        let mut blob = b"PK\x03\x04".to_vec();
        blob.extend_from_slice(b"........AndroidManifest.xml....classes.dex....");
        std::fs::write(&p, blob).unwrap();
        assert!(is_probable_apk(&p));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn emit_ir_artifact_from_jadx_sources_without_jsonl() {
        let ws = std::env::temp_dir().join(format!("rscan_ir_jadx_{}", super::new_job_id()));
        let out_dir = ws.join("reverse_out").join("job-jadx");
        let src_dir = out_dir.join("sources").join("com").join("demo");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("MainActivity.java"),
            "public class MainActivity {\n  public void onCreate(){\n  }\n}\n",
        )
        .unwrap();
        let target = ws.join("sample.apk");
        std::fs::write(
            &target,
            b"PK\x03\x04......AndroidManifest.xml....classes.dex....",
        )
        .unwrap();
        let job = ReverseJobMeta {
            id: "job-jadx".to_string(),
            kind: "decompile".to_string(),
            backend: "jadx".to_string(),
            mode: Some("full".to_string()),
            function: None,
            target: target.clone(),
            workspace: ws.clone(),
            status: ReverseJobStatus::Succeeded,
            created_at: 0,
            started_at: None,
            ended_at: None,
            exit_code: Some(0),
            program: "jadx".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: Vec::new(),
            error: None,
        };
        let ir = try_emit_ir_artifact(&ws, &job).unwrap();
        assert!(ir.is_some());
        let ir_path = ir.unwrap();
        let text = std::fs::read_to_string(&ir_path).unwrap();
        assert!(text.contains("\"kind\":\"function\""));
        assert!(text.contains("jadx::"));

        let _ = std::fs::remove_file(target);
        let _ = std::fs::remove_file(ir_path);
        let _ = std::fs::remove_dir_all(ws);
    }
}
fn build_reloc_symbol_map(bytes: &[u8]) -> Result<HashMap<u64, String>, RustpenError> {
    let mut map = HashMap::new();
    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::Elf(elf)) => {
            // dynsyms names
            let mut sym_names = HashMap::new();
            for (idx, sym) in elf.dynsyms.iter().enumerate() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    sym_names.insert(idx as u32, name.to_string());
                }
            }
            for r in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
                if let Some(name) = sym_names.get(&(r.r_sym as u32)) {
                    map.insert(r.r_offset, name.clone());
                }
            }
            for r in elf.pltrelocs.iter() {
                if let Some(name) = sym_names.get(&(r.r_sym as u32)) {
                    map.insert(r.r_offset, name.clone());
                }
            }
        }
        Ok(goblin::Object::PE(pe)) => {
            // use imports
            for imp in pe.imports.iter() {
                let addr = imp.rva as u64 + pe.image_base as u64;
                let name = if !imp.name.is_empty() {
                    imp.name.to_string()
                } else if imp.ordinal != 0 {
                    format!("#{}", imp.ordinal)
                } else {
                    "<ordinal>".to_string()
                };
                map.insert(addr, format!("{}!{}", imp.dll, name));
            }
        }
        _ => {}
    }
    Ok(map)
}
