use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader};

use crate::errors::RustpenError;

use super::orchestrator::ReverseOrchestrator;

const DEFAULT_GHIDRA_AUTO_INDEX_THRESHOLD_MB: u64 = 25;

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
    std::fs::create_dir_all(workspace)?;
    let orchestrator = ReverseOrchestrator::detect();
    let id = new_job_id();
    let jobs_root = workspace.join("jobs");
    let job_dir = jobs_root.join(&id);
    std::fs::create_dir_all(&job_dir)?;
    let out_dir = workspace.join("reverse_out").join(&id);
    std::fs::create_dir_all(&out_dir)?;

    let preferred = if engine_name.eq_ignore_ascii_case("auto") {
        None
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
    if should_auto_switch_ghidra_full_to_index(
        requested_mode,
        &plan.program,
        std::fs::metadata(input).ok().map(|m| m.len()),
        ghidra_auto_index_threshold_bytes(),
    ) {
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
        adaptive_note = Some(format!(
            "adaptive_ghidra_mode: full->index (file_size={} bytes >= threshold={} bytes)",
            file_size, threshold
        ));
    }
    let backend = preferred.unwrap_or("auto").to_string();
    let artifact_name = match effective_mode {
        super::model::DecompileMode::Full => "pseudocode.jsonl",
        super::model::DecompileMode::Index => "index.jsonl",
        super::model::DecompileMode::Function => "function.jsonl",
    };
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
        artifacts: vec![
            path_to_string(out_dir.join(artifact_name)),
            path_to_string(job_dir.join("stdout.log")),
            path_to_string(job_dir.join("stderr.log")),
        ],
        error: None,
    };
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    job.status = ReverseJobStatus::Running;
    job.started_at = Some(now_epoch_secs());
    save_job_meta(&job_dir.join("meta.json"), &job)?;

    let stdout_log = job_dir.join("stdout.log");
    let stderr_log = job_dir.join("stderr.log");
    let run_status = match run_with_logs_and_timeout(
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

    job.ended_at = Some(now_epoch_secs());
    job.exit_code = run_status;
    let pseudo_path = out_dir.join(artifact_name);
    let pseudo_ok = pseudo_path.is_file()
        && std::fs::metadata(&pseudo_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
    if run_status == Some(0) && pseudo_ok {
        job.status = ReverseJobStatus::Succeeded;
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
    let file = std::fs::File::open(&pseudo)?;
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
            a.ends_with("function.jsonl") || a.ends_with("pseudocode.jsonl") || a.ends_with("index.jsonl")
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
        let status = child.wait().map_err(|e| {
            RustpenError::ScanError(format!("wait failed for {}: {}", program, e))
        })?;
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
    use super::{is_ghidra_program, should_auto_switch_ghidra_full_to_index};

    #[test]
    fn ghidra_program_detection_works() {
        assert!(is_ghidra_program("analyzeHeadless"));
        assert!(is_ghidra_program("/opt/ghidra/support/analyzeHeadless"));
        assert!(!is_ghidra_program("idat64"));
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
            "idat64",
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
}
