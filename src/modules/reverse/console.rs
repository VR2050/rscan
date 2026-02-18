use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use goblin::Object;
use serde_json::Value;

use crate::errors::RustpenError;

use super::{
    BackendCatalog, DebugProfile, DecompileMode, DecompilerEngine, MalwareAnalyzer, ReverseAnalyzer,
    ReverseOrchestrator, ReverseTooling, RuleLibrary, analyzer::detect_format, inspect_job_health,
    list_jobs, load_job_by_id, load_job_pseudocode_rows, prune_jobs, run_decompile_job,
};

#[derive(Debug, Clone)]
pub struct ReverseConsoleConfig {
    pub input: PathBuf,
    pub workspace: PathBuf,
    pub pwndbg_init: Option<PathBuf>,
}

#[derive(Debug)]
struct OutputRouter {
    sink: Option<File>,
    sink_path: Option<PathBuf>,
    tee_stdout: bool,
}

impl OutputRouter {
    fn new() -> Self {
        Self {
            sink: None,
            sink_path: None,
            tee_stdout: false,
        }
    }
}

fn router() -> &'static Mutex<OutputRouter> {
    static ROUTER: OnceLock<Mutex<OutputRouter>> = OnceLock::new();
    ROUTER.get_or_init(|| Mutex::new(OutputRouter::new()))
}

fn out_write(data: &str) {
    let lock = router().lock();
    if let Ok(mut r) = lock {
        if r.sink.is_none() || r.tee_stdout {
            let _ = io::stdout().write_all(data.as_bytes());
            let _ = io::stdout().flush();
        }
        if let Some(sink) = r.sink.as_mut() {
            let _ = sink.write_all(data.as_bytes());
            let _ = sink.flush();
        }
    } else {
        let _ = io::stdout().write_all(data.as_bytes());
        let _ = io::stdout().flush();
    }
}

macro_rules! cprint {
    ($($arg:tt)*) => {{
        out_write(&format!($($arg)*));
    }};
}

macro_rules! cprintln {
    () => {{
        out_write("\n");
    }};
    ($($arg:tt)*) => {{
        out_write(&format!("{}\n", format!($($arg)*)));
    }};
}

pub fn run_interactive(cfg: ReverseConsoleConfig) -> Result<(), RustpenError> {
    let workspace = std::fs::canonicalize(&cfg.workspace).unwrap_or_else(|_| cfg.workspace.clone());
    cprintln!("rscan reverse interactive console");
    cprintln!("target: {}", cfg.input.display());
    cprintln!("type 'help' for commands");

    let mut last_job: Option<String> = None;
    let mut pinned_job: Option<String> = None;
    let mut row_cache: HashMap<String, Vec<Value>> = HashMap::new();
    loop {
        print!("rscan-re> ");
        io::stdout().flush().map_err(RustpenError::Io)?;

        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(RustpenError::Io)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or_default();

        match cmd {
            "bind-output" => {
                let path = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "bind-output <path> [tee]".to_string(),
                })?;
                let tee = parts
                    .next()
                    .map(|v| v.eq_ignore_ascii_case("tee"))
                    .unwrap_or(false);
                bind_output(path, tee)?;
                cprintln!("[rscan] output bound to {} (tee={})", path, tee);
            }
            "unbind-output" => {
                unbind_output();
                cprintln!("[rscan] output restored to current terminal");
            }
            "output-status" => {
                let (path, tee) = output_status();
                if let Some(p) = path {
                    cprintln!("[rscan] output sink={} tee={}", p.display(), tee);
                } else {
                    cprintln!("[rscan] output sink=stdout tee={}", tee);
                }
            }
            "tee-output" => {
                let mode = parts.next().unwrap_or("on");
                let on = matches!(
                    mode.to_ascii_lowercase().as_str(),
                    "on" | "1" | "true" | "yes"
                );
                set_tee_output(on);
                cprintln!("[rscan] tee-output={}", on);
            }
            "clear" | "cls" => {
                if let Err(e) = clear_screen() {
                    cprintln!("clear failed: {}", e);
                }
            }
            "help" => print_help(),
            "backend-status" => {
                let c = BackendCatalog::detect();
                cprintln!(
                    "{}",
                    serde_json::to_string_pretty(&c)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                );
            }
            "exit" | "quit" => break,
            "analyze" => {
                let rules = if let Some(rule_file) = parts.next() {
                    Some(RuleLibrary::load(Path::new(rule_file))?)
                } else {
                    None
                };
                run_analyze(&cfg.input, rules.as_ref())?;
            }
            "malware" => {
                let report = MalwareAnalyzer::triage_file(&cfg.input)?;
                cprintln!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                );
            }
            "shell-audit" => {
                let text = parts.collect::<Vec<_>>().join(" ");
                if text.is_empty() {
                    cprintln!("usage: shell-audit <text>");
                    continue;
                }
                let hits = MalwareAnalyzer::audit_shell_text(&text);
                cprintln!(
                    "{}",
                    serde_json::to_string_pretty(&hits)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                );
            }
            "plan" => {
                let engine = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "plan <engine>".to_string(),
                })?;
                let engine = DecompilerEngine::parse(engine).ok_or_else(|| {
                    RustpenError::ParseError(
                        "invalid engine. use objdump|radare2|ghidra|ida|jadx".to_string(),
                    )
                })?;
                let out_dir = parts.next().map(PathBuf::from);
                let plan = ReverseTooling::build_decompile_invocation(
                    engine,
                    &cfg.input,
                    out_dir.as_deref(),
                );
                cprintln!(
                    "{}",
                    serde_json::to_string_pretty(&plan)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                );
            }
            "pseudocode" => {
                let engine_name = parts.next().unwrap_or("auto");
                let out_dir = parts
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| workspace.join("reverse_out"));
                let mode = parts
                    .next()
                    .and_then(DecompileMode::parse)
                    .unwrap_or(DecompileMode::Index);
                let function = if mode == DecompileMode::Function {
                    Some(
                        parts
                            .next()
                            .ok_or_else(|| RustpenError::MissingArgument {
                                arg: "pseudocode ... function <name_or_ea>".to_string(),
                            })?
                            .to_string(),
                    )
                } else {
                    None
                };
                std::fs::create_dir_all(&out_dir)?;
                run_pseudocode(&cfg.input, engine_name, &out_dir, mode, function.as_deref())?;
            }
            "decompile" | "run" => {
                let engine_name = parts.next().unwrap_or("auto");
                let job_workspace = parts
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| workspace.clone());
                let timeout_secs = parts
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(600);
                let mode = parts
                    .next()
                    .and_then(DecompileMode::parse)
                    .unwrap_or(DecompileMode::Index);
                let function = if mode == DecompileMode::Function {
                    Some(
                        parts
                            .next()
                            .ok_or_else(|| RustpenError::MissingArgument {
                                arg: "decompile ... function <name_or_ea>".to_string(),
                            })?
                            .to_string(),
                    )
                } else {
                    None
                };
                cprintln!(
                    "[rscan] start decompile engine={} mode={:?} timeout={}s ...",
                    engine_name,
                    mode,
                    timeout_secs
                );
                let report = run_decompile_with_progress(
                    cfg.input.clone(),
                    job_workspace.clone(),
                    engine_name.to_string(),
                    timeout_secs,
                    mode,
                    function,
                )?;
                last_job = Some(report.job.id.clone());
                let funcs = load_job_rows_cached(&mut row_cache, &job_workspace, &report.job.id)
                    .map(|v| v.len());
                let func_count = funcs.as_ref().copied().unwrap_or(0);
                cprintln!(
                    "[rscan] job={} status={:?} functions={} stdout={} stderr={}",
                    report.job.id,
                    report.job.status,
                    func_count,
                    report.stdout_log.display(),
                    report.stderr_log.display()
                );
                if funcs.is_err() {
                    cprintln!(
                        "[rscan] warning: pseudocode artifact missing, check logs with 'jobs' and CLI job-logs"
                    );
                }
            }
            "jobs" => {
                cprintln!(
                    "{:22} {:10} {:7} {:12} target",
                    "job_id",
                    "status",
                    "backend",
                    "duration"
                );
                for job in list_jobs(&workspace)? {
                    let duration = match (job.started_at, job.ended_at) {
                        (Some(s), Some(e)) if e >= s => format!("{}s", e - s),
                        (Some(s), None) => format!("{}s+", now_epoch_secs().saturating_sub(s)),
                        _ => "-".to_string(),
                    };
                    cprintln!(
                        "{:22} {:10} {:7} {:12} {}",
                        job.id,
                        format!("{:?}", job.status),
                        job.backend,
                        duration,
                        job.target.display()
                    );
                }
            }
            "set-job" => {
                let job_id = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "set-job <job_id>".to_string(),
                })?;
                last_job = Some(job_id.to_string());
                cprintln!("[rscan] active job={}", job_id);
            }
            "pin-job" => {
                let job_id = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "pin-job <job_id>".to_string(),
                })?;
                pinned_job = Some(job_id.to_string());
                cprintln!("[rscan] pinned job={}", job_id);
            }
            "unpin-job" => {
                pinned_job = None;
                cprintln!("[rscan] pin cleared");
            }
            "active-job" => {
                let resolved = resolve_job_id(None, &last_job, &pinned_job, &workspace)?;
                if let Some(v) = resolved {
                    cprintln!("{}", v);
                } else {
                    cprintln!("none");
                }
            }
            "functions" => {
                let first = parts.next();
                let mut limit = 200usize;
                let job_arg = if let Some(v) = first {
                    if let Ok(n) = v.parse::<usize>() {
                        limit = n;
                        None
                    } else {
                        Some(v)
                    }
                } else {
                    None
                };
                let job_id = resolve_job_id(job_arg, &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: functions [job_id]");
                    continue;
                };
                last_job = Some(job_id.clone());
                if let Some(n) = parts.next().and_then(|v| v.parse::<usize>().ok()) {
                    limit = n;
                }
                let rows = load_job_rows_cached(&mut row_cache, &workspace, &job_id)?;
                for r in rows.iter().take(limit) {
                    let ea = r
                        .get("ea")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<no-ea>")
                        .to_string();
                    let name = r
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<no-name>")
                        .to_string();
                    cprintln!("{} {}", ea, name);
                }
                if rows.len() > limit {
                    cprintln!(
                        "[rscan] showing {}/{} (use bigger limit)",
                        limit,
                        rows.len()
                    );
                } else {
                    cprintln!("[rscan] total {}", rows.len());
                }
            }
            "show" => {
                let key = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "show <function_name_or_ea> [job_id]".to_string(),
                })?;
                let job_id = resolve_job_id(parts.next(), &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: show <function_name_or_ea> [job_id]");
                    continue;
                };
                last_job = Some(job_id.clone());
                let rows = load_job_rows_cached(&mut row_cache, &workspace, &job_id)?;
                let mut found = false;
                for r in rows {
                    let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
                    let name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                    if name == key || ea.eq_ignore_ascii_case(key) {
                        let code = r
                            .get("pseudocode")
                            .and_then(|v| v.as_str())
                            .unwrap_or("<no pseudocode>");
                        let err = r.get("error").and_then(|v| v.as_str()).unwrap_or_default();
                        cprintln!("[{}] {}", ea, name);
                        if let Some(sig) = r.get("signature").and_then(|v| v.as_str()) {
                            cprintln!("signature: {}", sig);
                        }
                        if let Some(size) = r.get("size").and_then(|v| v.as_u64()) {
                            cprintln!("size: {}", size);
                        }
                        let calls = as_str_vec(r.get("calls"));
                        if !calls.is_empty() {
                            cprintln!("calls: {}", calls.len());
                        }
                        if !err.is_empty() && err != "null" {
                            cprintln!("error: {}", err);
                        }
                        cprintln!("{}", code);
                        found = true;
                        break;
                    }
                }
                if !found {
                    cprintln!("function not found: {}", key);
                }
            }
            "search" => {
                let keyword = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "search <keyword> [job_id]".to_string(),
                })?;
                let job_id = resolve_job_id(parts.next(), &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: search <keyword> [job_id]");
                    continue;
                };
                last_job = Some(job_id.clone());
                let kw = keyword.to_ascii_lowercase();
                let rows = load_job_rows_cached(&mut row_cache, &workspace, &job_id)?;
                let mut shown = 0usize;
                for r in rows {
                    let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
                    let name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                    let code = r
                        .get("pseudocode")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let sig = r
                        .get("signature")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if name.to_ascii_lowercase().contains(&kw)
                        || ea.to_ascii_lowercase().contains(&kw)
                        || code.to_ascii_lowercase().contains(&kw)
                        || sig.to_ascii_lowercase().contains(&kw)
                    {
                        cprintln!("{} {}", ea, name);
                        shown += 1;
                        if shown >= 50 {
                            break;
                        }
                    }
                }
                if shown == 0 {
                    cprintln!("no hits for '{}'", keyword);
                }
            }
            "calls" => {
                let key = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "calls <function_name_or_ea> [job_id]".to_string(),
                })?;
                let rest = parts.collect::<Vec<_>>();
                let json_mode = rest.iter().any(|v| *v == "json" || *v == "--json");
                let explicit = rest
                    .iter()
                    .copied()
                    .find(|v| *v != "json" && *v != "--json");
                let job_id = resolve_job_id(explicit, &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: calls <function_name_or_ea> [job_id]");
                    continue;
                };
                last_job = Some(job_id.clone());
                let rows = load_job_rows_cached(&mut row_cache, &workspace, &job_id)?;
                let mut target: Option<&Value> = None;
                let mut ea_to_name = HashMap::new();
                for r in rows {
                    let ea = r
                        .get("ea")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let name = r
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !ea.is_empty() && !name.is_empty() {
                        ea_to_name.insert(ea.clone(), name);
                    }
                    if row_match_key(r, key) {
                        target = Some(r);
                    }
                }
                let Some(target) = target else {
                    cprintln!("function not found: {}", key);
                    continue;
                };
                let calls = as_str_vec(target.get("calls"));
                let call_names = as_str_vec(target.get("call_names"));
                if calls.is_empty() {
                    cprintln!("no calls found");
                    continue;
                }
                if json_mode {
                    let mut out = Vec::<Value>::new();
                    for (idx, c) in calls.iter().enumerate() {
                        let inferred = ea_to_name.get(c).cloned().unwrap_or_default();
                        let cname = call_names.get(idx).cloned().unwrap_or(inferred);
                        out.push(serde_json::json!({
                            "ea": c,
                            "name": cname,
                        }));
                    }
                    cprintln!(
                        "{}",
                        serde_json::to_string_pretty(&out)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    );
                } else {
                    for (idx, c) in calls.iter().enumerate() {
                        let inferred = ea_to_name.get(c).cloned().unwrap_or_default();
                        let cname = call_names.get(idx).cloned().unwrap_or(inferred);
                        if cname.is_empty() {
                            cprintln!("{}", c);
                        } else {
                            cprintln!("{} {}", c, cname);
                        }
                    }
                }
            }
            "xrefs" => {
                let key = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "xrefs <function_name_or_ea> [job_id]".to_string(),
                })?;
                let rest = parts.collect::<Vec<_>>();
                let json_mode = rest.iter().any(|v| *v == "json" || *v == "--json");
                let explicit = rest
                    .iter()
                    .copied()
                    .find(|v| *v != "json" && *v != "--json");
                let job_id = resolve_job_id(explicit, &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: xrefs <function_name_or_ea> [job_id]");
                    continue;
                };
                last_job = Some(job_id.clone());
                let rows = load_job_rows_cached(&mut row_cache, &workspace, &job_id)?;
                let mut target_ea = String::new();
                let mut target_name = String::new();
                for r in rows {
                    if row_match_key(r, key) {
                        target_ea = r
                            .get("ea")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        target_name = r
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        break;
                    }
                }
                if target_ea.is_empty() && target_name.is_empty() {
                    cprintln!("function not found: {}", key);
                    continue;
                }
                let target_ea_l = target_ea.to_ascii_lowercase();
                let target_name_l = target_name.to_ascii_lowercase();
                let key_l = key.to_ascii_lowercase();
                let mut hits = 0usize;
                let mut out = Vec::<Value>::new();
                for r in rows {
                    let caller_ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
                    let caller_name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                    let calls = as_str_vec(r.get("calls"));
                    let call_names = as_str_vec(r.get("call_names"));
                    let ext_refs = as_str_vec(r.get("ext_refs"));
                    let matched = calls.iter().any(|c| {
                        let c_l = c.to_ascii_lowercase();
                        c_l == target_ea_l || c_l == target_name_l || c_l == key_l
                    }) || call_names.iter().any(|c| {
                        let c_l = c.to_ascii_lowercase();
                        c_l == target_name_l || c_l == key_l
                    }) || ext_refs.iter().any(|c| {
                        let c_l = c.to_ascii_lowercase();
                        c_l == target_name_l || c_l == key_l
                    });
                    if matched
                        && !(caller_ea.eq_ignore_ascii_case(&target_ea)
                            && caller_name.eq_ignore_ascii_case(&target_name))
                    {
                        if json_mode {
                            out.push(serde_json::json!({
                                "ea": caller_ea,
                                "name": caller_name
                            }));
                        } else {
                            cprintln!("{} {}", caller_ea, caller_name);
                        }
                        hits += 1;
                    }
                }
                if json_mode {
                    cprintln!(
                        "{}",
                        serde_json::to_string_pretty(&out)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    );
                } else if hits == 0 {
                    cprintln!("no xrefs");
                }
            }
            "sections" => {
                let rest = parts.collect::<Vec<_>>();
                let json_mode = rest.iter().any(|v| *v == "json" || *v == "--json");
                let sections = list_sections(&cfg.input)?;
                if json_mode {
                    cprintln!(
                        "{}",
                        serde_json::to_string_pretty(&sections)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    );
                } else {
                    for sec in sections {
                        cprintln!(
                            "{} addr=0x{:x} size=0x{:x} flags=0x{:x}",
                            sec.name,
                            sec.addr,
                            sec.size,
                            sec.flags
                        );
                    }
                }
            }
            "imports" => {
                let rest = parts.collect::<Vec<_>>();
                let json_mode = rest.iter().any(|v| *v == "json" || *v == "--json");
                let imports = list_imports(&cfg.input)?;
                if json_mode {
                    cprintln!(
                        "{}",
                        serde_json::to_string_pretty(&imports)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    );
                } else if imports.is_empty() {
                    cprintln!("no imports");
                } else {
                    for i in imports {
                        cprintln!("{}", i);
                    }
                }
            }
            "symbols" => {
                let rest = parts.collect::<Vec<_>>();
                let json_mode = rest.iter().any(|v| *v == "json" || *v == "--json");
                let mut pattern: Option<String> = None;
                let mut limit = 200usize;
                for tok in rest {
                    if tok == "json" || tok == "--json" {
                        continue;
                    }
                    if let Ok(n) = tok.parse::<usize>() {
                        limit = n;
                    } else if pattern.is_none() {
                        pattern = Some(tok.to_ascii_lowercase());
                    }
                }
                let symbols = list_symbols(&cfg.input)?;
                let mut filtered = Vec::new();
                for sym in symbols {
                    if let Some(p) = &pattern {
                        if sym.name.to_ascii_lowercase().contains(p) {
                            filtered.push(sym);
                        }
                    } else {
                        filtered.push(sym);
                    }
                }
                if json_mode {
                    let out = filtered.into_iter().take(limit).collect::<Vec<_>>();
                    cprintln!(
                        "{}",
                        serde_json::to_string_pretty(&out)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    );
                } else {
                    let mut shown = 0usize;
                    for sym in filtered.into_iter().take(limit) {
                        cprintln!("0x{:016x} {:7} {}", sym.addr, sym.kind, sym.name);
                        shown += 1;
                    }
                    cprintln!("[rscan] shown {}", shown);
                }
            }
            "addr" => {
                let key = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "addr <symbol_or_pattern>".to_string(),
                })?;
                let key_l = key.to_ascii_lowercase();
                let symbols = list_symbols(&cfg.input)?;
                let mut hits = 0usize;
                for sym in symbols {
                    if sym.name.eq_ignore_ascii_case(key)
                        || sym.name.to_ascii_lowercase().contains(&key_l)
                    {
                        cprintln!("0x{:016x} {:7} {}", sym.addr, sym.kind, sym.name);
                        hits += 1;
                        if hits >= 100 {
                            break;
                        }
                    }
                }
                if hits == 0 {
                    cprintln!("no symbol match for '{}'", key);
                }
            }
            "strings" => {
                let pattern = parts.next().map(|s| s.to_ascii_lowercase());
                let limit = parts
                    .next()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(100);
                let text = std::fs::read(&cfg.input)?;
                let mut shown = 0usize;
                for s in extract_ascii_strings(&text, 4, 20_000) {
                    if let Some(p) = &pattern
                        && !s.to_ascii_lowercase().contains(p)
                    {
                        continue;
                    }
                    cprintln!("{}", s);
                    shown += 1;
                    if shown >= limit {
                        break;
                    }
                }
                cprintln!("[rscan] shown {}", shown);
            }
            "hexdump" => {
                let off_s = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "hexdump <offset_hex_or_dec> [len]".to_string(),
                })?;
                let offset = parse_u64_auto(off_s)?;
                let len = parts
                    .next()
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(128);
                let data = std::fs::read(&cfg.input)?;
                print_hexdump(&data, offset as usize, len);
            }
            "regs" => {
                let out = run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("info registers")],
                )?;
                cprint!("{}", out);
            }
            "stack" => {
                let count = parts.next().unwrap_or("32");
                let out = run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[format!("x/{}gx $rsp", count)],
                )?;
                cprint!("{}", out);
            }
            "vmmap" => {
                let out = run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("vmmap")],
                )?;
                cprint!("{}", out);
            }
            "heap" => {
                let out = run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("heap")],
                )?;
                cprint!("{}", out);
            }
            "disasm" => {
                let expr = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "disasm <symbol|addr>".to_string(),
                })?;
                let out = run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[format!("disassemble {}", expr)],
                )?;
                cprint!("{}", out);
            }
            "gdb" => {
                let cmdline = parts.collect::<Vec<_>>().join(" ");
                if cmdline.is_empty() {
                    cprintln!("usage: gdb <gdb_command>");
                    continue;
                }
                let out = run_gdb_quick(&cfg.input, cfg.pwndbg_init.as_deref(), &[cmdline])?;
                cprint!("{}", out);
            }
            "clear-jobs" => {
                let arg = parts.next();
                let removed = if let Some(v) = arg {
                    if v.eq_ignore_ascii_case("all") {
                        super::clear_jobs(&workspace, None)?
                    } else {
                        super::clear_jobs(&workspace, Some(v))?
                    }
                } else {
                    super::clear_jobs(&workspace, None)?
                };
                cprintln!("[rscan] removed {} job(s)", removed);
            }
            "prune-jobs" => {
                let mut keep = 20usize;
                let mut days: Option<u64> = None;
                let mut include_running = false;
                for tok in parts {
                    if tok.eq_ignore_ascii_case("running") || tok == "--include-running" {
                        include_running = true;
                        continue;
                    }
                    if let Some(d) = tok.strip_prefix("days=") {
                        days = d.parse::<u64>().ok();
                        continue;
                    }
                    if let Some(k) = tok.strip_prefix("keep=") {
                        keep = k.parse::<usize>().ok().unwrap_or(20);
                        continue;
                    }
                    if let Ok(n) = tok.parse::<usize>() {
                        keep = n;
                    }
                }
                let removed = prune_jobs(
                    &workspace,
                    super::JobPrunePolicy {
                        keep_latest: Some(keep),
                        older_than_days: days,
                        include_running,
                    },
                )?;
                cprintln!(
                    "[rscan] pruned {} job(s), kept latest {}, older_than_days={:?}, include_running={}",
                    removed,
                    keep.max(1),
                    days,
                    include_running
                );
            }
            "job-doctor" => {
                let job_id = resolve_job_id(parts.next(), &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: job-doctor [job_id]");
                    continue;
                };
                let health = inspect_job_health(&workspace, &job_id)?;
                cprintln!(
                    "{}",
                    serde_json::to_string_pretty(&health)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                );
            }
            "split-tail" => {
                let job_id = resolve_job_id(parts.next(), &last_job, &pinned_job, &workspace)?;
                let Some(job_id) = job_id else {
                    cprintln!("usage: split-tail [job_id] [stdout|stderr|both] [h|v]");
                    continue;
                };
                let stream = parts.next().unwrap_or("both");
                let orient = parts.next().unwrap_or("h");
                let horizontal = !orient.eq_ignore_ascii_case("v");
                let job = load_job_by_id(&workspace, &job_id)?;
                let job_dir = workspace.join("jobs").join(&job.id);
                let stdout = job_dir.join("stdout.log");
                let stderr = job_dir.join("stderr.log");
                let cmdline = match stream {
                    "stdout" => format!("tail -n +1 -f {}", shell_escape_path(&stdout)),
                    "stderr" => format!("tail -n +1 -f {}", shell_escape_path(&stderr)),
                    _ => format!(
                        "tail -n +1 -f {} {}",
                        shell_escape_path(&stdout),
                        shell_escape_path(&stderr)
                    ),
                };
                if let Err(e) = open_tmux_split(&cmdline, horizontal) {
                    cprintln!("split-tail failed: {}", e);
                }
            }
            "split-cmd" => {
                let orient = parts.next().unwrap_or("h");
                let horizontal = !orient.eq_ignore_ascii_case("v");
                let cmdline = parts.collect::<Vec<_>>().join(" ");
                if cmdline.is_empty() {
                    cprintln!("usage: split-cmd [h|v] <shell_command>");
                    continue;
                }
                if let Err(e) = open_tmux_split(&cmdline, horizontal) {
                    cprintln!("split-cmd failed: {}", e);
                }
            }
            "debug" => {
                let profile = parts.next().unwrap_or("pwndbg");
                let profile = DebugProfile::parse(profile).ok_or_else(|| {
                    RustpenError::ParseError("invalid profile, use pwngdb|pwndbg".to_string())
                })?;
                run_debug(
                    &cfg.input,
                    profile,
                    &workspace,
                    cfg.pwndbg_init.as_deref(),
                )?;
            }
            _ => {
                cprintln!("unknown command: {}", cmd);
            }
        }
    }

    Ok(())
}

fn run_analyze(path: &Path, rules: Option<&RuleLibrary>) -> Result<(), RustpenError> {
    let bytes = std::fs::read(path)?;
    let rules = rules.cloned().unwrap_or_default();
    let value = match detect_format(&bytes) {
        super::BinaryFormat::Apk => {
            serde_json::to_value(ReverseAnalyzer::analyze_apk_with_rules(path, &rules)?)
                .map_err(|e| RustpenError::ParseError(e.to_string()))?
        }
        _ => serde_json::to_value(ReverseAnalyzer::analyze_binary_with_rules(path, &rules)?)
            .map_err(|e| RustpenError::ParseError(e.to_string()))?,
    };
    cprintln!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|e| RustpenError::ParseError(e.to_string()))?
    );
    Ok(())
}

fn run_pseudocode(
    input: &Path,
    engine_name: &str,
    out_dir: &Path,
    mode: DecompileMode,
    function: Option<&str>,
) -> Result<(), RustpenError> {
    let orchestrator = ReverseOrchestrator::detect();
    let preferred = if engine_name.eq_ignore_ascii_case("auto") {
        None
    } else {
        Some(engine_name)
    };
    let plan = orchestrator.build_pseudocode_plan(input, out_dir, preferred, mode, function)?;
    cprintln!("running: {} {}", plan.program, plan.args.join(" "));
    ReverseOrchestrator::execute_plan(&plan)?;
    Ok(())
}

fn run_debug(
    input: &Path,
    profile: DebugProfile,
    workspace: &Path,
    pwndbg_init: Option<&Path>,
) -> Result<(), RustpenError> {
    let backends = BackendCatalog::detect();
    if !backends.gdb.available {
        return Err(RustpenError::ScanError(
            "gdb backend not found in PATH".to_string(),
        ));
    }
    if matches!(profile, DebugProfile::PwndbgCompat)
        && pwndbg_init.is_none()
        && !backends.pwndbg_init.available
    {
        cprintln!(
            "[rscan] pwndbg init not found; script will still run but pwndbg commands may be unavailable"
        );
    }
    let script = workspace.join("rscan_debug.gdb");
    let orchestrator = ReverseOrchestrator::detect();
    let plan = orchestrator.build_debug_plan(input, profile, &script, pwndbg_init)?;
    cprintln!("running: {} {}", plan.program, plan.args.join(" "));
    ReverseOrchestrator::execute_plan(&plan)?;
    Ok(())
}

fn print_help() {
    cprintln!("commands:");
    cprintln!("  bind-output <path> [tee]");
    cprintln!("  unbind-output");
    cprintln!("  output-status");
    cprintln!("  tee-output <on|off>");
    cprintln!("  clear|cls");
    cprintln!("  help");
    cprintln!("  backend-status");
    cprintln!("  analyze [rules_file]");
    cprintln!("  malware");
    cprintln!("  shell-audit <text>");
    cprintln!("  plan <objdump|radare2|ghidra|ida|jadx> [out_dir]");
    cprintln!("  pseudocode <auto|ghidra|ida> [out_dir] [index|full|function] [name_or_ea]");
    cprintln!("  decompile|run <auto|ghidra|ida|r2|jadx> [workspace] [timeout_secs] [index|full|function] [name_or_ea]");
    cprintln!("  jobs");
    cprintln!("  set-job <job_id>");
    cprintln!("  pin-job <job_id>");
    cprintln!("  unpin-job");
    cprintln!("  active-job");
    cprintln!("  functions [job_id] [limit]");
    cprintln!("  show <function_name_or_ea> [job_id]");
    cprintln!("  search <keyword> [job_id]");
    cprintln!("  calls <function_name_or_ea> [job_id] [json]");
    cprintln!("  xrefs <function_name_or_ea> [job_id] [json]");
    cprintln!("  sections [json]");
    cprintln!("  imports [json]");
    cprintln!("  symbols [pattern] [limit] [json]");
    cprintln!("  addr <symbol_or_pattern>");
    cprintln!("  strings [pattern] [limit]");
    cprintln!("  hexdump <offset_hex_or_dec> [len]");
    cprintln!("  # optional runtime debug (if gdb/pwndbg exists):");
    cprintln!("  regs");
    cprintln!("  stack [count]");
    cprintln!("  vmmap");
    cprintln!("  heap");
    cprintln!("  disasm <symbol_or_addr>");
    cprintln!("  gdb <gdb_command>");
    cprintln!("  clear-jobs [all|job_id]");
    cprintln!("  prune-jobs [keep_count|keep=N] [days=N] [running]");
    cprintln!("  job-doctor [job_id]");
    cprintln!("  split-tail [job_id] [stdout|stderr|both] [h|v]   # needs tmux");
    cprintln!("  split-cmd [h|v] <shell_command>                  # needs tmux");
    cprintln!("  debug [pwndbg|pwngdb]");
    cprintln!("  exit|quit");
}

fn run_decompile_with_progress(
    input: PathBuf,
    workspace: PathBuf,
    engine: String,
    timeout_secs: u64,
    mode: DecompileMode,
    function: Option<String>,
) -> Result<super::DecompileRunReport, RustpenError> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = run_decompile_job(
            &input,
            &workspace,
            &engine,
            mode,
            function.as_deref(),
            Some(timeout_secs),
        );
        let _ = tx.send(out);
    });
    let start = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(v) => return v,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cprintln!("[rscan] running... elapsed={}s", start.elapsed().as_secs());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(RustpenError::ScanError(
                    "decompile worker channel disconnected".to_string(),
                ));
            }
        }
    }
}

fn clear_screen() -> Result<(), RustpenError> {
    print!("\x1b[2J\x1b[H");
    io::stdout().flush().map_err(RustpenError::Io)
}

fn bind_output(path: &str, tee: bool) -> Result<(), RustpenError> {
    let file = OpenOptions::new().write(true).open(path).map_err(|e| {
        RustpenError::ScanError(format!("failed to open output sink {}: {}", path, e))
    })?;
    let lock = router()
        .lock()
        .map_err(|_| RustpenError::ScanError("output router lock poisoned".to_string()))?;
    let mut r = lock;
    r.sink = Some(file);
    r.sink_path = Some(PathBuf::from(path));
    r.tee_stdout = tee;
    Ok(())
}

fn unbind_output() {
    if let Ok(mut r) = router().lock() {
        r.sink = None;
        r.sink_path = None;
        r.tee_stdout = false;
    }
}

fn set_tee_output(on: bool) {
    if let Ok(mut r) = router().lock() {
        r.tee_stdout = on;
    }
}

fn output_status() -> (Option<PathBuf>, bool) {
    if let Ok(r) = router().lock() {
        return (r.sink_path.clone(), r.tee_stdout);
    }
    (None, false)
}

fn open_tmux_split(command: &str, horizontal: bool) -> Result<(), RustpenError> {
    if env::var_os("TMUX").is_none() {
        return Err(RustpenError::ScanError(
            "split requires tmux session; start with `tmux` first".to_string(),
        ));
    }
    let flag = if horizontal { "-h" } else { "-v" };
    let status = Command::new("tmux")
        .arg("split-window")
        .arg(flag)
        .arg(command)
        .status()
        .map_err(RustpenError::Io)?;
    if !status.success() {
        return Err(RustpenError::ScanError(format!(
            "tmux split failed with status {}",
            status
        )));
    }
    Ok(())
}

fn shell_escape_path(p: &Path) -> String {
    let s = p.display().to_string();
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn load_job_rows_cached<'a>(
    cache: &'a mut HashMap<String, Vec<Value>>,
    workspace: &Path,
    job_id: &str,
) -> Result<&'a Vec<Value>, RustpenError> {
    if !cache.contains_key(job_id) {
        let rows = load_job_pseudocode_rows(workspace, job_id)?;
        cache.insert(job_id.to_string(), rows);
    }
    cache.get(job_id).ok_or_else(|| {
        RustpenError::ScanError(format!(
            "failed to load cached pseudocode rows for {}",
            job_id
        ))
    })
}

fn resolve_job_id(
    explicit: Option<&str>,
    last_job: &Option<String>,
    pinned_job: &Option<String>,
    workspace: &Path,
) -> Result<Option<String>, RustpenError> {
    if let Some(v) = explicit {
        return Ok(Some(v.to_string()));
    }
    if let Some(v) = pinned_job {
        return Ok(Some(v.clone()));
    }
    if let Some(v) = last_job {
        return Ok(Some(v.clone()));
    }
    Ok(latest_succeeded_job_id(workspace)?)
}

fn latest_succeeded_job_id(workspace: &Path) -> Result<Option<String>, RustpenError> {
    let jobs = list_jobs(workspace)?;
    for job in jobs {
        if job.status == super::ReverseJobStatus::Succeeded {
            return Ok(Some(job.id));
        }
    }
    Ok(None)
}

fn row_match_key(r: &Value, key: &str) -> bool {
    let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
    let name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
    name.eq_ignore_ascii_case(key) || ea.eq_ignore_ascii_case(key)
}

fn as_str_vec(v: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(arr)) = v else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            out.push(s.to_string());
        }
    }
    out
}

#[derive(Debug, Clone, serde::Serialize)]
struct SectionInfo {
    name: String,
    addr: u64,
    size: u64,
    flags: u64,
}

fn list_sections(path: &Path) -> Result<Vec<SectionInfo>, RustpenError> {
    let bytes = std::fs::read(path)?;
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let mut out = Vec::new();
            for s in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(s.sh_name).unwrap_or("<unnamed>");
                out.push(SectionInfo {
                    name: name.to_string(),
                    addr: s.sh_addr,
                    size: s.sh_size,
                    flags: s.sh_flags,
                });
            }
            Ok(out)
        }
        Ok(Object::PE(pe)) => {
            let base = pe_image_base(&pe);
            let mut out = Vec::new();
            for s in &pe.sections {
                out.push(SectionInfo {
                    name: s.name().unwrap_or("<unnamed>").to_string(),
                    addr: base.saturating_add(s.virtual_address as u64),
                    size: s.virtual_size as u64,
                    flags: s.characteristics as u64,
                });
            }
            Ok(out)
        }
        Ok(_) => Err(RustpenError::ScanError(
            "sections command currently supports ELF/PE targets".to_string(),
        )),
        Err(e) => Err(RustpenError::ParseError(format!(
            "unable to parse target binary: {}",
            e
        ))),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct SymbolInfo {
    addr: u64,
    name: String,
    kind: String,
}

fn list_symbols(path: &Path) -> Result<Vec<SymbolInfo>, RustpenError> {
    let bytes = std::fs::read(path)?;
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let mut out = Vec::new();
            for sym in &elf.syms {
                if sym.st_value == 0 {
                    continue;
                }
                let name = elf.strtab.get_at(sym.st_name).unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let kind = match sym.st_type() {
                    goblin::elf::sym::STT_FUNC => "FUNC",
                    goblin::elf::sym::STT_OBJECT => "DATA",
                    _ => "OTHER",
                };
                out.push(SymbolInfo {
                    addr: sym.st_value,
                    name: name.to_string(),
                    kind: kind.to_string(),
                });
            }
            for sym in &elf.dynsyms {
                if sym.st_value == 0 {
                    continue;
                }
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let kind = match sym.st_type() {
                    goblin::elf::sym::STT_FUNC => "FUNC",
                    goblin::elf::sym::STT_OBJECT => "DATA",
                    _ => "OTHER",
                };
                out.push(SymbolInfo {
                    addr: sym.st_value,
                    name: name.to_string(),
                    kind: kind.to_string(),
                });
            }
            out.sort_by_key(|s| s.addr);
            out.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
            Ok(out)
        }
        Ok(Object::PE(pe)) => {
            let base = pe_image_base(&pe);
            let mut out = Vec::new();
            for exp in &pe.exports {
                if let Some(name) = exp.name {
                    out.push(SymbolInfo {
                        addr: base.saturating_add(exp.rva as u64),
                        name: name.to_string(),
                        kind: "EXPORT".to_string(),
                    });
                }
            }
            for imp in &pe.imports {
                out.push(SymbolInfo {
                    addr: base.saturating_add(imp.rva as u64),
                    name: format!("{}!{}", imp.dll, imp.name),
                    kind: "IMPORT".to_string(),
                });
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            out.dedup_by(|a, b| a.name == b.name && a.kind == b.kind);
            Ok(out)
        }
        Ok(_) => Err(RustpenError::ScanError(
            "symbols command currently supports ELF/PE targets".to_string(),
        )),
        Err(e) => Err(RustpenError::ParseError(format!(
            "unable to parse target binary: {}",
            e
        ))),
    }
}

fn pe_image_base(pe: &goblin::pe::PE) -> u64 {
    pe.header
        .optional_header
        .map(|o| o.windows_fields.image_base)
        .unwrap_or(0)
}

fn list_imports(path: &Path) -> Result<Vec<String>, RustpenError> {
    let bytes = std::fs::read(path)?;
    match Object::parse(&bytes) {
        Ok(Object::Elf(elf)) => {
            let mut out = Vec::new();
            for sym in &elf.dynsyms {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name)
                    && !name.is_empty()
                {
                    out.push(name.to_string());
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        }
        Ok(Object::PE(pe)) => {
            let mut out = Vec::new();
            for imp in &pe.imports {
                out.push(format!("{}!{}", imp.dll, imp.name));
            }
            out.sort();
            out.dedup();
            Ok(out)
        }
        Ok(_) => Err(RustpenError::ScanError(
            "imports command currently supports ELF/PE targets".to_string(),
        )),
        Err(e) => Err(RustpenError::ParseError(format!(
            "unable to parse target binary: {}",
            e
        ))),
    }
}

fn extract_ascii_strings(bytes: &[u8], min_len: usize, max_items: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                out.push(String::from_utf8_lossy(&cur).to_string());
                if out.len() >= max_items {
                    return out;
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len && out.len() < max_items {
        out.push(String::from_utf8_lossy(&cur).to_string());
    }
    out
}

fn parse_u64_auto(v: &str) -> Result<u64, RustpenError> {
    if let Some(hex) = v.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|e| RustpenError::ParseError(e.to_string()));
    }
    v.parse::<u64>()
        .map_err(|e| RustpenError::ParseError(e.to_string()))
}

fn print_hexdump(bytes: &[u8], offset: usize, len: usize) {
    if offset >= bytes.len() {
        cprintln!("offset out of range: {}", offset);
        return;
    }
    let end = offset.saturating_add(len).min(bytes.len());
    let mut i = offset;
    while i < end {
        let line_end = (i + 16).min(end);
        let chunk = &bytes[i..line_end];
        cprint!("{:08x}  ", i);
        for idx in 0..16 {
            if idx < chunk.len() {
                cprint!("{:02x} ", chunk[idx]);
            } else {
                cprint!("   ");
            }
        }
        cprint!(" |");
        for &b in chunk {
            let ch = if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            };
            cprint!("{}", ch);
        }
        cprintln!("|");
        i += 16;
    }
}

fn run_gdb_quick(
    input: &Path,
    pwndbg_init: Option<&Path>,
    commands: &[String],
) -> Result<String, RustpenError> {
    let backends = BackendCatalog::detect();
    let gdb = backends
        .gdb
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "gdb".to_string());
    let mut cmd = Command::new(gdb);
    cmd.arg("-q").arg("-nx").arg("--batch");
    if let Some(init) = pwndbg_init
        && init.exists()
    {
        cmd.arg("-ex").arg(format!("source {}", init.display()));
    }
    cmd.arg("-ex")
        .arg(format!("file {}", input.display()))
        .arg("-ex")
        .arg("set pagination off");
    for c in commands {
        cmd.arg("-ex").arg(c);
    }
    let out = cmd.output().map_err(RustpenError::Io)?;
    let mut merged = String::new();
    merged.push_str(&String::from_utf8_lossy(&out.stdout));
    if !out.stderr.is_empty() {
        merged.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok(merged)
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
