use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use goblin::Object;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::stdout;

use crate::errors::RustpenError;

use super::{
    BackendCatalog, DebugProfile, DecompileMode, DecompilerEngine, MalwareAnalyzer,
    ReverseAnalyzer, ReverseOrchestrator, ReverseTooling, RuleLibrary, analyzer::detect_format,
    clear_jobs, inspect_job_health, list_jobs, load_job_by_id, load_job_pseudocode_rows,
    prune_jobs, run_decompile_job,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Tabs};
use ratatui::Terminal;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use tantivy::schema::{Schema, TEXT, STORED, Value as TantivyValue};
use tantivy::{Index, TantivyDocument};

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
                if let Err(e) = (|| -> Result<(), RustpenError> {
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
                    Ok(())
                })() {
                    cprintln!("[rscan] pseudocode failed: {}", e);
                }
            }
            "decompile" | "run" => {
                if let Err(e) = (|| -> Result<(), RustpenError> {
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
                    let funcs =
                        load_job_rows_cached(&mut row_cache, &job_workspace, &report.job.id)
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
                    Ok(())
                })() {
                    cprintln!("[rscan] decompile failed: {}", e);
                    if let RustpenError::ScanError(msg) = &e {
                        if msg.contains("backend") || msg.contains("pseudocode backend") {
                            cprintln!(
                                "[rscan] hint: run 'backend-status' or set RSCAN_GHIDRA_HOME to your ghidra_core_headless_x86_min"
                            );
                        }
                    }
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
                match run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("info registers")],
                ) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
            }
            "stack" => {
                let count = parts.next().unwrap_or("32");
                match run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[format!("x/{}gx $rsp", count)],
                ) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
            }
            "vmmap" => {
                match run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("vmmap")],
                ) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
            }
            "heap" => {
                match run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[String::from("heap")],
                ) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
            }
            "disasm" => {
                let expr = parts.next().ok_or_else(|| RustpenError::MissingArgument {
                    arg: "disasm <symbol|addr>".to_string(),
                })?;
                match run_gdb_quick(
                    &cfg.input,
                    cfg.pwndbg_init.as_deref(),
                    &[format!("disassemble {}", expr)],
                ) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
            }
            "gdb" => {
                let cmdline = parts.collect::<Vec<_>>().join(" ");
                if cmdline.is_empty() {
                    cprintln!("usage: gdb <gdb_command>");
                    continue;
                }
                match run_gdb_quick(&cfg.input, cfg.pwndbg_init.as_deref(), &[cmdline]) {
                    Ok(out) => cprint!("{}", out),
                    Err(e) => cprintln!("[rscan] gdb failed: {}", e),
                }
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
                if let Err(e) =
                    run_debug(&cfg.input, profile, &workspace, cfg.pwndbg_init.as_deref())
                {
                    cprintln!("[rscan] debug failed: {}", e);
                }
            }
            _ => {
                cprintln!("unknown command: {}", cmd);
            }
        }
    }

    Ok(())
}

pub fn run_tui(cfg: ReverseConsoleConfig) -> Result<(), RustpenError> {
    let workspace = std::fs::canonicalize(&cfg.workspace).unwrap_or_else(|_| cfg.workspace.clone());
    let mut state = TuiState::new(cfg.input, workspace);

    enable_raw_mode().map_err(|e| RustpenError::ScanError(format!("enable raw mode: {}", e)))?;
    execute!(stdout(), EnterAlternateScreen)
        .map_err(|e| RustpenError::ScanError(format!("enter alt screen: {}", e)))?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)
        .map_err(|e| RustpenError::ScanError(format!("terminal init: {}", e)))?;

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            terminal
                .draw(|f| draw_tui(f, &mut state))
                .map_err(|e| RustpenError::ScanError(format!("draw: {}", e)))?;

            state.tick();

            if event::poll(Duration::from_millis(200))
                .map_err(|e| RustpenError::ScanError(format!("poll: {}", e)))?
            {
                if let Event::Key(k) = event::read()
                    .map_err(|e| RustpenError::ScanError(format!("read key: {}", e)))?
                {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    if state.handle_key(k)? {
                        break;
                    }
                }
            }
        }
        Ok::<(), RustpenError>(())
    }));

    disable_raw_mode().ok();
    execute!(stdout(), LeaveAlternateScreen).ok();
    match res {
        Ok(r) => r,
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            Err(RustpenError::ScanError(format!("tui panic: {}", msg)))
        }
    }
}

struct TuiState {
    input: PathBuf,
    workspace: PathBuf,
    jobs: Vec<super::ReverseJobMeta>,
    job_index: usize,
    rows: Vec<Value>,
    filtered: Vec<usize>,
    selected: usize,
    filter: String,
    search: String,
    pseudo_items: Vec<String>,
    asm_items: Vec<String>,
    current_code: String,
    current_asm: Vec<String>,
    calls_items: Vec<String>,
    xrefs_items: Vec<String>,
    ext_items: Vec<String>,
    strings_items: Vec<String>,
    func_strings_items: Vec<String>,
    global_strings: Vec<String>,
    strings_query: String,
    strings_global: bool,
    tab: TuiTab,
    focus: TuiFocus,
    project_index: Vec<Value>,
    right_selected: usize,
    strings_selected: usize,
    log: Vec<String>,
    input_mode: TuiInputMode,
    input_buf: String,
    pending_action: Option<TuiPendingAction>,
    notes: HashMap<String, NoteEntry>,
    note_path: Option<PathBuf>,
    jobs_view_height: usize,
    funcs_view_height: usize,
    right_view_height: usize,
    strings_view_height: usize,
    decompile_rx: Option<Receiver<Result<super::DecompileRunReport, RustpenError>>>,
    decompile_running: bool,
    decompile_last_tick: Instant,
}

#[derive(Clone, Copy)]
enum TuiInputMode {
    Normal,
    Prompt,
}

#[derive(Clone, Copy)]
enum TuiPendingAction {
    JumpTo,
    Filter,
    Search,
    Command,
    Comment,
    CommentLine,
    DeleteJob,
    StringSearch,
    Decompile,
}

#[derive(Clone, Copy)]
enum TuiTab {
    Pseudocode,
    Calls,
    Xrefs,
    Externals,
    Strings,
    Asm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TuiFocus {
    Jobs,
    Functions,
    Right,
    Strings,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NoteEntry {
    #[serde(default)]
    note: Option<String>,
    #[serde(default, alias = "lines")]
    pseudo: HashMap<usize, String>,
    #[serde(default)]
    asm: HashMap<usize, String>,
}

#[derive(Debug, Clone)]
struct DecompileRequest {
    mode: DecompileMode,
    function: Option<String>,
    skip_asm: bool,
    only_named: bool,
}

impl NoteEntry {
    fn has_any(&self) -> bool {
        self.note.is_some() || !self.pseudo.is_empty() || !self.asm.is_empty()
    }
}

impl TuiState {
    fn new(input: PathBuf, workspace: PathBuf) -> Self {
        let mut s = Self {
            input,
            workspace,
            jobs: Vec::new(),
            job_index: 0,
            rows: Vec::new(),
            filtered: Vec::new(),
            selected: 0,
            filter: String::new(),
            search: String::new(),
            pseudo_items: Vec::new(),
            asm_items: Vec::new(),
            current_code: String::new(),
            current_asm: Vec::new(),
            calls_items: Vec::new(),
            xrefs_items: Vec::new(),
            ext_items: Vec::new(),
            strings_items: Vec::new(),
            func_strings_items: Vec::new(),
            global_strings: Vec::new(),
            strings_query: String::new(),
            strings_global: false,
            tab: TuiTab::Pseudocode,
            focus: TuiFocus::Functions,
            right_selected: 0,
            strings_selected: 0,
            project_index: Vec::new(),
            log: Vec::new(),
            input_mode: TuiInputMode::Normal,
            input_buf: String::new(),
            pending_action: None,
            notes: HashMap::new(),
            note_path: None,
            jobs_view_height: 6,
            funcs_view_height: 10,
            right_view_height: 12,
            strings_view_height: 6,
            decompile_rx: None,
            decompile_running: false,
            decompile_last_tick: Instant::now(),
        };
        s.reload_jobs();
        s.select_default_job();
        s.load_current_job_rows();
        s.ensure_initial_index();
        s.update_detail();
        s.ensure_global_strings_loaded();
        s.refresh_global_strings_view();
        s
    }

    fn log(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        self.log.push(m);
        if self.log.len() > 200 {
            let _ = self.log.drain(0..50);
        }
    }

    fn reload_jobs(&mut self) {
        let mut jobs = list_jobs(&self.workspace).unwrap_or_default();
        jobs.retain(|j| j.status == super::ReverseJobStatus::Succeeded);
        jobs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        self.jobs = jobs;
        if self.job_index >= self.jobs.len() {
            self.job_index = 0;
        }
    }

    fn select_default_job(&mut self) {
        if self.jobs.is_empty() {
            return;
        }
        if let Some(pos) = self
            .jobs
            .iter()
            .position(|j| j.mode.as_deref() != Some("function"))
        {
            self.job_index = pos;
        }
    }

    fn has_non_function_job(&self) -> bool {
        self.jobs
            .iter()
            .any(|j| j.mode.as_deref() != Some("function"))
    }

    fn ensure_initial_index(&mut self) {
        if !self.jobs.is_empty() && self.has_non_function_job() {
            return;
        }
        if self.decompile_running {
            return;
        }
        self.log("[rscan] no full/index job found; auto-run index to build function list");
        let req = DecompileRequest {
            mode: DecompileMode::Index,
            function: None,
            skip_asm: false,
            only_named: false,
        };
        self.start_decompile_request(req);
    }

    fn current_job_id(&self) -> Option<String> {
        self.jobs.get(self.job_index).map(|j| j.id.clone())
    }

    fn load_current_job_rows(&mut self) {
        self.rows.clear();
        self.filtered.clear();
        self.selected = 0;
        self.right_selected = 0;
        if let Some(job_id) = self.current_job_id() {
            match load_job_pseudocode_rows(&self.workspace, &job_id) {
                Ok(rows) => {
                    self.rows = rows;
                    self.load_notes_for_job(&job_id);
                    self.apply_filters();
                    self.log(format!(
                        "[rscan] loaded {} functions for {} (notes={})",
                        self.rows.len(),
                        job_id,
                        self.notes.len()
                    ));
                }
                Err(e) => self.log(format!("[rscan] load job rows failed: {}", e)),
            }
        } else {
            self.notes.clear();
            self.note_path = None;
            self.log("[rscan] no completed jobs found");
        }
    }

    fn tick(&mut self) {
        if let Some(rx) = &self.decompile_rx {
            if let Ok(res) = rx.try_recv() {
                self.decompile_running = false;
                self.decompile_rx = None;
                match res {
                    Ok(report) => {
                        self.log(format!(
                            "[rscan] decompile finished: job={} status={:?}",
                            report.job.id, report.job.status
                        ));
                        self.reload_jobs();
                        if let Some(id) = self.current_job_id() {
                            if id != report.job.id {
                                if let Some(pos) =
                                    self.jobs.iter().position(|j| j.id == report.job.id)
                                {
                                    self.job_index = pos;
                                }
                            }
                        }
                        self.load_current_job_rows();
                    }
                    Err(e) => self.log(format!("[rscan] decompile failed: {}", e)),
                }
            }
        }
        if self.decompile_running && self.decompile_last_tick.elapsed() >= Duration::from_secs(3)
        {
            self.log("[rscan] decompile running...");
            self.decompile_last_tick = Instant::now();
        }
    }

    fn apply_filters(&mut self) {
        let filter_kw = self.filter.trim().to_ascii_lowercase();
        let search_kw = self.search.trim().to_ascii_lowercase();
        self.filtered = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| {
                if !filter_kw.is_empty() && !row_match_filter(r, &filter_kw) {
                    return None;
                }
                if !search_kw.is_empty() && !row_match_search(r, &search_kw) {
                    return None;
                }
                Some(idx)
            })
            .collect();
        self.selected = 0;
        self.right_selected = 0;
        self.update_detail();
    }

    fn update_detail(&mut self) {
        self.calls_items.clear();
        self.xrefs_items.clear();
        self.ext_items.clear();
        self.func_strings_items.clear();
        self.pseudo_items.clear();
        self.asm_items.clear();
        self.current_code.clear();
        self.current_asm.clear();
        let idx = match self.filtered.get(self.selected) {
            Some(v) => *v,
            None => return,
        };
        let r = &self.rows[idx];
        let job_mode = self
            .jobs
            .get(self.job_index)
            .and_then(|j| j.mode.clone())
            .unwrap_or_default();
        let mode_lower = job_mode.to_ascii_lowercase();
        let mut code = r
            .get("pseudocode")
            .and_then(|v| v.as_str())
            .unwrap_or("<no pseudocode>")
            .to_string();
        if code == "<no pseudocode>" && mode_lower == "index" {
            code = "index mode: pseudocode/asm not exported.\npress d to run full decompile or set RSCAN_TUI_MODE=full.".to_string();
        }
        let calls = as_str_vec(r.get("calls"));
        let call_names = as_str_vec(r.get("call_names"));
        let ext = as_str_vec(r.get("ext_refs"));
        let xrefs = as_str_vec(r.get("xrefs"));
        let mut asm = as_str_vec(r.get("asm"));
        if asm.is_empty() && mode_lower == "index" {
            asm.push("<index mode: asm not exported. run full decompile>".to_string());
        }

        self.current_code = code.clone();
        self.current_asm = asm.clone();

        for (idx, c) in calls.iter().enumerate() {
            let cname = call_names.get(idx).cloned().unwrap_or_default();
            if cname.is_empty() {
                self.calls_items.push(c.to_string());
            } else {
                self.calls_items.push(format!("{c} {cname}"));
            }
        }

        self.ext_items = ext;

        self.xrefs_items = xrefs;

        if !self.strings_global {
            self.func_strings_items = extract_strings(&code, 200);
        }
        if matches!(self.tab, TuiTab::Pseudocode) {
            self.rebuild_pseudo_items(&code);
        }
        if matches!(self.tab, TuiTab::Asm) {
            self.rebuild_asm_items(&asm);
        }

        let cur_len = match self.tab {
            TuiTab::Pseudocode => self.pseudo_items.len(),
            TuiTab::Asm => self.asm_items.len(),
            TuiTab::Calls => self.calls_items.len(),
            TuiTab::Xrefs => self.xrefs_items.len(),
            TuiTab::Externals => self.ext_items.len(),
            TuiTab::Strings => {
                if self.strings_global {
                    self.strings_items.len()
                } else {
                    self.func_strings_items.len()
                }
            }
        };
        self.clamp_right_selected(cur_len);
    }

    fn current_row(&self) -> Option<&Value> {
        let idx = self.filtered.get(self.selected)?;
        self.rows.get(*idx)
    }

    fn current_selected_label(&self) -> String {
        let Some(r) = self.current_row() else {
            return "<none>".to_string();
        };
        let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("");
        let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if ea.is_empty() && name.is_empty() {
            "<none>".to_string()
        } else if name.is_empty() {
            ea.to_string()
        } else if ea.is_empty() {
            name.to_string()
        } else {
            format!("{} {}", ea, name)
        }
    }

    fn current_row_key(&self) -> Option<String> {
        let r = self.current_row()?;
        let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
        if !ea.is_empty() {
            return Some(ea.to_string());
        }
        let name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        if !name.is_empty() {
            return Some(name.to_string());
        }
        None
    }

    fn current_line_no(&self) -> Option<usize> {
        if !matches!(self.tab, TuiTab::Pseudocode | TuiTab::Asm) {
            return None;
        }
        let total = match self.tab {
            TuiTab::Pseudocode => self.pseudo_items.len(),
            TuiTab::Asm => self.asm_items.len(),
            _ => 0,
        };
        if total == 0 {
            return None;
        }
        Some(self.right_selected.saturating_add(1))
    }

    fn notes_path_for_job(&self, job_id: &str) -> PathBuf {
        self.workspace
            .join("reverse_out")
            .join(job_id)
            .join("notes.json")
    }

    fn load_notes_for_job(&mut self, job_id: &str) {
        self.notes.clear();
        let path = self.notes_path_for_job(job_id);
        self.note_path = Some(path.clone());
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let serde_json::Value::Object(map) = v {
                    for (k, v) in map {
                        if let Some(s) = v.as_str() {
                            self.notes.insert(
                                k,
                                NoteEntry {
                                    note: Some(s.to_string()),
                                    pseudo: HashMap::new(),
                                    asm: HashMap::new(),
                                },
                            );
                        } else if let serde_json::Value::Object(obj) = v {
                            let note = obj.get("note").and_then(|v| v.as_str()).map(|s| s.to_string());
                            let mut pseudo = HashMap::new();
                            if let Some(line_map) = obj.get("lines").and_then(|v| v.as_object()) {
                                for (ln, val) in line_map {
                                    if let (Ok(n), Some(s)) = (ln.parse::<usize>(), val.as_str()) {
                                        pseudo.insert(n, s.to_string());
                                    }
                                }
                            }
                            if let Some(line_map) = obj.get("pseudo").and_then(|v| v.as_object()) {
                                for (ln, val) in line_map {
                                    if let (Ok(n), Some(s)) = (ln.parse::<usize>(), val.as_str()) {
                                        pseudo.insert(n, s.to_string());
                                    }
                                }
                            }
                            let mut asm = HashMap::new();
                            if let Some(line_map) = obj.get("asm").and_then(|v| v.as_object()) {
                                for (ln, val) in line_map {
                                    if let (Ok(n), Some(s)) = (ln.parse::<usize>(), val.as_str()) {
                                        asm.insert(n, s.to_string());
                                    }
                                }
                            }
                            self.notes.insert(k, NoteEntry { note, pseudo, asm });
                        }
                    }
                }
            }
        }
    }

    fn save_notes(&mut self) {
        let Some(path) = self.note_path.clone() else {
            return;
        };
        if let Ok(text) = serde_json::to_string_pretty(&self.notes) {
            let _ = std::fs::write(path, text);
        }
    }

    fn set_note_for_current(&mut self, note: String) {
        let Some(key) = self.current_row_key() else {
            self.log("[rscan] note: no function selected");
            return;
        };
        if note.trim().is_empty() {
            self.notes.remove(&key);
            self.save_notes();
            self.log(format!("[rscan] note cleared: {}", key));
            return;
        }
        self.notes
            .entry(key.clone())
            .or_insert_with(NoteEntry::default)
            .note = Some(note.trim().to_string());
        self.save_notes();
        self.log(format!("[rscan] note saved: {}", key));
        self.update_detail();
    }

    fn clear_note_for_current(&mut self) {
        let Some(key) = self.current_row_key() else {
            self.log("[rscan] note: no function selected");
            return;
        };
        if let Some(entry) = self.notes.get_mut(&key) {
            entry.note = None;
            if !entry.has_any() {
                self.notes.remove(&key);
            }
            self.save_notes();
            self.log(format!("[rscan] note cleared: {}", key));
            self.update_detail();
        }
    }

    fn set_line_note_for_current(&mut self, line_no: usize, note: String) {
        let Some(key) = self.current_row_key() else {
            self.log("[rscan] line note: no function selected");
            return;
        };
        let max_lines = match self.tab {
            TuiTab::Pseudocode => self.pseudo_items.len(),
            TuiTab::Asm => self.asm_items.len(),
            _ => 0,
        };
        if line_no == 0 || line_no > max_lines {
            self.log(format!("[rscan] line note: invalid line {}", line_no));
            return;
        }
        let entry = self
            .notes
            .entry(key.clone())
            .or_insert_with(NoteEntry::default);
        let target = match self.tab {
            TuiTab::Pseudocode => &mut entry.pseudo,
            TuiTab::Asm => &mut entry.asm,
            _ => {
                self.log("[rscan] line note: unsupported view");
                return;
            }
        };
        if note.trim().is_empty() {
            target.remove(&line_no);
            if !entry.has_any() {
                self.notes.remove(&key);
            }
            self.save_notes();
            self.log(format!("[rscan] line note cleared: {}:{}", key, line_no));
            self.update_detail();
            return;
        }
        target.insert(line_no, note.trim().to_string());
        self.save_notes();
        self.log(format!("[rscan] line note saved: {}:{}", key, line_no));
        self.update_detail();
    }

    fn clear_line_note_for_current(&mut self, line_no: usize) {
        let Some(key) = self.current_row_key() else {
            self.log("[rscan] line note: no function selected");
            return;
        };
        if let Some(entry) = self.notes.get_mut(&key) {
            match self.tab {
                TuiTab::Pseudocode => {
                    entry.pseudo.remove(&line_no);
                }
                TuiTab::Asm => {
                    entry.asm.remove(&line_no);
                }
                _ => {
                    self.log("[rscan] line note: unsupported view");
                    return;
                }
            }
            if !entry.has_any() {
                self.notes.remove(&key);
            }
            self.save_notes();
            self.log(format!("[rscan] line note cleared: {}:{}", key, line_no));
            self.update_detail();
        }
    }

    fn rebuild_pseudo_items(&mut self, code: &str) {
        let key = self.current_row_key();
        let entry = key.as_ref().and_then(|k| self.notes.get(k));
        self.pseudo_items = build_code_items(
            code.lines().map(|s| s.to_string()),
            entry.map(|e| &e.pseudo),
        );
        self.clamp_right_selected(self.pseudo_items.len());
    }

    fn rebuild_asm_items(&mut self, asm: &[String]) {
        let key = self.current_row_key();
        let entry = key.as_ref().and_then(|k| self.notes.get(k));
        self.asm_items = build_code_items(asm.iter().cloned(), entry.map(|e| &e.asm));
        self.clamp_right_selected(self.asm_items.len());
    }

    fn clamp_right_selected(&mut self, len: usize) {
        if len == 0 {
            self.right_selected = 0;
        } else if self.right_selected >= len {
            self.right_selected = len - 1;
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        let code = key.code;
        let mods = key.modifiers;
        let backspace_like = code == KeyCode::Backspace
            || code == KeyCode::Delete
            || matches!(code, KeyCode::Char('\u{7f}') | KeyCode::Char('\u{8}'))
            || (code == KeyCode::Char('h') && mods.contains(KeyModifiers::CONTROL));
        match self.input_mode {
            TuiInputMode::Normal => match code {
                KeyCode::Char('q') => return Ok(true),
                KeyCode::Char('r') => {
                    self.refresh_jobs();
                }
                KeyCode::Char('R') => {
                    self.refresh_all();
                }
                KeyCode::PageDown => {
                    self.page_down();
                }
                KeyCode::PageUp => {
                    self.page_up();
                }
                KeyCode::Home => {
                    self.jump_top();
                }
                KeyCode::End => {
                    self.jump_bottom();
                }
                KeyCode::Char('j') | KeyCode::Down => self.move_down(),
                KeyCode::Char('k') | KeyCode::Up => self.move_up(),
                KeyCode::Char('h') | KeyCode::Left => self.focus_left(),
                KeyCode::Char('l') | KeyCode::Right => self.focus_right(),
                KeyCode::Char('b') | KeyCode::Backspace | KeyCode::Esc => self.focus_left(),
                KeyCode::Delete => self.focus_left(),
                KeyCode::Char('J') => {
                    self.focus = TuiFocus::Jobs;
                }
                KeyCode::Char('n') => {
                    if self.job_index + 1 < self.jobs.len() {
                        self.job_index += 1;
                        self.load_current_job_rows();
                    }
                }
                KeyCode::Char('p') => {
                    if self.job_index > 0 {
                        self.job_index -= 1;
                        self.load_current_job_rows();
                    }
                }
                KeyCode::Char('/') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::Filter);
                    self.input_buf.clear();
                }
                KeyCode::Char('s') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::Search);
                    self.input_buf.clear();
                }
                KeyCode::Char('S') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::StringSearch);
                    self.input_buf.clear();
                }
                KeyCode::Char('c') => {
                    if self.focus == TuiFocus::Right && matches!(self.tab, TuiTab::Pseudocode | TuiTab::Asm) {
                        self.input_mode = TuiInputMode::Prompt;
                        self.pending_action = Some(TuiPendingAction::CommentLine);
                        self.input_buf.clear();
                    } else {
                        self.input_mode = TuiInputMode::Prompt;
                        self.pending_action = Some(TuiPendingAction::Comment);
                        self.input_buf.clear();
                    }
                }
                KeyCode::Char('C') => {
                    if self.focus == TuiFocus::Right && matches!(self.tab, TuiTab::Pseudocode | TuiTab::Asm) {
                        if let Some(line) = self.current_line_no() {
                            self.clear_line_note_for_current(line);
                        }
                    } else {
                        self.clear_note_for_current();
                    }
                }
                KeyCode::Char(';') => {
                    if self.focus == TuiFocus::Right && matches!(self.tab, TuiTab::Pseudocode | TuiTab::Asm) {
                        self.input_mode = TuiInputMode::Prompt;
                        self.pending_action = Some(TuiPendingAction::CommentLine);
                        self.input_buf.clear();
                    }
                }
                KeyCode::Char('x') => {
                    self.clear_filters();
                }
                KeyCode::Char('o') => {
                    self.activate_item();
                }
                KeyCode::Char('D') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::DeleteJob);
                    self.input_buf.clear();
                    self.log("[rscan] delete: type 'yes' to delete current job or enter job_id");
                }
                KeyCode::Char('g') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::JumpTo);
                    self.input_buf.clear();
                }
                KeyCode::Char(':') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::Command);
                    self.input_buf.clear();
                }
                KeyCode::Char('1') => self.set_tab(TuiTab::Pseudocode),
                KeyCode::Char('2') => self.set_tab(TuiTab::Calls),
                KeyCode::Char('3') => self.set_tab(TuiTab::Xrefs),
                KeyCode::Char('4') => self.set_tab(TuiTab::Externals),
                KeyCode::Char('5') => self.set_tab(TuiTab::Strings),
                KeyCode::Char('6') => self.set_tab(TuiTab::Asm),
                KeyCode::Char('a') => self.set_tab(TuiTab::Asm),
                KeyCode::Char('d') => {
                    self.input_mode = TuiInputMode::Prompt;
                    self.pending_action = Some(TuiPendingAction::Decompile);
                    self.input_buf.clear();
                    self.log("[rscan] decompile: <full|index|function> [name] [noasm] [only-named]");
                }
                KeyCode::Tab => {
                    self.focus = match self.focus {
                        TuiFocus::Jobs => TuiFocus::Functions,
                        TuiFocus::Functions => TuiFocus::Right,
                        TuiFocus::Right => TuiFocus::Strings,
                        TuiFocus::Strings => TuiFocus::Jobs,
                    };
                }
                KeyCode::Enter => self.activate_item(),
                KeyCode::Char('?') => {
                    self.log("keys: j/k move, h/l focus, b back, enter select/jump, pgup/pgdn/home/end scroll, / filter, s search, c note, ; line-note, C clear-note, x clear, g goto, : cmd, 1..6 tabs, d decompile, r refresh, R reindex, q quit");
                }
                _ => {}
            },
            TuiInputMode::Prompt => {
                if backspace_like {
                    self.input_buf.pop();
                    return Ok(false);
                }
                match code {
                KeyCode::Esc => {
                    self.input_mode = TuiInputMode::Normal;
                    self.input_buf.clear();
                    self.pending_action = None;
                }
                KeyCode::Enter => {
                    let val = self.input_buf.trim().to_string();
                    self.input_buf.clear();
                    self.input_mode = TuiInputMode::Normal;
                    match self.pending_action.take() {
                        Some(TuiPendingAction::Filter) => {
                            self.filter = val;
                            self.apply_filters();
                        }
                        Some(TuiPendingAction::Search) => {
                            self.search = val;
                            self.apply_filters();
                        }
                        Some(TuiPendingAction::JumpTo) => {
                            if !val.is_empty() {
                                self.jump_to(&val);
                            }
                        }
                        Some(TuiPendingAction::Comment) => {
                            self.set_note_for_current(val);
                        }
                        Some(TuiPendingAction::CommentLine) => {
                            if let Some(line) = self.current_line_no() {
                                self.set_line_note_for_current(line, val);
                            } else {
                                self.log("[rscan] line note: no line selected");
                            }
                        }
                        Some(TuiPendingAction::StringSearch) => {
                            self.set_string_search(val);
                        }
                        Some(TuiPendingAction::DeleteJob) => {
                            if val.is_empty() {
                                self.log("[rscan] delete canceled");
                            } else if val.eq_ignore_ascii_case("yes") || val.eq_ignore_ascii_case("y") {
                                if let Some(id) = self.current_job_id() {
                                    self.delete_job(&id);
                                } else {
                                    self.log("[rscan] delete: no job selected");
                                }
                            } else {
                                self.delete_job(&val);
                            }
                        }
                        Some(TuiPendingAction::Decompile) => {
                            self.start_decompile_from_input(&val);
                        }
                        Some(TuiPendingAction::Command) => {
                            if !val.is_empty() {
                                self.run_command(&val);
                            }
                        }
                        None => {}
                    }
                }
                KeyCode::Backspace => {
                    self.input_buf.pop();
                }
                KeyCode::Char(c) => self.input_buf.push(c),
                _ => {}
            }},
        }
        Ok(false)
    }

    fn jump_to(&mut self, key: &str) {
        if let Some(pos) = self.filtered.iter().position(|idx| {
            let r = &self.rows[*idx];
            row_match_key(r, key)
        }) {
            self.selected = pos;
            self.update_detail();
        } else {
            self.log(format!("[rscan] not found: {}", key));
        }
    }

    fn move_down(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                if self.job_index + 1 < self.jobs.len() {
                    self.job_index += 1;
                }
            }
            TuiFocus::Functions => {
                if self.selected + 1 < self.filtered.len() {
                    self.selected += 1;
                    self.update_detail();
                }
            }
            TuiFocus::Right => {
                let items = self.current_right_items();
                if self.right_selected + 1 < items.len() {
                    self.right_selected += 1;
                }
            }
            TuiFocus::Strings => {
                if self.strings_selected + 1 < self.strings_items.len() {
                    self.strings_selected += 1;
                }
            }
        }
    }

    fn move_up(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                if self.job_index > 0 {
                    self.job_index -= 1;
                }
            }
            TuiFocus::Functions => {
                if self.selected > 0 {
                    self.selected -= 1;
                    self.update_detail();
                }
            }
            TuiFocus::Right => {
                if self.right_selected > 0 {
                    self.right_selected -= 1;
                }
            }
            TuiFocus::Strings => {
                if self.strings_selected > 0 {
                    self.strings_selected -= 1;
                }
            }
        }
    }

    fn focus_left(&mut self) {
        self.focus = match self.focus {
            TuiFocus::Strings => TuiFocus::Right,
            TuiFocus::Right => TuiFocus::Functions,
            TuiFocus::Functions => TuiFocus::Jobs,
            TuiFocus::Jobs => TuiFocus::Jobs,
        };
        self.right_selected = 0;
    }

    fn focus_right(&mut self) {
        self.focus = match self.focus {
            TuiFocus::Jobs => TuiFocus::Functions,
            TuiFocus::Functions => TuiFocus::Right,
            TuiFocus::Right => TuiFocus::Strings,
            TuiFocus::Strings => TuiFocus::Strings,
        };
    }

    fn page_down(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                if self.jobs.is_empty() {
                    return;
                }
                let step = self.jobs_view_height.max(1);
                self.job_index = (self.job_index + step).min(self.jobs.len() - 1);
            }
            TuiFocus::Functions => {
                if self.filtered.is_empty() {
                    return;
                }
                let step = self.funcs_view_height.max(1);
                self.selected = (self.selected + step).min(self.filtered.len() - 1);
                self.update_detail();
            }
            TuiFocus::Right => {
                let items = self.current_right_items();
                if items.is_empty() {
                    return;
                }
                let step = self.right_view_height.max(1);
                self.right_selected = (self.right_selected + step).min(items.len() - 1);
            }
            TuiFocus::Strings => {
                let items = &self.strings_items;
                if items.is_empty() {
                    return;
                }
                let step = self.strings_view_height.max(1);
                self.strings_selected = (self.strings_selected + step).min(items.len() - 1);
            }
        }
    }

    fn page_up(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                let step = self.jobs_view_height.max(1);
                self.job_index = self.job_index.saturating_sub(step);
            }
            TuiFocus::Functions => {
                let step = self.funcs_view_height.max(1);
                self.selected = self.selected.saturating_sub(step);
                self.update_detail();
            }
            TuiFocus::Right => {
                let step = self.right_view_height.max(1);
                self.right_selected = self.right_selected.saturating_sub(step);
            }
            TuiFocus::Strings => {
                let step = self.strings_view_height.max(1);
                self.strings_selected = self.strings_selected.saturating_sub(step);
            }
        }
    }

    fn jump_top(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                self.job_index = 0;
            }
            TuiFocus::Functions => {
                self.selected = 0;
                self.update_detail();
            }
            TuiFocus::Right => {
                self.right_selected = 0;
            }
            TuiFocus::Strings => {
                self.strings_selected = 0;
            }
        }
    }

    fn jump_bottom(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                if !self.jobs.is_empty() {
                    self.job_index = self.jobs.len() - 1;
                }
            }
            TuiFocus::Functions => {
                if !self.filtered.is_empty() {
                    self.selected = self.filtered.len() - 1;
                    self.update_detail();
                }
            }
            TuiFocus::Right => {
                let items = self.current_right_items();
                if !items.is_empty() {
                    self.right_selected = items.len() - 1;
                }
            }
            TuiFocus::Strings => {
                let items = &self.strings_items;
                if !items.is_empty() {
                    self.strings_selected = items.len() - 1;
                }
            }
        }
    }

    fn clear_filters(&mut self) {
        self.filter.clear();
        self.search.clear();
        if self.strings_global {
            self.clear_string_search();
        }
        self.apply_filters();
        self.log("[rscan] filter/search cleared");
    }

    fn refresh_jobs(&mut self) {
        self.reload_jobs();
        self.load_current_job_rows();
    }

    fn refresh_all(&mut self) {
        self.refresh_jobs();
        match build_project_index(&self.workspace) {
            Ok(n) => {
                self.load_project_index();
                if let Err(e) = build_tantivy_index(&self.workspace) {
                    self.log(format!("[rscan] tantivy index failed: {}", e));
                }
                self.log(format!("[rscan] index refreshed: {} entries", n));
            }
            Err(e) => self.log(format!("[rscan] index refresh failed: {}", e)),
        }
    }

    fn set_tab(&mut self, tab: TuiTab) {
        self.tab = tab;
        self.right_selected = 0;
        match self.tab {
            TuiTab::Pseudocode => {
                if self.pseudo_items.is_empty() && !self.current_code.is_empty() {
                    let code = self.current_code.clone();
                    self.rebuild_pseudo_items(&code);
                }
            }
            TuiTab::Asm => {
                if self.asm_items.is_empty() && !self.current_asm.is_empty() {
                    let asm = self.current_asm.clone();
                    self.rebuild_asm_items(&asm);
                }
            }
            TuiTab::Strings => {
                if self.strings_global {
                    self.refresh_global_strings_view();
                } else if !self.current_code.is_empty() && self.func_strings_items.is_empty() {
                    self.func_strings_items = extract_strings(&self.current_code, 200);
                    self.clamp_right_selected(self.func_strings_items.len());
                }
            }
            _ => {}
        }
    }

    fn ensure_global_strings_loaded(&mut self) {
        if !self.global_strings.is_empty() {
            return;
        }
        match std::fs::read(&self.input) {
            Ok(bytes) => {
                self.global_strings = extract_ascii_strings(&bytes, 4, 20_000);
                self.log(format!(
                    "[rscan] loaded {} binary strings",
                    self.global_strings.len()
                ));
            }
            Err(e) => {
                self.log(format!("[rscan] string scan failed: {}", e));
            }
        }
    }

    fn set_string_search(&mut self, query: String) {
        let q = query.trim().to_string();
        if q.is_empty() {
            self.clear_string_search();
            return;
        }
        self.strings_query = q;
        self.strings_global = true;
        self.ensure_global_strings_loaded();
        self.refresh_global_strings_view();
        self.tab = TuiTab::Strings;
        self.right_selected = 0;
        self.strings_selected = 0;
        self.log(format!("[rscan] string search: {}", self.strings_query));
    }

    fn clear_string_search(&mut self) {
        if self.strings_global {
            self.strings_global = false;
            self.strings_query.clear();
            self.update_detail();
        }
        if !self.strings_query.is_empty() || self.strings_items.is_empty() {
            self.strings_query.clear();
            self.ensure_global_strings_loaded();
            self.refresh_global_strings_view();
        }
        self.log("[rscan] string search cleared");
    }

    fn refresh_global_strings_view(&mut self) {
        let kw = self.strings_query.to_ascii_lowercase();
        let mut out = Vec::new();
        for s in &self.global_strings {
            if s.to_ascii_lowercase().contains(&kw) {
                out.push(s.clone());
                if out.len() >= 2000 {
                    break;
                }
            }
        }
        if out.is_empty() {
            out.push(format!("<no matches for '{}'>", self.strings_query));
        }
        self.strings_items = out;
        self.clamp_right_selected(self.strings_items.len());
        if self.strings_selected >= self.strings_items.len() {
            self.strings_selected = self.strings_items.len().saturating_sub(1);
        }
    }

    fn default_decompile_mode(&self) -> DecompileMode {
        match self.tab {
            TuiTab::Pseudocode | TuiTab::Asm => DecompileMode::Full,
            _ => DecompileMode::Index,
        }
    }

    fn parse_decompile_input(&self, input: &str) -> DecompileRequest {
        let mut mode: Option<DecompileMode> = None;
        let mut function: Option<String> = None;
        let mut skip_asm = false;
        let mut only_named = false;
        let raw = input.trim();
        if raw.is_empty() {
            if let Ok(env_mode) = std::env::var("RSCAN_TUI_MODE") {
                if let Some(m) = DecompileMode::parse(&env_mode) {
                    mode = Some(m);
                }
            }
        }
        for tok in raw.split_whitespace() {
            let t = tok.to_ascii_lowercase();
            match t.as_str() {
                "full" => mode = Some(DecompileMode::Full),
                "index" => mode = Some(DecompileMode::Index),
                "function" | "func" | "fn" => mode = Some(DecompileMode::Function),
                "noasm" | "skip-asm" | "skipasm" | "asm=0" | "asm=off" | "asm=none" => {
                    skip_asm = true
                }
                "only-named" | "onlynamed" | "named" | "onlyname" => only_named = true,
                "current" | "." | "this" => {
                    function = self.current_row_key();
                }
                _ => {
                    if let Some(rest) = tok.strip_prefix("fn=")
                        .or_else(|| tok.strip_prefix("func="))
                        .or_else(|| tok.strip_prefix("function="))
                    {
                        if !rest.is_empty() {
                            function = Some(rest.to_string());
                            continue;
                        }
                    }
                    if let Some(rest) = tok.strip_prefix("name=") {
                        if !rest.is_empty() {
                            function = Some(rest.to_string());
                            continue;
                        }
                    }
                    if function.is_none() && !tok.starts_with('-') {
                        function = Some(tok.to_string());
                    }
                }
            }
        }
        let default_mode = self.default_decompile_mode();
        let mut mode = mode.unwrap_or_else(|| {
            if function.is_some() {
                DecompileMode::Function
            } else {
                default_mode
            }
        });
        if matches!(mode, DecompileMode::Function) && function.is_none() {
            function = self.current_row_key();
            if function.is_none() {
                mode = default_mode;
            }
        }
        DecompileRequest {
            mode,
            function,
            skip_asm,
            only_named,
        }
    }

    fn start_decompile_from_input(&mut self, input: &str) {
        let req = self.parse_decompile_input(input);
        self.start_decompile_request(req);
    }

    fn start_decompile_request(&mut self, req: DecompileRequest) {
        if self.decompile_running {
            self.log("[rscan] decompile already running");
            return;
        }
        if matches!(req.mode, DecompileMode::Function) && !self.has_non_function_job() {
            self.log("[rscan] function mode requires full/index list; running index first");
            let idx_req = DecompileRequest {
                mode: DecompileMode::Index,
                function: None,
                skip_asm: false,
                only_named: false,
            };
            self.start_decompile_request(idx_req);
            return;
        }
        let engine = std::env::var("RSCAN_TUI_ENGINE").unwrap_or_else(|_| "ghidra".to_string());
        let timeout = std::env::var("RSCAN_TUI_TIMEOUT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(900);
        if matches!(req.mode, DecompileMode::Function) && req.function.is_none() {
            self.log("[rscan] decompile: no function specified");
            return;
        }

        let (tx, rx) = mpsc::channel();
        let input = self.input.clone();
        let workspace = self.workspace.clone();
        let engine_for_thread = engine.clone();
        let mode = req.mode;
        let function = req.function.clone();
        let skip_asm = req.skip_asm;
        let only_named = req.only_named;
        std::thread::spawn(move || {
            let mut _env = TempEnv::new();
            if engine_for_thread.eq_ignore_ascii_case("ghidra")
                || engine_for_thread.eq_ignore_ascii_case("auto")
            {
                _env.set("RSCAN_GHIDRA_SKIP_ASM", if skip_asm { "1" } else { "0" });
                _env.set("RSCAN_GHIDRA_ONLY_NAMED", if only_named { "1" } else { "0" });
            }
            let out = run_decompile_job(
                &input,
                &workspace,
                &engine_for_thread,
                mode,
                function.as_deref(),
                Some(timeout),
            );
            let _ = tx.send(out);
        });
        self.decompile_rx = Some(rx);
        self.decompile_running = true;
        self.decompile_last_tick = Instant::now();
        let mut extra = Vec::new();
        if let Some(f) = &req.function {
            extra.push(format!("function={}", f));
        }
        if req.skip_asm {
            extra.push("skip_asm".to_string());
        }
        if req.only_named {
            extra.push("only_named".to_string());
        }
        let extra = if extra.is_empty() {
            String::new()
        } else {
            format!(" ({})", extra.join(", "))
        };
        let mode_label = match req.mode {
            DecompileMode::Full => "full",
            DecompileMode::Index => "index",
            DecompileMode::Function => "function",
        };
        self.log(format!(
            "[rscan] decompile started: engine={} mode={} timeout={}s{}",
            engine, mode_label, timeout, extra
        ));
    }

    fn delete_job(&mut self, job_id: &str) {
        match clear_jobs(&self.workspace, Some(job_id)) {
            Ok(n) => {
                if n == 0 {
                    self.log(format!("[rscan] delete: job not found {}", job_id));
                } else {
                    self.log(format!("[rscan] deleted job {}", job_id));
                }
                self.refresh_jobs();
            }
            Err(e) => self.log(format!("[rscan] delete failed: {}", e)),
        }
    }

    fn current_right_items(&self) -> &Vec<String> {
        match self.tab {
            TuiTab::Pseudocode => &self.pseudo_items,
            TuiTab::Asm => &self.asm_items,
            TuiTab::Calls => &self.calls_items,
            TuiTab::Xrefs => &self.xrefs_items,
            TuiTab::Externals => &self.ext_items,
            TuiTab::Strings => {
                if self.strings_global {
                    &self.strings_items
                } else {
                    &self.func_strings_items
                }
            }
        }
    }

    fn activate_item(&mut self) {
        match self.focus {
            TuiFocus::Jobs => {
                self.load_current_job_rows();
                self.focus = TuiFocus::Functions;
            }
            TuiFocus::Functions => {}
            TuiFocus::Right => {
                let key = {
                    let items = self.current_right_items();
                    if items.is_empty() {
                        None
                    } else {
                        items
                            .get(self.right_selected)
                            .and_then(|s| s.split_whitespace().next())
                            .map(|s| s.to_string())
                    }
                };
                let Some(key) = key else {
                    return;
                };
                if matches!(self.tab, TuiTab::Calls | TuiTab::Xrefs) && !key.is_empty() {
                    self.jump_to(&key);
                    self.focus = TuiFocus::Functions;
                }
            }
            TuiFocus::Strings => {}
        }
    }

    fn run_command(&mut self, cmdline: &str) {
        let mut parts = cmdline.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        match cmd {
            "filter" => {
                let kw = parts.collect::<Vec<_>>().join(" ");
                self.filter = kw;
                self.apply_filters();
            }
            "grep" | "lsearch" | "localsearch" => {
                let kw = parts.collect::<Vec<_>>().join(" ");
                self.search = kw;
                self.apply_filters();
            }
            "goto" | "show" => {
                let key = parts.collect::<Vec<_>>().join(" ");
                if !key.is_empty() {
                    self.jump_to(&key);
                }
            }
            "open" => {
                if let Some(id) = parts.next() {
                    if let Some(pos) = self.jobs.iter().position(|j| j.id == id) {
                        self.job_index = pos;
                        self.load_current_job_rows();
                    } else {
                        self.log(format!("[rscan] job not found: {}", id));
                    }
                } else {
                    self.load_current_job_rows();
                }
            }
            "find" => {
                let kw = parts.collect::<Vec<_>>().join(" ");
                if kw.is_empty() {
                    self.log("[rscan] find <keyword>");
                } else {
                    self.search_project_index(&kw);
                    self.filter = kw;
                    self.apply_filters();
                }
            }
            "search" => {
                let kw = parts.collect::<Vec<_>>().join(" ");
                if kw.is_empty() {
                    self.log("[rscan] search <keyword>");
                } else {
                    match search_tantivy(&self.workspace, &kw) {
                        Ok(hit) => {
                            if let Some((job_id, ea)) = hit {
                                if let Some(pos) = self.jobs.iter().position(|j| j.id == job_id) {
                                    self.job_index = pos;
                                    self.load_current_job_rows();
                                    if !ea.is_empty() {
                                        self.jump_to(&ea);
                                    }
                                }
                            } else {
                                self.log("[rscan] no hits");
                            }
                        }
                        Err(e) => self.log(format!("[rscan] search failed: {}", e)),
                    }
                    self.filter = kw;
                    self.apply_filters();
                }
            }
            "strings" | "str" => {
                let kw = parts.collect::<Vec<_>>().join(" ");
                if kw.is_empty() || kw.eq_ignore_ascii_case("clear") {
                    self.clear_string_search();
                } else {
                    self.set_string_search(kw);
                }
            }
            "load-strings" => {
                self.ensure_global_strings_loaded();
                self.refresh_global_strings_view();
            }
            "index" => {
                match build_project_index(&self.workspace) {
                    Ok(n) => {
                        self.log(format!("[rscan] project index built: {} entries", n));
                        self.load_project_index();
                        if let Err(e) = build_tantivy_index(&self.workspace) {
                            self.log(format!("[rscan] tantivy index failed: {}", e));
                        }
                    }
                    Err(e) => self.log(format!("[rscan] index failed: {}", e)),
                }
            }
            "refresh" | "reload" => {
                self.refresh_jobs();
                self.log("[rscan] refreshed");
            }
            "reindex" => {
                self.refresh_all();
            }
            "graph" => {
                let ty = parts.next().unwrap_or("calls");
                let out = parts.next().unwrap_or("reverse_out/graph.dot");
                let job_id = parts.next();
                let job_id = job_id
                    .map(|s| s.to_string())
                    .or_else(|| self.current_job_id());
                if job_id.is_none() {
                    self.log("[rscan] graph <calls|xrefs> <out> [job_id]");
                } else {
                    let res = export_graph(&self.workspace, &job_id.unwrap(), ty, out);
                    match res {
                        Ok(_) => self.log(format!("[rscan] graph exported: {}", out)),
                        Err(e) => self.log(format!("[rscan] graph failed: {}", e)),
                    }
                }
            }
            "job" => {
                if let Some(id) = parts.next() {
                    if let Some(pos) = self.jobs.iter().position(|j| j.id == id) {
                        self.job_index = pos;
                        self.load_current_job_rows();
                    } else {
                        self.log(format!("[rscan] job not found: {}", id));
                    }
                }
            }
            "delete" | "del" => {
                if let Some(id) = parts.next() {
                    self.delete_job(id);
                } else if let Some(id) = self.current_job_id() {
                    self.delete_job(&id);
                } else {
                    self.log("[rscan] delete <job_id>");
                }
            }
            "back" | "return" => {
                self.focus_left();
            }
            "note" | "comment" => {
                let rest = parts.collect::<Vec<_>>().join(" ");
                if rest.is_empty() {
                    if let Some(key) = self.current_row_key() {
                        if let Some(entry) = self.notes.get(&key) {
                            if let Some(note) = &entry.note {
                                self.log(format!("[rscan] note: {}", note));
                            } else {
                                let count = entry.pseudo.len() + entry.asm.len();
                                if count > 0 {
                                    self.log(format!("[rscan] note: <{} line notes>", count));
                                } else {
                                    self.log("[rscan] note: <none>");
                                }
                            }
                        } else {
                            self.log("[rscan] note: <none>");
                        }
                    } else {
                        self.log("[rscan] note: no function selected");
                    }
                } else if rest.eq_ignore_ascii_case("clear") {
                    self.clear_note_for_current();
                } else {
                    self.set_note_for_current(rest);
                }
            }
            "note-line" | "comment-line" => {
                let line = parts.next();
                let rest = parts.collect::<Vec<_>>().join(" ");
                let Some(line) = line.and_then(|v| v.parse::<usize>().ok()) else {
                    self.log("[rscan] note-line <line> <text>|clear");
                    return;
                };
                if rest.eq_ignore_ascii_case("clear") {
                    self.clear_line_note_for_current(line);
                } else {
                    self.set_line_note_for_current(line, rest);
                }
            }
            "clear" | "reset" => {
                self.clear_filters();
            }
            "decompile" => {
                let rest = parts.collect::<Vec<_>>().join(" ");
                self.start_decompile_from_input(&rest);
            }
            "tab" => {
                let t = parts.next().unwrap_or("");
                match t {
                    "1" | "p" | "pseudo" => self.set_tab(TuiTab::Pseudocode),
                    "2" | "c" | "calls" => self.set_tab(TuiTab::Calls),
                    "3" | "x" | "xrefs" => self.set_tab(TuiTab::Xrefs),
                    "4" | "e" | "ext" => self.set_tab(TuiTab::Externals),
                    "5" | "s" | "strings" => self.set_tab(TuiTab::Strings),
                    "6" | "a" | "asm" => self.set_tab(TuiTab::Asm),
                    _ => self.log("[rscan] tab: use 1..6 or p/c/x/e/s/a"),
                }
            }
            "help" => self.log("commands: filter <kw>, grep <kw>, clear, goto <key>, open [job_id], find <kw>, search <kw>, strings <kw|clear>, load-strings, index, reindex, refresh, graph <calls|xrefs> <out> [job_id], delete [job_id], note <text>|clear, note-line <n> <text>|clear, decompile, tab <1..6>"),
            _ => self.log("[rscan] unknown command"),
        }
    }

    fn load_project_index(&mut self) {
        self.project_index = load_project_index(&self.workspace).unwrap_or_default();
    }

    fn search_project_index(&mut self, keyword: &str) {
        if self.project_index.is_empty() {
            self.load_project_index();
        }
        if self.project_index.is_empty() {
            self.log("[rscan] project index empty; run :index");
            return;
        }
        let kw = keyword.to_ascii_lowercase();
        let mut hits = Vec::new();
        for r in &self.project_index {
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("");
            let sig = r.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            if name.to_ascii_lowercase().contains(&kw)
                || ea.to_ascii_lowercase().contains(&kw)
                || sig.to_ascii_lowercase().contains(&kw)
            {
                hits.push(r.clone());
                if hits.len() >= 20 {
                    break;
                }
            }
        }
        if hits.is_empty() {
            self.log("[rscan] no hits");
            return;
        }
        let first = hits[0].clone();
        let job_id = first.get("job_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let key = first.get("ea").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !job_id.is_empty() {
            if let Some(pos) = self.jobs.iter().position(|j| j.id == job_id) {
                self.job_index = pos;
                self.load_current_job_rows();
                if !key.is_empty() {
                    self.jump_to(&key);
                }
            }
        }
        self.log(format!("[rscan] hits: {}", hits.len()));
    }

}

fn draw_tui(f: &mut ratatui::Frame<'_>, state: &mut TuiState) {
    let size = f.size();
    let vchunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(5), Constraint::Length(5)].as_ref())
        .split(size);

    let header = Block::default().title("rscan reverse TUI").borders(Borders::ALL);
    let job_id = state
        .current_job_id()
        .unwrap_or_else(|| "none".to_string());
    let job_meta = state.jobs.get(state.job_index);
    let job_mode = job_meta
        .and_then(|j| j.mode.clone())
        .unwrap_or_else(|| "-".to_string());
    let job_status = job_meta
        .map(|j| format!("{:?}", j.status))
        .unwrap_or_else(|| "-".to_string());
    let focus_label = match state.focus {
        TuiFocus::Jobs => "jobs",
        TuiFocus::Functions => "funcs",
        TuiFocus::Right => "view",
        TuiFocus::Strings => "strings",
    };
    let funcs_total = state.rows.len();
    let funcs_view = state.filtered.len();
    let decomp_state = if state.decompile_running { "running" } else { "idle" };
    let header_text = Text::from(vec![
        Line::from(vec![
            Span::styled("target: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.input.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("job: ", Style::default().fg(Color::Yellow)),
            Span::raw(job_id),
            Span::raw("  "),
            Span::styled("mode: ", Style::default().fg(Color::Yellow)),
            Span::raw(job_mode),
            Span::raw("  "),
            Span::styled("status: ", Style::default().fg(Color::Yellow)),
            Span::raw(job_status),
            Span::raw("  "),
            Span::styled("funcs: ", Style::default().fg(Color::Yellow)),
            Span::raw(format!("{}/{}", funcs_view, funcs_total)),
        ]),
        Line::from(vec![
            Span::styled("sel: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.current_selected_label()),
            Span::raw("  "),
            Span::styled("filter: ", Style::default().fg(Color::Yellow)),
            Span::raw(if state.filter.is_empty() {
                "<none>".to_string()
            } else {
                state.filter.clone()
            }),
            Span::raw("  "),
            Span::styled("search: ", Style::default().fg(Color::Yellow)),
            Span::raw(if state.search.is_empty() {
                "<none>".to_string()
            } else {
                state.search.clone()
            }),
            Span::raw("  "),
            Span::styled("focus: ", Style::default().fg(Color::Yellow)),
            Span::raw(focus_label),
            Span::raw("  "),
            Span::styled("decompile: ", Style::default().fg(Color::Yellow)),
            Span::raw(decomp_state),
        ]),
    ]);
    f.render_widget(Paragraph::new(header_text).block(header), vchunks[0]);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(vchunks[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(5)].as_ref())
        .split(mid[0]);
    state.jobs_view_height = left[0].height.saturating_sub(2) as usize;
    state.funcs_view_height = left[1].height.saturating_sub(2) as usize;

    let job_items: Vec<ListItem> = state
        .jobs
        .iter()
        .map(|j| {
            let id = if j.id.len() > 8 {
                j.id[j.id.len() - 8..].to_string()
            } else {
                j.id.clone()
            };
            let mode = j.mode.clone().unwrap_or_else(|| "-".to_string());
            let status = format!("{:?}", j.status);
            ListItem::new(format!("{} {:9} {}", id, mode, status))
        })
        .collect();
    let jobs_title = format!("Jobs ({})", state.jobs.len());
    let jobs_border = if state.focus == TuiFocus::Jobs {
        Block::default()
            .title(jobs_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::default().title(jobs_title).borders(Borders::ALL)
    };
    let jobs_list = List::new(job_items)
        .block(jobs_border)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    f.render_stateful_widget(jobs_list, left[0], &mut list_state(state.job_index));

    let funcs_total = state.filtered.len();
    let view_h = state.funcs_view_height.max(1);
    let mut start = 0usize;
    if funcs_total > view_h {
        if state.selected + 1 > view_h {
            start = state.selected + 1 - view_h;
        }
        if start + view_h > funcs_total {
            start = funcs_total.saturating_sub(view_h);
        }
    }
    let end = (start + view_h).min(funcs_total);
    let list_items: Vec<ListItem> = if funcs_total == 0 {
        vec![ListItem::new("<empty>")]
    } else {
        state.filtered[start..end]
            .iter()
            .map(|idx| {
                let r = &state.rows[*idx];
                let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("<no-ea>");
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("<no-name>");
                let key = if !ea.is_empty() { ea } else { name };
                let note_mark = match state.notes.get(key) {
                    Some(entry) if entry.has_any() => " *",
                    _ => "",
                };
                ListItem::new(format!("{} {}{}", ea, name, note_mark))
            })
            .collect()
    };
    let funcs_title = format!("Functions ({}/{})", state.filtered.len(), state.rows.len());
    let list_border = if state.focus == TuiFocus::Functions {
        Block::default()
            .title(funcs_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::default().title(funcs_title).borders(Borders::ALL)
    };
    let list = List::new(list_items)
        .block(list_border)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    let selected = if funcs_total == 0 {
        0
    } else {
        state.selected.saturating_sub(start)
    };
    f.render_stateful_widget(list, left[1], &mut list_state(selected));

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Percentage(60),
                Constraint::Percentage(40),
            ]
            .as_ref(),
        )
        .split(mid[1]);
    state.right_view_height = right[1].height.saturating_sub(2) as usize;
    state.strings_view_height = right[2].height.saturating_sub(2) as usize;

    let tab_titles = ["Pseudocode", "Calls", "Xrefs", "Externals", "Strings", "Asm"]
        .iter()
        .map(|t| Line::from(Span::raw(*t)))
        .collect::<Vec<_>>();
    let tab_idx = match state.tab {
        TuiTab::Pseudocode => 0,
        TuiTab::Calls => 1,
        TuiTab::Xrefs => 2,
        TuiTab::Externals => 3,
        TuiTab::Strings => 4,
        TuiTab::Asm => 5,
    };
    let tabs = Tabs::new(tab_titles)
        .select(tab_idx)
        .block(Block::default().title("View").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Cyan));
    f.render_widget(tabs, right[0]);

    let view_title = match state.tab {
        TuiTab::Pseudocode => "Details: Pseudocode",
        TuiTab::Calls => "Details: Calls",
        TuiTab::Xrefs => "Details: Xrefs",
        TuiTab::Externals => "Details: Externals",
        TuiTab::Strings => "Details: Strings",
        TuiTab::Asm => "Details: Asm",
    };
    let right_border = if state.focus == TuiFocus::Right {
        Block::default()
            .title(view_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::default().title(view_title).borders(Borders::ALL)
    };

    let items = match state.tab {
        TuiTab::Pseudocode => &state.pseudo_items,
        TuiTab::Asm => &state.asm_items,
        TuiTab::Calls => &state.calls_items,
        TuiTab::Xrefs => &state.xrefs_items,
        TuiTab::Externals => &state.ext_items,
        TuiTab::Strings => &state.strings_items,
    };
    let total = items.len();
    let view_h = state.right_view_height.max(1);
    let mut start = 0usize;
    if total > view_h {
        if state.right_selected + 1 > view_h {
            start = state.right_selected + 1 - view_h;
        }
        if start + view_h > total {
            start = total.saturating_sub(view_h);
        }
    }
    let end = (start + view_h).min(total);
    let list_items = if items.is_empty() {
        vec![ListItem::new("<empty>")]
    } else {
        items[start..end]
            .iter()
            .map(|s| ListItem::new(s.clone()))
            .collect()
    };
    let selected = if items.is_empty() {
        0
    } else {
        state.right_selected.saturating_sub(start)
    };
    let list = List::new(list_items)
        .block(right_border)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, right[1], &mut list_state(selected));

    let strings_title = if state.strings_query.is_empty() {
        "Strings".to_string()
    } else {
        format!("Strings: {}", state.strings_query)
    };
    let strings_border = if state.focus == TuiFocus::Strings {
        Block::default()
            .title(strings_title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
    } else {
        Block::default().title(strings_title).borders(Borders::ALL)
    };
    let s_total = state.strings_items.len();
    let s_view_h = state.strings_view_height.max(1);
    let mut s_start = 0usize;
    if s_total > s_view_h {
        if state.strings_selected + 1 > s_view_h {
            s_start = state.strings_selected + 1 - s_view_h;
        }
        if s_start + s_view_h > s_total {
            s_start = s_total.saturating_sub(s_view_h);
        }
    }
    let s_end = (s_start + s_view_h).min(s_total);
    let strings_items = if s_total == 0 {
        vec![ListItem::new("<empty>")]
    } else {
        state.strings_items[s_start..s_end]
            .iter()
            .map(|s| ListItem::new(s.clone()))
            .collect()
    };
    let s_selected = if s_total == 0 {
        0
    } else {
        state.strings_selected.saturating_sub(s_start)
    };
    let strings_list = List::new(strings_items)
        .block(strings_border)
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    f.render_stateful_widget(strings_list, right[2], &mut list_state(s_selected));

    let bottom_inner_h = vchunks[2].height.saturating_sub(2) as usize;
    let max_log_lines = bottom_inner_h.saturating_sub(1).max(0);
    let log = if max_log_lines == 0 {
        String::new()
    } else {
        state
            .log
            .iter()
            .rev()
            .take(max_log_lines)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    };
    let input_hint = match state.input_mode {
        TuiInputMode::Normal => "(/ filter, s search, S strings, c note, ; line-note, C clear-note, x clear, g goto, : cmd, 1..6 tabs, h/l focus, b back, tab cycle, pgup/pgdn/home/end, enter jump, d decompile, r refresh, R reindex, ? help, q quit)",
        TuiInputMode::Prompt => match state.pending_action {
            Some(TuiPendingAction::Filter) => "filter> ",
            Some(TuiPendingAction::JumpTo) => "goto> ",
            Some(TuiPendingAction::Search) => "search> ",
            Some(TuiPendingAction::Command) => "cmd> ",
            Some(TuiPendingAction::Comment) => "note> ",
            Some(TuiPendingAction::CommentLine) => "line-note> ",
            Some(TuiPendingAction::DeleteJob) => "delete> ",
            Some(TuiPendingAction::StringSearch) => "string> ",
            Some(TuiPendingAction::Decompile) => "decompile> ",
            None => "input> ",
        },
    };
    let input_line = if matches!(state.input_mode, TuiInputMode::Prompt) {
        format!("{}{}", input_hint, state.input_buf)
    } else {
        input_hint.to_string()
    };

    let bottom_text = if log.is_empty() {
        input_line
    } else {
        format!("{}\n{}", log, input_line)
    };
    let bottom = Paragraph::new(bottom_text)
        .block(Block::default().title("Log").borders(Borders::ALL));
    f.render_widget(bottom, vchunks[2]);
}

fn list_state(selected: usize) -> ratatui::widgets::ListState {
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(selected));
    state
}

fn build_project_index(workspace: &Path) -> Result<usize, RustpenError> {
    let jobs = list_jobs(workspace)?;
    let out_dir = workspace.join("reverse_out");
    std::fs::create_dir_all(&out_dir)?;
    let out = out_dir.join("project_index.jsonl");
    let manifest_path = out_dir.join("project_index.manifest.json");
    let mut indexed: std::collections::HashSet<String> = load_manifest(&manifest_path);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out)?;
    let mut count = 0usize;
    for job in jobs {
        if job.status != super::ReverseJobStatus::Succeeded {
            continue;
        }
        if indexed.contains(&job.id) {
            continue;
        }
        let rows = load_job_pseudocode_rows(workspace, &job.id)?;
        for r in rows {
            let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("");
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let sig = r.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            let size = r.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let row = serde_json::json!({
                "job_id": job.id,
                "ea": ea,
                "name": name,
                "signature": sig,
                "size": size
            });
            let line = serde_json::to_string(&row).map_err(|e| RustpenError::ParseError(e.to_string()))?;
            writeln!(f, "{line}")?;
            count += 1;
        }
        indexed.insert(job.id);
    }
    save_manifest(&manifest_path, &indexed)?;
    Ok(count)
}

fn load_project_index(workspace: &Path) -> Result<Vec<Value>, RustpenError> {
    let path = workspace.join("reverse_out").join("project_index.jsonl");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(&path)?;
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

fn load_manifest(path: &Path) -> std::collections::HashSet<String> {
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(v) = serde_json::from_str::<Vec<String>>(&text) {
            return v.into_iter().collect();
        }
    }
    std::collections::HashSet::new()
}

fn save_manifest(path: &Path, set: &std::collections::HashSet<String>) -> Result<(), RustpenError> {
    let mut v: Vec<String> = set.iter().cloned().collect();
    v.sort();
    let text = serde_json::to_string_pretty(&v).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    std::fs::write(path, text)?;
    Ok(())
}

fn build_tantivy_index(workspace: &Path) -> Result<(), RustpenError> {
    let out_dir = workspace.join("reverse_out");
    std::fs::create_dir_all(&out_dir)?;
    let index_dir = out_dir.join("tantivy");
    let mut builder = Schema::builder();
    builder.add_text_field("job_id", STORED);
    builder.add_text_field("ea", STORED);
    builder.add_text_field("name", TEXT | STORED);
    builder.add_text_field("signature", TEXT | STORED);
    builder.add_text_field("all", TEXT);
    let schema = builder.build();
    let index = if index_dir.exists() {
        Index::open_in_dir(&index_dir).map_err(|e| RustpenError::ScanError(e.to_string()))?
    } else {
        std::fs::create_dir_all(&index_dir)?;
        Index::create_in_dir(&index_dir, schema.clone())
            .map_err(|e| RustpenError::ScanError(e.to_string()))?
    };
    let schema = index.schema();
    let job_id_f = schema.get_field("job_id").unwrap();
    let ea_f = schema.get_field("ea").unwrap();
    let name_f = schema.get_field("name").unwrap();
    let sig_f = schema.get_field("signature").unwrap();
    let all_f = schema.get_field("all").unwrap();

    let mut writer = index.writer(50_000_000).map_err(|e| RustpenError::ScanError(e.to_string()))?;
    writer.delete_all_documents().map_err(|e| RustpenError::ScanError(e.to_string()))?;
    let rows = load_project_index(workspace)?;
    for r in rows {
        let job_id = r.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
        let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("");
        let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let sig = r.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        let all = format!("{job_id} {ea} {name} {sig}");
        let _ = writer.add_document(tantivy::doc!(
            job_id_f => job_id,
            ea_f => ea,
            name_f => name,
            sig_f => sig,
            all_f => all
        ));
    }
    writer.commit().map_err(|e| RustpenError::ScanError(e.to_string()))?;
    Ok(())
}

fn search_tantivy(
    workspace: &Path,
    query: &str,
) -> Result<Option<(String, String)>, RustpenError> {
    let index_dir = workspace.join("reverse_out").join("tantivy");
    if !index_dir.exists() {
        return Ok(None);
    }
    let index = Index::open_in_dir(&index_dir).map_err(|e| RustpenError::ScanError(e.to_string()))?;
    let schema = index.schema();
    let all_f = schema.get_field("all").unwrap();
    let job_id_f = schema.get_field("job_id").unwrap();
    let ea_f = schema.get_field("ea").unwrap();
    let reader = index.reader().map_err(|e| RustpenError::ScanError(e.to_string()))?;
    reader.reload().ok();
    let searcher = reader.searcher();
    let qp = tantivy::query::QueryParser::for_index(&index, vec![all_f]);
    let q = qp.parse_query(query).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    let top = searcher.search(&q, &tantivy::collector::TopDocs::with_limit(1))
        .map_err(|e| RustpenError::ScanError(e.to_string()))?;
    if let Some((_score, addr)) = top.into_iter().next() {
        let doc: TantivyDocument = searcher
            .doc(addr)
            .map_err(|e| RustpenError::ScanError(e.to_string()))?;
        let job_id = doc.get_first(job_id_f).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let ea = doc.get_first(ea_f).and_then(|v| v.as_str()).unwrap_or("").to_string();
        return Ok(Some((job_id, ea)));
    }
    Ok(None)
}

fn export_graph(workspace: &Path, job_id: &str, ty: &str, out: &str) -> Result<(), RustpenError> {
    let rows = load_job_pseudocode_rows(workspace, job_id)?;
    let mut edges: Vec<(String, String)> = Vec::new();
    for r in rows {
        let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if ea.is_empty() {
            continue;
        }
        let list = match ty {
            "calls" => as_str_vec(r.get("calls")),
            "xrefs" => as_str_vec(r.get("xrefs")),
            _ => return Err(RustpenError::ParseError("graph type must be calls|xrefs".to_string())),
        };
        for t in list {
            edges.push((ea.clone(), t));
        }
    }
    let mut f = std::fs::File::create(out)?;
    writeln!(f, "digraph rscan {{")?;
    for (a, b) in edges {
        writeln!(f, "  \"{}\" -> \"{}\";", a, b)?;
    }
    writeln!(f, "}}")?;
    Ok(())
}

fn extract_strings(text: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_str = false;
    let mut esc = false;
    for ch in text.chars() {
        if out.len() >= limit {
            break;
        }
        if in_str {
            if esc {
                esc = false;
                buf.push(ch);
                continue;
            }
            if ch == '\\' {
                esc = true;
                continue;
            }
            if ch == '"' {
                if buf.len() >= 3 {
                    out.push(buf.clone());
                }
                buf.clear();
                in_str = false;
                continue;
            }
            buf.push(ch);
        } else if ch == '"' {
            in_str = true;
            buf.clear();
        }
    }
    out
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
    cprintln!(
        "  decompile|run <auto|ghidra|ida|r2|jadx> [workspace] [timeout_secs] [index|full|function] [name_or_ea]"
    );
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

struct TempEnv {
    saved: Vec<(String, Option<String>)>,
}

impl TempEnv {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn set(&mut self, key: &str, val: &str) {
        let prev = std::env::var(key).ok();
        self.saved.push((key.to_string(), prev));
        unsafe {
            std::env::set_var(key, val);
        }
    }
}

impl Drop for TempEnv {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(v) => unsafe {
                    std::env::set_var(key, v);
                },
                None => unsafe {
                    std::env::remove_var(key);
                },
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

fn row_match_filter(r: &Value, key: &str) -> bool {
    let ea = r.get("ea").and_then(|v| v.as_str()).unwrap_or_default();
    let name = r.get("name").and_then(|v| v.as_str()).unwrap_or_default();
    let sig = r.get("signature").and_then(|v| v.as_str()).unwrap_or_default();
    ea.to_ascii_lowercase().contains(key)
        || name.to_ascii_lowercase().contains(key)
        || sig.to_ascii_lowercase().contains(key)
}

fn row_match_search(r: &Value, key: &str) -> bool {
    let code = r
        .get("pseudocode")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if code.contains(key) {
        return true;
    }
    let asm = as_str_vec(r.get("asm"));
    if asm.iter().any(|l| l.to_ascii_lowercase().contains(key)) {
        return true;
    }
    let calls = as_str_vec(r.get("call_names"));
    if calls
        .iter()
        .any(|c| c.to_ascii_lowercase().contains(key))
    {
        return true;
    }
    let ext = as_str_vec(r.get("ext_refs"));
    ext.iter().any(|c| c.to_ascii_lowercase().contains(key))
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

fn build_code_items<I>(lines: I, notes: Option<&HashMap<usize, String>>) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut out = Vec::new();
    for (idx, line) in lines.into_iter().enumerate() {
        let ln = idx + 1;
        let mut item = format!("{:4} {}", ln, line);
        if let Some(map) = notes {
            if let Some(note) = map.get(&ln) {
                item.push_str("  // ");
                item.push_str(note);
            }
        }
        out.push(item);
    }
    if out.is_empty() {
        out.push("<empty>".to_string());
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
