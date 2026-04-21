use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crate::cores::engine::task::{
    EventKind, TaskEvent, TaskMeta, TaskStatus, append_task_event, ensure_task_dir, load_task_meta,
    new_task_id, now_epoch_secs, write_task_meta,
};
use crate::errors::RustpenError;
use crate::tui::zellij;

#[derive(Clone)]
pub(crate) struct ScriptTaskCtx {
    pub(crate) dir: PathBuf,
    pub(crate) meta: TaskMeta,
}

#[derive(Clone)]
pub(crate) struct ScriptRunResult {
    pub(crate) file: PathBuf,
    pub(crate) ok: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

pub(crate) fn load_script_files(dir: &PathBuf) -> Result<Vec<PathBuf>, RustpenError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        if matches!(p.extension().and_then(|s| s.to_str()), Some("rs")) {
            out.push(p);
        }
    }
    out.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(out)
}

pub(crate) fn read_script_text(path: &PathBuf) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

pub(crate) fn switch_script_selection(
    new_index: usize,
    scripts: &[PathBuf],
    selected: &mut usize,
    script_buffer: &mut String,
    script_dirty: &mut bool,
    status_line: &mut String,
) {
    if scripts.is_empty() {
        *selected = 0;
        script_buffer.clear();
        *script_dirty = false;
        return;
    }
    if *script_dirty {
        *status_line = "当前脚本有未保存内容，先按 S 保存".to_string();
        return;
    }
    *selected = new_index.min(scripts.len().saturating_sub(1));
    *script_buffer = read_script_text(&scripts[*selected]);
    *script_dirty = false;
}

fn script_template_for(_name: &str) -> String {
    "fn main() {\n    println!(\"hello from rscan script\");\n}\n".to_string()
}

pub(crate) fn create_script_file(dir: &PathBuf, name: &str) -> Result<PathBuf, RustpenError> {
    let mut final_name = name.trim().to_string();
    if final_name.is_empty() {
        return Err(RustpenError::ParseError(
            "script name cannot be empty".to_string(),
        ));
    }
    if final_name.ends_with(".py") {
        return Err(RustpenError::ParseError(
            "仅支持 Rust 脚本，请使用 .rs".to_string(),
        ));
    }
    if !final_name.ends_with(".rs") {
        final_name.push_str(".rs");
    }
    let path = dir.join(final_name.clone());
    if path.exists() {
        return Err(RustpenError::ParseError(format!(
            "script already exists: {}",
            path.display()
        )));
    }
    fs::write(&path, script_template_for(&final_name)).map_err(RustpenError::Io)?;
    Ok(path)
}

pub(crate) fn save_current_script(
    scripts: &[PathBuf],
    script_selected: usize,
    script_buffer: &str,
) -> Result<String, RustpenError> {
    let Some(path) = scripts.get(script_selected) else {
        return Err(RustpenError::MissingArgument {
            arg: "script file".to_string(),
        });
    };
    fs::write(path, script_buffer).map_err(RustpenError::Io)?;
    Ok(format!("saved: {}", path.display()))
}

fn command_available(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn resolve_helix_command() -> Option<String> {
    if let Ok(custom) = std::env::var("RSCAN_SCRIPT_EDITOR") {
        let custom = custom.trim();
        if !custom.is_empty() {
            return Some(custom.to_string());
        }
    }
    if command_available("hx") {
        return Some("hx".to_string());
    }
    if command_available("helix") {
        return Some("helix".to_string());
    }
    None
}

fn shell_quote_for_sh(raw: &str) -> String {
    let escaped = raw.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

pub(crate) fn open_script_in_helix(
    path: &PathBuf,
    workspace: &PathBuf,
) -> Result<String, RustpenError> {
    if !path.exists() {
        return Err(RustpenError::ParseError(format!(
            "script file not found: {}",
            path.display()
        )));
    }
    let editor = resolve_helix_command().ok_or_else(|| {
        RustpenError::ParseError(
            "未找到 helix，可安装 hx/helix 或设置 RSCAN_SCRIPT_EDITOR".to_string(),
        )
    })?;
    if zellij::is_managed_runtime() {
        let cmd = format!(
            "{} {}",
            editor,
            shell_quote_for_sh(&path.display().to_string())
        );
        let pane_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|name| format!("script-edit:{name}"))
            .unwrap_or_else(|| "script-edit".to_string());
        zellij::open_command_pane_in_tab(
            zellij::WORK_TAB,
            workspace,
            &cmd,
            workspace,
            Some(pane_name),
        )
        .map_err(RustpenError::ParseError)?;
        return Ok(format!("helix 已在 Work pane 打开: {}", path.display()));
    }
    Err(RustpenError::ParseError(
        "当前不是 zellij 托管模式，无法在独立 pane 打开 helix".to_string(),
    ))
}

fn update_script_task_progress(
    dir: &PathBuf,
    pct: f32,
    message: impl Into<String>,
) -> Result<(), RustpenError> {
    let message = message.into();
    let mut meta = load_task_meta(dir)?;
    meta.progress = Some(pct);
    write_task_meta(dir, &meta)?;
    append_task_event(
        dir,
        &TaskEvent {
            ts: now_epoch_secs(),
            level: "info".to_string(),
            kind: EventKind::Progress,
            message: Some(message),
            data: Some(pct.into()),
        },
    )?;
    Ok(())
}

fn spawn_script_progress_heartbeat(
    dir: PathBuf,
    path: PathBuf,
    done: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    thread::spawn(move || {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let stage = if ext == "rs" {
            "script: compiling/running"
        } else {
            "script: running"
        };
        let mut pct = 12.0f32;
        while !done.load(Ordering::Relaxed) {
            let _ = update_script_task_progress(&dir, pct, stage);
            pct = (pct + 8.0).min(72.0);
            thread::sleep(Duration::from_millis(400));
        }
        let _ = update_script_task_progress(&dir, 88.0, "script: finalizing");
    })
}

pub(crate) fn start_script_runner(
    path: PathBuf,
    task_dir: Option<PathBuf>,
) -> Receiver<ScriptRunResult> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let done = Arc::new(AtomicBool::new(false));
        let heartbeat = task_dir
            .as_ref()
            .map(|dir| spawn_script_progress_heartbeat(dir.clone(), path.clone(), done.clone()));
        let result = run_script_once(path);
        done.store(true, Ordering::Relaxed);
        if let Some(handle) = heartbeat {
            let _ = handle.join();
        }
        let _ = tx.send(result);
    });
    rx
}

fn run_script_once(path: PathBuf) -> ScriptRunResult {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match ext {
        "py" => run_process(path.clone(), "python3", vec![path.display().to_string()]),
        "rs" => run_rust_script(path),
        _ => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "unsupported script extension".to_string(),
        },
    }
}

fn run_rust_script(path: PathBuf) -> ScriptRunResult {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script")
        .replace([' ', '/'], "_");
    let bin = std::env::temp_dir().join(format!("rscan_script_{}_{}", stem, now_epoch_secs()));

    let compile = Command::new("rustc")
        .arg(&path)
        .arg("-O")
        .arg("-o")
        .arg(&bin)
        .output();

    let Ok(compile_out) = compile else {
        return ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "failed to launch rustc".to_string(),
        };
    };

    if !compile_out.status.success() {
        return ScriptRunResult {
            file: path,
            ok: false,
            exit_code: compile_out.status.code(),
            stdout: String::from_utf8_lossy(&compile_out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&compile_out.stderr).to_string(),
        };
    }

    let run = Command::new(&bin).output();
    let _ = fs::remove_file(&bin);
    match run {
        Ok(out) => ScriptRunResult {
            file: path,
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(e) => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

fn run_process(path: PathBuf, cmd: &str, args: Vec<String>) -> ScriptRunResult {
    match Command::new(cmd).args(args).output() {
        Ok(out) => ScriptRunResult {
            file: path,
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(e) => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to start '{}': {}", cmd, e),
        },
    }
}

pub(crate) fn poll_script_runner(
    rx: &mut Option<Receiver<ScriptRunResult>>,
) -> Option<ScriptRunResult> {
    let Some(r) = rx else {
        return None;
    };
    match r.try_recv() {
        Ok(done) => {
            *rx = None;
            Some(done)
        }
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => {
            *rx = None;
            None
        }
    }
}

pub(crate) fn start_script_task(
    workspace: &PathBuf,
    script_file: &PathBuf,
) -> Result<ScriptTaskCtx, RustpenError> {
    let task_id = new_task_id();
    let dir = ensure_task_dir(workspace, &task_id)?;
    let now = now_epoch_secs();
    let mut meta = TaskMeta {
        id: task_id,
        kind: "script".to_string(),
        tags: vec![script_file.display().to_string()],
        status: TaskStatus::Running,
        created_at: now,
        started_at: Some(now),
        ended_at: None,
        progress: Some(0.0),
        note: Some("script run".to_string()),
        artifacts: vec![script_file.clone()],
        logs: Vec::new(),
        extra: None,
    };
    crate::cores::engine::task::attach_task_runtime(
        &mut meta,
        crate::cores::engine::task::TaskRuntimeBinding {
            backend: if std::env::var("ZELLIJ").is_ok()
                || std::env::var("ZELLIJ_SESSION_NAME").is_ok()
            {
                "zellij-script-runner".to_string()
            } else {
                "script-runner".to_string()
            },
            session: std::env::var("ZELLIJ_SESSION_NAME").ok(),
            tab: std::env::var("RSCAN_ZELLIJ_ACTIVE_TAB").ok(),
            pane_name: Some("rscan-control".to_string()),
            role: Some("script-runner".to_string()),
            cwd: Some(workspace.clone()),
            command: Some(script_file.display().to_string()),
        },
    );
    write_task_meta(&dir, &meta)?;
    let _ = update_script_task_progress(&dir, 5.0, "script: queued");
    let _ = append_task_event(
        &dir,
        &TaskEvent {
            ts: now,
            level: "info".to_string(),
            kind: EventKind::Log,
            message: Some(format!("script start: {}", script_file.display())),
            data: None,
        },
    );
    Ok(ScriptTaskCtx { dir, meta })
}

pub(crate) fn finalize_script_task(
    task: &mut Option<ScriptTaskCtx>,
    done: &ScriptRunResult,
) -> Result<(), RustpenError> {
    let Some(mut ctx) = task.take() else {
        return Ok(());
    };

    let stdout_path = ctx.dir.join("stdout.log");
    let stderr_path = ctx.dir.join("stderr.log");
    fs::write(&stdout_path, &done.stdout).map_err(RustpenError::Io)?;
    fs::write(&stderr_path, &done.stderr).map_err(RustpenError::Io)?;

    ctx.meta.status = if done.ok {
        TaskStatus::Succeeded
    } else {
        TaskStatus::Failed
    };
    ctx.meta.ended_at = Some(now_epoch_secs());
    ctx.meta.progress = Some(100.0);
    ctx.meta.logs = vec![stdout_path.clone(), stderr_path.clone()];
    if !ctx.meta.artifacts.iter().any(|p| p == &done.file) {
        ctx.meta.artifacts.push(done.file.clone());
    }

    write_task_meta(&ctx.dir, &ctx.meta)?;
    let _ = append_task_event(
        &ctx.dir,
        &TaskEvent {
            ts: now_epoch_secs(),
            level: if done.ok { "info" } else { "error" }.to_string(),
            kind: EventKind::Control,
            message: Some(format!(
                "script finished: ok={} exit_code={}",
                done.ok,
                done.exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            )),
            data: None,
        },
    );
    Ok(())
}

pub(crate) fn append_output_block(
    output: &mut Vec<String>,
    out_header: &str,
    out_body: &str,
    err_header: &str,
    err_body: &str,
) {
    output.push(out_header.to_string());
    if out_body.trim().is_empty() {
        output.push("<empty>".to_string());
    } else {
        output.extend(out_body.lines().map(|s| s.to_string()));
    }
    output.push(err_header.to_string());
    if err_body.trim().is_empty() {
        output.push("<empty>".to_string());
    } else {
        output.extend(err_body.lines().map(|s| s.to_string()));
    }

    const MAX_LINES: usize = 600;
    if output.len() > MAX_LINES {
        let drop_n = output.len() - MAX_LINES;
        output.drain(0..drop_n);
    }
}
