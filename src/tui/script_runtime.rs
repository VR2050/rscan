use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::cores::engine::task::{
    EventKind, TaskEvent, TaskMeta, TaskStatus, append_task_event, ensure_task_dir, new_task_id,
    now_epoch_secs, write_task_meta,
};
use crate::errors::RustpenError;

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
        match p.extension().and_then(|s| s.to_str()) {
            Some("py") | Some("rs") => out.push(p),
            _ => {}
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

fn script_template_for(name: &str) -> String {
    if name.ends_with(".rs") {
        return "fn main() {\n    println!(\"hello from rscan script\");\n}\n".to_string();
    }
    "print(\"hello from rscan script\")\n".to_string()
}

pub(crate) fn create_script_file(dir: &PathBuf, name: &str) -> Result<PathBuf, RustpenError> {
    let mut final_name = name.trim().to_string();
    if !final_name.ends_with(".py") && !final_name.ends_with(".rs") {
        final_name.push_str(".py");
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

pub(crate) fn start_script_runner(path: PathBuf) -> Receiver<ScriptRunResult> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = run_script_once(path);
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
    let meta = TaskMeta {
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
    write_task_meta(&dir, &meta)?;
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
