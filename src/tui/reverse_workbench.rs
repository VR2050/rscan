use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::errors::RustpenError;
use crate::modules::reverse::ReverseJobMeta;

use super::project_store::ensure_project_layout;
use super::reverse_workbench_support::{
    active_project_hint_path, clear_active_target_hint, discover_binary_candidates,
    load_visible_reverse_jobs, read_active_target_hint, relative_or_full, resolve_active_project,
    run_analyze_now, run_zellij_filepicker, shorten_id, spawn_reverse_job,
    target_belongs_to_project, write_active_project_hint, write_active_target_hint,
};

const MAX_DISCOVERED_INPUTS: usize = 12;
const MAX_RECENT_JOBS: usize = 6;

pub(crate) fn run_reverse_workbench(
    root_ws: PathBuf,
    project: Option<PathBuf>,
    input: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let mut selected_input = input.or_else(|| read_active_target_hint(&root_ws));
    let mut transient_message = String::new();
    loop {
        let active_project = resolve_active_project(&root_ws, project.as_ref())?;
        ensure_project_layout(&active_project)?;
        let _ = write_active_project_hint(&root_ws, &active_project);
        if let Some(hinted_input) = read_active_target_hint(&root_ws) {
            if target_belongs_to_project(&active_project, &hinted_input) {
                let should_sync = selected_input
                    .as_ref()
                    .map(|current| current != &hinted_input)
                    .unwrap_or(true);
                if should_sync {
                    selected_input = Some(hinted_input);
                }
            } else {
                let _ = clear_active_target_hint(&root_ws);
                selected_input = None;
            }
        }
        if !selected_input
            .as_ref()
            .map(|path| path.is_file())
            .unwrap_or(true)
        {
            selected_input = None;
            let _ = clear_active_target_hint(&root_ws);
        }
        let discovered_inputs = discover_binary_candidates(&active_project, MAX_DISCOVERED_INPUTS);
        let recent_jobs =
            load_recent_jobs(&active_project, selected_input.as_deref(), MAX_RECENT_JOBS);

        draw_workbench(
            &root_ws,
            &active_project,
            selected_input.as_deref(),
            &discovered_inputs,
            &recent_jobs,
            &transient_message,
        )?;
        transient_message.clear();

        let cmd = read_command_line()?;
        let trimmed = cmd.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "q" | "quit" | "exit") {
            break;
        }
        if matches!(trimmed, "r" | "refresh") {
            continue;
        }
        if matches!(trimmed, "c" | "clear") {
            selected_input = None;
            let _ = clear_active_target_hint(&root_ws);
            transient_message = "已清空当前目标".to_string();
            continue;
        }
        if matches!(trimmed, "p" | "pick") {
            match select_binary_with_filepicker(&active_project, selected_input.as_deref()) {
                Ok(path) => {
                    let _ = write_active_target_hint(&root_ws, &path);
                    selected_input = Some(path.clone());
                    transient_message = format!("已选择目标: {}", path.display());
                }
                Err(e) => {
                    transient_message = format!("filepicker 选择失败: {e}");
                }
            }
            continue;
        }
        if matches!(trimmed, "a" | "analyze") {
            let Some(input) = selected_input.clone() else {
                transient_message =
                    "尚未选择目标；输入序号、路径或 p 调 zellij filepicker".to_string();
                continue;
            };
            transient_message = run_analyze_now(&active_project, &input)?;
            pause_if_interactive()?;
            continue;
        }
        if matches!(trimmed, "f" | "full") {
            let Some(input) = selected_input.clone() else {
                transient_message =
                    "尚未选择目标；输入序号、路径或 p 调 zellij filepicker".to_string();
                continue;
            };
            transient_message = spawn_reverse_job(&active_project, &input, "ghidra", "full")?;
            continue;
        }
        if matches!(trimmed, "i" | "index") {
            let Some(input) = selected_input.clone() else {
                transient_message =
                    "尚未选择目标；输入序号、路径或 p 调 zellij filepicker".to_string();
                continue;
            };
            transient_message = spawn_reverse_job(&active_project, &input, "auto", "index")?;
            continue;
        }
        if let Some((prefix, idx)) = parse_prefixed_index(trimmed) {
            if prefix == 'j' {
                if let Some(job) = recent_jobs.get(idx.saturating_sub(1)) {
                    transient_message = render_job_summary(&active_project, job);
                    pause_if_interactive()?;
                } else {
                    transient_message = format!("job 索引越界: {idx}");
                }
                continue;
            }
        }
        if let Ok(idx) = trimmed.parse::<usize>() {
            if let Some(path) = discovered_inputs.get(idx.saturating_sub(1)) {
                let _ = write_active_target_hint(&root_ws, path);
                selected_input = Some(path.clone());
                transient_message = format!("已选择候选目标: {}", path.display());
            } else {
                transient_message = format!("候选索引越界: {idx}");
            }
            continue;
        }

        let candidate = resolve_input_candidate(&active_project, trimmed);
        if candidate.is_file() {
            let _ = write_active_target_hint(&root_ws, &candidate);
            selected_input = Some(candidate.clone());
            transient_message = format!("已选择路径: {}", candidate.display());
            continue;
        }
        transient_message =
            format!("未知命令: {trimmed} | 可用: 序号 / 路径 / p / a / f / i / j<N> / r / q");
    }
    println!("reverse workbench 已退出；下方 reverse shell 仍可继续使用。");
    Ok(())
}

fn draw_workbench(
    root_ws: &Path,
    active_project: &Path,
    selected_input: Option<&Path>,
    discovered_inputs: &[PathBuf],
    recent_jobs: &[ReverseJobMeta],
    transient_message: &str,
) -> Result<(), RustpenError> {
    let mut stdout = io::stdout();
    write!(stdout, "\x1b[2J\x1b[H").map_err(RustpenError::Io)?;
    writeln!(stdout, "rscan reverse workbench").map_err(RustpenError::Io)?;
    writeln!(stdout, "root:    {}", root_ws.display()).map_err(RustpenError::Io)?;
    writeln!(stdout, "project: {}", active_project.display()).map_err(RustpenError::Io)?;
    writeln!(
        stdout,
        "hint:    {}",
        active_project_hint_path(root_ws).display()
    )
    .map_err(RustpenError::Io)?;
    writeln!(
        stdout,
        "tip:     若按键被 zellij 吞掉，先按 Ctrl-g 切到 Locked；此 pane 用整行命令避免快捷键冲突"
    )
    .map_err(RustpenError::Io)?;
    writeln!(stdout).map_err(RustpenError::Io)?;

    let target_label = selected_input
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<未选择>".to_string());
    writeln!(stdout, "selected target: {target_label}").map_err(RustpenError::Io)?;
    writeln!(
        stdout,
        concat!(
            "actions: [序号]=选择候选  p=filepicker  a=analyze  ",
            "f=full job  i=index job  j<N>=show job  r=refresh  q=quit"
        )
    )
    .map_err(RustpenError::Io)?;
    writeln!(stdout).map_err(RustpenError::Io)?;

    writeln!(stdout, "candidate binaries").map_err(RustpenError::Io)?;
    if discovered_inputs.is_empty() {
        writeln!(
            stdout,
            "  <none> | 可把样本放进 binaries/ 或 samples/，也可直接输入绝对/相对路径"
        )
        .map_err(RustpenError::Io)?;
    } else {
        for (idx, path) in discovered_inputs.iter().enumerate() {
            writeln!(
                stdout,
                "  {:>2}. {}",
                idx + 1,
                relative_or_full(active_project, path)
            )
            .map_err(RustpenError::Io)?;
        }
    }
    writeln!(stdout).map_err(RustpenError::Io)?;

    let jobs_title = if selected_input.is_some() {
        "current reverse job"
    } else {
        "reverse jobs"
    };
    writeln!(stdout, "{jobs_title}").map_err(RustpenError::Io)?;
    if recent_jobs.is_empty() {
        writeln!(
            stdout,
            "  <none yet> | full/index job 完成后会回流到 Control 的 Tasks/Results"
        )
        .map_err(RustpenError::Io)?;
    } else {
        for (idx, job) in recent_jobs.iter().enumerate() {
            writeln!(
                stdout,
                "  j{:>1}. {:<18} {:<9} {:<8} {:<8} {}",
                idx + 1,
                shorten_id(&job.id, 18),
                format!("{:?}", job.status).to_ascii_lowercase(),
                job.backend,
                job.mode.as_deref().unwrap_or("-"),
                job.target
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| job.target.display().to_string()),
            )
            .map_err(RustpenError::Io)?;
        }
    }
    writeln!(stdout).map_err(RustpenError::Io)?;

    if !transient_message.is_empty() {
        writeln!(stdout, "{transient_message}").map_err(RustpenError::Io)?;
        writeln!(stdout).map_err(RustpenError::Io)?;
    }

    write!(stdout, "workbench> ").map_err(RustpenError::Io)?;
    stdout.flush().map_err(RustpenError::Io)?;
    Ok(())
}

fn read_command_line() -> Result<String, RustpenError> {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(RustpenError::Io)?;
    Ok(buf)
}

fn load_recent_jobs(
    project: &Path,
    selected_input: Option<&Path>,
    limit: usize,
) -> Vec<ReverseJobMeta> {
    load_visible_reverse_jobs(project, selected_input, limit)
}

fn parse_prefixed_index(input: &str) -> Option<(char, usize)> {
    let mut chars = input.chars();
    let prefix = chars.next()?;
    let number = chars.as_str().trim();
    if !prefix.is_ascii_alphabetic() || number.is_empty() {
        return None;
    }
    let idx = number.parse::<usize>().ok()?;
    Some((prefix.to_ascii_lowercase(), idx))
}

fn resolve_input_candidate(project: &Path, raw: &str) -> PathBuf {
    let input = PathBuf::from(raw);
    if input.is_absolute() {
        input
    } else {
        project.join(input)
    }
}

fn select_binary_with_filepicker(
    _project: &Path,
    selected_input: Option<&Path>,
) -> Result<PathBuf, String> {
    run_zellij_filepicker(selected_input, "rscan reverse picker")
}
fn render_job_summary(project: &Path, job: &ReverseJobMeta) -> String {
    let artifacts = if job.artifacts.is_empty() {
        "<none>".to_string()
    } else {
        job.artifacts
            .iter()
            .take(3)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "job={} status={:?} backend={} mode={} target={} workspace={} artifacts={} note={}{}",
        job.id,
        job.status,
        job.backend,
        job.mode.as_deref().unwrap_or("-"),
        relative_or_full(project, &job.target),
        relative_or_full(project, &job.workspace),
        artifacts,
        job.note,
        job.error
            .as_ref()
            .map(|err| format!(" error={err}"))
            .unwrap_or_default()
    )
}

fn pause_if_interactive() -> Result<(), RustpenError> {
    let mut stdout = io::stdout();
    writeln!(stdout).map_err(RustpenError::Io)?;
    writeln!(stdout, "回车继续...").map_err(RustpenError::Io)?;
    stdout.flush().map_err(RustpenError::Io)?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(RustpenError::Io)?;
    Ok(())
}
