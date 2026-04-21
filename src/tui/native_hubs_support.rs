use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{IsTerminal, Read, Seek, SeekFrom, stdout};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::errors::RustpenError;

use super::view::{draw_inspect_hub, draw_work_hub};
use super::{
    InspectHubState, TaskView, WorkFocus, WorkHubState, ensure_project_layout,
    read_active_project_hint, same_path, write_active_project_hint,
};
use crate::tui::project_store::project_name_from_path;
use crate::tui::reverse_workbench_support::{relative_or_full, resolve_active_project};
use crate::tui::script_runtime::load_script_files;
use crate::tui::task_store::{load_tasks, load_text_artifact_snippets, preview_text_artifact};
use crate::tui::zellij;

type HubTerminal = Terminal<CrosstermBackend<std::io::Stdout>>;
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(120);

pub(super) fn build_work_detail_lines(state: &WorkHubState) -> Vec<String> {
    if state.focus == WorkFocus::Templates {
        if state.launcher_items.is_empty() {
            return vec![
                "template list is empty".to_string(),
                "暂无任务模板可执行".to_string(),
            ];
        }
        let mut out = vec![
            "任务模板 (Work/Templates)".to_string(),
            "j/k 选择  Enter 执行  末项=自定义命令".to_string(),
            String::new(),
        ];
        for (idx, (name, cmd)) in state.launcher_items.iter().enumerate().take(12) {
            let prefix = if idx == state.selected_template {
                ">>"
            } else {
                "  "
            };
            out.push(format!("{prefix} {} => {}", name, cmd));
        }
        let custom_idx = state.launcher_items.len();
        let custom_prefix = if custom_idx == state.selected_template {
            ">>"
        } else {
            "  "
        };
        out.push(format!("{custom_prefix} [自定义命令...]"));
        return out;
    }
    match state.focus {
        WorkFocus::Projects => {
            let Some(project) = state.projects.get(state.selected_project) else {
                return vec!["no project".to_string()];
            };
            vec![
                format!("name={}", project.name),
                format!("path={}", project.path.display()),
                format!(
                    "origin={}",
                    if project.imported {
                        "imported"
                    } else {
                        "local"
                    }
                ),
                format!("recent_tasks={}", state.tasks.len()),
                format!("scripts={}", state.scripts.len()),
                "Enter -> 在 Work 打开 project shell".to_string(),
                "移动 project 选择会立即同步 active project".to_string(),
            ]
        }
        WorkFocus::Tasks => {
            let Some(task) = state.tasks.get(state.selected_task) else {
                return vec![
                    "no task".to_string(),
                    "当前 project 没有 recent task".to_string(),
                ];
            };
            build_task_detail_lines(&state.active_project, task)
        }
        WorkFocus::Scripts => {
            let Some(script) = state.scripts.get(state.selected_script) else {
                return vec![
                    "no script".to_string(),
                    "project/scripts 下没有可运行脚本".to_string(),
                ];
            };
            vec![
                format!(
                    "file={}",
                    script
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("<invalid>")
                ),
                format!("path={}", relative_or_full(&state.active_project, script)),
                format!("runner={}", script_runner_label(script)),
                "Enter -> 在 Work 新开原生 command pane 跑脚本".to_string(),
                "E -> 在 Work 打开 helix 编辑脚本".to_string(),
                "N -> 新建 .rs 脚本模板".to_string(),
                "脚本运行结束后 pane 会自动落回交互 shell".to_string(),
            ]
        }
        WorkFocus::Results => {
            let Some(task) = state.tasks.get(state.selected_task) else {
                return vec![
                    "no result".to_string(),
                    "当前没有可展示结果的任务".to_string(),
                ];
            };
            vec![
                format!("task={}", task.meta.id),
                format!("kind={} | status={}", task.meta.kind, task.meta.status),
                format!("scroll_offset={}", state.result_scroll),
                "j/k 或 PgUp/PgDn/Home/End 滚动结果".to_string(),
                "Enter -> 打开任务日志".to_string(),
            ]
        }
        WorkFocus::Templates => {
            let mut out = vec![
                "任务模板 (Work/Templates)".to_string(),
                "j/k 选择  Enter 执行  末项=自定义命令".to_string(),
            ];
            for (idx, (name, cmd)) in state.launcher_items.iter().enumerate().take(12) {
                let prefix = if idx == state.selected_template {
                    ">>"
                } else {
                    "  "
                };
                out.push(format!("{prefix} {} => {}", name, cmd));
            }
            let custom_idx = state.launcher_items.len();
            let custom_prefix = if custom_idx == state.selected_template {
                ">>"
            } else {
                "  "
            };
            out.push(format!("{custom_prefix} [自定义命令...]"));
            out
        }
    }
}

pub(super) fn build_task_detail_lines(active_project: &Path, task: &TaskView) -> Vec<String> {
    let runtime = task.runtime_binding();
    let mut lines = vec![
        format!("id={}", task.meta.id),
        format!("kind={} | status={}", task.meta.kind, task.meta.status),
        format!("origin={}", task.origin_label()),
        format!("created={}", task.meta.created_at),
    ];
    if let Some(note) = task
        .meta
        .note
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("note={note}"));
    }
    if let Some(runtime) = runtime {
        lines.push(format!(
            "runtime.tab={}",
            runtime.tab.unwrap_or_else(|| "-".to_string())
        ));
        lines.push(format!(
            "runtime.pane={}",
            runtime.pane_name.unwrap_or_else(|| "-".to_string())
        ));
        lines.push(format!(
            "runtime.cwd={}",
            runtime
                .cwd
                .map(|path| relative_or_full(active_project, &path))
                .unwrap_or_else(|| "-".to_string())
        ));
    }
    if task.meta.artifacts.is_empty() {
        lines.push("artifacts=<none>".to_string());
    } else {
        lines.push(format!(
            "artifacts={}",
            task.meta
                .artifacts
                .iter()
                .take(3)
                .map(|path| relative_or_full(active_project, path))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}

pub(super) fn build_task_preview_lines(task: &TaskView) -> Vec<String> {
    let mut out = Vec::new();
    for (path, lines) in load_text_artifact_snippets(task, super::LOG_TAIL_MAX_LINES.min(40), 2) {
        if lines.is_empty() {
            continue;
        }
        out.push(format!(
            "[artifact:{}]",
            path.file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("artifact")
        ));
        out.extend(lines);
        out.push(String::new());
    }
    for path in preview_source_paths(task).into_iter().take(3) {
        let Some(lines) =
            read_log_tail_lines(&path, super::LOG_TAIL_MAX_LINES, super::LOG_TAIL_MAX_BYTES)
        else {
            continue;
        };
        if lines.is_empty() {
            continue;
        }
        out.push(format!(
            "[{}]",
            path.file_name().and_then(|v| v.to_str()).unwrap_or("log")
        ));
        out.extend(lines);
        out.push(String::new());
    }
    if out.is_empty() {
        return vec![
            "no preview yet".to_string(),
            "events.jsonl/stdout.log/stderr.log 还没有可读内容".to_string(),
        ];
    }
    while out.last().is_some_and(|line| line.is_empty()) {
        out.pop();
    }
    out
}

pub(super) fn build_work_result_lines(state: &WorkHubState) -> Vec<String> {
    let Some(task) = state.tasks.get(state.selected_task) else {
        return vec![
            "no result".to_string(),
            "当前没有可展示结果的任务".to_string(),
        ];
    };
    let mut out = vec![
        format!(
            "Task {} | kind={} | status={}",
            task.meta.id, task.meta.kind, task.meta.status
        ),
        "Result stream (artifact only; json/jsonl/log in Inspect)".to_string(),
        "-------------------------------------------------------".to_string(),
    ];
    for (path, lines) in load_text_artifact_snippets(task, super::LOG_TAIL_MAX_LINES.min(80), 6) {
        if !work_result_artifact_allowed(&path) || lines.is_empty() {
            continue;
        }
        out.push(String::new());
        out.push(format!(
            "== {} ==",
            path.file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("artifact")
        ));
        out.extend(lines);
    }
    if out.len() <= 3 {
        return if matches!(
            task.meta.status,
            crate::cores::engine::task::TaskStatus::Running
        ) {
            vec![
                "waiting result...".to_string(),
                "任务运行中，等待产出可展示结果（json/jsonl/log 已隐藏，请到 Inspect 查看）"
                    .to_string(),
            ]
        } else {
            vec![
                "no immediate result".to_string(),
                "未发现可展示结果（json/jsonl/log 已隐藏，请到 Inspect 查看）".to_string(),
            ]
        };
    }
    out
}

fn work_result_artifact_allowed(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "events.jsonl" | "stdout.log" | "stderr.log" | "meta.json"
    ) {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !matches!(ext.as_str(), "json" | "jsonl" | "log")
}

pub(super) fn task_detail_cache_signature(task: &TaskView) -> u64 {
    let mut hasher = DefaultHasher::new();
    task.dir.hash(&mut hasher);
    task.meta.id.hash(&mut hasher);
    task.meta.kind.hash(&mut hasher);
    task.meta.status.to_string().hash(&mut hasher);
    task.meta.created_at.hash(&mut hasher);
    task.meta.started_at.hash(&mut hasher);
    task.meta.ended_at.hash(&mut hasher);
    task.meta.note.hash(&mut hasher);
    for path in &task.meta.artifacts {
        path.hash(&mut hasher);
    }
    for path in &task.meta.logs {
        path.hash(&mut hasher);
    }
    if let Some(runtime) = task.runtime_binding() {
        runtime.backend.hash(&mut hasher);
        runtime.session.hash(&mut hasher);
        runtime.tab.hash(&mut hasher);
        runtime.pane_name.hash(&mut hasher);
        runtime.role.hash(&mut hasher);
        runtime.cwd.hash(&mut hasher);
        runtime.command.hash(&mut hasher);
    }
    if let Some((path, _)) = preview_text_artifact(task, 1) {
        hash_path_snapshot(&mut hasher, &path);
    }
    for (path, _) in load_text_artifact_snippets(task, 1, 2) {
        hash_path_snapshot(&mut hasher, &path);
    }
    for path in preview_source_paths(task) {
        hash_path_snapshot(&mut hasher, &path);
    }
    hasher.finish()
}

pub(super) fn load_recent_tasks(active_project: &Path) -> Vec<TaskView> {
    let mut tasks = load_tasks(active_project.to_path_buf()).unwrap_or_default();
    tasks.truncate(super::MAX_RECENT_TASKS);
    tasks
}

pub(super) fn load_recent_scripts(active_project: &Path) -> Vec<PathBuf> {
    let scripts_dir = active_project.join("scripts");
    let mut scripts = load_script_files(&scripts_dir).unwrap_or_default();
    let script_project_main = scripts_dir
        .join("rscan_script_project")
        .join("src")
        .join("main.rs");
    if script_project_main.is_file() && !scripts.iter().any(|p| same_path(p, &script_project_main))
    {
        scripts.push(script_project_main);
    }
    scripts.truncate(super::MAX_RECENT_SCRIPTS);
    scripts
}

pub(super) fn ensure_work_script_project(active_project: &Path) -> Result<PathBuf, RustpenError> {
    let scripts_dir = active_project.join("scripts");
    fs::create_dir_all(&scripts_dir).map_err(RustpenError::Io)?;
    let project_dir = scripts_dir.join("rscan_script_project");
    if !project_dir.exists() {
        let status = std::process::Command::new("cargo")
            .args(["new", "--bin", "rscan_script_project", "--vcs", "none"])
            .current_dir(&scripts_dir)
            .status()
            .map_err(RustpenError::Io)?;
        if !status.success() {
            return Err(RustpenError::ParseError(
                "cargo new rscan_script_project 失败".to_string(),
            ));
        }
    }

    let cargo_toml = project_dir.join("Cargo.toml");
    let mut text = fs::read_to_string(&cargo_toml).map_err(RustpenError::Io)?;
    let deps = [
        (
            "reqwest",
            "reqwest = { version = \"0.12\", features = [\"blocking\", \"json\"] }",
        ),
        (
            "serde",
            "serde = { version = \"1\", features = [\"derive\"] }",
        ),
        ("serde_json", "serde_json = \"1\""),
        ("goblin", "goblin = \"0.8\""),
        ("iced_x86", "iced-x86 = \"1\""),
    ];
    if !text.contains("[dependencies]") {
        text.push_str("\n[dependencies]\n");
    }
    for (needle, line) in deps {
        if !text.contains(needle) {
            text.push_str(line);
            text.push('\n');
        }
    }
    fs::write(&cargo_toml, text).map_err(RustpenError::Io)?;

    let main_rs = project_dir.join("src").join("main.rs");
    if !main_rs.exists() {
        fs::create_dir_all(main_rs.parent().unwrap_or(&project_dir)).map_err(RustpenError::Io)?;
        fs::write(
            &main_rs,
            "use goblin::Object;\nuse iced_x86::Decoder;\nuse serde::{Deserialize, Serialize};\n\n#[derive(Debug, Serialize, Deserialize)]\nstruct Msg {\n    ok: bool,\n}\n\nfn main() {\n    let _ = Decoder::new(64, &[], 0);\n    let _ = Object::parse(&[]);\n    println!(\"{}\", serde_json::to_string(&Msg { ok: true }).unwrap());\n}\n",
        )
        .map_err(RustpenError::Io)?;
    }

    Ok(main_rs)
}

pub(super) fn ensure_interactive_terminal(label: &str) -> Result<(), RustpenError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(RustpenError::Generic(format!(
            "{label} 需要交互式终端(tty)"
        )));
    }
    Ok(())
}

pub(super) fn run_work_hub(root_ws: PathBuf) -> Result<(), RustpenError> {
    ensure_interactive_terminal("work hub")?;
    let mut state = WorkHubState::new(root_ws)?;
    let mut terminal = init_terminal()?;
    let res = (|| -> Result<(), RustpenError> {
        loop {
            state.refresh(false)?;
            terminal
                .draw(|f| draw_work_hub(f, &state))
                .map_err(RustpenError::Io)?;
            if !event::poll(EVENT_POLL_INTERVAL).map_err(RustpenError::Io)? {
                continue;
            }
            match event::read().map_err(RustpenError::Io)? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    if state.handle_key(key)? {
                        break;
                    }
                }
                Event::Mouse(mouse) => {
                    let area = terminal.size().map_err(RustpenError::Io)?;
                    state.handle_mouse(mouse, area);
                }
                _ => {}
            }
        }
        Ok(())
    })();
    restore_terminal(&mut terminal)?;
    res
}

pub(super) fn run_inspect_hub(root_ws: PathBuf) -> Result<(), RustpenError> {
    ensure_interactive_terminal("inspect hub")?;
    let mut state = InspectHubState::new(root_ws)?;
    let mut terminal = init_terminal()?;
    let res = (|| -> Result<(), RustpenError> {
        loop {
            state.refresh(false)?;
            terminal
                .draw(|f| draw_inspect_hub(f, &state))
                .map_err(RustpenError::Io)?;
            if !event::poll(EVENT_POLL_INTERVAL).map_err(RustpenError::Io)? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(RustpenError::Io)? else {
                continue;
            };
            if key.kind == KeyEventKind::Release {
                continue;
            }
            if state.handle_key(key)? {
                break;
            }
        }
        Ok(())
    })();
    restore_terminal(&mut terminal)?;
    res
}

pub(super) fn init_terminal() -> Result<HubTerminal, RustpenError> {
    enable_raw_mode().map_err(RustpenError::Io)?;
    let mut out = stdout();
    crossterm::execute!(
        out,
        crossterm::terminal::EnterAlternateScreen,
        EnableMouseCapture
    )
    .map_err(RustpenError::Io)?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend).map_err(RustpenError::Io)
}

pub(super) fn restore_terminal(terminal: &mut HubTerminal) -> Result<(), RustpenError> {
    disable_raw_mode().map_err(RustpenError::Io)?;
    crossterm::execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )
    .map_err(RustpenError::Io)?;
    terminal.show_cursor().ok();
    Ok(())
}

pub(super) fn resolve_project(root_ws: &Path) -> Result<PathBuf, RustpenError> {
    let active_project =
        resolve_active_project(root_ws, read_active_project_hint(root_ws).as_ref())?;
    ensure_project_layout(&active_project)?;
    let _ = write_active_project_hint(root_ws, &active_project);
    Ok(active_project)
}

pub(super) fn open_project_shell(project: &PathBuf) -> String {
    let pane_name = format!(
        "work-{}",
        shortened_label(&project_name_from_path(project), 16)
    );
    zellij::open_shell_pane_in_tab(zellij::WORK_TAB, project, project, Some(pane_name))
        .unwrap_or_else(|e| format!("打开 project shell 失败: {e}"))
}

pub(super) fn run_script_in_work_tab(project: &PathBuf, script: &PathBuf) -> String {
    let pane_name = format!("run-{}", shortened_label(&file_stem_or_name(script), 16));
    let cmd = build_script_run_command(script);
    zellij::open_command_pane_in_tab(zellij::WORK_TAB, project, &cmd, project, Some(pane_name))
        .unwrap_or_else(|e| format!("打开 script pane 失败: {e}"))
}

pub(super) fn build_script_run_command(script: &Path) -> String {
    let shell = shell_quote(&user_shell());
    let script_path = shell_quote(&script.display().to_string());
    let pretty = shell_quote(
        &script
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("script")
            .to_string(),
    );

    match script.extension().and_then(|value| value.to_str()) {
        Some("rs") => format!(
            "printf 'running %s\\n\\n' {pretty}; \
tmp=\"$(mktemp /tmp/rscan_script_XXXXXX)\"; \
rustc {script_path} -O -o \"$tmp\" && \"$tmp\"; \
code=$?; rm -f \"$tmp\"; \
printf '\\n[exit %s]\\n' \"$code\"; \
exec {shell} -i"
        ),
        _ => format!(
            "printf 'running %s\\n\\n' {pretty}; \
python3 {script_path}; \
code=$?; \
printf '\\n[exit %s]\\n' \"$code\"; \
exec {shell} -i"
        ),
    }
}

pub(super) fn focus_lower_shell() -> String {
    if std::env::var("ZELLIJ").is_err() && std::env::var("ZELLIJ_SESSION_NAME").is_err() {
        return "当前不在 zellij session 内".to_string();
    }
    let status = std::process::Command::new("zellij")
        .args(["action", "move-focus", "down"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => "已聚焦下方 shell".to_string(),
        Ok(_) => "聚焦下方 shell 失败".to_string(),
        Err(e) => format!("聚焦下方 shell 失败: {e}"),
    }
}

pub(super) fn shifted_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let upper = len.saturating_sub(1) as isize;
    (current as isize + delta).clamp(0, upper) as usize
}

pub(super) fn edge_index(len: usize, top: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if top { 0 } else { len - 1 }
}

pub(super) fn script_runner_label(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("rs") => "rustc -O && exec",
        _ => "python3",
    }
}

pub(super) fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn preview_source_paths(task: &TaskView) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for path in &task.meta.logs {
        push_unique_path(&mut out, path.clone());
    }
    push_unique_path(&mut out, task.dir.join("events.jsonl"));
    push_unique_path(&mut out, task.dir.join("stdout.log"));
    push_unique_path(&mut out, task.dir.join("stderr.log"));
    out.into_iter().filter(|path| path.is_file()).collect()
}

fn hash_path_snapshot(hasher: &mut DefaultHasher, path: &Path) {
    path.hash(hasher);
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    meta.len().hash(hasher);
    if let Ok(modified) = meta.modified()
        && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
    {
        duration.as_secs().hash(hasher);
        duration.subsec_nanos().hash(hasher);
    }
}

fn read_log_tail_lines(path: &Path, max_lines: usize, max_bytes: u64) -> Option<Vec<String>> {
    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start)).ok()?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let text = if start > 0 {
        text.lines().skip(1).collect::<Vec<_>>().join("\n")
    } else {
        text
    };
    let mut lines: Vec<String> = text
        .lines()
        .rev()
        .take(max_lines)
        .map(str::to_string)
        .collect();
    lines.reverse();
    Some(lines)
}

fn push_unique_path(items: &mut Vec<PathBuf>, path: PathBuf) {
    if items.iter().any(|item| same_path(item, &path)) {
        return;
    }
    items.push(path);
}

fn shortened_label(raw: &str, max: usize) -> String {
    let safe: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect();
    let safe = if safe.is_empty() {
        "pane".to_string()
    } else {
        safe
    };
    safe.chars().take(max).collect()
}

fn file_stem_or_name(path: &Path) -> String {
    path.file_stem()
        .or_else(|| path.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("script")
        .to_string()
}

fn user_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "zsh".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::task::{TaskMeta, TaskStatus};
    use crate::tui::models::TaskOrigin;

    fn make_task(base_name: &str, kind: &str, artifact_body: &str) -> (PathBuf, TaskView) {
        let base = std::env::temp_dir().join(format!(
            "rscan_native_hub_{base_name}_{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let task_dir = base.join("tasks").join(format!("task-{kind}"));
        std::fs::create_dir_all(&task_dir).unwrap();
        let artifact = task_dir.join(format!("{kind}-result.txt"));
        std::fs::write(&artifact, artifact_body).unwrap();
        let task = TaskView {
            meta: TaskMeta {
                id: format!("task-{kind}"),
                kind: kind.to_string(),
                tags: vec!["https://example.com".to_string()],
                status: TaskStatus::Succeeded,
                created_at: 1,
                started_at: Some(1),
                ended_at: Some(2),
                progress: Some(100.0),
                note: None,
                artifacts: vec![artifact],
                logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
                extra: None,
            },
            dir: task_dir,
            origin: TaskOrigin::Task,
        };
        (base, task)
    }

    #[test]
    fn pane_command_targets_hidden_pane_route() {
        assert!(
            super::super::build_work_hub_command("/tmp/rscan", Path::new("/tmp/ws"))
                .contains("pane --kind work")
        );
        assert!(
            super::super::build_inspect_hub_command("/tmp/rscan", Path::new("/tmp/ws"))
                .contains("pane --kind inspect")
        );
    }

    #[test]
    fn shifted_index_stays_bounded() {
        assert_eq!(shifted_index(0, 0, 3), 0);
        assert_eq!(shifted_index(0, 3, -1), 0);
        assert_eq!(shifted_index(1, 3, 1), 2);
        assert_eq!(shifted_index(2, 3, 1), 2);
    }

    #[test]
    fn script_command_uses_expected_runner() {
        let py = build_script_run_command(Path::new("/tmp/demo.py"));
        let rs = build_script_run_command(Path::new("/tmp/demo.rs"));
        assert!(py.contains("python3"));
        assert!(rs.contains("rustc"));
    }

    #[test]
    fn task_preview_lines_include_artifact_content() {
        let (base, task) = make_task(
            "preview",
            "web",
            "OK 200 https://example.com/admin\nOK 200 https://example.com/debug\n",
        );

        let lines = build_task_preview_lines(&task);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("[artifact:web-result.txt]"))
        );
        assert!(lines.iter().any(|line| line.contains("/admin")));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn work_result_lines_hide_json_like_artifacts() {
        let (base, mut task) = make_task("result_filter", "vuln", "{\"ok\":true}\n");
        let task_dir = task.dir.clone();
        let json_path = task_dir.join("scan-result.json");
        std::fs::write(&json_path, "{\"id\":\"x\"}\n").unwrap();
        task.meta.artifacts = vec![json_path];
        let state = super::super::WorkHubState {
            root_ws: base.clone(),
            projects: Vec::new(),
            active_project: base.clone(),
            selected_project: 0,
            tasks: vec![task],
            selected_task: 0,
            scripts: Vec::new(),
            selected_script: 0,
            result_scroll: 0,
            focus: super::super::WorkFocus::Results,
            command_mode: false,
            command_buffer: String::new(),
            command_candidates: Vec::new(),
            command_candidate_idx: 0,
            script_new_mode: false,
            script_new_buffer: String::new(),
            launcher_items: Vec::new(),
            selected_template: 0,
            message: String::new(),
            last_refresh: std::time::Instant::now(),
        };
        let lines = build_work_result_lines(&state);
        assert!(lines.iter().any(|line| line.contains("json/jsonl/log")));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn task_detail_cache_signature_changes_when_artifact_changes() {
        let (base, task) = make_task("signature", "vuln", "matched=word:body\n");
        let before = task_detail_cache_signature(&task);
        let artifact = task.meta.artifacts[0].clone();
        std::thread::sleep(Duration::from_millis(2));
        std::fs::write(&artifact, "matched=word:body,status:code\n").unwrap();
        let after = task_detail_cache_signature(&task);
        assert_ne!(before, after);

        let _ = std::fs::remove_dir_all(base);
    }
}
