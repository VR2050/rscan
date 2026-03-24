use std::path::PathBuf;

use crate::cores::engine::task::{TaskRuntimeBinding, update_task_runtime_binding};

use super::models::{TaskOrigin, TaskView};
use super::task_store::{REVERSE_JOB_RUNTIME_FILE, load_tasks};
use super::zellij;
use super::zellij_registry;

pub(crate) fn open_task_logs_by_id(workspace: &PathBuf, task_id: &str) -> String {
    match load_task_by_id(workspace, task_id) {
        Ok(task) => open_task_logs_in_runtime(&task),
        Err(e) => e,
    }
}

pub(crate) fn open_task_shell_by_id(workspace: &PathBuf, task_id: &str) -> String {
    match load_task_by_id(workspace, task_id) {
        Ok(task) => open_task_shell_in_runtime(&task),
        Err(e) => e,
    }
}

pub(crate) fn open_task_artifacts_by_id(workspace: &PathBuf, task_id: &str) -> String {
    match load_task_by_id(workspace, task_id) {
        Ok(task) => open_task_artifacts_in_runtime(&task),
        Err(e) => e,
    }
}

pub(crate) fn open_reverse_workspace_shell(workspace: &PathBuf) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }
    match zellij::open_shell_pane_in_tab(
        zellij::REVERSE_TAB,
        workspace,
        workspace,
        Some("reverse-workspace".to_string()),
    ) {
        Ok(msg) => {
            let _ = zellij_registry::record_pane(
                workspace,
                "reverse-workspace".to_string(),
                zellij::REVERSE_TAB.to_string(),
                workspace.clone(),
                Some("reverse-workspace".to_string()),
                None,
            );
            format!("{msg} | reverse workspace shell 已打开")
        }
        Err(e) => format!("打开 Reverse shell 失败: {e}"),
    }
}

pub(crate) fn open_task_logs_in_runtime(task: &TaskView) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }
    let pane_name = short_task_pane_name("logs", &task.meta.id);
    let cmd = build_logs_follow_command(task);
    let workspace = task.workspace_root().unwrap_or_else(|| task.dir.clone());
    match zellij::open_command_pane_in_tab(
        zellij::INSPECT_TAB,
        &workspace,
        &cmd,
        &task.dir,
        Some(pane_name.clone()),
    ) {
        Ok(msg) => {
            remember_runtime(
                task,
                zellij::INSPECT_TAB,
                &pane_name,
                "inspect-logs",
                task.dir.clone(),
                Some(cmd),
            );
            format!("{msg} | 已在 Inspect 跟随 {}", task.meta.id)
        }
        Err(e) => format!("打开任务日志失败: {e}"),
    }
}

pub(crate) fn open_task_shell_in_runtime(task: &TaskView) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }
    let tab = preferred_shell_tab(task);
    let pane_name = short_task_pane_name("task", &task.meta.id);
    let cwd = preferred_shell_cwd(task);
    let workspace = task.workspace_root().unwrap_or_else(|| cwd.clone());
    match zellij::open_shell_pane_in_tab(tab, &workspace, &cwd, Some(pane_name.clone())) {
        Ok(msg) => {
            remember_runtime(task, tab, &pane_name, "task-shell", cwd.clone(), None);
            format!("{msg} | 已在 {tab} 打开任务 shell {}", task.meta.id)
        }
        Err(e) => format!("打开任务 shell 失败: {e}"),
    }
}

pub(crate) fn open_task_artifacts_in_runtime(task: &TaskView) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }
    let pane_name = short_task_pane_name("art", &task.meta.id);
    let cmd = build_artifact_shell_command(task);
    let cwd = preferred_artifact_cwd(task);
    let workspace = task.workspace_root().unwrap_or_else(|| cwd.clone());
    match zellij::open_command_pane_in_tab(
        zellij::INSPECT_TAB,
        &workspace,
        &cmd,
        &cwd,
        Some(pane_name.clone()),
    ) {
        Ok(msg) => {
            remember_runtime(
                task,
                zellij::INSPECT_TAB,
                &pane_name,
                "inspect-artifacts",
                cwd.clone(),
                Some(cmd),
            );
            format!("{msg} | 已在 Inspect 打开任务目录 {}", task.meta.id)
        }
        Err(e) => format!("打开任务产物视图失败: {e}"),
    }
}

fn load_task_by_id(workspace: &PathBuf, task_id: &str) -> Result<TaskView, String> {
    let tasks = load_tasks(workspace.clone()).map_err(|e| format!("读取任务索引失败: {e}"))?;
    tasks
        .into_iter()
        .find(|t| t.meta.id == task_id)
        .ok_or_else(|| format!("task 不存在: {task_id}"))
}

fn preferred_shell_tab(task: &TaskView) -> &'static str {
    let kind = task.meta.kind.as_str();
    if kind == "reverse"
        || kind.starts_with("reverse-")
        || kind == "decompile"
        || kind.starts_with("decompile-")
    {
        zellij::REVERSE_TAB
    } else {
        zellij::WORK_TAB
    }
}

fn remember_runtime(
    task: &TaskView,
    tab: &str,
    pane_name: &str,
    role: &str,
    cwd: PathBuf,
    command: Option<String>,
) {
    let registry_cwd = cwd.clone();
    let registry_command = command.clone();
    let binding = TaskRuntimeBinding {
        backend: "zellij".to_string(),
        session: Some(zellij::config().session),
        tab: Some(tab.to_string()),
        pane_name: Some(pane_name.to_string()),
        role: Some(role.to_string()),
        cwd: Some(cwd),
        command,
    };
    match task.origin {
        TaskOrigin::Task => {
            let _ = update_task_runtime_binding(&task.dir, binding);
        }
        TaskOrigin::ReverseJob => {
            if let Ok(text) = serde_json::to_string_pretty(&binding) {
                let _ = std::fs::write(task.dir.join(REVERSE_JOB_RUNTIME_FILE), text);
            }
        }
    }
    if let Some(workspace) = task.workspace_root() {
        let _ = zellij_registry::record_pane(
            &workspace,
            pane_name.to_string(),
            tab.to_string(),
            registry_cwd,
            Some(role.to_string()),
            registry_command,
        );
    }
}

fn preferred_shell_cwd(task: &TaskView) -> PathBuf {
    match task.origin {
        TaskOrigin::Task => task.dir.clone(),
        TaskOrigin::ReverseJob => task
            .runtime_binding()
            .and_then(|runtime| runtime.cwd)
            .unwrap_or_else(|| task.dir.clone()),
    }
}

fn preferred_artifact_cwd(task: &TaskView) -> PathBuf {
    match task.origin {
        TaskOrigin::Task => task.dir.clone(),
        TaskOrigin::ReverseJob => task
            .runtime_binding()
            .and_then(|runtime| runtime.cwd)
            .unwrap_or_else(|| task.dir.clone()),
    }
}

fn build_logs_follow_command(task: &TaskView) -> String {
    let shell = shell_quote(&user_shell());
    let id = shell_quote(&task.meta.id);
    let kind = shell_quote(&task.meta.kind);
    let status = shell_quote(&task.meta.status.to_string());
    let cwd = shell_quote(&task.dir.display().to_string());
    format!(
        "printf 'task=%s kind=%s status=%s\\n' {id} {kind} {status}; \
printf 'cwd=%s\\n\\n' {cwd}; \
files=''; \
for f in events.jsonl stdout.log stderr.log; do \
  if [ -e \"$f\" ]; then files=\"$files $f\"; fi; \
done; \
if [ -z \"$files\" ]; then \
  echo 'no event/log file yet; dropping to shell'; \
  exec {shell} -i; \
else \
  exec tail -n 80 -F $files; \
fi"
    )
}

fn build_artifact_shell_command(task: &TaskView) -> String {
    let shell = shell_quote(&user_shell());
    let id = shell_quote(&task.meta.id);
    let kind = shell_quote(&task.meta.kind);
    let status = shell_quote(&task.meta.status.to_string());
    let mut script = format!(
        "printf 'task=%s kind=%s status=%s\\n\\n' {id} {kind} {status}; \
printf 'artifacts/logs known to task metadata:\\n';"
    );
    if task.meta.artifacts.is_empty() && task.meta.logs.is_empty() {
        script.push_str("printf ' - <none recorded>\\n';");
    } else {
        for path in task.meta.artifacts.iter().chain(task.meta.logs.iter()) {
            let path = shell_quote(&path.display().to_string());
            script.push_str(&format!("printf ' - %s\\n' {path};"));
        }
    }
    script.push_str("printf '\\nworkspace listing:\\n'; ls -lah; printf '\\n';");
    script.push_str(&format!("exec {shell} -i"));
    script
}

fn short_task_pane_name(prefix: &str, task_id: &str) -> String {
    let short = task_id.trim_start_matches("task-");
    let short = &short[..short.len().min(10)];
    format!("{}-{}", prefix, short)
}

fn user_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "zsh".to_string())
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}
