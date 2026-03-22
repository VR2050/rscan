use std::path::Path;

use ratatui::text::Line;

use crate::cores::engine::task::TaskStatus;
use crate::tui::zellij_registry;

use super::models::{InputMode, ResultKindFilter, TaskTab, TaskView};
use super::view::{build_event_lines, build_logs_lines, build_notes_lines, line_s};

pub(crate) fn build_dashboard_lines(
    tasks: &[TaskView],
    workspace: &Path,
    zellij_managed: bool,
    zellij_session: Option<&str>,
) -> Vec<Line<'static>> {
    use std::collections::BTreeMap;

    let total = tasks.len();
    let queued = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Queued)
        .count();
    let running = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Running)
        .count();
    let failed = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Failed)
        .count();
    let succeeded = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Succeeded)
        .count();

    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for task in tasks {
        *kinds.entry(task.meta.kind.clone()).or_insert(0) += 1;
    }

    let runtime_line = if zellij_managed {
        format!(
            "runtime: zellij managed | session={} | Control/Work/Inspect/Reverse tabs active",
            zellij_session.unwrap_or("attached")
        )
    } else {
        "runtime: native TUI | aux panel carries output/problems + optional mini terminal"
            .to_string()
    };
    let success_rate = if total == 0 {
        "n/a".to_string()
    } else {
        format!("{:.0}%", (succeeded as f64 / total as f64) * 100.0)
    };

    let mut out = vec![
        line_s("rscan workbench"),
        line_s(&runtime_line),
        line_s(
            "execution: structured tasks stay in Tasks/Results; L/W/A open native panes; `zrun` stays ad-hoc",
        ),
        line_s("surface: Dashboard / Tasks / Launcher / Scripts / Results / Projects"),
        line_s(""),
        line_s(&format!(
            "queue: total={} queued={} running={} succeeded={} failed={} | success-rate={}",
            total, queued, running, succeeded, failed, success_rate
        )),
        line_s(""),
        line_s("module mix:"),
    ];

    if zellij_managed {
        append_registry_summary(&mut out, workspace);
    }

    if kinds.is_empty() {
        out.push(line_s("- <none>"));
    } else {
        for (kind, count) in kinds {
            out.push(line_s(&format!("- {}: {}", kind, count)));
        }
    }

    out.push(line_s(""));
    out.push(line_s("recent tasks:"));
    for task in tasks.iter().take(12) {
        out.push(line_s(&format!(
            "- {} [{}] {}",
            task.meta.id, task.meta.kind, task.meta.status
        )));
    }

    out
}

pub(crate) fn build_task_detail_lines(
    cur: &TaskView,
    task_tab: TaskTab,
    note_buffer: &str,
    mode: InputMode,
) -> Vec<Line<'static>> {
    match task_tab {
        TaskTab::Overview => build_overview_lines(cur),
        TaskTab::Events => build_event_lines(&cur.dir, 120),
        TaskTab::Logs => build_logs_lines(&cur.dir, 80),
        TaskTab::Notes => build_notes_lines(cur, note_buffer, mode),
    }
}

pub(crate) fn build_result_panel_lines(
    cur: &TaskView,
    result_kind_filter: ResultKindFilter,
    result_failed_first: bool,
    result_query: &str,
) -> Vec<Line<'static>> {
    let mut lines = build_effect_lines(cur);
    lines.push(line_s(""));
    lines.push(line_s(&format!(
        "view: filter={} sort={}",
        result_kind_filter.label(),
        if result_failed_first {
            "failed-first"
        } else {
            "created-desc"
        }
    )));
    lines.push(line_s("快捷键: f=模块过滤  o=失败优先排序"));
    lines.push(line_s(&format!(
        "query: {}",
        if result_query.is_empty() {
            "<none>"
        } else {
            result_query
        }
    )));
    lines.push(line_s("快捷键: /=搜索  x=清空搜索"));
    lines
}

fn build_overview_lines(cur: &TaskView) -> Vec<Line<'static>> {
    let meta = &cur.meta;
    let workspace = cur.workspace_root();
    let workspace_label = workspace
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "-".to_string());

    let mut lines = vec![
        format!("id: {}", meta.id),
        format!("origin: {}", cur.origin_label()),
        format!("kind: {}", meta.kind),
        format!("status: {}", meta.status),
        format!("workspace: {}", workspace_label),
        format!("dir: {}", display_path(&cur.dir, workspace.as_deref())),
        format!("created_at: {}", meta.created_at),
        format!(
            "started_at: {}",
            meta.started_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "ended_at: {}",
            meta.ended_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "progress: {}",
            meta.progress
                .map(|v| format!("{:.1}%", v))
                .unwrap_or_else(|| "-".into())
        ),
        format!("tags: {}", meta.tags.join(",")),
    ];
    if let Some(note) = &meta.note {
        lines.push(format!("note: {}", note));
    }
    if !meta.artifacts.is_empty() {
        lines.push(format!(
            "artifacts: {}",
            meta.artifacts
                .iter()
                .map(|p| display_path(p, workspace.as_deref()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !meta.logs.is_empty() {
        lines.push(format!(
            "logs: {}",
            meta.logs
                .iter()
                .map(|p| display_path(p, workspace.as_deref()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    append_runtime_lines(&mut lines, cur);
    lines.push("".to_string());
    lines.push("native ops: L=logs pane  W=task shell  A=artifact shell".to_string());
    lines.into_iter().map(|s| line_s(&s)).collect()
}

fn build_effect_lines(cur: &TaskView) -> Vec<Line<'static>> {
    let workspace = cur.workspace_root();
    let mut lines = vec![
        format!("task: {}", cur.meta.id),
        format!("module: {}", cur.meta.kind),
        format!("origin: {}", cur.origin_label()),
        format!("status: {}", cur.meta.status),
        format!(
            "progress: {}",
            cur.meta
                .progress
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string())
        ),
        format!("task dir: {}", display_path(&cur.dir, workspace.as_deref())),
    ];

    append_runtime_lines(&mut lines, cur);
    lines.push("".to_string());
    lines.push("recent events:".to_string());

    let events = super::task_store::load_events(&cur.dir, 20);
    if events.is_empty() {
        lines.push("- <no events>".to_string());
    } else {
        for ev in events {
            lines.push(format!(
                "- [{}][{:?}] {}",
                ev.level,
                ev.kind,
                ev.message.unwrap_or_default()
            ));
        }
    }

    lines.push("".to_string());
    lines.push("native ops: L=logs pane  W=task shell  A=artifact shell".to_string());
    lines.push("".to_string());
    lines.push("stdout tail:".to_string());
    let stdout = super::task_store::load_log_tail(&cur.dir, "stdout.log", 20);
    if stdout.is_empty() {
        lines.push("- <empty>".to_string());
    } else {
        lines.extend(stdout);
    }

    lines.push("".to_string());
    lines.push("stderr tail:".to_string());
    let stderr = super::task_store::load_log_tail(&cur.dir, "stderr.log", 20);
    if stderr.is_empty() {
        lines.push("- <empty>".to_string());
    } else {
        lines.extend(stderr);
    }

    lines.into_iter().map(|s| line_s(&s)).collect()
}

fn append_registry_summary(out: &mut Vec<Line<'static>>, workspace: &Path) {
    out.push(line_s(""));
    out.push(line_s("native pane registry:"));
    match zellij_registry::summarize_registry(workspace, 6) {
        Ok(summary) if summary.total > 0 => {
            let tabs = summary
                .tab_counts
                .iter()
                .map(|(tab, count)| format!("{tab}={count}"))
                .collect::<Vec<_>>()
                .join(" | ");
            out.push(line_s(&format!(
                "count={} | {}",
                summary.total,
                if tabs.is_empty() {
                    "<none>".to_string()
                } else {
                    tabs
                }
            )));
            out.push(line_s("recent bindings:"));
            for entry in summary.recent {
                let role = entry.role.as_deref().unwrap_or("-");
                out.push(line_s(&format!(
                    "- [{}] {} role={} cwd={}",
                    entry.tab,
                    entry.name,
                    role,
                    display_path(&entry.cwd, Some(workspace))
                )));
            }
        }
        _ => out.push(line_s("- <none recorded yet>")),
    }
    out.push(line_s(""));
}

fn append_runtime_lines(lines: &mut Vec<String>, cur: &TaskView) {
    let workspace = cur.workspace_root();
    let Some(runtime) = cur.runtime_binding() else {
        lines.push("runtime: unbound".to_string());
        return;
    };

    lines.push("".to_string());
    lines.push(format!("runtime.backend: {}", runtime.backend));
    lines.push(format!(
        "runtime.session: {}",
        runtime.session.unwrap_or_else(|| "-".to_string())
    ));
    lines.push(format!(
        "runtime.tab: {}",
        runtime.tab.unwrap_or_else(|| "-".to_string())
    ));
    lines.push(format!(
        "runtime.pane: {}",
        runtime.pane_name.clone().unwrap_or_else(|| "-".to_string())
    ));
    lines.push(format!(
        "runtime.role: {}",
        runtime.role.unwrap_or_else(|| "-".to_string())
    ));
    lines.push(format!(
        "runtime.cwd: {}",
        runtime
            .cwd
            .as_deref()
            .map(|path| display_path(path, workspace.as_deref()))
            .unwrap_or_else(|| "-".to_string())
    ));
    if let Some(command) = runtime
        .command
        .as_deref()
        .filter(|cmd| !cmd.trim().is_empty())
    {
        lines.push(format!("runtime.command: {}", command));
    }

    if let (Some(ws), Some(pane_name)) = (workspace.as_deref(), runtime.pane_name.as_deref())
        && let Some(entry) = zellij_registry::find_recorded_pane(ws, pane_name)
    {
        lines.push(format!("registry.tab: {}", entry.tab));
        lines.push(format!(
            "registry.cwd: {}",
            display_path(&entry.cwd, Some(ws))
        ));
    }
}

fn display_path(path: &Path, workspace: Option<&Path>) -> String {
    if let Some(workspace) = workspace
        && let Ok(rel) = path.strip_prefix(workspace)
    {
        let text = rel.display().to_string();
        return if text.is_empty() {
            ".".to_string()
        } else {
            text
        };
    }
    path.display().to_string()
}
