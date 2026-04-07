use std::collections::BTreeMap;
use std::path::Path;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::cores::engine::task::{TaskEvent, TaskStatus};
use crate::tui::zellij_registry;

use super::models::{InputMode, ResultKindFilter, TaskTab, TaskView};
use super::task_store::{
    task_has_displayable_result, task_has_log_output, task_has_previewable_artifact,
};
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
    let unbound = tasks
        .iter()
        .filter(|t| t.runtime_binding().is_none())
        .count();
    let hot_kind = kinds
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(kind, count)| format!("{kind} ({count})"))
        .unwrap_or_else(|| "-".to_string());

    let mut out = vec![
        section_line("Overview"),
        status_summary_line(total, queued, running, succeeded, failed),
        metric_line("success-rate", &success_rate, Color::Green),
        metric_line("hot-module", &hot_kind, Color::Cyan),
        metric_line("runtime", &runtime_line, Color::LightBlue),
        metric_line("unbound-runtime", &unbound.to_string(), Color::Yellow),
        line_s(""),
        section_line("Focus"),
        line_s(
            "Tasks/Results carry structured execution truth; native panes are drill-down surfaces.",
        ),
        line_s("Use L/W/A for logs, shell, artifacts; keep zrun for ad-hoc commands."),
        line_s(""),
        section_line("Module Mix"),
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
    out.push(section_line("Recent Tasks"));
    for task in tasks.iter().take(12) {
        out.push(task_snapshot_line(task));
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
    lines.push(section_line("Result View"));
    lines.push(metric_line(
        "filter",
        result_kind_filter.label(),
        Color::LightMagenta,
    ));
    lines.push(metric_line(
        "sort",
        if result_failed_first {
            "failed-first"
        } else {
            "created-desc"
        },
        Color::LightGreen,
    ));
    lines.push(metric_line(
        "query",
        if result_query.is_empty() {
            "<none>"
        } else {
            result_query
        },
        Color::Yellow,
    ));
    lines.push(line_s(
        "快捷键: f=模块过滤  o=失败优先排序  /=搜索  x=清空搜索",
    ));
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
        section_line("Task Summary"),
        Line::from(vec![
            badge_span(&meta.status),
            Span::raw(" "),
            Span::styled(
                meta.kind.clone(),
                Style::default()
                    .fg(kind_color(&meta.kind))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}", meta.id)),
        ]),
        metric_line("origin", cur.origin_label(), Color::LightBlue),
        metric_line("workspace", &workspace_label, Color::Gray),
        metric_line(
            "dir",
            &display_path(&cur.dir, workspace.as_deref()),
            Color::Gray,
        ),
        metric_line("progress", &progress_bar(meta.progress), Color::Green),
        metric_line("tags", &join_or_dash(&meta.tags), Color::Yellow),
        metric_line("created", &meta.created_at.to_string(), Color::Gray),
        metric_line(
            "started",
            &meta
                .started_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            Color::Gray,
        ),
        metric_line(
            "ended",
            &meta
                .ended_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            Color::Gray,
        ),
    ];
    if let Some(note) = &meta.note {
        lines.push(metric_line("note", note, Color::LightCyan));
    }
    if !meta.artifacts.is_empty() {
        lines.push(metric_line(
            "artifacts",
            &meta
                .artifacts
                .iter()
                .map(|p| display_path(p, workspace.as_deref()))
                .collect::<Vec<_>>()
                .join(", "),
            Color::LightBlue,
        ));
    }
    if !meta.logs.is_empty() {
        lines.push(metric_line(
            "logs",
            &meta
                .logs
                .iter()
                .map(|p| display_path(p, workspace.as_deref()))
                .collect::<Vec<_>>()
                .join(", "),
            Color::LightBlue,
        ));
    }

    lines.push(line_s(""));
    append_runtime_lines(&mut lines, cur);
    lines.push(line_s(""));
    lines.push(section_line("Native Ops"));
    lines.push(line_s("L=logs pane  W=task shell  A=artifact shell"));
    lines
}

fn build_effect_lines(cur: &TaskView) -> Vec<Line<'static>> {
    let workspace = cur.workspace_root();
    let events = super::task_store::load_events(&cur.dir, 20);
    let stdout = super::task_store::load_log_tail(&cur.dir, "stdout.log", 20);
    let stderr = super::task_store::load_log_tail(&cur.dir, "stderr.log", 20);
    let artifact_preview = super::task_store::preview_text_artifact(cur, 20);
    let mut lines = vec![
        section_line("Execution Summary"),
        Line::from(vec![
            badge_span(&cur.meta.status),
            Span::raw(" "),
            Span::styled(
                cur.meta.kind.clone(),
                Style::default()
                    .fg(kind_color(&cur.meta.kind))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {}", cur.meta.id)),
        ]),
        metric_line("origin", cur.origin_label(), Color::LightBlue),
        metric_line("progress", &progress_bar(cur.meta.progress), Color::Green),
        metric_line(
            "task-dir",
            &display_path(&cur.dir, workspace.as_deref()),
            Color::Gray,
        ),
        metric_line(
            "artifacts",
            &cur.meta.artifacts.len().to_string(),
            Color::LightBlue,
        ),
        metric_line("logs", &cur.meta.logs.len().to_string(), Color::LightBlue),
    ];

    lines.push(line_s(""));
    lines.push(section_line("Module Signals"));
    lines.extend(module_signal_lines(cur, &events, &stdout, &stderr));
    let result_state = if task_has_previewable_artifact(cur) {
        "artifact-ready"
    } else if task_has_log_output(cur) {
        "logs-only"
    } else if matches!(cur.meta.status, TaskStatus::Queued | TaskStatus::Running) {
        "launching"
    } else {
        "empty"
    };
    lines.push(metric_line("result-state", result_state, result_state_color(result_state)));
    let findings = key_findings(cur, &stdout);
    if !findings.is_empty() {
        lines.push(line_s(""));
        lines.push(section_line("Key Findings"));
        for finding in findings {
            lines.push(line_s(&format!("- {finding}")));
        }
    } else if cur.meta.status == TaskStatus::Succeeded && !task_has_displayable_result(cur) {
        lines.push(line_s(""));
        lines.push(section_line("Result Diagnosis"));
        lines.push(line_s(
            "- task 已结束，但当前任务目录内没有可展示的 artifact，也没有可读 stdout/stderr 内容",
        ));
        lines.push(line_s(
            "- 这通常意味着任务只完成了状态写回，没有把结果正文落到当前 project/tasks/<id>/ 中",
        ));
    } else if matches!(cur.meta.status, TaskStatus::Queued | TaskStatus::Running)
        && !task_has_displayable_result(cur)
    {
        lines.push(line_s(""));
        lines.push(section_line("Result Diagnosis"));
        lines.push(line_s("- 任务已进入队列或执行中，结果正文尚未落盘；先看 Recent Events / Stdout Tail"));
    }
    lines.push(line_s(""));
    append_runtime_lines(&mut lines, cur);
    lines.push(line_s(""));
    lines.push(section_line("Recent Events"));

    if events.is_empty() {
        lines.push(line_s("- <no events>"));
    } else {
        for ev in events {
            let color = match ev.level.to_ascii_lowercase().as_str() {
                "error" => Color::Red,
                "warn" => Color::Yellow,
                "debug" => Color::Blue,
                _ => Color::Gray,
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("[{}] ", ev.level.to_ascii_uppercase()),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{:?}] ", ev.kind),
                    Style::default().fg(Color::LightCyan),
                ),
                Span::raw(ev.message.unwrap_or_default()),
            ]));
        }
    }

    lines.push(line_s(""));
    lines.push(section_line("Native Ops"));
    lines.push(line_s("L=logs pane  W=task shell  A=artifact shell"));
    lines.push(line_s(""));
    lines.push(section_line("Stdout Tail"));
    if stdout.is_empty() {
        lines.push(line_s("- <empty>"));
    } else {
        lines.extend(stdout.into_iter().map(|line| {
            Line::from(vec![
                Span::styled("out> ", Style::default().fg(Color::LightBlue)),
                Span::raw(line),
            ])
        }));
    }

    lines.push(line_s(""));
    lines.push(section_line("Stderr Tail"));
    if stderr.is_empty() {
        lines.push(line_s("- <empty>"));
    } else {
        lines.extend(stderr.into_iter().map(|line| {
            Line::from(vec![
                Span::styled("err> ", Style::default().fg(Color::LightRed)),
                Span::raw(line),
            ])
        }));
    }

    if let Some((path, preview_lines)) = artifact_preview {
        lines.push(line_s(""));
        lines.push(section_line("Artifact Preview"));
        lines.push(metric_line(
            "path",
            &display_path(&path, workspace.as_deref()),
            Color::LightBlue,
        ));
        if preview_lines.is_empty() {
            lines.push(line_s("- <empty>"));
        } else {
            lines.extend(preview_lines.into_iter().map(|line| {
                Line::from(vec![
                    Span::styled("art> ", Style::default().fg(Color::LightMagenta)),
                    Span::raw(line),
                ])
            }));
        }
    }

    lines
}

fn result_state_color(state: &str) -> Color {
    match state {
        "artifact-ready" => Color::Green,
        "logs-only" => Color::Yellow,
        "launching" => Color::LightBlue,
        _ => Color::LightRed,
    }
}

fn key_findings(cur: &TaskView, stdout: &[String]) -> Vec<String> {
    let kind = cur.meta.kind.as_str();
    if kind == "host" || kind.starts_with("host-") {
        return host_findings(cur, stdout);
    }
    if kind == "web" || kind.starts_with("web-") {
        return web_findings(cur, stdout);
    }
    if kind == "vuln" || kind.starts_with("vuln-") {
        return vuln_findings(cur, stdout);
    }
    if kind == "reverse" || kind.starts_with("reverse-") || kind == "decompile" {
        return reverse_findings(cur, stdout);
    }
    Vec::new()
}

fn host_findings(cur: &TaskView, stdout: &[String]) -> Vec<String> {
    let mut findings = Vec::new();
    for artifact in &cur.meta.artifacts {
        let lines = super::task_store::load_path_tail(artifact, 24);
        if let Some(header) = lines.iter().find(|line| line.contains("open=")) {
            findings.push(condense_text(header));
        }
        let ports = lines
            .iter()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
                    return None;
                }
                let cols = trimmed.split_whitespace().collect::<Vec<_>>();
                cols.first().map(|port| (*port).to_string())
            })
            .take(8)
            .collect::<Vec<_>>();
        if !ports.is_empty() {
            findings.push(format!("open ports: {}", ports.join(", ")));
            break;
        }
    }
    if findings.is_empty() {
        findings.extend(
            stdout
                .iter()
                .filter(|line| line.contains("open=") || line.contains("PORT PROTO"))
                .map(|line| condense_text(line))
                .take(3),
        );
    }
    findings
}

fn web_findings(cur: &TaskView, stdout: &[String]) -> Vec<String> {
    let artifact_hits = super::task_store::load_text_artifact_snippets(cur, 24, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .filter_map(|line| extract_web_finding(&line))
        .take(8)
        .collect::<Vec<_>>();
    if !artifact_hits.is_empty() {
        return artifact_hits;
    }

    stdout
        .iter()
        .filter_map(|line| extract_web_finding(line))
        .take(6)
        .collect()
}

fn vuln_findings(cur: &TaskView, stdout: &[String]) -> Vec<String> {
    let artifact_hits = super::task_store::load_text_artifact_snippets(cur, 30, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .filter_map(|line| extract_vuln_finding(&line))
        .take(8)
        .collect::<Vec<_>>();
    if !artifact_hits.is_empty() {
        return artifact_hits;
    }

    stdout
        .iter()
        .filter_map(|line| extract_vuln_finding(line))
        .take(6)
        .collect()
}

fn reverse_findings(cur: &TaskView, stdout: &[String]) -> Vec<String> {
    let mut findings = cur
        .meta
        .artifacts
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .filter(|name| {
            name.contains("pseudo")
                || name.contains("asm")
                || name.contains("index")
                || name.contains("cfg")
                || name.contains("strings")
        })
        .take(6)
        .collect::<Vec<_>>();
    if findings.is_empty() {
        findings.extend(
            stdout
                .iter()
                .filter(|line| {
                    line.contains("rows=") || line.contains("funcs=") || line.contains("asm=")
                })
                .map(|line| condense_text(line))
                .take(3),
        );
    }
    findings
}

fn extract_web_finding(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !(trimmed.contains("http://") || trimmed.contains("https://")) {
        return None;
    }
    Some(condense_text(trimmed))
}

fn extract_vuln_finding(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("scan=ok ")
        || lower.starts_with("no findings")
        || lower.starts_with("matched=")
        || lower.starts_with("err ")
        || lower.contains(" matched=")
        || lower.contains("payload")
        || lower.contains("poc")
        || lower.contains("match")
        || lower.contains("template")
        || lower.contains("http://")
        || lower.contains("https://")
    {
        return Some(condense_text(trimmed));
    }
    None
}

fn append_registry_summary(out: &mut Vec<Line<'static>>, workspace: &Path) {
    out.push(line_s(""));
    out.push(section_line("Native Pane Registry"));
    match zellij_registry::summarize_registry(workspace, 6) {
        Ok(summary) if summary.total > 0 => {
            let tabs = summary
                .tab_counts
                .iter()
                .map(|(tab, count)| format!("{tab}={count}"))
                .collect::<Vec<_>>()
                .join(" | ");
            out.push(metric_line(
                "tabs",
                if tabs.is_empty() { "<none>" } else { &tabs },
                Color::LightBlue,
            ));
            out.push(metric_line(
                "bindings",
                &summary.total.to_string(),
                Color::LightBlue,
            ));
            out.push(line_s("recent:"));
            for entry in summary.recent {
                let role = entry.role.as_deref().unwrap_or("-");
                out.push(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", entry.tab),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(entry.name, Style::default().fg(Color::Cyan)),
                    Span::raw(format!(
                        " role={} cwd={}",
                        role,
                        display_path(&entry.cwd, Some(workspace))
                    )),
                ]));
            }
        }
        _ => out.push(line_s("- <none recorded yet>")),
    }
    out.push(line_s(""));
}

fn append_runtime_lines(lines: &mut Vec<Line<'static>>, cur: &TaskView) {
    let workspace = cur.workspace_root();
    let Some(runtime) = cur.runtime_binding() else {
        lines.push(section_line("Runtime"));
        lines.push(metric_line("runtime", "unbound", Color::Yellow));
        return;
    };

    lines.push(section_line("Runtime"));
    lines.push(metric_line("backend", &runtime.backend, Color::LightBlue));
    lines.push(metric_line(
        "session",
        &runtime.session.unwrap_or_else(|| "-".to_string()),
        Color::LightBlue,
    ));
    lines.push(metric_line(
        "tab",
        &runtime.tab.unwrap_or_else(|| "-".to_string()),
        Color::LightBlue,
    ));
    lines.push(metric_line(
        "pane",
        &runtime.pane_name.clone().unwrap_or_else(|| "-".to_string()),
        Color::LightBlue,
    ));
    lines.push(metric_line(
        "role",
        &runtime.role.unwrap_or_else(|| "-".to_string()),
        Color::LightBlue,
    ));
    lines.push(metric_line(
        "cwd",
        &runtime
            .cwd
            .as_deref()
            .map(|path| display_path(path, workspace.as_deref()))
            .unwrap_or_else(|| "-".to_string()),
        Color::Gray,
    ));
    if let Some(command) = runtime
        .command
        .as_deref()
        .filter(|cmd| !cmd.trim().is_empty())
    {
        lines.push(metric_line("command", command, Color::Gray));
    }

    if let (Some(ws), Some(pane_name)) = (workspace.as_deref(), runtime.pane_name.as_deref())
        && let Some(entry) = zellij_registry::find_recorded_pane(ws, pane_name)
    {
        lines.push(metric_line("registry.tab", &entry.tab, Color::LightMagenta));
        lines.push(metric_line(
            "registry.cwd",
            &display_path(&entry.cwd, Some(ws)),
            Color::Gray,
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

fn section_line(title: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            title.to_string(),
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
    ])
}

fn metric_line(label: &str, value: &str, color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>14}: "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(value.to_string(), Style::default().fg(color)),
    ])
}

fn status_summary_line(
    total: usize,
    queued: usize,
    running: usize,
    succeeded: usize,
    failed: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" total {total} "),
            Style::default().fg(Color::Black).bg(Color::White),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" queued {queued} "),
            Style::default().fg(Color::Black).bg(Color::LightBlue),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" run {running} "),
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" ok {succeeded} "),
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" fail {failed} "),
            Style::default().fg(Color::White).bg(Color::Red),
        ),
    ])
}

fn task_snapshot_line(task: &TaskView) -> Line<'static> {
    Line::from(vec![
        badge_span(&task.meta.status),
        Span::raw(" "),
        Span::styled(
            format!("{:<8}", task.meta.kind),
            Style::default().fg(kind_color(&task.meta.kind)),
        ),
        Span::raw(format!(
            "{}  {}",
            shorten_id(&task.meta.id, 14),
            progress_bar(task.meta.progress)
        )),
    ])
}

fn badge_span(status: &TaskStatus) -> Span<'static> {
    let (label, color) = match status {
        TaskStatus::Queued => ("QUEUED", Color::LightBlue),
        TaskStatus::Running => ("RUN", Color::Yellow),
        TaskStatus::Succeeded => ("OK", Color::Green),
        TaskStatus::Failed => ("FAIL", Color::Red),
        TaskStatus::Canceled => ("STOP", Color::DarkGray),
    };
    Span::styled(
        format!("[{label}]"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn kind_color(kind: &str) -> Color {
    if kind == "host" || kind.starts_with("host-") {
        Color::LightBlue
    } else if kind == "web" || kind.starts_with("web-") {
        Color::LightMagenta
    } else if kind == "vuln" || kind.starts_with("vuln-") {
        Color::LightRed
    } else if kind == "reverse"
        || kind.starts_with("reverse-")
        || kind == "decompile"
        || kind.starts_with("decompile-")
    {
        Color::LightCyan
    } else if kind == "script" || kind.starts_with("script-") {
        Color::LightYellow
    } else {
        Color::Gray
    }
}

fn progress_bar(progress: Option<f32>) -> String {
    let Some(progress) = progress else {
        return "[..........]".to_string();
    };
    let progress = progress.clamp(0.0, 100.0);
    let width = 10usize;
    let filled = ((progress / 100.0) * width as f32).round() as usize;
    format!(
        "[{}{}] {:>3.0}%",
        "=".repeat(filled.min(width)),
        ".".repeat(width.saturating_sub(filled.min(width))),
        progress
    )
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

fn shorten_id(id: &str, max: usize) -> String {
    id.chars().take(max).collect()
}

fn module_signal_lines(
    cur: &TaskView,
    events: &[TaskEvent],
    stdout: &[String],
    stderr: &[String],
) -> Vec<Line<'static>> {
    let artifact_names = cur
        .meta
        .artifacts
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .collect::<Vec<_>>();
    let note_summary = cur
        .meta
        .note
        .as_deref()
        .map(condense_text)
        .unwrap_or_else(|| "-".to_string());
    let stage_summary = stage_summary(events);
    let stderr_signal = stderr
        .iter()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| condense_text(line))
        .unwrap_or_else(|| "-".to_string());
    let event_warnings = events
        .iter()
        .filter(|ev| matches!(ev.level.to_ascii_lowercase().as_str(), "warn" | "error"))
        .count();
    let log_footprint = format!(
        "events={} stdout={} stderr={} flagged={}",
        events.len(),
        stdout.len(),
        stderr.len(),
        event_warnings
    );
    let artifact_summary = summarize_artifacts(&artifact_names);
    let target_summary = summarize_targets(&cur.meta.tags);

    let kind = cur.meta.kind.as_str();
    let mut lines = if kind == "host" || kind.starts_with("host-") {
        vec![
            line_s("Host scan: 突出目标、阶段推进、可疑端口/服务线索。"),
            metric_line("targets", &target_summary, Color::LightCyan),
            metric_line(
                "scan-stages",
                &stage_summary_with_fallback(&stage_summary, "host probes pending"),
                Color::LightBlue,
            ),
            metric_line(
                "scan-hints",
                &host_signal_hint(events, &artifact_names, &cur.meta.tags),
                Color::Yellow,
            ),
        ]
    } else if kind == "web" || kind.starts_with("web-") {
        vec![
            line_s("Web scan: 突出 URL/domain、目录枚举、响应落盘与命中路径。"),
            metric_line("targets", &target_summary, Color::LightCyan),
            metric_line(
                "route-stages",
                &stage_summary_with_fallback(&stage_summary, "web stages pending"),
                Color::LightBlue,
            ),
            metric_line(
                "response-hints",
                &web_signal_hint(events, &artifact_names, &cur.meta.tags),
                Color::Yellow,
            ),
        ]
    } else if kind == "vuln" || kind.starts_with("vuln-") {
        vec![
            line_s("Vuln scan: 突出模板加载、命中证据、严重级别与失败模板。"),
            metric_line("scope", &target_summary, Color::LightCyan),
            metric_line(
                "matcher-stages",
                &stage_summary_with_fallback(&stage_summary, "template stages pending"),
                Color::LightBlue,
            ),
            metric_line(
                "evidence-hints",
                &vuln_signal_hint(events, &cur.meta.tags, cur.meta.note.as_deref()),
                Color::Yellow,
            ),
        ]
    } else if kind == "reverse"
        || kind.starts_with("reverse-")
        || kind == "decompile"
        || kind.starts_with("decompile-")
    {
        vec![
            line_s("Reverse job: 突出 backend/mode/function 与伪代码、CFG、字符串类产物。"),
            metric_line("target", &target_summary, Color::LightCyan),
            metric_line(
                "job-flags",
                &reverse_tag_hint(&cur.meta.tags),
                Color::LightBlue,
            ),
            metric_line(
                "analysis-stages",
                &stage_summary_with_fallback(&stage_summary, "reverse stages pending"),
                Color::Yellow,
            ),
        ]
    } else if kind == "script" || kind.starts_with("script-") {
        vec![
            line_s("Script run: 突出 runner 生命周期、stderr、产物与脚本路径。"),
            metric_line("script-tags", &target_summary, Color::LightCyan),
            metric_line(
                "runner-stages",
                &stage_summary_with_fallback(&stage_summary, "script stages pending"),
                Color::LightBlue,
            ),
            metric_line(
                "stderr-signal",
                &stderr_signal,
                if stderr_signal == "-" {
                    Color::Green
                } else {
                    Color::LightRed
                },
            ),
        ]
    } else {
        vec![
            line_s("Generic task: 以 note、runtime、events、artifacts 为主线观察执行效果。"),
            metric_line("targets", &target_summary, Color::LightCyan),
            metric_line(
                "recent-stages",
                &stage_summary_with_fallback(&stage_summary, "generic stages pending"),
                Color::LightBlue,
            ),
        ]
    };

    lines.push(metric_line("note", &note_summary, Color::LightCyan));
    lines.push(metric_line(
        "artifact-mix",
        &artifact_summary,
        Color::LightBlue,
    ));
    lines.push(metric_line("log-footprint", &log_footprint, Color::Gray));
    lines.push(metric_line(
        "runtime-bound",
        if cur.runtime_binding().is_some() {
            "yes"
        } else {
            "no"
        },
        if cur.runtime_binding().is_some() {
            Color::Green
        } else {
            Color::Yellow
        },
    ));
    lines
}

fn condense_text(text: &str) -> String {
    let compact = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let shortened = chars.by_ref().take(88).collect::<String>();
    if chars.next().is_some() {
        format!("{shortened}...")
    } else if shortened.is_empty() {
        "-".to_string()
    } else {
        shortened
    }
}

fn summarize_targets(tags: &[String]) -> String {
    let mut picks = tags
        .iter()
        .filter(|tag| {
            !tag.starts_with("job:")
                && !tag.starts_with("backend:")
                && !tag.starts_with("mode:")
                && !tag.starts_with("function:")
        })
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    if picks.is_empty() {
        picks = tags.iter().take(4).cloned().collect();
    }
    if picks.is_empty() {
        "-".to_string()
    } else {
        picks.join(", ")
    }
}

fn stage_summary(events: &[TaskEvent]) -> Vec<String> {
    let mut stages = Vec::new();
    for event in events {
        let Some(message) = event.message.as_deref() else {
            continue;
        };
        let message = message.trim();
        if message.is_empty() {
            continue;
        }
        let stage = message
            .split(':')
            .next()
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .unwrap_or(message);
        if !stages.iter().any(|item| item == stage) {
            stages.push(stage.to_string());
        }
        if stages.len() >= 5 {
            break;
        }
    }
    stages
}

fn stage_summary_with_fallback(stages: &[String], fallback: &str) -> String {
    if stages.is_empty() {
        fallback.to_string()
    } else {
        stages.join(" -> ")
    }
}

fn summarize_artifacts(names: &[String]) -> String {
    if names.is_empty() {
        return "<none>".to_string();
    }
    let mut families: BTreeMap<&'static str, usize> = BTreeMap::new();
    for name in names {
        let lower = name.to_ascii_lowercase();
        let family = if lower.ends_with(".json") || lower.ends_with(".jsonl") {
            "json"
        } else if lower.ends_with(".html") || lower.ends_with(".htm") {
            "html"
        } else if lower.ends_with(".txt") || lower.ends_with(".log") || lower.ends_with(".md") {
            "text"
        } else if lower.ends_with(".csv") || lower.ends_with(".tsv") {
            "table"
        } else if lower.ends_with(".asm") || lower.contains("asm") {
            "asm"
        } else if lower.contains("pseudo") || lower.contains("decomp") {
            "pseudo"
        } else if lower.contains("cfg") {
            "cfg"
        } else if lower.contains("string") {
            "strings"
        } else if lower.contains("xref") || lower.contains("call") {
            "xref"
        } else if lower.contains('.') {
            "other"
        } else {
            "dir"
        };
        *families.entry(family).or_insert(0) += 1;
    }
    let summary = families
        .into_iter()
        .map(|(family, count)| format!("{family}:{count}"))
        .collect::<Vec<_>>()
        .join(" | ");
    let examples = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    format!("{summary} | sample={examples}")
}

fn host_signal_hint(events: &[TaskEvent], artifacts: &[String], tags: &[String]) -> String {
    let target_count = tags.iter().filter(|tag| !tag.contains(':')).count();
    let port_artifacts = artifacts
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("port") || lower.contains("service") || lower.contains("nmap")
        })
        .count();
    let retries = events
        .iter()
        .filter(|ev| {
            ev.message
                .as_deref()
                .map(|msg| {
                    let low = msg.to_ascii_lowercase();
                    low.contains("retry") || low.contains("timeout") || low.contains("refused")
                })
                .unwrap_or(false)
        })
        .count();
    format!("targets={target_count} port-artifacts={port_artifacts} retry-signals={retries}")
}

fn web_signal_hint(events: &[TaskEvent], artifacts: &[String], tags: &[String]) -> String {
    let url_like = tags
        .iter()
        .filter(|tag| tag.contains("://") || tag.contains('/'))
        .count();
    let hit_signals = events
        .iter()
        .filter(|ev| {
            ev.message
                .as_deref()
                .map(|msg| {
                    let low = msg.to_ascii_lowercase();
                    low.contains("200")
                        || low.contains("302")
                        || low.contains("found")
                        || low.contains("hit")
                })
                .unwrap_or(false)
        })
        .count();
    let output_files = artifacts
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".json")
                || lower.ends_with(".html")
                || lower.ends_with(".txt")
                || lower.contains("report")
        })
        .count();
    format!("url-tags={url_like} hit-signals={hit_signals} output-files={output_files}")
}

fn vuln_signal_hint(events: &[TaskEvent], tags: &[String], note: Option<&str>) -> String {
    let severity = tags
        .iter()
        .find(|tag| {
            let low = tag.to_ascii_lowercase();
            low.contains("critical")
                || low.contains("high")
                || low.contains("medium")
                || low.contains("low")
        })
        .cloned()
        .or_else(|| {
            note.and_then(|text| {
                let low = text.to_ascii_lowercase();
                ["critical", "high", "medium", "low"]
                    .into_iter()
                    .find(|level| low.contains(level))
                    .map(|level| level.to_string())
            })
        })
        .unwrap_or_else(|| "severity:unknown".to_string());
    let template_events = events
        .iter()
        .filter(|ev| {
            ev.message
                .as_deref()
                .map(|msg| {
                    let low = msg.to_ascii_lowercase();
                    low.contains("template") || low.contains("matcher") || low.contains("evidence")
                })
                .unwrap_or(false)
        })
        .count();
    format!("{severity} | template-signals={template_events}")
}

fn reverse_tag_hint(tags: &[String]) -> String {
    let mut picks = tags
        .iter()
        .filter(|tag| {
            tag.starts_with("backend:")
                || tag.starts_with("mode:")
                || tag.starts_with("function:")
                || tag.starts_with("job:")
        })
        .take(5)
        .cloned()
        .collect::<Vec<_>>();
    if picks.is_empty() {
        picks.push("reverse-job".to_string());
    }
    picks.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::task::{TaskMeta, TaskStatus};
    use crate::tui::models::TaskOrigin;
    use std::path::PathBuf;

    fn temp_task_dir(name: &str) -> PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_pane_text_{name}_{ns:x}"))
    }

    fn build_task(kind: &str, artifact_path: PathBuf, tag: &str) -> TaskView {
        let dir = artifact_path.parent().unwrap().to_path_buf();
        TaskView {
            meta: TaskMeta {
                id: format!("task-{kind}"),
                kind: kind.to_string(),
                tags: vec![tag.to_string()],
                status: TaskStatus::Succeeded,
                created_at: 1,
                started_at: Some(1),
                ended_at: Some(2),
                progress: Some(100.0),
                note: None,
                artifacts: vec![artifact_path],
                logs: vec![dir.join("stdout.log"), dir.join("stderr.log")],
                extra: None,
            },
            dir,
            origin: TaskOrigin::Task,
        }
    }

    #[test]
    fn web_findings_reads_urls_from_artifact() {
        let dir = temp_task_dir("web_findings");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-fuzz-result.txt");
        std::fs::write(
            &artifact,
            "OK 200 https://example.com/admin\nOK 200 https://example.com/debug\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let findings = web_findings(&task, &[]);
        assert!(findings.iter().any(|line| line.contains("/admin")));
        assert!(findings.iter().any(|line| line.contains("/debug")));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vuln_findings_reads_match_details_from_artifact() {
        let dir = temp_task_dir("vuln_findings");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("vuln-scan-result.txt");
        std::fs::write(
            &artifact,
            "HIGH cvescan GET https://example.com/login\n      matched=word:body,status:code\n",
        )
        .unwrap();
        let task = build_task("vuln", artifact, "https://example.com");

        let findings = vuln_findings(&task, &[]);
        assert!(findings.iter().any(|line| line.contains("cvescan")));
        assert!(
            findings
                .iter()
                .any(|line| line.contains("matched=word:body"))
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn build_result_panel_lines_includes_artifact_key_findings() {
        let dir = temp_task_dir("result_panel");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-fuzz-result.txt");
        std::fs::write(
            &artifact,
            "OK 200 https://example.com/admin\nOK 200 https://example.com/debug\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let lines = build_result_panel_lines(&task, ResultKindFilter::Web, false, "admin");
        let rendered = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("Key Findings"));
        assert!(rendered.contains("https://example.com/admin"));
        assert!(rendered.contains("query"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn web_findings_falls_back_to_stdout() {
        let dir = temp_task_dir("web_stdout_findings");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-fuzz-result.txt");
        std::fs::write(&artifact, "noise-only\n").unwrap();
        std::fs::write(
            dir.join("stdout.log"),
            "OK 200 https://example.com/stdout-hit\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let findings = web_findings(
            &task,
            &["OK 200 https://example.com/stdout-hit".to_string()],
        );
        assert!(findings.iter().any(|line| line.contains("stdout-hit")));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vuln_signal_hint_extracts_severity_from_note() {
        let hint = vuln_signal_hint(&[], &[], Some("detected critical issue on target"));
        assert!(hint.contains("critical"));
    }
}
