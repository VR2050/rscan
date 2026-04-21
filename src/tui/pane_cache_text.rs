use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, ListItem, Row};

use crate::cores::engine::task::TaskStatus;

use super::models::{ProjectEntry, ProjectTemplate, TaskView};
use super::task_store::{
    ResultState, load_log_tail, load_path_tail, load_text_artifact_snippets,
    task_has_displayable_result, task_previewable_artifact_count, task_result_state,
};
use super::view::line_s;

pub(crate) fn build_task_table_rows(tasks: &[TaskView]) -> Vec<Row<'static>> {
    if tasks.is_empty() {
        return vec![Row::new(vec!["无任务，使用 --task-workspace 生成任务"])];
    }

    tasks.iter().map(task_table_row).collect()
}

pub(crate) fn build_task_compact_items(tasks: &[TaskView]) -> Vec<ListItem<'static>> {
    if tasks.is_empty() {
        return vec![ListItem::new("<empty>")];
    }

    tasks.iter().map(task_compact_item).collect()
}

pub(crate) fn build_result_list_items(
    all_tasks: &[TaskView],
    result_indices: &[usize],
) -> Vec<ListItem<'static>> {
    if result_indices.is_empty() {
        return vec![ListItem::new("<empty>")];
    }

    result_indices
        .iter()
        .map(|&idx| {
            let task = &all_tasks[idx];
            let (status_label, status_color) = result_status_badge(task);
            let summary = task_result_summary(task);
            let previewable_count = task_previewable_artifact_count(task);
            let artifact_count = task.meta.artifacts.len();
            let result_state = task_result_state(task);
            let result_color = result_state_color(result_state);
            let runtime = if task.runtime_binding().is_some() {
                "bound"
            } else {
                "plain"
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(
                        format!("[{status_label}] "),
                        Style::default()
                            .fg(status_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<8}", task.meta.kind),
                        Style::default()
                            .fg(kind_color(&task.meta.kind))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "{}  {}",
                        shorten_id(&task.meta.id, 14),
                        progress_bar(task.meta.progress, 10)
                    )),
                ]),
                Line::from(vec![
                    Span::styled(summary, Style::default().fg(Color::White)),
                    Span::raw("  "),
                    Span::styled(
                        format!("art:{previewable_count}/{artifact_count:<2} "),
                        Style::default().fg(Color::LightBlue),
                    ),
                    Span::styled(
                        format!("res:{} ", result_state.label()),
                        Style::default().fg(result_color),
                    ),
                    Span::styled(
                        format!("rt:{runtime:<5} "),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]),
            ])
        })
        .collect()
}

fn result_status_badge(task: &TaskView) -> (&'static str, Color) {
    status_badge(&task.meta.status)
}

fn result_state_color(state: ResultState) -> Color {
    match state {
        ResultState::ArtifactReady => Color::LightGreen,
        ResultState::LogsOnly => Color::Yellow,
        ResultState::Launching => Color::LightBlue,
        ResultState::NonPreviewableArtifact => Color::LightMagenta,
        ResultState::Empty => Color::LightRed,
    }
}

pub(crate) fn build_dashboard_recent_items(
    tasks: &[TaskView],
    limit: usize,
) -> Vec<ListItem<'static>> {
    if tasks.is_empty() {
        return vec![ListItem::new("<no tasks>")];
    }

    tasks
        .iter()
        .take(limit)
        .map(|task| {
            let (status_label, status_color) = status_badge(&task.meta.status);
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{status_label}] "),
                    Style::default()
                        .fg(status_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<8}", task.meta.kind),
                    Style::default().fg(kind_color(&task.meta.kind)),
                ),
                Span::raw(shorten_id(&task.meta.id, 14)),
            ]))
        })
        .collect()
}

pub(crate) fn build_script_file_items(scripts: &[PathBuf]) -> Vec<ListItem<'static>> {
    if scripts.is_empty() {
        return vec![ListItem::new("<empty> (N 创建 .rs 脚本)")];
    }

    scripts
        .iter()
        .map(|path| {
            let label = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            ListItem::new(label)
        })
        .collect()
}

pub(crate) fn build_script_output_lines(script_output: &[String]) -> Vec<Line<'static>> {
    if script_output.is_empty() {
        return vec![line_s("<empty output>")];
    }

    script_output.iter().map(|line| line_s(line)).collect()
}

pub(crate) fn build_project_list_items(projects: &[ProjectEntry]) -> Vec<ListItem<'static>> {
    if projects.is_empty() {
        return vec![ListItem::new("<empty>")];
    }

    projects
        .iter()
        .map(|project| {
            let mark = if project.imported { "import" } else { "local" };
            ListItem::new(format!("[{}] {}", mark, project.name))
        })
        .collect()
}

pub(crate) fn build_project_detail_lines(
    projects: &[ProjectEntry],
    project_selected: usize,
    current_project: &Path,
    project_template: ProjectTemplate,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        line_s("项目管理"),
        line_s("Enter: 切换项目"),
        line_s("N: 新建项目   I: 导入项目   D: 删除/移除项目"),
        line_s("C: 复制项目   M: 重命名项目   E: 导出项目快照"),
        line_s("T: 切换新建项目模板"),
        line_s(""),
        line_s(&format!("new-template: {}", project_template.label())),
        line_s(""),
    ];
    if let Some(project) = projects.get(project_selected) {
        lines.push(line_s(&format!("name: {}", project.name)));
        lines.push(line_s(&format!(
            "type: {}",
            if project.imported {
                "imported"
            } else {
                "local"
            }
        )));
        lines.push(line_s(&format!("path: {}", project.path.display())));
        lines.push(line_s(&format!(
            "active: {}",
            if project.path == current_project {
                "yes"
            } else {
                "no"
            }
        )));
    } else {
        lines.push(line_s("<no project>"));
    }
    lines
}

pub(crate) fn build_launcher_list_items(
    launcher_items: &[(&'static str, &'static str)],
) -> Vec<ListItem<'static>> {
    launcher_items
        .iter()
        .map(|item| ListItem::new(item.0))
        .collect()
}

pub(crate) fn build_launcher_detail_lines(
    launcher_items: &[(&'static str, &'static str)],
    launcher_selected: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("内置快捷任务（Enter 执行）"),
        Line::from("命令会以新的 rscan 进程启动，并写入 task/workspace"),
        Line::from("在 zellij 模式下，普通模块命令不会跳去终端页；请在 Tasks/Results 里跟踪"),
        Line::from(""),
    ];
    if let Some((_, cmd)) = launcher_items.get(launcher_selected) {
        lines.push(Line::from(vec![Span::styled(
            "command:",
            Style::default().fg(Color::Yellow),
        )]));
        lines.push(Line::from(cmd.to_string()));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("支持模块: host / web / vuln / reverse"));
    lines.push(Line::from(
        "按 : 进入命令模式可手动输入 (h.quick|h.tcp|w.dir|w.fuzz|w.dns|v.scan|r.analyze|r.plan|r.run)",
    ));
    lines.push(Line::from(
        "也支持层级命令: host/web/vuln/reverse (Tab 补全)",
    ));
    lines.push(Line::from(
        "reverse run 会把 decompile job 写入 jobs/reverse_out，并回流到统一 Tasks/Results",
    ));
    lines.push(Line::from("zrun <cmd> 会在 Work tab 打开真实终端 pane"));
    lines.push(Line::from(
        "zfocus <tab> 可直接聚焦 Control/Work/Inspect/Reverse",
    ));
    lines.push(Line::from(
        "zlogs/zshell/zart <task_id> 可把历史任务送进 Inspect/Work/Reverse",
    ));
    lines.push(Line::from("zrev 会打开 Reverse workspace shell"));
    lines.push(Line::from(
        "命令编辑: Left/Right/Home/End, Ctrl+Shift+C/V, Ctrl+Z/Y",
    ));
    lines.push(Line::from("命令补全: Tab/Shift+Tab  历史: Up/Down"));
    lines
}

fn task_table_row(task: &TaskView) -> Row<'static> {
    let (status_label, status_color) = status_badge(&task.meta.status);
    Row::new(vec![
        Cell::from(shorten_id(&task.meta.id, 12)).style(Style::default().fg(Color::Cyan)),
        Cell::from(task.meta.kind.clone()).style(
            Style::default()
                .fg(kind_color(&task.meta.kind))
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(status_label).style(
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(progress_bar(task.meta.progress, 8)),
        Cell::from(task.meta.created_at.to_string()),
        Cell::from(
            task.meta
                .note
                .as_deref()
                .unwrap_or(task.origin_label())
                .chars()
                .take(28)
                .collect::<String>(),
        ),
    ])
}

fn task_compact_item(task: &TaskView) -> ListItem<'static> {
    let (status_label, status_color) = status_badge(&task.meta.status);
    ListItem::new(Line::from(vec![
        Span::styled(
            format!("[{status_label}] "),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<8}", task.meta.kind),
            Style::default().fg(kind_color(&task.meta.kind)),
        ),
        Span::raw(format!(
            "{}  {}",
            shorten_id(&task.meta.id, 12),
            progress_label(task.meta.progress)
        )),
    ]))
}

fn status_badge(status: &TaskStatus) -> (&'static str, Color) {
    match status {
        TaskStatus::Succeeded => ("OK", Color::Green),
        TaskStatus::Failed => ("FAIL", Color::Red),
        TaskStatus::Running => ("RUN", Color::Yellow),
        TaskStatus::Queued => ("Q", Color::LightBlue),
        TaskStatus::Canceled => ("STOP", Color::DarkGray),
    }
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

fn progress_label(progress: Option<f32>) -> String {
    progress
        .map(|value| format!("{value:>5.0}%"))
        .unwrap_or_else(|| "   --".to_string())
}

fn progress_bar(progress: Option<f32>, width: usize) -> String {
    let Some(progress) = progress else {
        return format!("[{}]", ".".repeat(width));
    };
    let progress = progress.clamp(0.0, 100.0);
    let filled = ((progress / 100.0) * width as f32).round() as usize;
    format!(
        "[{}{}] {:>3.0}%",
        "=".repeat(filled.min(width)),
        ".".repeat(width.saturating_sub(filled.min(width))),
        progress
    )
}

fn shorten_id(id: &str, max: usize) -> String {
    id.chars().take(max).collect()
}

fn task_result_summary(task: &TaskView) -> String {
    if let Some(summary) = structured_result_summary(task) {
        return summary.chars().take(42).collect();
    }

    if task_result_state(task) == ResultState::NonPreviewableArtifact {
        let artifact_names = task
            .meta
            .artifacts
            .iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .take(2)
            .collect::<Vec<_>>();
        if !artifact_names.is_empty() {
            return format!("artifact only: {}", artifact_names.join(", "))
                .chars()
                .take(42)
                .collect();
        }
    }

    let note = task.meta.note.as_deref().unwrap_or("").trim();
    if !note.is_empty() {
        return note.chars().take(42).collect();
    }

    if task.meta.status == TaskStatus::Succeeded && !task_has_displayable_result(task) {
        return "completed but no previewable result".to_string();
    }

    let artifact_names = task
        .meta
        .artifacts
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .take(2)
        .collect::<Vec<_>>();
    if !artifact_names.is_empty() {
        return artifact_names.join(", ").chars().take(42).collect();
    }

    let log_names = task
        .meta
        .logs
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .take(2)
        .collect::<Vec<_>>();
    if !log_names.is_empty() {
        return log_names.join(", ").chars().take(42).collect();
    }

    task.origin_label().chars().take(42).collect()
}

fn structured_result_summary(task: &TaskView) -> Option<String> {
    let kind = task.meta.kind.as_str();
    if kind == "host" || kind.starts_with("host-") {
        return host_result_summary(task);
    }
    if kind == "web" || kind.starts_with("web-") {
        return web_result_summary(task);
    }
    if kind == "vuln" || kind.starts_with("vuln-") {
        return vuln_result_summary(task);
    }
    if kind == "reverse" || kind.starts_with("reverse-") || kind == "decompile" {
        return reverse_result_summary(task);
    }
    None
}

fn host_result_summary(task: &TaskView) -> Option<String> {
    for path in &task.meta.artifacts {
        if let Some(summary) = summarize_host_structured_artifact(path) {
            return Some(summary);
        }
        let lines = load_path_tail(path, 20);
        for line in &lines {
            if let Some(rest) = line.split("open=").nth(1) {
                let open_count = rest.split_whitespace().next().unwrap_or("?");
                let ports = extract_port_rows(&lines);
                if ports.is_empty() {
                    return Some(format!("open={open_count}"));
                }
                return Some(format!("open={open_count} ports={}", ports.join(",")));
            }
        }
        let ports = extract_port_rows(&lines);
        if !ports.is_empty() {
            return Some(format!("ports={}", ports.join(",")));
        }
    }

    let stdout = load_log_tail(&task.dir, "stdout.log", 20);
    let ports = extract_port_rows(&stdout);
    if !ports.is_empty() {
        return Some(format!("ports={}", ports.join(",")));
    }
    stdout
        .iter()
        .find_map(|line| line.contains("open=").then(|| condense_line(line)))
}

fn summarize_host_structured_artifact(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    summarize_host_json_value(&value)
}

fn summarize_host_json_value(value: &serde_json::Value) -> Option<String> {
    let mut open_ports = BTreeSet::new();
    let mut services = BTreeSet::new();

    match value {
        serde_json::Value::Array(rows) => {
            for row in rows {
                let is_open = row
                    .get("status")
                    .and_then(|v| v.as_str())
                    .is_some_and(|status| status.eq_ignore_ascii_case("open"));
                if is_open && let Some(port) = row.get("port").and_then(|v| v.as_u64()) {
                    open_ports.insert(port as u16);
                }
                if let Some(meta_pairs) = row.get("metadata").and_then(|v| v.as_array()) {
                    for item in meta_pairs {
                        let Some(pair) = item.as_array() else {
                            continue;
                        };
                        if pair.len() != 2 {
                            continue;
                        }
                        let Some(key) = pair[0].as_str() else {
                            continue;
                        };
                        if key != "service" {
                            continue;
                        }
                        if let Some(service) = pair[1].as_str()
                            && !service.trim().is_empty()
                        {
                            services.insert(service.to_string());
                        }
                    }
                }
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(ports) = map.get("open_ports").and_then(|v| v.as_array()) {
                for p in ports.iter().filter_map(|v| v.as_u64()) {
                    open_ports.insert(p as u16);
                }
            }
            if let Some(details) = map.get("details").and_then(|v| v.as_array()) {
                for detail in details {
                    if let Some(port) = detail.get("port").and_then(|v| v.as_u64()) {
                        open_ports.insert(port as u16);
                    }
                    if let Some(service) = detail.get("service").and_then(|v| v.as_str())
                        && !service.trim().is_empty()
                    {
                        services.insert(service.to_string());
                    }
                }
            }
        }
        _ => {}
    }

    if open_ports.is_empty() && services.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    if !open_ports.is_empty() {
        parts.push(format!(
            "ports={}",
            open_ports
                .iter()
                .take(6)
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if !services.is_empty() {
        parts.push(format!(
            "services={}",
            services
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    Some(parts.join(" "))
}

fn extract_port_rows(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (port, service) = parse_port_row(trimmed)?;
            Some(match service {
                Some(svc) => format!("{port}/{svc}"),
                None => port,
            })
        })
        .take(4)
        .collect()
}

fn parse_port_row(trimmed: &str) -> Option<(String, Option<String>)> {
    if trimmed.is_empty() || trimmed.starts_with("IP ") || trimmed.contains(" PORT ") {
        return None;
    }
    let cols = trimmed.split_whitespace().collect::<Vec<_>>();
    if cols.len() < 2 {
        return None;
    }
    let port = if cols.first()?.chars().all(|ch| ch.is_ascii_digit()) {
        cols.first()?.to_string()
    } else if cols[0].parse::<std::net::IpAddr>().is_ok()
        && cols[1].chars().all(|ch| ch.is_ascii_digit())
    {
        cols[1].to_string()
    } else {
        return None;
    };
    let service = parse_service_from_meta(trimmed);
    Some((port, service))
}

fn parse_service_from_meta(line: &str) -> Option<String> {
    let marker = "(\"service\", \"";
    let (_, rest) = line.split_once(marker)?;
    let (svc, _) = rest.split_once("\")")?;
    let svc = svc.trim();
    if svc.is_empty() {
        None
    } else {
        Some(svc.to_string())
    }
}

fn web_result_summary(task: &TaskView) -> Option<String> {
    let artifact_lines = load_text_artifact_snippets(task, 24, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .collect::<Vec<_>>();

    let artifact_hits = artifact_lines
        .iter()
        .filter_map(|line| summarize_web_hit(line))
        .take(3)
        .collect::<Vec<_>>();
    if !artifact_hits.is_empty() {
        return Some(artifact_hits.join(" | "));
    }
    let artifact_errors = artifact_lines
        .iter()
        .filter_map(|line| summarize_web_error(line))
        .collect::<Vec<_>>();
    if !artifact_errors.is_empty() {
        return Some(format_web_error_summary(&artifact_errors));
    }

    let stdout = load_log_tail(&task.dir, "stdout.log", 24);
    let hits = stdout
        .iter()
        .filter_map(|line| summarize_web_hit(line))
        .take(3)
        .collect::<Vec<_>>();
    if !hits.is_empty() {
        return Some(hits.join(" | "));
    }
    let errors = stdout
        .iter()
        .filter_map(|line| summarize_web_error(line))
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        return Some(format_web_error_summary(&errors));
    }
    stdout
        .iter()
        .find(|line| line.contains("processed") || line.contains("saved output"))
        .map(|line| condense_line(line))
}

fn vuln_result_summary(task: &TaskView) -> Option<String> {
    let artifact_hits = load_text_artifact_snippets(task, 30, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .filter_map(|line| summarize_vuln_line(&line))
        .take(4)
        .collect::<Vec<_>>();
    if !artifact_hits.is_empty() {
        return Some(artifact_hits.join(" | "));
    }

    let stdout = load_log_tail(&task.dir, "stdout.log", 30);
    let hits = stdout
        .iter()
        .filter_map(|line| summarize_vuln_line(line))
        .take(3)
        .collect::<Vec<_>>();
    if !hits.is_empty() {
        return Some(hits.join(" | "));
    }
    stdout.first().map(|line| condense_line(line))
}

fn reverse_result_summary(task: &TaskView) -> Option<String> {
    let names = task
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
        .take(3)
        .collect::<Vec<_>>();
    if !names.is_empty() {
        return Some(names.join(", "));
    }
    load_log_tail(&task.dir, "stdout.log", 10)
        .iter()
        .find(|line| line.contains("rows=") || line.contains("funcs=") || line.contains("asm="))
        .map(|line| condense_line(line))
}

fn condense_line(line: &str) -> String {
    let compact = line.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(88).collect()
}

fn summarize_web_hit(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !(trimmed.contains("http://") || trimmed.contains("https://")) {
        return None;
    }
    let mut cols = trimmed.split_whitespace();
    let first = cols.next()?;
    let second = cols.next().unwrap_or("");
    let url = cols.next_back().unwrap_or("");
    if url.is_empty() {
        return Some(condense_line(trimmed));
    }
    Some(format!("{first} {second} {url}"))
}

fn summarize_web_error(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("error ")
        || lower.starts_with("err ")
        || lower.contains("networkerror")
        || lower.contains("error:")
        || lower.contains("error sending request")
        || lower.contains("timeout")
    {
        return Some(condense_line(trimmed));
    }
    None
}

fn format_web_error_summary(errors: &[String]) -> String {
    let first = errors.first().cloned().unwrap_or_default();
    format!("errors={} {first}", errors.len())
}

fn summarize_vuln_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("scan=ok ") || lower.starts_with("no findings") {
        return Some(condense_line(trimmed));
    }
    if lower.starts_with("matched=") || lower.contains(" matched=") {
        return Some(condense_line(trimmed));
    }
    if lower.starts_with("err ") {
        return Some(condense_line(trimmed));
    }
    if !(lower.contains("template")
        || lower.contains("payload")
        || lower.contains("poc")
        || lower.contains("match")
        || lower.contains("http://")
        || lower.contains("https://"))
    {
        return None;
    }
    Some(condense_line(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::task::{TaskMeta, TaskStatus};
    use crate::tui::models::TaskOrigin;

    fn temp_task_dir(name: &str) -> PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_pane_cache_{name}_{ns:x}"))
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
    fn web_result_summary_prefers_artifact_hits() {
        let dir = temp_task_dir("web_summary");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-dir-result.txt");
        std::fs::write(
            &artifact,
            "OK 200 https://example.com/admin\nCLIENT 404 https://example.com/robots.txt\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let summary = web_result_summary(&task).unwrap();
        assert!(summary.contains("OK 200 https://example.com/admin"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vuln_result_summary_reads_matched_lines_from_artifact() {
        let dir = temp_task_dir("vuln_summary");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("vuln-scan-result.txt");
        std::fs::write(
            &artifact,
            "scan=ok requests=12 findings=1 errors=0\nHIGH cvescan GET https://example.com/login\n      matched=word:body,status:code\n",
        )
        .unwrap();
        let task = build_task("vuln", artifact, "https://example.com");

        let summary = vuln_result_summary(&task).unwrap();
        assert!(summary.contains("scan=ok") || summary.contains("matched=word:body"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn build_result_list_items_renders_artifact_derived_summary() {
        let dir = temp_task_dir("result_list");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-dir-result.txt");
        std::fs::write(&artifact, "OK 200 https://example.com/admin\n").unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let items = build_result_list_items(std::slice::from_ref(&task), &[0]);
        let rendered = format!("{:?}", items[0]);
        assert!(rendered.contains("art:1/1"));
        assert!(rendered.contains("artifact-ready"));
        assert!(rendered.contains("https://example.com/admin"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn host_result_summary_reads_ports_and_services_from_json_artifact() {
        let dir = temp_task_dir("host_json_summary");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("host-port-result.json");
        std::fs::write(
            &artifact,
            r#"[{"target_ip":"127.0.0.1","port":80,"protocol":"Tcp","status":"Open","metadata":[["service","http"]]},{"target_ip":"127.0.0.1","port":443,"protocol":"Tcp","status":"Open","metadata":[["service","https"]]}]"#,
        )
        .unwrap();
        let task = build_task("host", artifact, "127.0.0.1");

        let summary = host_result_summary(&task).unwrap();
        assert!(summary.contains("ports=80,443"));
        assert!(summary.contains("services=http,https"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn host_result_summary_parses_ip_port_style_raw_rows() {
        let dir = temp_task_dir("host_raw_ip_port");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("host-tcp-result.txt");
        std::fs::write(
            &artifact,
            "             IP   PORT PROTO    STATUS    LAT(ms) META\n      127.0.0.1     80   tcp      open          1 [(\"service\", \"http\")]\n",
        )
        .unwrap();
        let task = build_task("host", artifact, "127.0.0.1");

        let summary = host_result_summary(&task).unwrap();
        assert!(summary.contains("ports=80/http"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn web_result_summary_falls_back_to_stdout_when_no_artifact_hit() {
        let dir = temp_task_dir("web_stdout_fallback");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-dir-result.txt");
        std::fs::write(&artifact, "not-a-url-line\n").unwrap();
        std::fs::write(
            dir.join("stdout.log"),
            "OK 200 https://example.com/fallback\nsaved output -> somewhere\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let summary = web_result_summary(&task).unwrap();
        assert!(summary.contains("https://example.com/fallback"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn web_result_summary_reports_error_count_when_no_hits() {
        let dir = temp_task_dir("web_error_summary");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("web-dir-result.txt");
        std::fs::write(
            &artifact,
            "ERROR network timeout on request\nERR dial tcp 127.0.0.1: connection refused\n",
        )
        .unwrap();
        let task = build_task("web", artifact, "https://example.com");

        let summary = web_result_summary(&task).unwrap();
        assert!(summary.contains("errors=2"));
        assert!(summary.to_ascii_lowercase().contains("timeout") || summary.contains("ERR"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn vuln_result_summary_falls_back_to_stdout_when_artifact_has_no_match_signal() {
        let dir = temp_task_dir("vuln_stdout_fallback");
        std::fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("vuln-scan-result.txt");
        std::fs::write(&artifact, "plain line without useful markers\n").unwrap();
        std::fs::write(
            dir.join("stdout.log"),
            "HIGH template-x GET https://example.com/login\n",
        )
        .unwrap();
        let task = build_task("vuln", artifact, "https://example.com");

        let summary = vuln_result_summary(&task).unwrap();
        assert!(summary.contains("template-x"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
