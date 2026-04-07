use std::path::{Path, PathBuf};

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, ListItem, Row};

use crate::cores::engine::task::TaskStatus;

use super::models::{ProjectEntry, ProjectTemplate, TaskView};
use super::task_store::{
    load_log_tail, load_path_tail, load_text_artifact_snippets, task_has_displayable_result,
    task_has_log_output, task_has_previewable_artifact,
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
            let artifact_count = task.meta.artifacts.len();
            let result_state = if task_has_previewable_artifact(task) {
                "artifact"
            } else if task_has_log_output(task) {
                "logs"
            } else {
                "empty"
            };
            let result_color = if task_has_previewable_artifact(task) {
                Color::LightGreen
            } else if task_has_log_output(task) {
                Color::Yellow
            } else {
                Color::LightRed
            };
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
                    Span::styled(
                        format!("art:{artifact_count:<2} "),
                        Style::default().fg(Color::LightBlue),
                    ),
                    Span::styled(
                        format!("res:{result_state:<8} "),
                        Style::default().fg(result_color),
                    ),
                    Span::styled(
                        format!("rt:{runtime:<5} "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(summary),
                ]),
            ])
        })
        .collect()
}

fn result_status_badge(task: &TaskView) -> (&'static str, Color) {
    if task.meta.status == TaskStatus::Succeeded && !task_has_displayable_result(task) {
        ("EMPTY", Color::LightRed)
    } else {
        status_badge(&task.meta.status)
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
        return vec![ListItem::new("<empty> (N 创建新脚本)")];
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

    if task.meta.status == TaskStatus::Succeeded && !task_has_displayable_result(task) {
        return "completed but no result payload".to_string();
    }

    let note = task.meta.note.as_deref().unwrap_or("").trim();
    if !note.is_empty() {
        return note.chars().take(42).collect();
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

fn extract_port_rows(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
                return None;
            }
            let cols = trimmed.split_whitespace().collect::<Vec<_>>();
            let port = cols.first().copied()?;
            let service = cols.get(2).copied().filter(|col| !col.ends_with(')'));
            Some(match service {
                Some(svc) if !svc.chars().all(|ch| ch.is_ascii_digit()) => format!("{port}/{svc}"),
                _ => port.to_string(),
            })
        })
        .take(4)
        .collect()
}

fn web_result_summary(task: &TaskView) -> Option<String> {
    let artifact_hits = load_text_artifact_snippets(task, 24, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .filter_map(|line| summarize_web_hit(&line))
        .take(3)
        .collect::<Vec<_>>();
    if !artifact_hits.is_empty() {
        return Some(artifact_hits.join(" | "));
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
        assert!(rendered.contains("art:1"));
        assert!(rendered.contains("https://example.com/admin"));

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
