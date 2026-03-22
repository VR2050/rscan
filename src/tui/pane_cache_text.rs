use std::path::{Path, PathBuf};

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, ListItem, Row};

use crate::cores::engine::task::TaskStatus;

use super::models::{ProjectEntry, ProjectTemplate, TaskView};
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
            ListItem::new(format!(
                "[{}] {} {}",
                task.meta.status, task.meta.kind, task.meta.id
            ))
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
    let status_style = match task.meta.status {
        TaskStatus::Succeeded => Style::default().fg(Color::Green),
        TaskStatus::Failed => Style::default().fg(Color::Red),
        TaskStatus::Running => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    };
    Row::new(vec![
        Cell::from(task.meta.id.clone()).style(Style::default().fg(Color::Cyan)),
        Cell::from(task.meta.kind.clone()).style(Style::default().fg(Color::Magenta)),
        Cell::from(task.meta.status.to_string()).style(status_style),
        Cell::from(
            task.meta
                .progress
                .map(|value| format!("{value:.1}%"))
                .unwrap_or_else(|| "-".to_string()),
        ),
        Cell::from(task.meta.created_at.to_string()),
        Cell::from(task.meta.note.clone().unwrap_or_default()),
    ])
}

fn task_compact_item(task: &TaskView) -> ListItem<'static> {
    let status = match task.meta.status {
        TaskStatus::Succeeded => "OK",
        TaskStatus::Failed => "FAIL",
        TaskStatus::Running => "RUN",
        TaskStatus::Queued => "Q",
        TaskStatus::Canceled => "C",
    };
    let progress = task
        .meta
        .progress
        .map(|value| format!("{value:.0}%"))
        .unwrap_or_else(|| "-".to_string());
    ListItem::new(format!(
        "[{}] {:<6} {:<10} {}",
        status, task.meta.kind, task.meta.id, progress
    ))
}
