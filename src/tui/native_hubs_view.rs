use std::path::PathBuf;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::cores::engine::task::TaskStatus;

use super::support::build_work_detail_lines;
use super::{InspectFocus, InspectHubState, ProjectEntry, TaskView, WorkFocus, WorkHubState};

pub(super) fn draw_work_hub(f: &mut Frame<'_>, state: &WorkHubState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.size());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(40),
            Constraint::Percentage(36),
        ])
        .split(layout[1]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(body[2]);

    let header = vec![
        Line::from(vec![
            Span::styled(
                "Work Hub",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  native workspace"),
        ]),
        Line::from(format!(
            "root={} | project={}",
            state.root_ws.display(),
            state.active_project.display()
        )),
    ];
    f.render_widget(
        Paragraph::new(header)
            .block(panel("rscan x zellij", false))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    draw_project_list(
        f,
        body[0],
        &state.projects,
        state.selected_project,
        state.focus == WorkFocus::Projects,
        "Projects",
    );
    draw_task_list(
        f,
        body[1],
        &state.tasks,
        state.selected_task,
        state.focus == WorkFocus::Tasks,
        "Recent Tasks",
    );
    draw_script_list(
        f,
        right[0],
        &state.scripts,
        state.selected_script,
        state.focus == WorkFocus::Scripts,
        "Scripts",
    );
    let detail = build_work_detail_lines(state);
    f.render_widget(
        Paragraph::new(lines_from_strings(detail))
            .block(panel("Selection", false))
            .wrap(Wrap { trim: true }),
        right[1],
    );

    let footer = vec![
        Line::from("h/l=切焦点  j/k=移动  Enter=动作  b=下方 shell  r=刷新  q=退出"),
        Line::from(state.message.clone()),
    ];
    f.render_widget(
        Paragraph::new(footer)
            .block(panel("Actions", false))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
}

pub(super) fn draw_inspect_hub(f: &mut Frame<'_>, state: &InspectHubState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.size());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(34),
            Constraint::Percentage(44),
        ])
        .split(layout[1]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(54), Constraint::Percentage(46)])
        .split(body[2]);

    let header = vec![
        Line::from(vec![
            Span::styled(
                "Inspect Hub",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  native inspect workspace"),
        ]),
        Line::from(format!(
            "project={} | filter={}",
            state.active_project.display(),
            state.status_filter.label()
        )),
    ];
    f.render_widget(
        Paragraph::new(header)
            .block(panel("rscan x zellij", false))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    draw_project_list(
        f,
        body[0],
        &state.projects,
        state.selected_project,
        state.focus == InspectFocus::Projects,
        "Projects",
    );
    draw_task_list(
        f,
        body[1],
        &state.tasks,
        state.selected_task,
        state.focus == InspectFocus::Tasks,
        &format!("Tasks [{}]", state.status_filter.label()),
    );
    f.render_widget(
        Paragraph::new(lines_from_strings(state.detail_lines.clone()))
            .block(panel("Detail", false))
            .wrap(Wrap { trim: true }),
        right[0],
    );
    f.render_widget(
        Paragraph::new(lines_from_strings(state.preview_lines.clone()))
            .block(panel("Log Preview", false))
            .wrap(Wrap { trim: false }),
        right[1],
    );

    let footer = vec![
        Line::from(
            "h/l=切焦点  j/k=移动  Enter/L=日志  A=artifacts  W=shell  F=过滤  b=下方 shell",
        ),
        Line::from(state.message.clone()),
    ];
    f.render_widget(
        Paragraph::new(footer)
            .block(panel("Actions", false))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
}

fn draw_project_list(
    f: &mut Frame<'_>,
    area: Rect,
    projects: &[ProjectEntry],
    selected: usize,
    focused: bool,
    title: &str,
) {
    let items: Vec<ListItem<'static>> = if projects.is_empty() {
        vec![ListItem::new(Line::raw("<none>"))]
    } else {
        projects
            .iter()
            .map(|project| {
                let label = if project.imported {
                    format!("ext {}", project.name)
                } else {
                    format!("loc {}", project.name)
                };
                ListItem::new(Line::raw(label))
            })
            .collect()
    };
    let mut state = ListState::default();
    state.select((!projects.is_empty()).then_some(selected.min(projects.len().saturating_sub(1))));
    let list = List::new(items)
        .block(panel(title, focused))
        .highlight_style(highlight_style())
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_task_list(
    f: &mut Frame<'_>,
    area: Rect,
    tasks: &[TaskView],
    selected: usize,
    focused: bool,
    title: &str,
) {
    let items: Vec<ListItem<'static>> = if tasks.is_empty() {
        vec![ListItem::new(Line::raw("<none>"))]
    } else {
        tasks.iter().map(task_list_item).collect()
    };
    let mut state = ListState::default();
    state.select((!tasks.is_empty()).then_some(selected.min(tasks.len().saturating_sub(1))));
    let list = List::new(items)
        .block(panel(title, focused))
        .highlight_style(highlight_style())
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_script_list(
    f: &mut Frame<'_>,
    area: Rect,
    scripts: &[PathBuf],
    selected: usize,
    focused: bool,
    title: &str,
) {
    let items: Vec<ListItem<'static>> = if scripts.is_empty() {
        vec![ListItem::new(Line::raw("<none>"))]
    } else {
        scripts
            .iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("<invalid>");
                ListItem::new(Line::raw(name.to_string()))
            })
            .collect()
    };
    let mut state = ListState::default();
    state.select((!scripts.is_empty()).then_some(selected.min(scripts.len().saturating_sub(1))));
    let list = List::new(items)
        .block(panel(title, focused))
        .highlight_style(highlight_style())
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
}

fn task_list_item(task: &TaskView) -> ListItem<'static> {
    let status = task.meta.status.to_string();
    let note = task
        .meta
        .note
        .as_deref()
        .unwrap_or(task.origin_label())
        .chars()
        .take(30)
        .collect::<String>();
    let line = Line::from(vec![
        Span::styled(
            format!("{:<8}", task.meta.kind),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!("{:<10}", status),
            Style::default().fg(task_status_color(&task.meta.status)),
        ),
        Span::raw(format!("{:<14}", super::shorten_id(&task.meta.id, 14))),
        Span::raw(note),
    ]);
    ListItem::new(line)
}

fn panel(title: &str, focused: bool) -> Block<'static> {
    let style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .title(title.to_string())
        .borders(Borders::ALL)
        .border_style(style)
}

fn highlight_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Rgb(120, 202, 255))
        .add_modifier(Modifier::BOLD)
}

fn task_status_color(status: &TaskStatus) -> Color {
    match status {
        TaskStatus::Running => Color::Yellow,
        TaskStatus::Failed => Color::Red,
        TaskStatus::Succeeded => Color::Green,
        TaskStatus::Queued => Color::LightBlue,
        TaskStatus::Canceled => Color::DarkGray,
    }
}

fn lines_from_strings(lines: Vec<String>) -> Vec<Line<'static>> {
    lines.into_iter().map(Line::raw).collect()
}
