use std::path::PathBuf;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::cores::engine::task::TaskStatus;

use super::support::{build_work_detail_lines, build_work_result_lines};
use super::{InspectFocus, InspectHubState, ProjectEntry, TaskView, WorkFocus, WorkHubState};

#[derive(Copy, Clone, Debug)]
struct WorkRects {
    projects: Rect,
    templates: Rect,
    tasks: Rect,
    scripts: Rect,
    results: Rect,
    selection: Rect,
}

fn split_work_rects(area: Rect) -> WorkRects {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
        ])
        .split(area);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(34),
            Constraint::Percentage(44),
        ])
        .split(layout[1]);
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(body[0]);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(body[2]);

    WorkRects {
        projects: left[0],
        templates: left[1],
        tasks: body[1],
        scripts: right[0],
        results: right[1],
        selection: right[2],
    }
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    let right = rect.x.saturating_add(rect.width);
    let bottom = rect.y.saturating_add(rect.height);
    x >= rect.x && x < right && y >= rect.y && y < bottom
}

pub(super) fn work_focus_at(area: Rect, x: u16, y: u16) -> Option<WorkFocus> {
    let rects = split_work_rects(area);
    if rect_contains(rects.projects, x, y) {
        return Some(WorkFocus::Projects);
    }
    if rect_contains(rects.templates, x, y) {
        return Some(WorkFocus::Templates);
    }
    if rect_contains(rects.tasks, x, y) {
        return Some(WorkFocus::Tasks);
    }
    if rect_contains(rects.scripts, x, y) {
        return Some(WorkFocus::Scripts);
    }
    if rect_contains(rects.results, x, y) {
        return Some(WorkFocus::Results);
    }
    None
}

pub(super) fn draw_work_hub(f: &mut Frame<'_>, state: &WorkHubState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
        ])
        .split(f.size());
    let rects = split_work_rects(f.size());

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
        rects.projects,
        &state.projects,
        state.selected_project,
        state.focus == WorkFocus::Projects,
        "Projects",
    );
    draw_template_list(
        f,
        rects.templates,
        &state.launcher_items,
        state.selected_template,
        state.focus == WorkFocus::Templates,
        "Templates",
    );
    draw_task_list(
        f,
        rects.tasks,
        &state.tasks,
        state.selected_task,
        state.focus == WorkFocus::Tasks,
        "Recent Tasks",
    );
    draw_script_list(
        f,
        rects.scripts,
        &state.scripts,
        state.selected_script,
        state.focus == WorkFocus::Scripts,
        "Scripts [2=focus N=new E=edit Enter=run]",
    );
    let result_preview = build_work_result_lines(state);
    let result_scroll = state.result_scroll.min(u16::MAX as usize) as u16;
    f.render_widget(
        Paragraph::new(lines_from_strings(result_preview))
            .block(panel("Results", state.focus == WorkFocus::Results))
            .wrap(Wrap { trim: false })
            .scroll((result_scroll, 0)),
        rects.results,
    );
    let detail = build_work_detail_lines(state);
    f.render_widget(
        Paragraph::new(lines_from_strings(detail))
            .block(panel("Selection", false))
            .wrap(Wrap { trim: true }),
        rects.selection,
    );

    let footer = vec![
        Line::from(
            "h/l/tab=切焦点  j/k=移动/滚动  PgUp/PgDn/Home/End=快速移动  Enter=动作  1=模板区  2=脚本区  3=结果区  i/:=自定义命令(Tab补全)  N=新建脚本  E=编辑脚本  b=下方shell  r=刷新  q=退出",
        ),
        Line::from(format!(
            "{} | 脚本提示: 按2到Scripts，N新建，E编辑，Enter运行",
            state.message
        )),
    ];
    let footer_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(4)])
        .split(layout[2]);
    f.render_widget(
        Paragraph::new(footer)
            .block(panel("Actions", false))
            .wrap(Wrap { trim: true }),
        footer_layout[0],
    );

    let command_title = if state.command_mode {
        "Command Input (active)"
    } else {
        "Command Input"
    };
    let command_hint = if state.command_mode {
        "Enter=run  Tab=complete  Esc=cancel"
    } else {
        "按 i/: 激活输入框"
    };
    let command_input = if state.command_mode {
        format!("work.cmd> {}█", state.command_buffer)
    } else {
        format!("work.cmd> {}", state.command_buffer)
    };
    let command_lines = vec![Line::from(command_input), Line::from(command_hint)];
    f.render_widget(
        Paragraph::new(command_lines)
            .block(panel(command_title, state.command_mode))
            .wrap(Wrap { trim: true }),
        footer_layout[1],
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

fn draw_template_list(
    f: &mut Frame<'_>,
    area: Rect,
    templates: &[(&'static str, &'static str)],
    selected: usize,
    focused: bool,
    title: &str,
) {
    let mut items: Vec<ListItem<'static>> = templates
        .iter()
        .map(|(name, cmd)| ListItem::new(Line::raw(format!("{name} -> {cmd}"))))
        .collect();
    items.push(ListItem::new(Line::raw("[自定义命令...]")));
    let mut state = ListState::default();
    state.select((!items.is_empty()).then_some(selected.min(items.len().saturating_sub(1))));
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
            Style::default().fg(kind_color(&task.meta.kind)),
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
