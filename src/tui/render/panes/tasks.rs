use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};

use super::RenderCtx;
use crate::cores::engine::task::TaskStatus;
use crate::tui::models::TaskTab;
use crate::tui::view::{
    build_event_lines, build_logs_lines, build_notes_lines, build_overview_lines,
};

pub(super) fn draw_tasks(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

    let table_rows: Vec<Row> = if ctx.tasks.is_empty() {
        vec![Row::new(vec!["无任务，使用 --task-workspace 生成任务"])]
    } else {
        ctx.tasks
            .iter()
            .map(|t| {
                let status_style = match t.meta.status {
                    TaskStatus::Succeeded => Style::default().fg(Color::Green),
                    TaskStatus::Failed => Style::default().fg(Color::Red),
                    TaskStatus::Running => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                };
                Row::new(vec![
                    Cell::from(t.meta.id.clone()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(t.meta.kind.clone()).style(Style::default().fg(Color::Magenta)),
                    Cell::from(t.meta.status.to_string()).style(status_style),
                    Cell::from(
                        t.meta
                            .progress
                            .map(|v| format!("{:.1}%", v))
                            .unwrap_or_else(|| "-".into()),
                    ),
                    Cell::from(t.meta.created_at.to_string()),
                    Cell::from(t.meta.note.as_ref().map(|n| n.as_str()).unwrap_or("")),
                ])
            })
            .collect()
    };
    let mut table_state = TableState::default();
    table_state.select(if ctx.tasks.is_empty() {
        None
    } else {
        Some(ctx.task_selected.min(ctx.tasks.len().saturating_sub(1)))
    });
    let widths = [
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Min(10),
    ];
    let table = Table::new(table_rows, &widths)
        .header(Row::new(vec!["ID", "模块", "状态", "进度", "创建", "备注"]).bottom_margin(0))
        .block(Block::default().borders(Borders::ALL).title("Tasks"))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(table, body[0], &mut table_state);

    let detail_lines: Vec<Line> = ctx
        .tasks
        .get(ctx.task_selected)
        .map(|cur| match ctx.task_tab {
            TaskTab::Overview => build_overview_lines(cur),
            TaskTab::Events => build_event_lines(&cur.dir, 120),
            TaskTab::Logs => build_logs_lines(&cur.dir, 80),
            TaskTab::Notes => build_notes_lines(cur, ctx.note_buffer, ctx.input_mode),
        })
        .unwrap_or_else(|| vec![Line::from(Span::raw("无详情"))]);
    let detail_widget =
        Paragraph::new(detail_lines).block(Block::default().borders(Borders::ALL).title("Detail"));
    f.render_widget(detail_widget.scroll((ctx.detail_scroll, 0)), body[1]);
}
