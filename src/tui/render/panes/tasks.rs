use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, Paragraph, Row, Table, TableState};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_tasks(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if is_compact(area) {
        draw_tasks_compact(f, area, ctx);
        return;
    }
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

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
    let tasks_title = "Tasks";
    let table = Table::new(ctx.task_table_rows.to_vec(), &widths)
        .header(Row::new(vec!["ID", "模块", "状态", "进度", "创建", "备注"]).bottom_margin(0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Tasks))
                .title(tasks_title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(table, body[0], &mut table_state);

    let detail_widget = Paragraph::new(ctx.task_detail_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Tasks))
            .title(if ctx.zellij_managed {
                "Detail / Native Runtime"
            } else {
                "Detail"
            }),
    );
    f.render_widget(detail_widget.scroll((ctx.detail_scroll, 0)), body[1]);
}

fn is_compact(area: Rect) -> bool {
    area.width < 70 || area.height < 10
}

fn draw_tasks_compact(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if area.height >= 8 {
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)].as_ref())
            .split(area);
        let mut state = ratatui::widgets::ListState::default();
        state.select(if ctx.tasks.is_empty() {
            None
        } else {
            Some(ctx.task_selected.min(ctx.tasks.len().saturating_sub(1)))
        });
        let list = List::new(ctx.task_compact_items.to_vec())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(pane_border_style(ctx, MainPane::Tasks))
                    .title("Tasks (compact)"),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">> ");
        f.render_stateful_widget(list, body[0], &mut state);

        let detail = Paragraph::new(ctx.task_detail_lines.to_vec()).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Tasks))
                .title("Detail / Preview"),
        );
        f.render_widget(detail.scroll((ctx.detail_scroll, 0)), body[1]);
        return;
    }

    let mut state = ratatui::widgets::ListState::default();
    state.select(if ctx.tasks.is_empty() {
        None
    } else {
        Some(ctx.task_selected.min(ctx.tasks.len().saturating_sub(1)))
    });
    let title = if ctx.tasks.is_empty() {
        "Tasks (compact)"
    } else {
        "Tasks (compact, height too small for detail)"
    };
    let list = List::new(ctx.task_compact_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Tasks))
                .title(title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
}
