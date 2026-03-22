use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListState, Paragraph};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_results(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if is_compact(area) {
        draw_results_compact(f, area, ctx);
        return;
    }
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)].as_ref())
        .split(area);

    let mut state = ListState::default();
    state.select(if ctx.result_indices.is_empty() {
        None
    } else {
        Some(
            ctx.result_selected
                .min(ctx.result_indices.len().saturating_sub(1)),
        )
    });
    let list_title = if ctx.zellij_managed {
        "Execution Tasks [f=kind o=order /=search L=logs W=shell A=artifacts]"
    } else {
        "Execution Tasks"
    };
    let list = List::new(ctx.result_list_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Results))
                .title(list_title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut state);

    let detail = Paragraph::new(ctx.result_detail_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Results))
            .title(if ctx.zellij_managed {
                "Module Execution Effect / Native Ops"
            } else {
                "Module Execution Effect"
            }),
    );
    f.render_widget(detail.scroll((ctx.effect_scroll, 0)), body[1]);
}

fn is_compact(area: Rect) -> bool {
    area.width < 70 || area.height < 10
}

fn draw_results_compact(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let mut state = ListState::default();
    state.select(if ctx.result_indices.is_empty() {
        None
    } else {
        Some(
            ctx.result_selected
                .min(ctx.result_indices.len().saturating_sub(1)),
        )
    });
    let list = List::new(ctx.result_list_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Results))
                .title("Results (compact)"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, area, &mut state);
}
