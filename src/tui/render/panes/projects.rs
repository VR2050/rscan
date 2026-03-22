use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListState, Paragraph};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_projects(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)].as_ref())
        .split(area);

    let mut state = ListState::default();
    state.select(if ctx.projects.is_empty() {
        None
    } else {
        Some(
            ctx.project_selected
                .min(ctx.projects.len().saturating_sub(1)),
        )
    });
    let list = List::new(ctx.project_list_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Projects))
                .title("Projects"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut state);

    let detail = Paragraph::new(ctx.project_detail_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Projects))
            .title("Project Detail"),
    );
    f.render_widget(detail, body[1]);
}
