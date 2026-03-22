use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListState, Paragraph};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_launcher(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

    let mut list_state = ListState::default();
    list_state.select(Some(
        ctx.launcher_selected
            .min(ctx.launcher_items.len().saturating_sub(1)),
    ));
    let list = List::new(ctx.launcher_list_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Launcher))
                .title("Launcher"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut list_state);

    let p = Paragraph::new(ctx.launcher_detail_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Launcher))
            .title("Detail"),
    );
    f.render_widget(p, body[1]);
}
