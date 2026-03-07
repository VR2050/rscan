use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use super::RenderCtx;
use crate::tui::view::build_dashboard_lines;

pub(super) fn draw_dashboard(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let lines = build_dashboard_lines(ctx.all_tasks);
    let w = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Dashboard"));
    f.render_widget(w, area);
}
