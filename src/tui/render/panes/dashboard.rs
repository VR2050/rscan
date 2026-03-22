use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_dashboard(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let w = Paragraph::new(ctx.dashboard_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Dashboard))
            .title("Dashboard"),
    );
    f.render_widget(w, area);
}
