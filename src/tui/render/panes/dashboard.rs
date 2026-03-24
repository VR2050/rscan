use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, Paragraph, Wrap};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_dashboard(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let shell = Block::default()
        .borders(Borders::ALL)
        .border_style(pane_border_style(ctx, MainPane::Dashboard))
        .title("Dashboard");
    let inner = shell.inner(area);
    f.render_widget(shell, area);
    if inner.width < 12 || inner.height < 8 {
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(4)].as_ref())
        .split(inner);
    let stat_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ]
            .as_ref(),
        )
        .split(rows[0]);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(38)].as_ref())
        .split(rows[1]);

    draw_stat_card(
        f,
        stat_cols[0],
        "Total",
        &ctx.dashboard_total.to_string(),
        Color::White,
    );
    draw_stat_card(
        f,
        stat_cols[1],
        "Running",
        &ctx.dashboard_running.to_string(),
        Color::Yellow,
    );
    draw_stat_card(
        f,
        stat_cols[2],
        "Failed",
        &ctx.dashboard_failed.to_string(),
        Color::Red,
    );
    draw_stat_card(
        f,
        stat_cols[3],
        "Succeeded",
        &ctx.dashboard_succeeded.to_string(),
        Color::Green,
    );

    let summary = Paragraph::new(ctx.dashboard_lines.to_vec())
        .block(Block::default().title("Summary").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(summary, body[0]);

    let recent = List::new(ctx.dashboard_recent_items.to_vec()).block(
        Block::default()
            .title("Recent Activity")
            .borders(Borders::ALL),
    );
    f.render_widget(recent, body[1]);
}

fn draw_stat_card(f: &mut Frame<'_>, area: Rect, title: &str, value: &str, color: Color) {
    let widget = Paragraph::new(vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            value.to_string(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(widget, area);
}
