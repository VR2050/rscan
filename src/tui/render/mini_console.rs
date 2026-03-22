use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs};

use super::RenderCtx;
use crate::tui::models::MiniConsoleLayout;
use crate::tui::view::mini_console_rect_for_layout;

pub(super) fn draw_mini_console(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if !ctx.mini_console_visible {
        return;
    }

    let dock = mini_console_rect_for_layout(
        area,
        ctx.mini_console_layout,
        ctx.mini_float_x_pct,
        ctx.mini_float_y_pct,
        ctx.mini_float_w_pct,
        ctx.mini_float_h_pct,
    );
    let console_title = if ctx.zellij_managed {
        "Aux / Runtime"
    } else {
        "Console / Logs"
    };
    let title = if ctx.mini_console_layout == MiniConsoleLayout::Floating {
        format!(
            "{} [{}{} x={} y={} w={} h={}]",
            console_title,
            ctx.mini_console_layout.label(),
            if ctx.mini_popup_mode { " popup" } else { "" },
            ctx.mini_float_x_pct,
            ctx.mini_float_y_pct,
            ctx.mini_float_w_pct,
            ctx.mini_float_h_pct
        )
    } else {
        format!("{console_title} [{}]", ctx.mini_console_layout.label())
    };
    let border_style = if ctx.mini_console_layout == MiniConsoleLayout::Floating {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
        .split(dock);
    let content_inner_h = sections[1].height.saturating_sub(2) as usize;
    let max_scroll = ctx
        .mini_console_lines
        .len()
        .saturating_sub(content_inner_h.max(1))
        .min(u16::MAX as usize) as u16;
    let render_scroll = ctx.mini_console_scroll.min(max_scroll);
    let terminal_tab = if ctx.zellij_managed {
        "Zellij"
    } else {
        "Terminal"
    };
    let tabs = Tabs::new(vec!["Output", terminal_tab, "Problems"])
        .select(ctx.mini_console_tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    let widget = Paragraph::new(ctx.mini_console_lines.to_vec()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title("Content"),
    );
    f.render_widget(Clear, dock);
    f.render_widget(tabs, sections[0]);
    f.render_widget(widget.scroll((render_scroll, 0)), sections[1]);
}
