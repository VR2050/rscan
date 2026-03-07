use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs};

use super::RenderCtx;
use crate::tui::models::MiniConsoleLayout;
use crate::tui::view::{build_mini_console_lines, mini_console_rect_for_layout};

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
    let mini_lines = build_mini_console_lines(
        ctx.mini_console_tab,
        ctx.pane,
        ctx.all_tasks,
        ctx.tasks,
        ctx.task_selected,
        ctx.result_indices,
        ctx.result_selected,
        ctx.script_output,
        ctx.mini_terminal_lines,
        ctx.status_line,
    );
    let title = if ctx.mini_console_layout == MiniConsoleLayout::Floating {
        format!(
            "Console / Logs [{}{} x={} y={} w={} h={}]",
            ctx.mini_console_layout.label(),
            if ctx.mini_popup_mode { " popup" } else { "" },
            ctx.mini_float_x_pct,
            ctx.mini_float_y_pct,
            ctx.mini_float_w_pct,
            ctx.mini_float_h_pct
        )
    } else {
        format!("Console / Logs [{}]", ctx.mini_console_layout.label())
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
    let max_scroll = mini_lines
        .len()
        .saturating_sub(content_inner_h.max(1))
        .min(u16::MAX as usize) as u16;
    let render_scroll = ctx.mini_console_scroll.min(max_scroll);
    let tabs = Tabs::new(vec!["Output", "Terminal", "Problems"])
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
    let widget = Paragraph::new(mini_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title("Content"),
    );
    f.render_widget(Clear, dock);
    f.render_widget(tabs, sections[0]);
    f.render_widget(widget.scroll((render_scroll, 0)), sections[1]);
}
