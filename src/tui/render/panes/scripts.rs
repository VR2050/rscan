use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListState, Paragraph};

use super::{RenderCtx, pane_border_style};
use crate::tui::models::MainPane;

pub(super) fn draw_scripts(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(24), Constraint::Percentage(76)].as_ref())
        .split(area);

    let mut state = ListState::default();
    state.select(if ctx.scripts.is_empty() {
        None
    } else {
        Some(ctx.script_selected.min(ctx.scripts.len().saturating_sub(1)))
    });
    let list = List::new(ctx.script_file_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Scripts))
                .title("Scripts"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(7)].as_ref())
        .split(body[1]);

    let mut title = "Edit".to_string();
    if let Some(path) = ctx.scripts.get(ctx.script_selected) {
        title = format!(
            "Edit: {}{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("<unknown>"),
            if ctx.script_dirty { " *" } else { "" }
        );
    }
    let editor = Paragraph::new(ctx.script_buffer).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Scripts))
            .title(title),
    );
    f.render_widget(editor, right[0]);

    let tail = if ctx.script_output_lines.is_empty() {
        vec![
            Line::from("N:new(.rs)  I/H:helix  S:save  R:run"),
            Line::from("日志为空"),
        ]
    } else {
        ctx.script_output_lines
            .iter()
            .rev()
            .take(5)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
    };
    let out = Paragraph::new(tail).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pane_border_style(ctx, MainPane::Scripts))
            .title("Run Log (tail)"),
    );
    f.render_widget(out, right[1]);
}
