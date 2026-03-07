use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::RenderCtx;

pub(super) fn draw_scripts(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)].as_ref())
        .split(area);

    let file_items = if ctx.scripts.is_empty() {
        vec![ListItem::new("<empty> (N 创建新脚本)")]
    } else {
        ctx.scripts
            .iter()
            .map(|p| {
                ListItem::new(
                    p.file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| p.display().to_string()),
                )
            })
            .collect::<Vec<_>>()
    };
    let mut state = ListState::default();
    state.select(if ctx.scripts.is_empty() {
        None
    } else {
        Some(ctx.script_selected.min(ctx.scripts.len().saturating_sub(1)))
    });
    let list = List::new(file_items)
        .block(Block::default().borders(Borders::ALL).title("Scripts"))
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
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(body[1]);

    let mut title = "Editor".to_string();
    if let Some(path) = ctx.scripts.get(ctx.script_selected) {
        title = format!(
            "Editor: {}{}",
            path.display(),
            if ctx.script_dirty { " *" } else { "" }
        );
    }
    let editor = Paragraph::new(ctx.script_buffer)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(editor, right[0]);

    let out_text = if ctx.script_output.is_empty() {
        "<empty output>".to_string()
    } else {
        ctx.script_output.join("\n")
    };
    let out = Paragraph::new(out_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Output / Logs"),
    );
    f.render_widget(out, right[1]);
}
