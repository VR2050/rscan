use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
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
    let list_title = "Results";
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
                "Impact / Signals / Native Ops"
            } else {
                "Impact / Signals"
            }),
    );
    f.render_widget(detail.scroll((ctx.effect_scroll, 0)), body[1]);
}

fn is_compact(area: Rect) -> bool {
    area.width < 70 || area.height < 10
}

fn draw_results_compact(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if area.height >= 6 {
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
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
        f.render_stateful_widget(list, body[0], &mut state);

        let detail = Paragraph::new(ctx.result_detail_lines.to_vec()).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Results))
                .title("Impact / Preview"),
        );
        f.render_widget(detail.scroll((ctx.effect_scroll, 0)), body[1]);
        return;
    }

    let mut state = ListState::default();
    state.select(if ctx.result_indices.is_empty() {
        None
    } else {
        Some(
            ctx.result_selected
                .min(ctx.result_indices.len().saturating_sub(1)),
        )
    });
    let title = if ctx.result_indices.is_empty() {
        "Results (compact)".to_string()
    } else {
        let tiny_hint = compact_detail_hint(ctx.result_detail_lines);
        if tiny_hint.is_empty() {
            "Results (compact, enlarge terminal for detail pane)".to_string()
        } else {
            format!("Results (compact) | {}", truncate_for_title(&tiny_hint, 44))
        }
    };
    let list = List::new(ctx.result_list_items.to_vec())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(pane_border_style(ctx, MainPane::Results))
                .title(title.as_str()),
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

fn compact_detail_hint(lines: &[Line<'_>]) -> String {
    let candidates = lines
        .iter()
        .map(line_plain_text)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>();

    if let Some(hit) = candidates.iter().find(|text| is_key_finding_line(text)) {
        return hit.clone();
    }

    candidates
        .into_iter()
        .find(|text| !is_section_header_line(text))
        .unwrap_or_default()
}

fn line_plain_text(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>()
}

fn truncate_for_title(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out = input
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn is_key_finding_line(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("open ports:")
        || lower.contains("services:")
        || lower.contains("ports=")
        || lower.contains("service=")
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("matched=")
        || lower.contains("cve-")
        || lower.contains("errors=")
        || lower.contains("networkerror")
        || lower.starts_with("error ")
        || lower.starts_with("err ")
}

fn is_section_header_line(text: &str) -> bool {
    if !text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == ' ' || ch == '/' || ch == '-')
    {
        return false;
    }
    matches!(
        text,
        "Result View"
            | "Execution Summary"
            | "Module Signals"
            | "Key Findings"
            | "Recent Events"
            | "Native Ops"
            | "Stdout Tail"
            | "Stderr Tail"
            | "Artifact Preview"
            | "Runtime"
            | "Result Diagnosis"
            | "Task Summary"
    )
}
