use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::RenderCtx;
use crate::tui::view::{build_effect_lines, line_s};

pub(super) fn draw_results(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)].as_ref())
        .split(area);

    let items = if ctx.result_indices.is_empty() {
        vec![ListItem::new("<empty>")]
    } else {
        ctx.result_indices
            .iter()
            .map(|&idx| {
                let t = &ctx.all_tasks[idx];
                ListItem::new(format!("[{}] {} {}", t.meta.status, t.meta.kind, t.meta.id))
            })
            .collect::<Vec<_>>()
    };
    let mut state = ListState::default();
    state.select(if ctx.result_indices.is_empty() {
        None
    } else {
        Some(
            ctx.result_selected
                .min(ctx.result_indices.len().saturating_sub(1)),
        )
    });
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Execution Tasks"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut state);

    let lines = ctx
        .result_indices
        .get(ctx.result_selected)
        .and_then(|idx| ctx.all_tasks.get(*idx))
        .map(|cur| {
            let mut lines = build_effect_lines(cur);
            lines.push(line_s(""));
            lines.push(line_s(&format!(
                "view: filter={} sort={}",
                ctx.result_kind_filter.label(),
                if ctx.result_failed_first {
                    "failed-first"
                } else {
                    "created-desc"
                }
            )));
            lines.push(line_s("快捷键: f=模块过滤  o=失败优先排序"));
            lines.push(line_s(&format!(
                "query: {}",
                if ctx.result_query.is_empty() {
                    "<none>"
                } else {
                    ctx.result_query
                }
            )));
            lines.push(line_s("快捷键: /=搜索  x=清空搜索"));
            lines
        })
        .unwrap_or_else(|| vec![line_s("无执行效果数据")]);
    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Module Execution Effect"),
    );
    f.render_widget(detail.scroll((ctx.effect_scroll, 0)), body[1]);
}
