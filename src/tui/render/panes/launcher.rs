use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::RenderCtx;

pub(super) fn draw_launcher(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)].as_ref())
        .split(area);

    let items = ctx
        .launcher_items
        .iter()
        .map(|item| ListItem::new(item.0))
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    list_state.select(Some(
        ctx.launcher_selected
            .min(ctx.launcher_items.len().saturating_sub(1)),
    ));
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Launcher"))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut list_state);

    let mut desc = vec![
        Line::from("内置快捷任务（Enter 执行）"),
        Line::from("命令会以新的 rscan 进程启动，并写入 task/workspace"),
        Line::from(""),
    ];
    if let Some((_, cmd)) = ctx.launcher_items.get(ctx.launcher_selected) {
        desc.push(Line::from(Span::styled(
            "command:",
            Style::default().fg(Color::Yellow),
        )));
        desc.push(Line::from(cmd.to_string()));
    }
    desc.push(Line::from(""));
    desc.push(Line::from("支持模块: host / web / vuln / reverse"));
    desc.push(Line::from(
        "按 : 进入命令模式可手动输入 (h.quick|h.tcp|w.dir|w.fuzz|w.dns|v.scan|r.analyze|r.plan)",
    ));
    let p = Paragraph::new(desc).block(Block::default().borders(Borders::ALL).title("Detail"));
    f.render_widget(p, body[1]);
}
