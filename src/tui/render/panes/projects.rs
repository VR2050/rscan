use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::RenderCtx;
use crate::tui::view::line_s;

pub(super) fn draw_projects(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)].as_ref())
        .split(area);

    let items = if ctx.projects.is_empty() {
        vec![ListItem::new("<empty>")]
    } else {
        ctx.projects
            .iter()
            .map(|p| {
                let mark = if p.imported { "import" } else { "local" };
                ListItem::new(format!("[{}] {}", mark, p.name))
            })
            .collect::<Vec<_>>()
    };
    let mut state = ListState::default();
    state.select(if ctx.projects.is_empty() {
        None
    } else {
        Some(
            ctx.project_selected
                .min(ctx.projects.len().saturating_sub(1)),
        )
    });
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Projects"))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    f.render_stateful_widget(list, body[0], &mut state);

    let mut lines = vec![
        line_s("项目管理"),
        line_s("Enter: 切换项目"),
        line_s("N: 新建项目   I: 导入项目   D: 删除/移除项目"),
        line_s("C: 复制项目   M: 重命名项目   E: 导出项目快照"),
        line_s("T: 切换新建项目模板"),
        line_s(""),
        line_s(&format!("new-template: {}", ctx.project_template.label())),
        line_s(""),
    ];
    if let Some(p) = ctx.projects.get(ctx.project_selected) {
        lines.push(line_s(&format!("name: {}", p.name)));
        lines.push(line_s(&format!(
            "type: {}",
            if p.imported { "imported" } else { "local" }
        )));
        lines.push(line_s(&format!("path: {}", p.path.display())));
        lines.push(line_s(&format!(
            "active: {}",
            if p.path == *ctx.current_project {
                "yes"
            } else {
                "no"
            }
        )));
    } else {
        lines.push(line_s("<no project>"));
    }
    let detail = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Project Detail"),
    );
    f.render_widget(detail, body[1]);
}
