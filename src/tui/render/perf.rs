use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::RenderCtx;

pub(super) fn draw_perf_panel(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    if ctx.zellij_managed {
        return;
    }
    if area.width < 24 || area.height < 6 {
        return;
    }
    let w = 28.min(area.width.saturating_sub(2));
    let h = 5.min(area.height.saturating_sub(2));
    let x = area.x + area.width.saturating_sub(w).saturating_sub(1);
    let y = area.y + 1;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };

    let cpu = ctx
        .perf_cpu_pct
        .map(|v| format!("{v:>5.1}%"))
        .unwrap_or_else(|| "  --.-%".to_string());
    let mem = if ctx.perf_mem_total_mb > 0 {
        format!("{}/{}MB", ctx.perf_mem_used_mb, ctx.perf_mem_total_mb)
    } else {
        "--/--MB".to_string()
    };
    let rss = if ctx.perf_proc_rss_mb > 0 {
        format!("{}MB", ctx.perf_proc_rss_mb)
    } else {
        "--MB".to_string()
    };
    let load = if ctx.perf_loadavg.is_empty() {
        "-".to_string()
    } else {
        ctx.perf_loadavg.to_string()
    };

    let lines = vec![
        Line::from(format!("CPU  {}", cpu)),
        Line::from(format!("MEM  {}", mem)),
        Line::from(format!("RSS  {}", rss)),
        Line::from(format!("LOAD {}", load)),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .title("PERF");
    let widget = Paragraph::new(lines).block(block);
    f.render_widget(Clear, rect);
    f.render_widget(widget, rect);
}
