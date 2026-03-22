use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

use super::RenderCtx;
use crate::tui::models::MainPane;

mod dashboard;
mod launcher;
mod projects;
mod results;
mod scripts;
mod tasks;

pub(super) fn draw_active_pane(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    match ctx.pane {
        MainPane::Dashboard => dashboard::draw_dashboard(f, area, ctx),
        MainPane::Tasks => tasks::draw_tasks(f, area, ctx),
        MainPane::Launcher => launcher::draw_launcher(f, area, ctx),
        MainPane::Scripts => scripts::draw_scripts(f, area, ctx),
        MainPane::Results => results::draw_results(f, area, ctx),
        MainPane::Projects => projects::draw_projects(f, area, ctx),
    }
}

pub(crate) fn draw_tasks_pane(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    tasks::draw_tasks(f, area, ctx);
}

pub(crate) fn draw_results_pane(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    results::draw_results(f, area, ctx);
}

pub(crate) fn pane_border_style(ctx: &RenderCtx<'_>, pane: MainPane) -> Style {
    if ctx.pane == pane {
        let phase = (ctx.ui_tick / 3) % 4;
        let color = match phase {
            0 => Color::Cyan,
            1 => Color::LightCyan,
            2 => Color::White,
            _ => Color::LightCyan,
        };
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}
