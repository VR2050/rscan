use ratatui::Frame;
use ratatui::layout::Rect;

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
