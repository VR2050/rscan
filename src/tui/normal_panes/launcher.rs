use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::command_exec::execute_short_command;
use crate::tui::task_store::{apply_filter, load_tasks};

pub(super) fn handle_launcher_key(
    key: KeyCode,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match key {
        KeyCode::Up => {
            *ctx.launcher_selected = ctx.launcher_selected.saturating_sub(1);
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Down => {
            *ctx.launcher_selected =
                (*ctx.launcher_selected + 1).min(ctx.launcher_items.len().saturating_sub(1));
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Enter => {
            if let Some((_, cmd)) = ctx.launcher_items.get(*ctx.launcher_selected) {
                *ctx.status_line = execute_short_command(ctx.current_project, cmd);
                *ctx.all_tasks = load_tasks(ctx.current_project.clone())?;
                *ctx.tasks = apply_filter(ctx.all_tasks, *ctx.filter);
                *ctx.result_selected =
                    (*ctx.result_selected).min(ctx.all_tasks.len().saturating_sub(1));
            }
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
