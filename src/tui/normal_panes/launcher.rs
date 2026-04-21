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
                let exec = execute_short_command(ctx.current_project, cmd);
                *ctx.status_line = exec.status_line;
                *ctx.all_tasks = load_tasks(ctx.current_project.clone())?;
                *ctx.tasks = apply_filter(ctx.all_tasks, *ctx.filter);
                if let Some(task_id) = exec.task_id.as_deref() {
                    *ctx.result_selected = 0;
                    if let Some(pos) = ctx.tasks.iter().position(|task| task.meta.id == task_id) {
                        *ctx.task_selected = pos;
                    } else {
                        *ctx.task_selected =
                            (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
                    }
                } else {
                    *ctx.task_selected =
                        (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
                    *ctx.result_selected = 0;
                }
            }
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
