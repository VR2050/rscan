use crossterm::event::KeyCode;

use super::NonNormalInputCtx;
use crate::errors::RustpenError;
use crate::tui::command_exec::execute_short_command;
use crate::tui::models::InputMode;
use crate::tui::task_store::{apply_filter, load_tasks};

pub(super) fn handle_command_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.cmd_buffer.clear();
        }
        KeyCode::Enter => {
            *ctx.status_line = execute_short_command(ctx.current_project, ctx.cmd_buffer);
            *ctx.input_mode = InputMode::Normal;
            ctx.cmd_buffer.clear();

            *ctx.all_tasks = load_tasks(ctx.current_project.join("tasks"))?;
            *ctx.tasks = apply_filter(ctx.all_tasks, ctx.filter);
            *ctx.task_selected = (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
            *ctx.result_selected =
                (*ctx.result_selected).min(ctx.all_tasks.len().saturating_sub(1));
        }
        KeyCode::Backspace => {
            ctx.cmd_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.cmd_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}
