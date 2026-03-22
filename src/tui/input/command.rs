mod completion;
mod editing;

use arboard::Clipboard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::NonNormalInputCtx;
use crate::errors::RustpenError;
use crate::tui::command_exec::execute_short_command;
use crate::tui::models::InputMode;
use crate::tui::task_store::{apply_filter, load_tasks};

use self::completion::{clear_completion, handle_completion};
use self::editing::{
    clamp_cursor, history_next, history_prev, insert_char_at_cursor, insert_str_at_cursor,
    next_char_boundary, prev_char_boundary, push_history, push_undo, redo, reset_history_nav, undo,
};

pub(super) fn handle_command_input(
    key: KeyEvent,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    let is_ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);

    match key.code {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            reset_command_state(ctx);
        }
        KeyCode::Enter => finish_command(ctx)?,
        KeyCode::Backspace => {
            if *ctx.cmd_cursor > 0 {
                push_undo(ctx);
                let prev = prev_char_boundary(ctx.cmd_buffer, *ctx.cmd_cursor);
                ctx.cmd_buffer.drain(prev..*ctx.cmd_cursor);
                *ctx.cmd_cursor = prev;
                reset_history_nav(ctx);
                clear_completion(ctx);
            }
        }
        KeyCode::Delete => {
            if *ctx.cmd_cursor < ctx.cmd_buffer.len() {
                push_undo(ctx);
                let next = next_char_boundary(ctx.cmd_buffer, *ctx.cmd_cursor);
                ctx.cmd_buffer.drain(*ctx.cmd_cursor..next);
                reset_history_nav(ctx);
                clear_completion(ctx);
            }
        }
        KeyCode::Up => {
            clear_completion(ctx);
            history_prev(ctx);
        }
        KeyCode::Down => {
            clear_completion(ctx);
            history_next(ctx);
        }
        KeyCode::Tab => {
            handle_completion(ctx, false);
        }
        KeyCode::BackTab => {
            handle_completion(ctx, true);
        }
        KeyCode::Left => {
            *ctx.cmd_cursor = prev_char_boundary(ctx.cmd_buffer, *ctx.cmd_cursor);
        }
        KeyCode::Right => {
            *ctx.cmd_cursor = next_char_boundary(ctx.cmd_buffer, *ctx.cmd_cursor);
        }
        KeyCode::Home => {
            *ctx.cmd_cursor = 0;
        }
        KeyCode::End => {
            *ctx.cmd_cursor = ctx.cmd_buffer.len();
        }
        KeyCode::Char(c) => return handle_command_char(c, is_ctrl, is_shift, ctx),
        _ => {}
    }

    clamp_cursor(ctx);
    Ok(())
}

pub(super) fn handle_command_paste(text: &str, ctx: &mut NonNormalInputCtx<'_>) {
    if text.is_empty() {
        return;
    }
    push_undo(ctx);
    insert_str_at_cursor(ctx, text);
    reset_history_nav(ctx);
    clear_completion(ctx);
    clamp_cursor(ctx);
}

fn finish_command(ctx: &mut NonNormalInputCtx<'_>) -> Result<(), RustpenError> {
    let trimmed = ctx.cmd_buffer.trim().to_string();
    if !trimmed.is_empty() {
        push_history(ctx, &trimmed);
    }
    *ctx.status_line = execute_short_command(ctx.current_project, ctx.cmd_buffer);
    *ctx.input_mode = InputMode::Normal;
    reset_command_state(ctx);

    *ctx.all_tasks = load_tasks(ctx.current_project.clone())?;
    *ctx.tasks = apply_filter(ctx.all_tasks, ctx.filter);
    *ctx.task_selected = (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
    *ctx.result_selected = (*ctx.result_selected).min(ctx.all_tasks.len().saturating_sub(1));
    Ok(())
}

fn reset_command_state(ctx: &mut NonNormalInputCtx<'_>) {
    ctx.cmd_buffer.clear();
    *ctx.cmd_cursor = 0;
    ctx.cmd_undo_stack.clear();
    ctx.cmd_redo_stack.clear();
    reset_history_nav(ctx);
    clear_completion(ctx);
}

fn handle_command_char(
    c: char,
    is_ctrl: bool,
    is_shift: bool,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    if is_ctrl && is_shift && (c == 'c' || c == 'C') {
        *ctx.status_line = match copy_to_clipboard(ctx.cmd_buffer) {
            Ok(()) => "copied command to clipboard".to_string(),
            Err(e) => format!("copy failed: {e}"),
        };
        return Ok(());
    }
    if is_ctrl && is_shift && (c == 'v' || c == 'V') {
        match paste_from_clipboard() {
            Ok(text) => {
                handle_command_paste(&text, ctx);
                *ctx.status_line = "pasted from clipboard".to_string();
            }
            Err(e) => *ctx.status_line = format!("paste failed: {e}"),
        }
        return Ok(());
    }
    if is_ctrl && (c == 'z' || c == 'Z') {
        undo(ctx);
        clear_completion(ctx);
        return Ok(());
    }
    if is_ctrl && (c == 'y' || c == 'Y') {
        redo(ctx);
        clear_completion(ctx);
        return Ok(());
    }

    if !is_ctrl {
        push_undo(ctx);
        insert_char_at_cursor(ctx, c);
        reset_history_nav(ctx);
        clear_completion(ctx);
    }
    clamp_cursor(ctx);
    Ok(())
}

fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard
        .set_text(text.to_string())
        .map_err(|e| e.to_string())
}

fn paste_from_clipboard() -> Result<String, String> {
    let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.get_text().map_err(|e| e.to_string())
}
