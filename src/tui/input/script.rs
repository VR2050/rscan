use crossterm::event::KeyCode;

use super::NonNormalInputCtx;
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::script_runtime::{create_script_file, load_script_files, read_script_text};

pub(super) fn handle_script_new_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.script_new_buffer.clear();
        }
        KeyCode::Enter => {
            let name = ctx.script_new_buffer.trim().to_string();
            if name.is_empty() {
                *ctx.status_line = "文件名不能为空".to_string();
            } else {
                match create_script_file(ctx.scripts_dir, &name) {
                    Ok(path) => {
                        *ctx.scripts = load_script_files(ctx.scripts_dir)?;
                        if let Some(pos) = ctx.scripts.iter().position(|p| p == &path) {
                            *ctx.script_selected = pos;
                        } else {
                            *ctx.script_selected = ctx.scripts.len().saturating_sub(1);
                        }
                        *ctx.script_buffer = read_script_text(&path);
                        *ctx.script_dirty = false;
                        *ctx.status_line = format!("created script: {}", path.display());
                    }
                    Err(e) => {
                        *ctx.status_line = format!("create script failed: {}", e);
                    }
                }
            }
            ctx.script_new_buffer.clear();
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.script_new_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.script_new_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}
