use crossterm::event::KeyCode;

use super::NonNormalInputCtx;
use crate::tui::models::InputMode;

pub(super) fn handle_result_search_input(key: KeyCode, ctx: &mut NonNormalInputCtx<'_>) {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.result_search_buffer.clear();
        }
        KeyCode::Enter => {
            *ctx.result_query = ctx.result_search_buffer.trim().to_string();
            *ctx.result_selected = 0;
            *ctx.effect_scroll = 0;
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.result_search_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.result_search_buffer.push(c);
        }
        _ => {}
    }
}
