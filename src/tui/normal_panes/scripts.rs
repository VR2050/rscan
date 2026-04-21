use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::script_runtime::{
    open_script_in_helix, save_current_script, start_script_runner, start_script_task,
    switch_script_selection,
};

pub(super) fn handle_scripts_key(
    key: KeyCode,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    fn open_in_helix(ctx: &mut PaneNormalCtx<'_>) -> PaneNormalAction {
        if ctx.scripts.is_empty() {
            *ctx.status_line = "没有可编辑的脚本".to_string();
            return PaneNormalAction::Handled;
        }
        if *ctx.script_dirty {
            match save_current_script(ctx.scripts, *ctx.script_selected, ctx.script_buffer) {
                Ok(msg) => {
                    *ctx.script_dirty = false;
                    *ctx.status_line = msg;
                }
                Err(e) => {
                    *ctx.status_line = format!("自动保存失败，已取消打开 Helix: {}", e);
                    return PaneNormalAction::Handled;
                }
            }
        }
        if let Some(path) = ctx.scripts.get(*ctx.script_selected) {
            match open_script_in_helix(path, ctx.current_project) {
                Ok(msg) => *ctx.status_line = msg,
                Err(err) => *ctx.status_line = format!("打开 Helix 失败: {}", err),
            }
        }
        PaneNormalAction::Handled
    }

    match key {
        KeyCode::Up => {
            if !ctx.scripts.is_empty() {
                let next = ctx.script_selected.saturating_sub(1);
                switch_script_selection(
                    next,
                    ctx.scripts,
                    ctx.script_selected,
                    ctx.script_buffer,
                    ctx.script_dirty,
                    ctx.status_line,
                );
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Down => {
            if !ctx.scripts.is_empty() {
                let next = (*ctx.script_selected + 1).min(ctx.scripts.len().saturating_sub(1));
                switch_script_selection(
                    next,
                    ctx.scripts,
                    ctx.script_selected,
                    ctx.script_buffer,
                    ctx.script_dirty,
                    ctx.status_line,
                );
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('N') | KeyCode::Char('n') => {
            ctx.script_new_buffer.clear();
            *ctx.input_mode = InputMode::ScriptNewInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('i') | KeyCode::Char('I') => Ok(open_in_helix(ctx)),
        KeyCode::Char('S') | KeyCode::Char('s') => {
            if ctx.scripts.is_empty() {
                *ctx.status_line = "没有可保存的脚本".to_string();
            } else {
                match save_current_script(ctx.scripts, *ctx.script_selected, ctx.script_buffer) {
                    Ok(msg) => {
                        *ctx.script_dirty = false;
                        *ctx.status_line = msg;
                    }
                    Err(e) => {
                        *ctx.status_line = format!("save failed: {}", e);
                    }
                }
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('R') | KeyCode::Char('r') => {
            if *ctx.script_running {
                *ctx.status_line = "已有脚本正在运行".to_string();
                return Ok(PaneNormalAction::Handled);
            }
            if ctx.scripts.is_empty() {
                *ctx.status_line = "没有脚本可运行".to_string();
                return Ok(PaneNormalAction::Handled);
            }
            if *ctx.script_dirty {
                match save_current_script(ctx.scripts, *ctx.script_selected, ctx.script_buffer) {
                    Ok(_) => *ctx.script_dirty = false,
                    Err(e) => {
                        *ctx.status_line = format!("自动保存失败，已取消运行: {}", e);
                        return Ok(PaneNormalAction::ContinueLoop);
                    }
                }
            }
            if let Some(path) = ctx.scripts.get(*ctx.script_selected) {
                *ctx.script_task = start_script_task(ctx.current_project, path).ok();
                *ctx.script_runner_rx = Some(start_script_runner(
                    path.clone(),
                    ctx.script_task.as_ref().map(|task| task.dir.clone()),
                ));
                *ctx.script_running = true;
                *ctx.status_line = format!("running script: {}", path.display());
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('H') | KeyCode::Char('h') => Ok(open_in_helix(ctx)),
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
