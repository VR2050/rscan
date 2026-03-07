use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::models::{InputMode, MainPane, TaskTab};

pub(super) fn handle_results_key(
    key: KeyCode,
    pane: &mut MainPane,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match key {
        KeyCode::Up => {
            if !ctx.result_indices.is_empty() {
                *ctx.result_selected = ctx.result_selected.saturating_sub(1);
                *ctx.effect_scroll = 0;
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Down => {
            if !ctx.result_indices.is_empty() {
                *ctx.result_selected =
                    (*ctx.result_selected + 1).min(ctx.result_indices.len().saturating_sub(1));
                *ctx.effect_scroll = 0;
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::PageDown => {
            *ctx.effect_scroll = ctx.effect_scroll.saturating_add(5);
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::PageUp => {
            *ctx.effect_scroll = ctx.effect_scroll.saturating_sub(5);
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('f') => {
            *ctx.result_kind_filter = ctx.result_kind_filter.next();
            *ctx.result_selected = 0;
            *ctx.effect_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('o') => {
            *ctx.result_failed_first = !*ctx.result_failed_first;
            *ctx.result_selected = 0;
            *ctx.effect_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('/') => {
            *ctx.result_search_buffer = ctx.result_query.clone();
            *ctx.input_mode = InputMode::ResultSearchInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('x') => {
            ctx.result_query.clear();
            *ctx.result_selected = 0;
            *ctx.effect_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Enter => {
            if let Some(idx) = ctx.result_indices.get(*ctx.result_selected)
                && let Some(cur) = ctx.all_tasks.get(*idx)
                && let Some(pos) = ctx.tasks.iter().position(|t| t.meta.id == cur.meta.id)
            {
                *ctx.task_selected = pos;
                *pane = MainPane::Tasks;
                *ctx.task_tab = TaskTab::Logs;
                *ctx.detail_scroll = 0;
                *ctx.status_line = format!("已定位到任务: {}", cur.meta.id);
            }
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
