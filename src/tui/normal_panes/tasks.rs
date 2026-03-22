use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::models::{InputMode, TaskTab};
use crate::tui::task_actions::{
    open_task_artifacts_in_runtime, open_task_logs_in_runtime, open_task_shell_in_runtime,
};
use crate::tui::task_store::apply_filter;

pub(super) fn handle_tasks_key(
    key: KeyCode,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match key {
        KeyCode::Char('s') => {
            *ctx.filter = ctx.filter.next();
            *ctx.tasks = apply_filter(ctx.all_tasks, *ctx.filter);
            *ctx.task_selected = (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
            *ctx.detail_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('t') => {
            *ctx.task_tab = match *ctx.task_tab {
                TaskTab::Overview => TaskTab::Events,
                TaskTab::Events => TaskTab::Logs,
                TaskTab::Logs => TaskTab::Notes,
                TaskTab::Notes => TaskTab::Overview,
            };
            *ctx.detail_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('n') => {
            ctx.note_buffer.clear();
            *ctx.input_mode = InputMode::NoteInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('L') => {
            if let Some(task) = ctx
                .tasks
                .get(*ctx.task_selected)
                .or_else(|| ctx.all_tasks.first())
            {
                *ctx.status_line = open_task_logs_in_runtime(task);
            } else {
                *ctx.status_line = "当前没有可打开日志的任务".to_string();
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('W') => {
            if let Some(task) = ctx
                .tasks
                .get(*ctx.task_selected)
                .or_else(|| ctx.all_tasks.first())
            {
                *ctx.status_line = open_task_shell_in_runtime(task);
            } else {
                *ctx.status_line = "当前没有可打开 shell 的任务".to_string();
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('A') => {
            if let Some(task) = ctx
                .tasks
                .get(*ctx.task_selected)
                .or_else(|| ctx.all_tasks.first())
            {
                *ctx.status_line = open_task_artifacts_in_runtime(task);
            } else {
                *ctx.status_line = "当前没有可检查产物的任务".to_string();
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Enter => {
            *ctx.detail_scroll = 0;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::PageDown => {
            *ctx.detail_scroll = ctx.detail_scroll.saturating_add(5);
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::PageUp => {
            *ctx.detail_scroll = ctx.detail_scroll.saturating_sub(5);
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Up => {
            if !ctx.tasks.is_empty() {
                *ctx.task_selected = ctx.task_selected.saturating_sub(1);
                *ctx.detail_scroll = 0;
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Down => {
            if !ctx.tasks.is_empty() {
                *ctx.task_selected =
                    (*ctx.task_selected + 1).min(ctx.tasks.len().saturating_sub(1));
                *ctx.detail_scroll = 0;
            }
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
