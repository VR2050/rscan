use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::task_store::apply_filter;

pub(super) fn handle_dashboard_key(
    key: KeyCode,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match key {
        KeyCode::Char('s') => {
            *ctx.filter = ctx.filter.next();
            *ctx.tasks = apply_filter(ctx.all_tasks, *ctx.filter);
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
