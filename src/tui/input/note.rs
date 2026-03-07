use crossterm::event::KeyCode;

use super::NonNormalInputCtx;
use crate::cores::engine::task::{
    EventKind, TaskEvent, append_task_event, now_epoch_secs, write_task_meta,
};
use crate::tui::models::InputMode;

pub(super) fn handle_note_input(key: KeyCode, ctx: &mut NonNormalInputCtx<'_>) {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.note_buffer.clear();
        }
        KeyCode::Enter => {
            if let Some(cur) = ctx.tasks.get_mut(*ctx.task_selected) {
                let mut meta = cur.meta.clone();
                let existing = meta.note.clone().unwrap_or_default();
                let new_note = if existing.is_empty() {
                    ctx.note_buffer.clone()
                } else {
                    format!("{existing}\n{}", ctx.note_buffer)
                };
                meta.note = Some(new_note);
                let _ = write_task_meta(&cur.dir, &meta);
                let ev = TaskEvent {
                    ts: now_epoch_secs(),
                    level: "info".to_string(),
                    kind: EventKind::Control,
                    message: Some(format!("note: {}", ctx.note_buffer)),
                    data: None,
                };
                let _ = append_task_event(&cur.dir, &ev);
                cur.meta = meta;
            }
            *ctx.input_mode = InputMode::Normal;
            ctx.note_buffer.clear();
        }
        KeyCode::Backspace => {
            ctx.note_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.note_buffer.push(c);
        }
        _ => {}
    }
}
