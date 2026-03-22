use super::super::NonNormalInputCtx;

pub(super) fn clamp_cursor(ctx: &mut NonNormalInputCtx<'_>) {
    *ctx.cmd_cursor = (*ctx.cmd_cursor).min(ctx.cmd_buffer.len());
    while *ctx.cmd_cursor > 0 && !ctx.cmd_buffer.is_char_boundary(*ctx.cmd_cursor) {
        *ctx.cmd_cursor -= 1;
    }
}

pub(super) fn prev_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    if i == 0 {
        return 0;
    }
    i -= 1;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

pub(super) fn next_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    if i >= s.len() {
        return s.len();
    }
    i += 1;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

pub(super) fn push_undo(ctx: &mut NonNormalInputCtx<'_>) {
    ctx.cmd_undo_stack
        .push((ctx.cmd_buffer.clone(), *ctx.cmd_cursor));
    if ctx.cmd_undo_stack.len() > 200 {
        ctx.cmd_undo_stack.remove(0);
    }
    ctx.cmd_redo_stack.clear();
}

pub(super) fn undo(ctx: &mut NonNormalInputCtx<'_>) {
    if let Some((prev_buf, prev_cursor)) = ctx.cmd_undo_stack.pop() {
        ctx.cmd_redo_stack
            .push((ctx.cmd_buffer.clone(), *ctx.cmd_cursor));
        *ctx.cmd_buffer = prev_buf;
        *ctx.cmd_cursor = prev_cursor.min(ctx.cmd_buffer.len());
        clamp_cursor(ctx);
        *ctx.status_line = "undo".to_string();
    }
}

pub(super) fn redo(ctx: &mut NonNormalInputCtx<'_>) {
    if let Some((next_buf, next_cursor)) = ctx.cmd_redo_stack.pop() {
        ctx.cmd_undo_stack
            .push((ctx.cmd_buffer.clone(), *ctx.cmd_cursor));
        *ctx.cmd_buffer = next_buf;
        *ctx.cmd_cursor = next_cursor.min(ctx.cmd_buffer.len());
        clamp_cursor(ctx);
        *ctx.status_line = "redo".to_string();
    }
}

pub(super) fn insert_char_at_cursor(ctx: &mut NonNormalInputCtx<'_>, c: char) {
    ctx.cmd_buffer.insert(*ctx.cmd_cursor, c);
    *ctx.cmd_cursor += c.len_utf8();
}

pub(super) fn insert_str_at_cursor(ctx: &mut NonNormalInputCtx<'_>, text: &str) {
    let sanitized = text.replace("\r\n", "\n").replace('\r', "\n");
    ctx.cmd_buffer.insert_str(*ctx.cmd_cursor, &sanitized);
    *ctx.cmd_cursor += sanitized.len();
}

pub(super) fn push_history(ctx: &mut NonNormalInputCtx<'_>, cmd: &str) {
    if ctx.cmd_history.last().is_some_and(|last| last == cmd) {
        return;
    }
    ctx.cmd_history.push(cmd.to_string());
    if ctx.cmd_history.len() > 200 {
        ctx.cmd_history.remove(0);
    }
}

pub(super) fn reset_history_nav(ctx: &mut NonNormalInputCtx<'_>) {
    *ctx.cmd_history_idx = None;
    ctx.cmd_history_scratch.take();
}

pub(super) fn history_prev(ctx: &mut NonNormalInputCtx<'_>) {
    if ctx.cmd_history.is_empty() {
        return;
    }
    let next_idx = match *ctx.cmd_history_idx {
        None => {
            *ctx.cmd_history_scratch = Some(ctx.cmd_buffer.clone());
            ctx.cmd_history.len().saturating_sub(1)
        }
        Some(idx) => idx.saturating_sub(1),
    };
    *ctx.cmd_history_idx = Some(next_idx);
    apply_history_entry(ctx, next_idx);
}

pub(super) fn history_next(ctx: &mut NonNormalInputCtx<'_>) {
    let Some(idx) = *ctx.cmd_history_idx else {
        return;
    };
    let next_idx = idx + 1;
    if next_idx < ctx.cmd_history.len() {
        *ctx.cmd_history_idx = Some(next_idx);
        apply_history_entry(ctx, next_idx);
        return;
    }
    *ctx.cmd_history_idx = None;
    if let Some(scratch) = ctx.cmd_history_scratch.take() {
        *ctx.cmd_buffer = scratch;
    } else {
        ctx.cmd_buffer.clear();
    }
    *ctx.cmd_cursor = ctx.cmd_buffer.len();
    clamp_cursor(ctx);
}

fn apply_history_entry(ctx: &mut NonNormalInputCtx<'_>, idx: usize) {
    if let Some(cmd) = ctx.cmd_history.get(idx) {
        *ctx.cmd_buffer = cmd.clone();
        *ctx.cmd_cursor = ctx.cmd_buffer.len();
        clamp_cursor(ctx);
    }
}
