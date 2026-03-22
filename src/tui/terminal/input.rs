pub(crate) fn key_event_to_bytes(key: crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    use crossterm::event::{KeyCode, KeyModifiers};

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                if c.is_ascii_alphabetic() {
                    let value = (c.to_ascii_uppercase() as u8) - 0x40;
                    return Some(vec![value]);
                }
                if c == ' ' {
                    return Some(vec![0]);
                }
            }
            Some(c.to_string().into_bytes())
        }
        KeyCode::Enter => Some(vec![b'\n']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        _ => None,
    }
}

pub(crate) fn mouse_event_to_bytes(
    session: &super::TerminalSession,
    kind: crossterm::event::MouseEventKind,
    modifiers: crossterm::event::KeyModifiers,
    col: u16,
    row: u16,
) -> Option<Vec<u8>> {
    use alacritty_terminal::term::TermMode;

    if !session.term.mode().contains(TermMode::MOUSE_MODE)
        && !session.term.mode().contains(TermMode::SGR_MOUSE)
        && !session.term.mode().contains(TermMode::UTF8_MOUSE)
    {
        return None;
    }

    let mut cb = 0u8;
    if modifiers.contains(crossterm::event::KeyModifiers::SHIFT) {
        cb |= 4;
    }
    if modifiers.contains(crossterm::event::KeyModifiers::ALT) {
        cb |= 8;
    }
    if modifiers.contains(crossterm::event::KeyModifiers::CONTROL) {
        cb |= 16;
    }

    let (code, is_release) = match kind {
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left) => (0, false),
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Middle) => (1, false),
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Right) => (2, false),
        crossterm::event::MouseEventKind::Up(_) => (0, true),
        crossterm::event::MouseEventKind::Drag(crossterm::event::MouseButton::Left) => (32, false),
        crossterm::event::MouseEventKind::Drag(crossterm::event::MouseButton::Middle) => {
            (33, false)
        }
        crossterm::event::MouseEventKind::Drag(crossterm::event::MouseButton::Right) => (34, false),
        crossterm::event::MouseEventKind::ScrollUp => (64, false),
        crossterm::event::MouseEventKind::ScrollDown => (65, false),
        _ => return None,
    };

    cb |= code;
    let x = col.saturating_add(1);
    let y = row.saturating_add(1);
    let suffix = if is_release { 'm' } else { 'M' };
    Some(format!("\x1b[<{};{};{}{}", cb, x, y, suffix).into_bytes())
}
