use std::io::{IsTerminal, Stdout, stdout};

use crossterm::event::{
    KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::errors::RustpenError;

pub(crate) type NativeReverseTerminal = Terminal<CrosstermBackend<Stdout>>;

pub(crate) fn key_event_release_supported() -> bool {
    matches!(
        crossterm::terminal::supports_keyboard_enhancement(),
        Ok(true)
    )
}

pub(crate) fn ensure_tty(name: &str) -> Result<(), RustpenError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(RustpenError::Generic(format!("{name} 需要交互式终端(tty)")));
    }
    Ok(())
}

pub(crate) fn enter_alt_terminal() -> Result<NativeReverseTerminal, RustpenError> {
    enable_raw_mode().map_err(RustpenError::Io)?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen).map_err(RustpenError::Io)?;
    if key_event_release_supported() {
        execute!(
            out,
            PushKeyboardEnhancementFlags(
                KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                    | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
            )
        )
        .map_err(RustpenError::Io)?;
    }
    Terminal::new(CrosstermBackend::new(out)).map_err(RustpenError::Io)
}

pub(crate) fn leave_alt_terminal(terminal: &mut NativeReverseTerminal) -> Result<(), RustpenError> {
    disable_raw_mode().map_err(RustpenError::Io)?;
    if key_event_release_supported() {
        execute!(
            terminal.backend_mut(),
            PopKeyboardEnhancementFlags,
            LeaveAlternateScreen
        )
        .map_err(RustpenError::Io)?;
    } else {
        execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(RustpenError::Io)?;
    }
    terminal.show_cursor().ok();
    Ok(())
}
