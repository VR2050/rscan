mod input;
mod pty;
mod render;

use std::os::unix::io::RawFd;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::Term;
use alacritty_terminal::vte::ansi::Processor;
use ratatui::text::Line;

pub(crate) use input::{key_event_to_bytes, mouse_event_to_bytes};
pub(crate) use pty::{
    read_terminal, resize_terminal, scroll_terminal, selection_text, start_terminal_session,
    terminal_mode, wrap_bracketed_paste, write_terminal,
};
pub(crate) use render::render_terminal_view;

pub(crate) struct TerminalView {
    pub(crate) lines: Vec<Line<'static>>,
    pub(crate) cursor: Option<(u16, u16)>,
}

#[derive(Clone, Copy)]
pub(crate) struct TerminalSelection {
    pub(crate) start: (u16, u16),
    pub(crate) end: (u16, u16),
}

pub(crate) struct TerminalSession {
    master_fd: RawFd,
    term: Term<VoidListener>,
    parser: Processor,
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.master_fd);
        }
    }
}

struct TerminalSize {
    columns: usize,
    screen_lines: usize,
}

impl Dimensions for TerminalSize {
    fn total_lines(&self) -> usize {
        self.screen_lines
    }

    fn screen_lines(&self) -> usize {
        self.screen_lines
    }

    fn columns(&self) -> usize {
        self.columns
    }
}
