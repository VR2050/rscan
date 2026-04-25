#[cfg(unix)]
use std::ffi::CString;
use std::path::PathBuf;

#[cfg(unix)]
use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::grid::Scroll;
use alacritty_terminal::term::TermMode;
use alacritty_terminal::term::cell::Flags;
#[cfg(unix)]
use alacritty_terminal::term::{Config as TermConfig, Term};
#[cfg(unix)]
use alacritty_terminal::vte::ansi::Processor;

use crate::errors::RustpenError;

use super::{TerminalSelection, TerminalSession, TerminalSize};

pub(crate) fn start_terminal_session(cwd: &PathBuf) -> Result<TerminalSession, RustpenError> {
    #[cfg(not(unix))]
    {
        let _ = cwd;
        return Err(RustpenError::Generic(
            "mini terminal PTY 暂不支持当前平台；请使用 zellij managed runtime".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
        let shell_c = CString::new(shell.clone()).map_err(|e| {
            RustpenError::Generic(format!("invalid shell path for PTY: {shell} ({e})"))
        })?;
        let arg0 = CString::new(shell)
            .map_err(|e| RustpenError::Generic(format!("invalid shell arg for PTY: {e}")))?;
        let arg1 = CString::new("-i")
            .map_err(|e| RustpenError::Generic(format!("invalid shell arg for PTY: {e}")))?;

        let mut master_fd: libc::c_int = -1;
        let pid = unsafe {
            libc::forkpty(
                &mut master_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if pid < 0 {
            return Err(RustpenError::Io(std::io::Error::last_os_error()));
        }
        if pid == 0 {
            unsafe {
                let _ = libc::chdir(
                    CString::new(cwd.display().to_string())
                        .unwrap_or_else(|_| CString::new("/").unwrap())
                        .as_ptr(),
                );
                let _ = libc::setenv(
                    CString::new("TERM").unwrap().as_ptr(),
                    CString::new("xterm-256color").unwrap().as_ptr(),
                    1,
                );
                let argv = vec![arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
                libc::execvp(shell_c.as_ptr(), argv.as_ptr());
                libc::_exit(1);
            }
        }

        let size = TerminalSize {
            columns: 80,
            screen_lines: 24,
        };
        unsafe {
            let mut ws = libc::winsize {
                ws_row: size.screen_lines as u16,
                ws_col: size.columns as u16,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let _ = libc::ioctl(master_fd, libc::TIOCSWINSZ, &mut ws);
            let flags = libc::fcntl(master_fd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        let mut config = TermConfig::default();
        config.scrolling_history = 2000;
        Ok(TerminalSession {
            master_fd,
            term: Term::new(config, &size, VoidListener),
            parser: Processor::new(),
        })
    }
}

pub(crate) fn write_terminal(session: &TerminalSession, data: &[u8]) -> Result<(), RustpenError> {
    #[cfg(not(unix))]
    {
        let _ = session;
        let _ = data;
        return Ok(());
    }

    #[cfg(unix)]
    {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        while offset < data.len() {
            let written = unsafe {
                libc::write(
                    session.master_fd,
                    data[offset..].as_ptr() as *const libc::c_void,
                    (data.len() - offset) as libc::size_t,
                )
            };
            if written > 0 {
                offset += written as usize;
                continue;
            }
            if written == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            return Err(RustpenError::Io(err));
        }
        Ok(())
    }
}

pub(crate) fn read_terminal(session: &mut TerminalSession) -> Result<bool, RustpenError> {
    #[cfg(not(unix))]
    {
        let _ = session;
        return Ok(false);
    }

    #[cfg(unix)]
    {
        let mut buf = [0u8; 4096];
        let mut changed = false;
        loop {
            let read = unsafe {
                libc::read(
                    session.master_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len() as libc::size_t,
                )
            };
            if read > 0 {
                session
                    .parser
                    .advance(&mut session.term, &buf[..read as usize]);
                changed = true;
                continue;
            }
            if read == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                break;
            }
            return Err(RustpenError::Io(err));
        }
        Ok(changed)
    }
}

pub(crate) fn resize_terminal(session: &mut TerminalSession, columns: u16, screen_lines: u16) {
    if columns == 0 || screen_lines == 0 {
        return;
    }

    let size = TerminalSize {
        columns: columns as usize,
        screen_lines: screen_lines as usize,
    };
    session.term.resize(size);
    #[cfg(unix)]
    unsafe {
        let mut ws = libc::winsize {
            ws_row: screen_lines,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let _ = libc::ioctl(session.master_fd, libc::TIOCSWINSZ, &mut ws);
    }
}

pub(crate) fn terminal_mode(session: &TerminalSession) -> TermMode {
    *session.term.mode()
}

pub(crate) fn scroll_terminal(session: &mut TerminalSession, scroll: Scroll) {
    session.term.scroll_display(scroll);
}

pub(crate) fn wrap_bracketed_paste(session: &TerminalSession, text: &str) -> Vec<u8> {
    if session.term.mode().contains(TermMode::BRACKETED_PASTE) {
        let mut out = Vec::with_capacity(text.len() + 20);
        out.extend_from_slice(b"\x1b[200~");
        out.extend_from_slice(text.as_bytes());
        out.extend_from_slice(b"\x1b[201~");
        return out;
    }
    text.as_bytes().to_vec()
}

pub(crate) fn selection_text(session: &TerminalSession, sel: TerminalSelection) -> String {
    let grid = session.term.grid();
    let rows = session.term.screen_lines();
    let cols = session.term.columns();
    let (sx, sy) = sel.start;
    let (ex, ey) = sel.end;
    let (min_y, max_y) = if sy <= ey { (sy, ey) } else { (ey, sy) };
    let (min_x, max_x) = if sx <= ex { (sx, ex) } else { (ex, sx) };
    let mut out = String::new();

    for y in min_y as usize..=max_y as usize {
        if y >= rows {
            continue;
        }
        let start_x = if y as u16 == min_y { min_x } else { 0 };
        let end_x = if y as u16 == max_y {
            max_x
        } else {
            (cols.saturating_sub(1)) as u16
        };
        let mut line = String::new();
        for x in start_x as usize..=end_x as usize {
            if x >= cols {
                continue;
            }
            let cell = &grid[alacritty_terminal::index::Line(y as i32)]
                [alacritty_terminal::index::Column(x)];
            if cell
                .flags
                .contains(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }
            line.push(cell.c);
        }
        out.push_str(line.trim_end_matches(' '));
        if y as u16 != max_y {
            out.push('\n');
        }
    }

    out
}
