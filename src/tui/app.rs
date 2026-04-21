use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use super::app_state::{AppState, KeyDispatchAction};
use super::render::draw_frame;
use crate::errors::RustpenError;

pub fn run_tui(workspace: Option<PathBuf>, refresh_ms: Option<u64>) -> Result<(), RustpenError> {
    let root_ws = workspace.unwrap_or(std::env::current_dir()?);
    let base_tick = Duration::from_millis(refresh_ms.unwrap_or(500).max(100));
    let active_tick = Duration::from_millis(120);
    let mut state = AppState::new(root_ws)?;

    if std::env::var("RSCAN_ZELLIJ_BOOTSTRAP").is_err() {
        if crate::tui::zellij::is_enabled() {
            match crate::tui::zellij::bootstrap_layout(&state.root_ws(), refresh_ms) {
                Ok(crate::tui::zellij::BootstrapResult::Launched) => {
                    return Ok(());
                }
                Ok(crate::tui::zellij::BootstrapResult::Continue) => {}
                Err(e) => {
                    // Fallback to in-process TUI if zellij bootstrap fails.
                    eprintln!("[rscan] zellij bootstrap failed: {e}");
                }
            }
        }
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(RustpenError::Generic(
            "TUI 需要交互式终端(tty)。请直接在 alacritty/zellij pane 中运行。".to_string(),
        ));
    }

    enable_raw_mode().map_err(RustpenError::Io)?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )
    .map_err(RustpenError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(RustpenError::Io)?;

    let res = (|| -> Result<(), RustpenError> {
        loop {
            state.poll_terminal_output()?;
            state.poll_perf_refresh()?;
            state.poll_script_completion()?;
            state.poll_task_refresh()?;
            state.push_status_line();
            state.refresh_render_caches()?;
            state.advance_ui_tick();
            let footer_text = state.footer_text();

            if state.should_draw_frame(&footer_text) {
                terminal
                    .draw(|f| {
                        let render_ctx = state.render_ctx(&footer_text);
                        draw_frame(f, &render_ctx);
                    })
                    .ok();
            }

            let tick = if state.terminal_active() {
                Duration::from_millis(16)
            } else if state.has_live_activity() {
                active_tick
            } else {
                base_tick
            };
            if !event::poll(tick).map_err(RustpenError::Io)? {
                continue;
            }
            match event::read().map_err(RustpenError::Io)? {
                Event::Key(key) => match state.handle_key(key)? {
                    KeyDispatchAction::Quit => return Ok(()),
                    KeyDispatchAction::ContinueLoop => continue,
                    KeyDispatchAction::None => {}
                },
                Event::Paste(text) => match state.handle_paste(&text)? {
                    KeyDispatchAction::Quit => return Ok(()),
                    KeyDispatchAction::ContinueLoop => continue,
                    KeyDispatchAction::None => {}
                },
                Event::Mouse(mouse) => match state.handle_mouse(mouse)? {
                    KeyDispatchAction::Quit => return Ok(()),
                    KeyDispatchAction::ContinueLoop => continue,
                    KeyDispatchAction::None => {}
                },
                _ => {}
            }
        }
    })();

    disable_raw_mode().map_err(RustpenError::Io)?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )
    .map_err(RustpenError::Io)?;
    terminal.show_cursor().ok();
    res
}
