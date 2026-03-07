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
    let tick = Duration::from_millis(refresh_ms.unwrap_or(500).max(100));
    let mut state = AppState::new(root_ws)?;

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

    let res = loop {
        state.refresh_result_indices();
        state.push_status_line();
        state.poll_script_completion()?;
        let footer_text = state.footer_text();

        terminal
            .draw(|f| {
                let render_ctx = state.render_ctx(&footer_text);
                draw_frame(f, &render_ctx);
            })
            .ok();

        if !event::poll(tick).map_err(RustpenError::Io)? {
            continue;
        }
        if let Event::Key(key) = event::read().map_err(RustpenError::Io)? {
            match state.handle_key(key)? {
                KeyDispatchAction::Quit => break Ok(()),
                KeyDispatchAction::ContinueLoop => continue,
                KeyDispatchAction::None => {}
            }
        }
    };

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
