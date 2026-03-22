use crossterm::event::KeyEvent;

use super::super::{AppState, KeyDispatchAction};
use crate::errors::RustpenError;
use crate::tui::input::{NonNormalInputCtx, handle_non_normal_input, handle_non_normal_paste};
use crate::tui::models::InputMode;
use crate::tui::terminal::{
    key_event_to_bytes, scroll_terminal, terminal_mode, wrap_bracketed_paste, write_terminal,
};

impl AppState {
    fn build_non_normal_ctx(&mut self) -> NonNormalInputCtx<'_> {
        NonNormalInputCtx {
            input_mode: &mut self.input_mode,
            root_ws: &self.root_ws,
            current_project: &mut self.current_project,
            scripts_dir: &mut self.scripts_dir,
            filter: self.filter,
            project_template: self.project_template,
            script_running: self.script_running,
            task_selected: &mut self.task_selected,
            result_selected: &mut self.result_selected,
            effect_scroll: &mut self.effect_scroll,
            project_selected: &mut self.project_selected,
            script_selected: &mut self.script_selected,
            all_tasks: &mut self.all_tasks,
            tasks: &mut self.tasks,
            scripts: &mut self.scripts,
            projects: &mut self.projects,
            status_line: &mut self.status_line,
            note_buffer: &mut self.note_buffer,
            cmd_buffer: &mut self.cmd_buffer,
            cmd_cursor: &mut self.cmd_cursor,
            cmd_undo_stack: &mut self.cmd_undo_stack,
            cmd_redo_stack: &mut self.cmd_redo_stack,
            cmd_history: &mut self.cmd_history,
            cmd_history_idx: &mut self.cmd_history_idx,
            cmd_history_scratch: &mut self.cmd_history_scratch,
            cmd_completion: &mut self.cmd_completion,
            cmd_completion_idx: &mut self.cmd_completion_idx,
            cmd_completion_seed: &mut self.cmd_completion_seed,
            script_buffer: &mut self.script_buffer,
            script_dirty: &mut self.script_dirty,
            script_new_buffer: &mut self.script_new_buffer,
            project_new_buffer: &mut self.project_new_buffer,
            project_import_buffer: &mut self.project_import_buffer,
            project_copy_buffer: &mut self.project_copy_buffer,
            project_rename_buffer: &mut self.project_rename_buffer,
            result_search_buffer: &mut self.result_search_buffer,
            result_query: &mut self.result_query,
        }
    }

    pub(super) fn handle_non_normal_key(
        &mut self,
        key: KeyEvent,
    ) -> Result<KeyDispatchAction, RustpenError> {
        let mut mode_ctx = self.build_non_normal_ctx();
        handle_non_normal_input(key, &mut mode_ctx)?;
        Ok(KeyDispatchAction::None)
    }

    pub(super) fn handle_terminal_key(
        &mut self,
        key: KeyEvent,
    ) -> Result<KeyDispatchAction, RustpenError> {
        if crate::tui::zellij::is_managed_runtime() {
            self.input_mode = InputMode::Normal;
            self.status_line =
                "zellij mode: use g 聚焦 Control 下方 shell；zrun 会打开 Work pane".to_string();
            return Ok(KeyDispatchAction::ContinueLoop);
        }

        let is_ctrl = key
            .modifiers
            .contains(crossterm::event::KeyModifiers::CONTROL);
        let is_shift = key
            .modifiers
            .contains(crossterm::event::KeyModifiers::SHIFT);
        if matches!(key.code, crossterm::event::KeyCode::Esc)
            || (is_ctrl
                && matches!(
                    key.code,
                    crossterm::event::KeyCode::Char('g') | crossterm::event::KeyCode::Char('G')
                ))
        {
            self.input_mode = InputMode::Normal;
            self.status_line = "terminal input: off".to_string();
            return Ok(KeyDispatchAction::ContinueLoop);
        }
        if matches!(
            key.code,
            crossterm::event::KeyCode::PageUp | crossterm::event::KeyCode::PageDown
        ) {
            if let Some(session) = self.terminal_session.as_mut() {
                let mode = terminal_mode(session);
                if mode.contains(alacritty_terminal::term::TermMode::ALT_SCREEN) {
                    // In alt screen, forward scroll keys to app.
                    if let Some(bytes) = key_event_to_bytes(key) {
                        write_terminal(session, &bytes)?;
                    }
                } else {
                    match key.code {
                        crossterm::event::KeyCode::PageUp => {
                            scroll_terminal(session, alacritty_terminal::grid::Scroll::PageUp);
                            self.terminal_scroll_offset =
                                self.terminal_scroll_offset.saturating_add(1);
                            self.terminal_dirty = true;
                        }
                        crossterm::event::KeyCode::PageDown => {
                            scroll_terminal(session, alacritty_terminal::grid::Scroll::PageDown);
                            self.terminal_scroll_offset =
                                self.terminal_scroll_offset.saturating_sub(1);
                            self.terminal_dirty = true;
                        }
                        _ => {}
                    }
                }
            }
            return Ok(KeyDispatchAction::ContinueLoop);
        }
        if is_ctrl && is_shift {
            match key.code {
                crossterm::event::KeyCode::Char('c') | crossterm::event::KeyCode::Char('C') => {
                    if let Some((_, row)) = self.terminal_cursor {
                        if let Some(line) = self.terminal_screen_lines.get(row as usize) {
                            let text = line
                                .spans
                                .iter()
                                .map(|s| s.content.clone().into_owned())
                                .collect::<String>();
                            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                let _ = clipboard.set_text(text);
                                self.status_line = "terminal copied line".to_string();
                            }
                        }
                    }
                    return Ok(KeyDispatchAction::ContinueLoop);
                }
                crossterm::event::KeyCode::Char('v') | crossterm::event::KeyCode::Char('V') => {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        if let Ok(text) = clipboard.get_text() {
                            if let Some(session) = self.terminal_session.as_ref() {
                                let data = wrap_bracketed_paste(session, &text);
                                write_terminal(session, &data)?;
                                self.status_line = "terminal pasted".to_string();
                            }
                        }
                    }
                    return Ok(KeyDispatchAction::ContinueLoop);
                }
                _ => {}
            }
        }
        match key.code {
            crossterm::event::KeyCode::Backspace => {
                self.terminal_input_buffer.pop();
            }
            crossterm::event::KeyCode::Enter => {
                self.terminal_input_buffer.clear();
            }
            crossterm::event::KeyCode::Char(c) => {
                if !is_ctrl {
                    self.terminal_input_buffer.push(c);
                }
            }
            _ => {}
        }
        if let Some(bytes) = key_event_to_bytes(key) {
            if let Some(session) = self.terminal_session.as_ref() {
                write_terminal(session, &bytes)?;
            }
        }
        Ok(KeyDispatchAction::ContinueLoop)
    }

    pub(crate) fn handle_paste(&mut self, text: &str) -> Result<KeyDispatchAction, RustpenError> {
        if text.is_empty() || matches!(self.input_mode, InputMode::Normal) {
            return Ok(KeyDispatchAction::None);
        }
        if matches!(self.input_mode, InputMode::TerminalInput) {
            if crate::tui::zellij::is_managed_runtime() {
                self.input_mode = InputMode::Normal;
                self.status_line =
                    "zellij mode: 粘贴请直接在 Control shell 或 Work pane 中完成".to_string();
                return Ok(KeyDispatchAction::ContinueLoop);
            }
            if let Some(session) = self.terminal_session.as_ref() {
                let data = wrap_bracketed_paste(session, text);
                write_terminal(session, &data)?;
            }
            self.terminal_input_buffer.push_str(text);
            return Ok(KeyDispatchAction::ContinueLoop);
        }
        let mut mode_ctx = self.build_non_normal_ctx();
        handle_non_normal_paste(text, &mut mode_ctx)?;
        Ok(KeyDispatchAction::None)
    }
}
