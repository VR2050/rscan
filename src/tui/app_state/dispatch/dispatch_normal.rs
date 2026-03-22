use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::super::{AppState, KeyDispatchAction};
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::normal_global::{GlobalNormalAction, GlobalNormalCtx, handle_global_normal_key};
use crate::tui::normal_panes::{PaneNormalAction, PaneNormalCtx, handle_pane_normal_key};

impl AppState {
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Result<KeyDispatchAction, RustpenError> {
        if key.kind == KeyEventKind::Release {
            return Ok(KeyDispatchAction::ContinueLoop);
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::SHIFT)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
            && !matches!(self.input_mode, InputMode::TerminalInput)
        {
            return Ok(KeyDispatchAction::Quit);
        }

        if matches!(self.input_mode, InputMode::TerminalInput) {
            return self.handle_terminal_key(key);
        }

        match self.input_mode {
            InputMode::Normal => self.handle_normal_key(key),
            _ => self.handle_non_normal_key(key),
        }
    }

    pub(crate) fn handle_mouse(
        &mut self,
        mouse: crossterm::event::MouseEvent,
    ) -> Result<KeyDispatchAction, RustpenError> {
        if crate::tui::zellij::is_managed_runtime() {
            return Ok(KeyDispatchAction::None);
        }

        use crate::tui::terminal::TerminalSelection;
        use crate::tui::terminal::{
            mouse_event_to_bytes, scroll_terminal, selection_text, terminal_mode, write_terminal,
        };
        use crossterm::event::{MouseButton, MouseEventKind};

        let Some(rect) = self.mini_terminal_rect() else {
            return Ok(KeyDispatchAction::None);
        };
        let x = mouse.column;
        let y = mouse.row;
        let in_rect = x >= rect.x
            && x < rect.x.saturating_add(rect.width)
            && y >= rect.y
            && y < rect.y.saturating_add(rect.height);

        if !in_rect {
            if self.terminal_selecting {
                self.terminal_selecting = false;
            }
            return Ok(KeyDispatchAction::None);
        }

        let col = x.saturating_sub(rect.x);
        let row = y.saturating_sub(rect.y);
        let pos = (col, row);

        if let Some(session) = self.terminal_session.as_mut() {
            let mode = terminal_mode(session);
            if mode.contains(alacritty_terminal::term::TermMode::MOUSE_MODE)
                || mode.contains(alacritty_terminal::term::TermMode::SGR_MOUSE)
                || mode.contains(alacritty_terminal::term::TermMode::UTF8_MOUSE)
            {
                if let Some(bytes) =
                    mouse_event_to_bytes(session, mouse.kind, mouse.modifiers, col, row)
                {
                    write_terminal(session, &bytes)?;
                    return Ok(KeyDispatchAction::ContinueLoop);
                }
            }
            match mouse.kind {
                MouseEventKind::ScrollUp => {
                    if mode.contains(alacritty_terminal::term::TermMode::ALT_SCREEN)
                        || mode.contains(alacritty_terminal::term::TermMode::MOUSE_MODE)
                    {
                        // Forward to app if mouse reporting is active.
                        let _ = mode;
                    } else {
                        scroll_terminal(session, alacritty_terminal::grid::Scroll::PageUp);
                        self.terminal_dirty = true;
                        return Ok(KeyDispatchAction::ContinueLoop);
                    }
                }
                MouseEventKind::ScrollDown => {
                    if mode.contains(alacritty_terminal::term::TermMode::ALT_SCREEN)
                        || mode.contains(alacritty_terminal::term::TermMode::MOUSE_MODE)
                    {
                        let _ = mode;
                    } else {
                        scroll_terminal(session, alacritty_terminal::grid::Scroll::PageDown);
                        self.terminal_dirty = true;
                        return Ok(KeyDispatchAction::ContinueLoop);
                    }
                }
                MouseEventKind::Down(MouseButton::Left) => {
                    if !mode.contains(alacritty_terminal::term::TermMode::MOUSE_MODE) {
                        self.terminal_selecting = true;
                        self.terminal_sel_start = Some(pos);
                        self.terminal_sel_end = Some(pos);
                        self.terminal_dirty = true;
                        return Ok(KeyDispatchAction::ContinueLoop);
                    }
                }
                MouseEventKind::Drag(MouseButton::Left) => {
                    if self.terminal_selecting {
                        self.terminal_sel_end = Some(pos);
                        self.terminal_dirty = true;
                        return Ok(KeyDispatchAction::ContinueLoop);
                    }
                }
                MouseEventKind::Up(MouseButton::Left) => {
                    if self.terminal_selecting {
                        self.terminal_selecting = false;
                        if let (Some(start), Some(end)) =
                            (self.terminal_sel_start, self.terminal_sel_end)
                        {
                            let sel = TerminalSelection { start, end };
                            let text = selection_text(session, sel);
                            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                                let _ = clipboard.set_text(text);
                                self.status_line = "terminal selection copied".to_string();
                            }
                        }
                        self.terminal_dirty = true;
                        return Ok(KeyDispatchAction::ContinueLoop);
                    }
                }
                _ => {}
            }
        }
        Ok(KeyDispatchAction::None)
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> Result<KeyDispatchAction, RustpenError> {
        let mut global_ctx = self.build_global_normal_ctx();
        match handle_global_normal_key(key.code, key.modifiers, &mut global_ctx)? {
            GlobalNormalAction::Quit => return Ok(KeyDispatchAction::Quit),
            GlobalNormalAction::Handled => return Ok(KeyDispatchAction::None),
            GlobalNormalAction::Unhandled => {}
        }

        let mut pane_ctx = PaneNormalCtx {
            filter: &mut self.filter,
            input_mode: &mut self.input_mode,
            status_line: &mut self.status_line,
            all_tasks: &mut self.all_tasks,
            tasks: &mut self.tasks,
            task_selected: &mut self.task_selected,
            detail_scroll: &mut self.detail_scroll,
            task_tab: &mut self.task_tab,
            launcher_items: &self.launcher_items,
            launcher_selected: &mut self.launcher_selected,
            scripts: &mut self.scripts,
            script_selected: &mut self.script_selected,
            script_buffer: &mut self.script_buffer,
            script_dirty: &mut self.script_dirty,
            script_new_buffer: &mut self.script_new_buffer,
            scripts_dir: &mut self.scripts_dir,
            script_running: &mut self.script_running,
            script_task: &mut self.script_task,
            script_runner_rx: &mut self.script_runner_rx,
            result_indices: &self.result_indices,
            result_selected: &mut self.result_selected,
            effect_scroll: &mut self.effect_scroll,
            result_kind_filter: &mut self.result_kind_filter,
            result_failed_first: &mut self.result_failed_first,
            result_search_buffer: &mut self.result_search_buffer,
            result_query: &mut self.result_query,
            note_buffer: &mut self.note_buffer,
            projects: &mut self.projects,
            project_selected: &mut self.project_selected,
            project_new_buffer: &mut self.project_new_buffer,
            project_import_buffer: &mut self.project_import_buffer,
            project_copy_buffer: &mut self.project_copy_buffer,
            project_rename_buffer: &mut self.project_rename_buffer,
            project_template: &mut self.project_template,
            current_project: &mut self.current_project,
            root_ws: &self.root_ws,
        };
        match handle_pane_normal_key(key.code, &mut self.pane, &mut pane_ctx)? {
            PaneNormalAction::ContinueLoop => Ok(KeyDispatchAction::ContinueLoop),
            PaneNormalAction::Handled | PaneNormalAction::Unhandled => Ok(KeyDispatchAction::None),
        }
    }

    fn build_global_normal_ctx(&mut self) -> GlobalNormalCtx<'_> {
        GlobalNormalCtx {
            pane: &mut self.pane,
            detail_scroll: &mut self.detail_scroll,
            effect_scroll: &mut self.effect_scroll,
            main_layout: &mut self.main_layout,
            input_mode: &mut self.input_mode,
            cmd_buffer: &mut self.cmd_buffer,
            cmd_cursor: &mut self.cmd_cursor,
            cmd_undo_stack: &mut self.cmd_undo_stack,
            cmd_redo_stack: &mut self.cmd_redo_stack,
            cmd_history_idx: &mut self.cmd_history_idx,
            cmd_history_scratch: &mut self.cmd_history_scratch,
            cmd_completion: &mut self.cmd_completion,
            cmd_completion_idx: &mut self.cmd_completion_idx,
            cmd_completion_seed: &mut self.cmd_completion_seed,
            status_line: &mut self.status_line,
            mini_console_visible: &mut self.mini_console_visible,
            mini_console_layout: &mut self.mini_console_layout,
            mini_popup_mode: &mut self.mini_popup_mode,
            mini_popup_saved_geom: &mut self.mini_popup_saved_geom,
            mini_float_x_pct: &mut self.mini_float_x_pct,
            mini_float_y_pct: &mut self.mini_float_y_pct,
            mini_float_w_pct: &mut self.mini_float_w_pct,
            mini_float_h_pct: &mut self.mini_float_h_pct,
            mini_console_tab: &mut self.mini_console_tab,
            mini_console_scroll: &mut self.mini_console_scroll,
            terminal_session: &mut self.terminal_session,
            root_ws: &self.root_ws,
            current_project: &self.current_project,
            scripts_dir: &self.scripts_dir,
            filter: self.filter,
            script_dirty: self.script_dirty,
            script_buffer: &mut self.script_buffer,
            projects: &mut self.projects,
            project_selected: &mut self.project_selected,
            all_tasks: &mut self.all_tasks,
            tasks: &mut self.tasks,
            scripts: &mut self.scripts,
            task_selected: &mut self.task_selected,
            result_selected: &mut self.result_selected,
            script_selected: &mut self.script_selected,
        }
    }
}
