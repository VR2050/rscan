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
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Ok(KeyDispatchAction::Quit);
        }

        match self.input_mode {
            InputMode::Normal => self.handle_normal_key(key),
            _ => self.handle_non_normal_key(key.code),
        }
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
            input_mode: &mut self.input_mode,
            cmd_buffer: &mut self.cmd_buffer,
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
