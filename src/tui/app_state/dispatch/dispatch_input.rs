use crossterm::event::KeyCode;

use super::super::{AppState, KeyDispatchAction};
use crate::errors::RustpenError;
use crate::tui::input::{NonNormalInputCtx, handle_non_normal_input};

impl AppState {
    pub(super) fn handle_non_normal_key(
        &mut self,
        key_code: KeyCode,
    ) -> Result<KeyDispatchAction, RustpenError> {
        let mut mode_ctx = NonNormalInputCtx {
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
            script_buffer: &mut self.script_buffer,
            script_dirty: &mut self.script_dirty,
            script_new_buffer: &mut self.script_new_buffer,
            project_new_buffer: &mut self.project_new_buffer,
            project_import_buffer: &mut self.project_import_buffer,
            project_copy_buffer: &mut self.project_copy_buffer,
            project_rename_buffer: &mut self.project_rename_buffer,
            result_search_buffer: &mut self.result_search_buffer,
            result_query: &mut self.result_query,
        };
        handle_non_normal_input(key_code, &mut mode_ctx)?;
        Ok(KeyDispatchAction::None)
    }
}
