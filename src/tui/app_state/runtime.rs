use super::AppState;
use crate::cores::engine::task::now_epoch_secs;
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::script_runtime::{append_output_block, finalize_script_task, poll_script_runner};
use crate::tui::task_store::{apply_filter, build_result_indices, load_tasks};
use crate::tui::view::append_mini_terminal_line;

impl AppState {
    pub(crate) fn refresh_result_indices(&mut self) {
        self.result_indices = build_result_indices(
            &self.all_tasks,
            self.result_kind_filter,
            self.result_failed_first,
            &self.result_query,
        );
        if self.result_selected >= self.result_indices.len() {
            self.result_selected = self.result_indices.len().saturating_sub(1);
        }
    }

    pub(crate) fn push_status_line(&mut self) {
        if !self.status_line.is_empty() && self.status_line != self.last_status_pushed {
            append_mini_terminal_line(
                &mut self.mini_terminal_lines,
                format!("[{}] {}", now_epoch_secs(), self.status_line),
            );
            self.last_status_pushed = self.status_line.clone();
        }
    }

    pub(crate) fn poll_script_completion(&mut self) -> Result<(), RustpenError> {
        if let Some(done) = poll_script_runner(&mut self.script_runner_rx) {
            self.script_running = false;
            self.status_line = format!(
                "script finished: {} ({})",
                done.file.display(),
                if done.ok { "ok" } else { "failed" }
            );
            append_output_block(
                &mut self.script_output,
                "[script] stdout",
                &done.stdout,
                "[script] stderr",
                &done.stderr,
            );
            let _ = finalize_script_task(&mut self.script_task, &done);
            self.all_tasks = load_tasks(self.current_project.join("tasks"))?;
            self.tasks = apply_filter(&self.all_tasks, self.filter);
            if self.task_selected >= self.tasks.len() {
                self.task_selected = self.tasks.len().saturating_sub(1);
            }
            if self.result_selected >= self.all_tasks.len() {
                self.result_selected = self.all_tasks.len().saturating_sub(1);
            }
        }
        Ok(())
    }

    pub(crate) fn footer_text(&self) -> String {
        match self.input_mode {
            InputMode::CommandInput => format!(":{}", self.cmd_buffer),
            InputMode::NoteInput => format!("note> {}", self.note_buffer),
            InputMode::ScriptNewInput => format!("script.new> {}", self.script_new_buffer),
            InputMode::ProjectNewInput => format!(
                "project.new[template={}]> {}",
                self.project_template.label(),
                self.project_new_buffer
            ),
            InputMode::ProjectImportInput => {
                format!("project.import> {}", self.project_import_buffer)
            }
            InputMode::ProjectCopyInput => format!("project.copy> {}", self.project_copy_buffer),
            InputMode::ProjectRenameInput => {
                format!("project.rename> {}", self.project_rename_buffer)
            }
            InputMode::ResultSearchInput => {
                format!("results.search> {}", self.result_search_buffer)
            }
            InputMode::ScriptEdit => {
                "script edit: Esc退出  Enter换行  Backspace删除  S保存".to_string()
            }
            InputMode::Normal => self.status_line.clone(),
        }
    }
}
