use super::AppState;
use crate::cores::engine::task::TaskStatus;
use crate::tui::models::{MainPane, MiniConsoleTab, TaskView};
use crate::tui::view::build_mini_console_lines;

impl AppState {
    pub(super) fn refresh_mini_console_cache(
        &mut self,
        task_signature: u64,
        zellij_managed: bool,
        zellij_session: Option<&str>,
    ) {
        if !self.mini_console_visible {
            let had_content =
                self.mini_console_cache_key.is_some() || !self.mini_console_lines.is_empty();
            self.mini_console_cache_key = None;
            self.mini_console_lines.clear();
            if had_content {
                self.mini_console_render_serial = self.mini_console_render_serial.wrapping_add(1);
            }
            return;
        }

        let uses_terminal_tab = self.mini_console_tab == MiniConsoleTab::Terminal;
        let uses_script_output = self.pane == MainPane::Scripts && !uses_terminal_tab;
        let uses_task_context = !uses_terminal_tab && self.pane != MainPane::Scripts;
        let selected_task = selected_mini_console_task(
            uses_task_context,
            self.pane,
            &self.all_tasks,
            &self.tasks,
            self.task_selected,
            &self.result_indices,
            self.result_selected,
        );
        let mini_console_key = super::MiniConsoleCacheKey {
            project: self.current_project.clone(),
            pane: self.pane,
            tab: self.mini_console_tab,
            task_signature: if uses_task_context { task_signature } else { 0 },
            selected_task_id: selected_task.map(|task| task.meta.id.clone()),
            selected_task_live_serial: selected_task_live_serial(
                selected_task,
                self.task_poll_serial,
            ),
            status_line: self.status_line.clone(),
            zellij_managed,
            zellij_session: zellij_session.map(str::to_string),
            script_output_serial: if uses_script_output {
                self.script_output_serial
            } else {
                0
            },
            mini_terminal_serial: if uses_terminal_tab && zellij_managed {
                self.mini_terminal_serial
            } else {
                0
            },
            terminal_view_serial: if uses_terminal_tab && !zellij_managed {
                self.terminal_view_serial
            } else {
                0
            },
        };
        if self.mini_console_cache_key.as_ref() == Some(&mini_console_key) {
            return;
        }

        self.mini_console_lines = build_mini_console_lines(
            self.mini_console_tab,
            self.pane,
            &self.all_tasks,
            &self.tasks,
            self.task_selected,
            &self.result_indices,
            self.result_selected,
            &self.script_output,
            &self.mini_terminal_lines,
            &self.terminal_screen_lines,
            &self.status_line,
            zellij_managed,
            zellij_session,
            crate::tui::zellij::managed_tabs(),
        );
        self.mini_console_cache_key = Some(mini_console_key);
        self.mini_console_render_serial = self.mini_console_render_serial.wrapping_add(1);
    }
}

fn selected_mini_console_task<'a>(
    uses_task_context: bool,
    pane: MainPane,
    all_tasks: &'a [TaskView],
    tasks: &'a [TaskView],
    task_selected: usize,
    result_indices: &[usize],
    result_selected: usize,
) -> Option<&'a TaskView> {
    if !uses_task_context {
        return None;
    }
    if pane == MainPane::Results {
        return result_indices
            .get(result_selected)
            .and_then(|idx| all_tasks.get(*idx));
    }
    tasks.get(task_selected).or_else(|| all_tasks.first())
}

fn selected_task_live_serial(task: Option<&TaskView>, task_poll_serial: u64) -> u64 {
    if matches!(
        task.map(|task| &task.meta.status),
        Some(TaskStatus::Running | TaskStatus::Queued)
    ) {
        task_poll_serial
    } else {
        0
    }
}
