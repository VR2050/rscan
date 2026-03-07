use super::AppState;
use crate::tui::render::RenderCtx;

impl AppState {
    pub(crate) fn render_ctx<'a>(&'a self, footer_text: &'a str) -> RenderCtx<'a> {
        RenderCtx {
            pane: self.pane,
            filter: self.filter,
            task_tab: self.task_tab,
            result_kind_filter: self.result_kind_filter,
            result_failed_first: self.result_failed_first,
            input_mode: self.input_mode,
            project_template: self.project_template,
            current_project: &self.current_project,
            script_running: self.script_running,
            all_tasks: &self.all_tasks,
            tasks: &self.tasks,
            task_selected: self.task_selected,
            detail_scroll: self.detail_scroll,
            note_buffer: &self.note_buffer,
            launcher_items: &self.launcher_items,
            launcher_selected: self.launcher_selected,
            scripts: &self.scripts,
            script_selected: self.script_selected,
            script_buffer: &self.script_buffer,
            script_dirty: self.script_dirty,
            script_output: &self.script_output,
            result_indices: &self.result_indices,
            result_selected: self.result_selected,
            effect_scroll: self.effect_scroll,
            result_query: &self.result_query,
            projects: &self.projects,
            project_selected: self.project_selected,
            footer_text,
            mini_console_visible: self.mini_console_visible,
            mini_console_layout: self.mini_console_layout,
            mini_float_x_pct: self.mini_float_x_pct,
            mini_float_y_pct: self.mini_float_y_pct,
            mini_float_w_pct: self.mini_float_w_pct,
            mini_float_h_pct: self.mini_float_h_pct,
            mini_popup_mode: self.mini_popup_mode,
            mini_console_tab: self.mini_console_tab,
            mini_console_scroll: self.mini_console_scroll,
            mini_terminal_lines: &self.mini_terminal_lines,
            status_line: &self.status_line,
        }
    }
}
