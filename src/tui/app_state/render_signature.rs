use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::AppState;

impl AppState {
    pub(crate) fn should_draw_frame(&mut self, footer_text: &str) -> bool {
        let signature = self.frame_render_signature(footer_text);
        if self.last_frame_signature == Some(signature) {
            return false;
        }
        self.last_frame_signature = Some(signature);
        true
    }

    fn frame_render_signature(&self, footer_text: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        let zellij_managed = crate::tui::zellij::is_managed_runtime();
        let zellij_session = crate::tui::zellij::session_name();
        let terminal_size = crossterm::terminal::size().ok();

        self.pane.hash(&mut hasher);
        self.main_layout.hash(&mut hasher);
        self.filter.hash(&mut hasher);
        self.task_tab.hash(&mut hasher);
        self.result_kind_filter.hash(&mut hasher);
        self.result_failed_first.hash(&mut hasher);
        self.input_mode.hash(&mut hasher);
        self.project_template.hash(&mut hasher);
        self.current_project.hash(&mut hasher);
        self.project_selected.hash(&mut hasher);
        self.task_selected.hash(&mut hasher);
        self.detail_scroll.hash(&mut hasher);
        self.launcher_selected.hash(&mut hasher);
        self.script_selected.hash(&mut hasher);
        self.script_dirty.hash(&mut hasher);
        self.result_selected.hash(&mut hasher);
        self.effect_scroll.hash(&mut hasher);
        self.script_running.hash(&mut hasher);
        footer_text.hash(&mut hasher);
        zellij_managed.hash(&mut hasher);
        zellij_session.hash(&mut hasher);
        terminal_size.hash(&mut hasher);

        self.mini_console_visible.hash(&mut hasher);
        self.mini_console_layout.hash(&mut hasher);
        self.mini_float_x_pct.hash(&mut hasher);
        self.mini_float_y_pct.hash(&mut hasher);
        self.mini_float_w_pct.hash(&mut hasher);
        self.mini_float_h_pct.hash(&mut hasher);
        self.mini_popup_mode.hash(&mut hasher);
        self.mini_console_tab.hash(&mut hasher);
        self.mini_console_scroll.hash(&mut hasher);

        if !zellij_managed {
            self.perf_cpu_pct.map(f64::to_bits).hash(&mut hasher);
            self.perf_mem_used_mb.hash(&mut hasher);
            self.perf_mem_total_mb.hash(&mut hasher);
            self.perf_proc_rss_mb.hash(&mut hasher);
            self.perf_loadavg.hash(&mut hasher);
        }

        self.dashboard_render_serial.hash(&mut hasher);
        self.task_detail_render_serial.hash(&mut hasher);
        self.result_detail_render_serial.hash(&mut hasher);
        self.mini_console_render_serial.hash(&mut hasher);
        self.task_pane_render_serial.hash(&mut hasher);
        self.result_list_render_serial.hash(&mut hasher);
        self.scripts_pane_render_serial.hash(&mut hasher);
        self.projects_pane_render_serial.hash(&mut hasher);
        self.launcher_pane_render_serial.hash(&mut hasher);
        self.ui_tick.hash(&mut hasher);
        self.script_buffer.hash(&mut hasher);

        hasher.finish()
    }
}
