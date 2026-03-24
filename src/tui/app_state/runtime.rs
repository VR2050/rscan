use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use super::AppState;
use crate::cores::engine::task::{TaskStatus, now_epoch_secs};
use crate::errors::RustpenError;
use crate::tui::models::{InputMode, TaskTab, TaskView};
use crate::tui::pane_cache_text::build_dashboard_recent_items;
use crate::tui::pane_text::{
    build_dashboard_lines, build_result_panel_lines, build_task_detail_lines,
};
use crate::tui::perf::{read_cpu_stat, read_loadavg, read_meminfo, read_proc_rss_mb};
use crate::tui::script_runtime::{append_output_block, finalize_script_task, poll_script_runner};
use crate::tui::task_store::{apply_filter, build_result_indices, load_tasks};
use crate::tui::terminal::{
    TerminalSelection, read_terminal, render_terminal_view, resize_terminal,
    start_terminal_session, terminal_mode,
};
use crate::tui::view::{append_mini_terminal_line, line_s, mini_console_rect_for_layout};

impl AppState {
    pub(crate) fn refresh_render_caches(&mut self) -> Result<(), RustpenError> {
        let task_signature = task_collection_signature(&self.all_tasks);
        let zellij_managed = crate::tui::zellij::is_managed_runtime();
        let zellij_session = crate::tui::zellij::session_name();
        let registry_signature =
            crate::tui::zellij_registry::registry_signature(&self.current_project);

        let dashboard_key = super::DashboardCacheKey {
            project: self.current_project.clone(),
            task_signature,
            zellij_managed,
            zellij_session: zellij_session.clone(),
            registry_signature,
        };
        if self.dashboard_cache_key.as_ref() != Some(&dashboard_key) {
            self.dashboard_total = self.all_tasks.len();
            self.dashboard_running = self
                .all_tasks
                .iter()
                .filter(|t| t.meta.status == TaskStatus::Running)
                .count();
            self.dashboard_failed = self
                .all_tasks
                .iter()
                .filter(|t| t.meta.status == TaskStatus::Failed)
                .count();
            self.dashboard_succeeded = self
                .all_tasks
                .iter()
                .filter(|t| t.meta.status == TaskStatus::Succeeded)
                .count();
            self.dashboard_lines = build_dashboard_lines(
                &self.all_tasks,
                &self.current_project,
                zellij_managed,
                zellij_session.as_deref(),
            );
            self.dashboard_recent_items = build_dashboard_recent_items(&self.all_tasks, 10);
            self.dashboard_cache_key = Some(dashboard_key);
            self.dashboard_render_serial = self.dashboard_render_serial.wrapping_add(1);
        }

        let result_live_serial = if self.has_live_activity() && !self.result_query.trim().is_empty()
        {
            self.task_poll_serial
        } else {
            0
        };
        let result_indices_key = super::ResultIndicesCacheKey {
            project: self.current_project.clone(),
            task_signature,
            live_serial: result_live_serial,
            filter: self.result_kind_filter,
            failed_first: self.result_failed_first,
            query: self.result_query.clone(),
        };
        if self.result_indices_cache_key.as_ref() != Some(&result_indices_key) {
            self.result_indices = build_result_indices(
                &self.all_tasks,
                self.result_kind_filter,
                self.result_failed_first,
                &self.result_query,
            );
            if self.result_selected >= self.result_indices.len() {
                self.result_selected = self.result_indices.len().saturating_sub(1);
            }
            self.result_indices_cache_key = Some(result_indices_key);
        }

        let selected_task = self
            .tasks
            .get(self.task_selected)
            .or_else(|| self.all_tasks.first());
        let task_detail_key = super::TaskDetailCacheKey {
            project: self.current_project.clone(),
            task_signature,
            live_serial: task_live_serial(selected_task, self.task_poll_serial),
            task_tab: self.task_tab,
            task_id: selected_task.map(|task| task.meta.id.clone()),
            note_buffer: if self.task_tab == TaskTab::Notes {
                self.note_buffer.clone()
            } else {
                String::new()
            },
            note_mode: matches!(self.input_mode, InputMode::NoteInput),
        };
        if self.task_detail_cache_key.as_ref() != Some(&task_detail_key) {
            self.task_detail_lines = selected_task
                .map(|task| {
                    build_task_detail_lines(task, self.task_tab, &self.note_buffer, self.input_mode)
                })
                .unwrap_or_else(|| vec![line_s("无详情")]);
            self.task_detail_cache_key = Some(task_detail_key);
            self.task_detail_render_serial = self.task_detail_render_serial.wrapping_add(1);
        }

        let selected_result_task = self
            .result_indices
            .get(self.result_selected)
            .and_then(|idx| self.all_tasks.get(*idx));
        let result_detail_key = super::ResultDetailCacheKey {
            project: self.current_project.clone(),
            task_signature,
            live_serial: task_live_serial(selected_result_task, self.task_poll_serial),
            task_id: selected_result_task.map(|task| task.meta.id.clone()),
            filter: self.result_kind_filter,
            failed_first: self.result_failed_first,
            query: self.result_query.clone(),
        };
        if self.result_detail_cache_key.as_ref() != Some(&result_detail_key) {
            self.result_detail_lines = selected_result_task
                .map(|task| {
                    build_result_panel_lines(
                        task,
                        self.result_kind_filter,
                        self.result_failed_first,
                        &self.result_query,
                    )
                })
                .unwrap_or_else(|| vec![line_s("无执行效果数据")]);
            self.result_detail_cache_key = Some(result_detail_key);
            self.result_detail_render_serial = self.result_detail_render_serial.wrapping_add(1);
        }

        self.refresh_task_pane_cache(task_signature);
        self.refresh_result_list_cache(task_signature);
        self.refresh_scripts_pane_cache();
        self.refresh_projects_pane_cache();
        self.refresh_launcher_pane_cache();
        self.refresh_mini_console_cache(task_signature, zellij_managed, zellij_session.as_deref());

        Ok(())
    }

    pub(crate) fn push_status_line(&mut self) {
        if !self.status_line.is_empty() && self.status_line != self.last_status_pushed {
            append_mini_terminal_line(
                &mut self.mini_terminal_lines,
                format!("[{}] {}", now_epoch_secs(), self.status_line),
            );
            self.mini_terminal_serial = self.mini_terminal_serial.wrapping_add(1);
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
            self.script_output_serial = self.script_output_serial.wrapping_add(1);
            let _ = finalize_script_task(&mut self.script_task, &done);
            self.all_tasks = load_tasks(self.current_project.clone())?;
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

    pub(crate) fn poll_terminal_output(&mut self) -> Result<(), RustpenError> {
        if crate::tui::zellij::is_managed_runtime() {
            self.terminal_session = None;
            if !self.terminal_screen_lines.is_empty() {
                self.terminal_screen_lines.clear();
                self.terminal_view_serial = self.terminal_view_serial.wrapping_add(1);
            }
            self.terminal_cursor = None;
            self.terminal_partial_line.clear();
            self.terminal_input_buffer.clear();
            self.terminal_last_size = None;
            self.terminal_scroll_offset = 0;
            self.terminal_dirty = false;
            if matches!(self.input_mode, InputMode::TerminalInput) {
                self.input_mode = InputMode::Normal;
            }
            return Ok(());
        }

        let terminal_surface_active = self.terminal_active();
        if self.terminal_session.is_none() && terminal_surface_active {
            self.terminal_session = Some(start_terminal_session(&self.current_project)?);
            if let Some(session) = self.terminal_session.as_ref() {
                let _ = crate::tui::terminal::write_terminal(session, b"\nexport PS1='rscan$ '\n");
            }
            self.status_line = "terminal ready (press g to input)".to_string();
        }
        let terminal_viewport = if terminal_surface_active {
            self.mini_terminal_viewport()
        } else {
            None
        };
        if let Some(session) = self.terminal_session.as_mut() {
            if let Some(viewport) = terminal_viewport.as_ref() {
                let (cols, rows) = viewport.size();
                if self.terminal_last_size != Some((cols, rows)) {
                    resize_terminal(session, cols, rows);
                    self.terminal_last_size = Some((cols, rows));
                    self.terminal_dirty = true;
                }
            }
            let changed = read_terminal(session)?;
            let mode = terminal_mode(session);
            if mode.contains(alacritty_terminal::term::TermMode::ALT_SCREEN) {
                self.terminal_scroll_offset = 0;
            }
            if !terminal_surface_active {
                if changed {
                    self.terminal_dirty = true;
                }
                return Ok(());
            }
            let mut blink_changed = false;
            if self.terminal_last_blink.elapsed() >= std::time::Duration::from_millis(520) {
                self.terminal_blink_on = !self.terminal_blink_on;
                self.terminal_last_blink = std::time::Instant::now();
                blink_changed = true;
            }
            if changed || blink_changed || self.terminal_dirty {
                let selection = self
                    .terminal_sel_start
                    .zip(self.terminal_sel_end)
                    .map(|(start, end)| TerminalSelection { start, end });
                let view = render_terminal_view(session, self.terminal_blink_on, selection);
                self.terminal_screen_lines = view.lines;
                self.terminal_view_serial = self.terminal_view_serial.wrapping_add(1);
                self.terminal_cursor = view.cursor;
                self.terminal_partial_line.clear();
                self.terminal_dirty = false;
            }
        }
        Ok(())
    }

    pub(crate) fn poll_perf_refresh(&mut self) -> Result<(), RustpenError> {
        let refresh_interval = if crate::tui::zellij::is_managed_runtime() {
            std::time::Duration::from_millis(2200)
        } else {
            self.perf_refresh_interval
        };
        if self.perf_last_refresh.elapsed() < refresh_interval {
            return Ok(());
        }
        self.perf_last_refresh = Instant::now();

        if let Some((total, idle)) = read_cpu_stat() {
            if self.last_cpu_total > 0 && total >= self.last_cpu_total {
                let total_delta = total.saturating_sub(self.last_cpu_total);
                let idle_delta = idle.saturating_sub(self.last_cpu_idle);
                if total_delta > 0 {
                    let used = (total_delta.saturating_sub(idle_delta)) as f64;
                    self.perf_cpu_pct = Some((used / total_delta as f64) * 100.0);
                }
            }
            self.last_cpu_total = total;
            self.last_cpu_idle = idle;
        }
        if let Some((used, total)) = read_meminfo() {
            self.perf_mem_used_mb = used;
            self.perf_mem_total_mb = total;
        }
        if let Some(rss) = read_proc_rss_mb() {
            self.perf_proc_rss_mb = rss;
        }
        if let Some(load) = read_loadavg() {
            self.perf_loadavg = load;
        }
        Ok(())
    }

    pub(crate) fn advance_ui_tick(&mut self) {
        let pulse_interval = if self.terminal_active() {
            Some(std::time::Duration::from_millis(240))
        } else if self.has_live_activity() {
            Some(std::time::Duration::from_millis(360))
        } else {
            None
        };
        let Some(pulse_interval) = pulse_interval else {
            return;
        };
        if self.last_ui_tick_advance.elapsed() >= pulse_interval {
            self.ui_tick = self.ui_tick.wrapping_add(1);
            self.last_ui_tick_advance = Instant::now();
        }
    }

    pub(crate) fn poll_task_refresh(&mut self) -> Result<(), RustpenError> {
        let refresh_interval = if self.has_live_activity() {
            std::time::Duration::from_millis(320)
        } else {
            self.task_refresh_interval
        };
        if self.last_task_refresh.elapsed() < refresh_interval {
            return Ok(());
        }
        self.last_task_refresh = Instant::now();
        self.task_poll_serial = self.task_poll_serial.wrapping_add(1);
        self.all_tasks = load_tasks(self.current_project.clone())?;
        self.tasks = apply_filter(&self.all_tasks, self.filter);
        if self.task_selected >= self.tasks.len() {
            self.task_selected = self.tasks.len().saturating_sub(1);
        }
        if self.result_selected >= self.all_tasks.len() {
            self.result_selected = self.all_tasks.len().saturating_sub(1);
        }
        Ok(())
    }

    pub(crate) fn footer_text(&self) -> String {
        match self.input_mode {
            InputMode::CommandInput => format!(
                ":{}  [Tab=complete  Up/Down=history]",
                render_buffer_with_cursor(&self.cmd_buffer, self.cmd_cursor)
            ),
            InputMode::TerminalInput => self.status_line.clone(),
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

    pub(crate) fn mini_terminal_rect(&self) -> Option<ratatui::layout::Rect> {
        self.mini_terminal_viewport().map(|viewport| viewport.rect)
    }

    fn mini_terminal_viewport(&self) -> Option<MiniTerminalViewport> {
        use crate::tui::models::MiniConsoleTab;

        if !self.mini_console_visible || self.mini_console_tab != MiniConsoleTab::Terminal {
            return None;
        }
        let (cols, rows) = crossterm::terminal::size().ok()?;
        if cols < 10 || rows < 10 {
            return None;
        }

        let outer_w = cols.saturating_sub(2);
        let outer_h = rows.saturating_sub(2);
        let body_h = outer_h.saturating_sub(4);
        if outer_w == 0 || body_h == 0 {
            return None;
        }
        let area = ratatui::layout::Rect {
            x: 1,
            y: 4,
            width: outer_w,
            height: body_h,
        };
        let dock = mini_console_rect_for_layout(
            area,
            self.mini_console_layout,
            self.mini_float_x_pct,
            self.mini_float_y_pct,
            self.mini_float_w_pct,
            self.mini_float_h_pct,
        );
        let content = ratatui::layout::Rect {
            x: dock.x,
            y: dock.y + 3,
            width: dock.width,
            height: dock.height.saturating_sub(3),
        };
        let inner = ratatui::layout::Rect {
            x: content.x + 1,
            y: content.y + 1,
            width: content.width.saturating_sub(2),
            height: content.height.saturating_sub(2),
        };
        if inner.width == 0 || inner.height == 0 {
            return None;
        }
        Some(MiniTerminalViewport { rect: inner })
    }
}

struct MiniTerminalViewport {
    rect: ratatui::layout::Rect,
}

impl MiniTerminalViewport {
    fn size(&self) -> (u16, u16) {
        (self.rect.width, self.rect.height)
    }
}

fn render_buffer_with_cursor(buffer: &str, cursor: usize) -> String {
    let mut c = cursor.min(buffer.len());
    while c > 0 && !buffer.is_char_boundary(c) {
        c -= 1;
    }
    if c == buffer.len() {
        return format!("{buffer}|");
    }
    format!("{}|{}", &buffer[..c], &buffer[c..])
}

fn task_collection_signature(tasks: &[TaskView]) -> u64 {
    let mut hasher = DefaultHasher::new();
    tasks.len().hash(&mut hasher);
    for task in tasks {
        task.dir.hash(&mut hasher);
        task.meta.id.hash(&mut hasher);
        task.meta.kind.hash(&mut hasher);
        task_status_code(&task.meta.status).hash(&mut hasher);
        task.meta.created_at.hash(&mut hasher);
        task.meta.started_at.hash(&mut hasher);
        task.meta.ended_at.hash(&mut hasher);
        task.meta.progress.map(f32::to_bits).hash(&mut hasher);
        task.meta.note.hash(&mut hasher);
        task.meta.tags.hash(&mut hasher);
        task.meta.artifacts.hash(&mut hasher);
        task.meta.logs.hash(&mut hasher);
        for path in &task.meta.artifacts {
            hash_task_path_state(path, &mut hasher);
        }
        for path in &task.meta.logs {
            hash_task_path_state(path, &mut hasher);
        }
        task.origin.hash(&mut hasher);
        task.meta
            .extra
            .as_ref()
            .map(|extra| extra.to_string())
            .hash(&mut hasher);
    }
    hasher.finish()
}

fn hash_task_path_state(path: &std::path::Path, hasher: &mut DefaultHasher) {
    path.hash(hasher);
    let Ok(meta) = std::fs::metadata(path) else {
        0u8.hash(hasher);
        return;
    };
    1u8.hash(hasher);
    meta.len().hash(hasher);
    meta.is_dir().hash(hasher);
    meta.is_file().hash(hasher);
    let modified = meta
        .modified()
        .ok()
        .and_then(|ts| ts.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|dur| dur.as_secs());
    modified.hash(hasher);
}

fn task_status_code(status: &TaskStatus) -> u8 {
    match status {
        TaskStatus::Queued => 0,
        TaskStatus::Running => 1,
        TaskStatus::Succeeded => 2,
        TaskStatus::Failed => 3,
        TaskStatus::Canceled => 4,
    }
}

fn task_live_serial(task: Option<&TaskView>, task_poll_serial: u64) -> u64 {
    if matches!(
        task.map(|task| &task.meta.status),
        Some(TaskStatus::Running | TaskStatus::Queued)
    ) {
        task_poll_serial
    } else {
        0
    }
}
