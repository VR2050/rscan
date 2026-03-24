use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use ratatui::text::Line;
use ratatui::widgets::{ListItem, Row};

use super::models::{
    InputMode, MainLayout, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectEntry,
    ProjectTemplate, ResultKindFilter, StatusFilter, TaskTab, TaskView,
};
use super::script_runtime::{ScriptRunResult, ScriptTaskCtx};
use super::terminal::TerminalSession;

mod dispatch;
mod init;
mod mini_console_cache;
mod pane_render_cache;
mod render_ctx;
mod render_signature;
mod runtime;

pub(crate) enum KeyDispatchAction {
    None,
    ContinueLoop,
    Quit,
}

#[derive(Clone, PartialEq, Eq)]
struct DashboardCacheKey {
    project: PathBuf,
    task_signature: u64,
    zellij_managed: bool,
    zellij_session: Option<String>,
    registry_signature: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct ResultIndicesCacheKey {
    project: PathBuf,
    task_signature: u64,
    live_serial: u64,
    filter: ResultKindFilter,
    failed_first: bool,
    query: String,
}

#[derive(Clone, PartialEq, Eq)]
struct TaskDetailCacheKey {
    project: PathBuf,
    task_signature: u64,
    live_serial: u64,
    task_tab: TaskTab,
    task_id: Option<String>,
    note_buffer: String,
    note_mode: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct ResultDetailCacheKey {
    project: PathBuf,
    task_signature: u64,
    live_serial: u64,
    task_id: Option<String>,
    filter: ResultKindFilter,
    failed_first: bool,
    query: String,
}

#[derive(Clone, PartialEq, Eq)]
struct MiniConsoleCacheKey {
    project: PathBuf,
    pane: MainPane,
    tab: MiniConsoleTab,
    task_signature: u64,
    selected_task_id: Option<String>,
    selected_task_live_serial: u64,
    zellij_managed: bool,
    zellij_session: Option<String>,
    script_output_serial: u64,
    mini_terminal_serial: u64,
    terminal_view_serial: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct TaskPaneCacheKey {
    project: PathBuf,
    task_signature: u64,
    filter: StatusFilter,
}

#[derive(Clone, PartialEq, Eq)]
struct ResultListCacheKey {
    project: PathBuf,
    task_signature: u64,
    filter: ResultKindFilter,
    failed_first: bool,
    query: String,
}

#[derive(Clone, PartialEq, Eq)]
struct ScriptsPaneCacheKey {
    project: PathBuf,
    scripts_signature: u64,
    script_output_serial: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct ProjectsPaneCacheKey {
    project: PathBuf,
    projects_signature: u64,
    project_selected: usize,
    current_project: PathBuf,
    project_template: ProjectTemplate,
}

#[derive(Clone, PartialEq, Eq)]
struct LauncherPaneCacheKey {
    selected: usize,
    items_signature: u64,
}

pub(crate) struct AppState {
    root_ws: PathBuf,

    pane: MainPane,
    filter: StatusFilter,
    task_tab: TaskTab,
    result_kind_filter: ResultKindFilter,
    result_failed_first: bool,
    input_mode: InputMode,
    project_template: ProjectTemplate,
    main_layout: MainLayout,

    current_project: PathBuf,
    projects: Vec<ProjectEntry>,
    project_selected: usize,
    scripts_dir: PathBuf,

    all_tasks: Vec<TaskView>,
    tasks: Vec<TaskView>,
    task_selected: usize,
    detail_scroll: u16,

    launcher_items: Vec<(&'static str, &'static str)>,
    launcher_selected: usize,

    scripts: Vec<PathBuf>,
    script_selected: usize,
    script_buffer: String,
    script_dirty: bool,
    script_new_buffer: String,
    script_output: Vec<String>,
    script_output_serial: u64,
    script_runner_rx: Option<Receiver<ScriptRunResult>>,
    script_running: bool,
    script_task: Option<ScriptTaskCtx>,

    result_indices: Vec<usize>,
    result_selected: usize,
    effect_scroll: u16,
    result_query: String,
    result_search_buffer: String,

    note_buffer: String,
    cmd_buffer: String,
    cmd_cursor: usize,
    cmd_undo_stack: Vec<(String, usize)>,
    cmd_redo_stack: Vec<(String, usize)>,
    cmd_history: Vec<String>,
    cmd_history_idx: Option<usize>,
    cmd_history_scratch: Option<String>,
    cmd_completion: Vec<String>,
    cmd_completion_idx: Option<usize>,
    cmd_completion_seed: String,
    project_new_buffer: String,
    project_import_buffer: String,
    project_copy_buffer: String,
    project_rename_buffer: String,

    mini_console_visible: bool,
    mini_console_layout: MiniConsoleLayout,
    mini_float_x_pct: u16,
    mini_float_y_pct: u16,
    mini_float_w_pct: u16,
    mini_float_h_pct: u16,
    mini_popup_mode: bool,
    mini_popup_saved_geom: Option<(u16, u16, u16, u16)>,
    mini_console_tab: MiniConsoleTab,
    mini_console_scroll: u16,
    mini_terminal_lines: Vec<String>,
    mini_terminal_serial: u64,
    terminal_screen_lines: Vec<ratatui::text::Line<'static>>,
    terminal_view_serial: u64,
    terminal_cursor: Option<(u16, u16)>,
    terminal_blink_on: bool,
    terminal_last_blink: Instant,
    terminal_scroll_offset: i32,
    terminal_selecting: bool,
    terminal_sel_start: Option<(u16, u16)>,
    terminal_sel_end: Option<(u16, u16)>,
    terminal_last_size: Option<(u16, u16)>,
    terminal_dirty: bool,
    terminal_partial_line: String,
    terminal_input_buffer: String,
    terminal_session: Option<TerminalSession>,
    last_status_pushed: String,
    status_line: String,
    last_task_refresh: Instant,
    task_refresh_interval: Duration,
    perf_last_refresh: Instant,
    perf_refresh_interval: Duration,
    perf_cpu_pct: Option<f64>,
    perf_mem_used_mb: u64,
    perf_mem_total_mb: u64,
    perf_proc_rss_mb: u64,
    perf_loadavg: String,
    last_cpu_total: u64,
    last_cpu_idle: u64,
    task_poll_serial: u64,
    dashboard_cache_key: Option<DashboardCacheKey>,
    dashboard_total: usize,
    dashboard_running: usize,
    dashboard_failed: usize,
    dashboard_succeeded: usize,
    dashboard_lines: Vec<Line<'static>>,
    dashboard_recent_items: Vec<ListItem<'static>>,
    result_indices_cache_key: Option<ResultIndicesCacheKey>,
    task_detail_cache_key: Option<TaskDetailCacheKey>,
    task_detail_lines: Vec<Line<'static>>,
    result_detail_cache_key: Option<ResultDetailCacheKey>,
    result_detail_lines: Vec<Line<'static>>,
    mini_console_cache_key: Option<MiniConsoleCacheKey>,
    mini_console_lines: Vec<Line<'static>>,
    mini_console_render_serial: u64,
    task_pane_cache_key: Option<TaskPaneCacheKey>,
    task_table_rows: Vec<Row<'static>>,
    task_compact_items: Vec<ListItem<'static>>,
    task_pane_render_serial: u64,
    result_list_cache_key: Option<ResultListCacheKey>,
    result_list_items: Vec<ListItem<'static>>,
    result_list_render_serial: u64,
    scripts_pane_cache_key: Option<ScriptsPaneCacheKey>,
    script_file_items: Vec<ListItem<'static>>,
    script_output_lines: Vec<Line<'static>>,
    scripts_pane_render_serial: u64,
    projects_pane_cache_key: Option<ProjectsPaneCacheKey>,
    project_list_items: Vec<ListItem<'static>>,
    project_detail_lines: Vec<Line<'static>>,
    projects_pane_render_serial: u64,
    launcher_pane_cache_key: Option<LauncherPaneCacheKey>,
    launcher_list_items: Vec<ListItem<'static>>,
    launcher_detail_lines: Vec<Line<'static>>,
    launcher_pane_render_serial: u64,
    dashboard_render_serial: u64,
    task_detail_render_serial: u64,
    result_detail_render_serial: u64,
    ui_tick: u64,
    last_ui_tick_advance: Instant,
    last_frame_signature: Option<u64>,
}

impl AppState {
    pub(crate) fn terminal_active(&self) -> bool {
        if crate::tui::zellij::is_managed_runtime() {
            return false;
        }
        (self.mini_console_visible && self.mini_console_tab == MiniConsoleTab::Terminal)
            || matches!(self.input_mode, InputMode::TerminalInput)
    }

    pub(crate) fn has_live_activity(&self) -> bool {
        self.script_running
            || self.all_tasks.iter().any(|task| {
                matches!(
                    task.meta.status,
                    crate::cores::engine::task::TaskStatus::Running
                        | crate::cores::engine::task::TaskStatus::Queued
                )
            })
    }

    pub(crate) fn root_ws(&self) -> &PathBuf {
        &self.root_ws
    }
}
