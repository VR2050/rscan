use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use super::models::{
    InputMode, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectEntry, ProjectTemplate,
    ResultKindFilter, StatusFilter, TaskTab, TaskView,
};
use super::script_runtime::{ScriptRunResult, ScriptTaskCtx};

mod dispatch;
mod init;
mod render_ctx;
mod runtime;

pub(crate) enum KeyDispatchAction {
    None,
    ContinueLoop,
    Quit,
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
    last_status_pushed: String,
    status_line: String,
}
