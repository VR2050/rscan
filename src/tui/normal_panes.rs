use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use crossterm::event::KeyCode;

use super::models::{
    InputMode, MainPane, ProjectEntry, ProjectTemplate, ResultKindFilter, StatusFilter, TaskTab,
    TaskView,
};
use super::script_runtime::{ScriptRunResult, ScriptTaskCtx};
use crate::errors::RustpenError;

mod dashboard;
mod launcher;
mod projects;
mod results;
mod scripts;
mod tasks;

pub(crate) enum PaneNormalAction {
    Handled,
    Unhandled,
    ContinueLoop,
}

pub(crate) struct PaneNormalCtx<'a> {
    pub(crate) filter: &'a mut StatusFilter,
    pub(crate) input_mode: &'a mut InputMode,
    pub(crate) status_line: &'a mut String,

    pub(crate) all_tasks: &'a mut Vec<TaskView>,
    pub(crate) tasks: &'a mut Vec<TaskView>,
    pub(crate) task_selected: &'a mut usize,
    pub(crate) detail_scroll: &'a mut u16,
    pub(crate) task_tab: &'a mut TaskTab,

    pub(crate) launcher_items: &'a [(&'static str, &'static str)],
    pub(crate) launcher_selected: &'a mut usize,

    pub(crate) scripts: &'a mut Vec<PathBuf>,
    pub(crate) script_selected: &'a mut usize,
    pub(crate) script_buffer: &'a mut String,
    pub(crate) script_dirty: &'a mut bool,
    pub(crate) script_new_buffer: &'a mut String,
    pub(crate) scripts_dir: &'a mut PathBuf,
    pub(crate) script_running: &'a mut bool,
    pub(crate) script_task: &'a mut Option<ScriptTaskCtx>,
    pub(crate) script_runner_rx: &'a mut Option<Receiver<ScriptRunResult>>,

    pub(crate) result_indices: &'a [usize],
    pub(crate) result_selected: &'a mut usize,
    pub(crate) effect_scroll: &'a mut u16,
    pub(crate) result_kind_filter: &'a mut ResultKindFilter,
    pub(crate) result_failed_first: &'a mut bool,
    pub(crate) result_search_buffer: &'a mut String,
    pub(crate) result_query: &'a mut String,

    pub(crate) note_buffer: &'a mut String,

    pub(crate) projects: &'a mut Vec<ProjectEntry>,
    pub(crate) project_selected: &'a mut usize,
    pub(crate) project_new_buffer: &'a mut String,
    pub(crate) project_import_buffer: &'a mut String,
    pub(crate) project_copy_buffer: &'a mut String,
    pub(crate) project_rename_buffer: &'a mut String,
    pub(crate) project_template: &'a mut ProjectTemplate,
    pub(crate) current_project: &'a mut PathBuf,
    pub(crate) root_ws: &'a PathBuf,
}

pub(crate) fn handle_pane_normal_key(
    key: KeyCode,
    pane: &mut MainPane,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match *pane {
        MainPane::Dashboard => dashboard::handle_dashboard_key(key, ctx),
        MainPane::Tasks => tasks::handle_tasks_key(key, ctx),
        MainPane::Launcher => launcher::handle_launcher_key(key, ctx),
        MainPane::Scripts => scripts::handle_scripts_key(key, ctx),
        MainPane::Results => results::handle_results_key(key, pane, ctx),
        MainPane::Projects => projects::handle_projects_key(key, ctx),
    }
}
