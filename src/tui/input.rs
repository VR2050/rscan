use std::path::PathBuf;

use crossterm::event::KeyCode;

use super::models::{InputMode, ProjectEntry, ProjectTemplate, StatusFilter, TaskView};
use crate::errors::RustpenError;

mod command;
mod note;
mod project;
mod results;
mod script;

pub(crate) struct NonNormalInputCtx<'a> {
    pub(crate) input_mode: &'a mut InputMode,
    pub(crate) root_ws: &'a PathBuf,
    pub(crate) current_project: &'a mut PathBuf,
    pub(crate) scripts_dir: &'a mut PathBuf,

    pub(crate) filter: StatusFilter,
    pub(crate) project_template: ProjectTemplate,
    pub(crate) script_running: bool,

    pub(crate) task_selected: &'a mut usize,
    pub(crate) result_selected: &'a mut usize,
    pub(crate) effect_scroll: &'a mut u16,
    pub(crate) project_selected: &'a mut usize,
    pub(crate) script_selected: &'a mut usize,

    pub(crate) all_tasks: &'a mut Vec<TaskView>,
    pub(crate) tasks: &'a mut Vec<TaskView>,
    pub(crate) scripts: &'a mut Vec<PathBuf>,
    pub(crate) projects: &'a mut Vec<ProjectEntry>,

    pub(crate) status_line: &'a mut String,
    pub(crate) note_buffer: &'a mut String,
    pub(crate) cmd_buffer: &'a mut String,
    pub(crate) script_buffer: &'a mut String,
    pub(crate) script_dirty: &'a mut bool,
    pub(crate) script_new_buffer: &'a mut String,
    pub(crate) project_new_buffer: &'a mut String,
    pub(crate) project_import_buffer: &'a mut String,
    pub(crate) project_copy_buffer: &'a mut String,
    pub(crate) project_rename_buffer: &'a mut String,
    pub(crate) result_search_buffer: &'a mut String,
    pub(crate) result_query: &'a mut String,
}

pub(crate) fn handle_non_normal_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match *ctx.input_mode {
        InputMode::CommandInput => command::handle_command_input(key, ctx)?,
        InputMode::NoteInput => note::handle_note_input(key, ctx),
        InputMode::ScriptEdit => script::handle_script_edit_input(key, ctx),
        InputMode::ScriptNewInput => script::handle_script_new_input(key, ctx)?,
        InputMode::ProjectNewInput => project::handle_project_new_input(key, ctx)?,
        InputMode::ProjectImportInput => project::handle_project_import_input(key, ctx)?,
        InputMode::ProjectCopyInput => project::handle_project_copy_input(key, ctx)?,
        InputMode::ProjectRenameInput => project::handle_project_rename_input(key, ctx)?,
        InputMode::ResultSearchInput => results::handle_result_search_input(key, ctx),
        InputMode::Normal => {}
    }

    Ok(())
}
