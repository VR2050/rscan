use std::fs;
use std::path::PathBuf;

use super::AppState;
use crate::errors::RustpenError;
use crate::tui::command_exec::launcher_commands;
use crate::tui::models::{
    InputMode, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectTemplate, ResultKindFilter,
    StatusFilter, TaskTab,
};
use crate::tui::project_store::{ensure_project_layout, load_projects};
use crate::tui::script_runtime::{load_script_files, read_script_text};
use crate::tui::task_store::{apply_filter, build_result_indices, load_tasks};

impl AppState {
    pub(crate) fn new(root_ws: PathBuf) -> Result<Self, RustpenError> {
        let mut projects = load_projects(&root_ws)?;
        let project_selected = 0usize;
        let current_project = projects
            .first()
            .map(|p| p.path.clone())
            .unwrap_or_else(|| root_ws.clone());
        ensure_project_layout(&current_project)?;

        let filter = StatusFilter::All;
        let result_kind_filter = ResultKindFilter::All;
        let result_failed_first = false;
        let result_query = String::new();
        let all_tasks = load_tasks(current_project.join("tasks"))?;
        let tasks = apply_filter(&all_tasks, filter);

        let launcher_items = launcher_commands();
        let launcher_selected = 0usize;

        let scripts_dir = current_project.join("scripts");
        let _ = fs::create_dir_all(&scripts_dir);
        let scripts = load_script_files(&scripts_dir)?;
        let script_selected = 0usize;
        let script_buffer = scripts.first().map(read_script_text).unwrap_or_default();

        let result_indices = build_result_indices(
            &all_tasks,
            result_kind_filter,
            result_failed_first,
            &result_query,
        );

        Ok(Self {
            root_ws,
            pane: MainPane::Dashboard,
            filter,
            task_tab: TaskTab::Overview,
            result_kind_filter,
            result_failed_first,
            input_mode: InputMode::Normal,
            project_template: ProjectTemplate::Minimal,
            current_project,
            projects: std::mem::take(&mut projects),
            project_selected,
            scripts_dir,
            all_tasks,
            tasks,
            task_selected: 0,
            detail_scroll: 0,
            launcher_items,
            launcher_selected,
            scripts,
            script_selected,
            script_buffer,
            script_dirty: false,
            script_new_buffer: String::new(),
            script_output: vec![
                "[script] script pane ready".to_string(),
                "[script] N:new  i:edit  S:save  R:run".to_string(),
            ],
            script_runner_rx: None,
            script_running: false,
            script_task: None,
            result_indices,
            result_selected: 0,
            effect_scroll: 0,
            result_query,
            result_search_buffer: String::new(),
            note_buffer: String::new(),
            cmd_buffer: String::new(),
            project_new_buffer: String::new(),
            project_import_buffer: String::new(),
            project_copy_buffer: String::new(),
            project_rename_buffer: String::new(),
            mini_console_visible: true,
            mini_console_layout: MiniConsoleLayout::DockRightBottom,
            mini_float_x_pct: 52,
            mini_float_y_pct: 58,
            mini_float_w_pct: 46,
            mini_float_h_pct: 36,
            mini_popup_mode: false,
            mini_popup_saved_geom: None,
            mini_console_tab: MiniConsoleTab::Output,
            mini_console_scroll: 0,
            mini_terminal_lines: vec!["[terminal] mini terminal ready".to_string()],
            last_status_pushed: String::new(),
            status_line: "提示: zellij Normal 模式会拦截按键，按 Ctrl-g 切到 Locked 模式"
                .to_string(),
        })
    }
}
