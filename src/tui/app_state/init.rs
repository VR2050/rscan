use std::fs;
use std::path::PathBuf;

use super::AppState;
use crate::errors::RustpenError;
use crate::tui::command_catalog::launcher_commands;
use crate::tui::models::{
    InputMode, MainLayout, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectTemplate,
    ResultKindFilter, StatusFilter, TaskTab,
};
use crate::tui::project_store::{ensure_project_layout, load_projects, same_path};
use crate::tui::reverse_workbench_support::{read_active_project_hint, write_active_project_hint};
use crate::tui::script_runtime::{load_script_files, read_script_text};
use crate::tui::task_store::{apply_filter, build_result_indices, load_tasks};

impl AppState {
    pub(crate) fn new(root_ws: PathBuf) -> Result<Self, RustpenError> {
        let zellij_managed = crate::tui::zellij::is_managed_runtime();
        let zellij_session = crate::tui::zellij::session_name();
        let zellij_tabs = crate::tui::zellij::managed_tabs().join(" | ");
        let mini_terminal_lines = if zellij_managed {
            let session = zellij_session
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            vec![
                format!("[zellij] session={session}"),
                format!("[zellij] tabs={zellij_tabs}"),
                "[zellij] g 聚焦 Control 下方 shell；普通模块命令直接走后台 task engine"
                    .to_string(),
                "[zellij] zrun <cmd> 会在 Work tab 打开真实终端 pane".to_string(),
                "[zellij] L/W/A 可把当前任务送进 Inspect/Work/Reverse 原生 pane".to_string(),
            ]
        } else {
            vec!["[terminal] mini terminal ready".to_string()]
        };
        let status_line = if zellij_managed {
            format!(
                "{} | session={}",
                "zellij mode: Ctrl-g 切到 Locked；g=Control shell；L/W/A=task native panes；: 启动后台 task；zrun 打开 Work",
                zellij_session.unwrap_or_else(|| "unknown".to_string())
            )
        } else {
            "提示: g 进入 mini terminal，Esc/Ctrl-g 退出".to_string()
        };

        let mut projects = load_projects(&root_ws)?;
        let hinted_project = read_active_project_hint(&root_ws);
        let project_selected = hinted_project
            .as_ref()
            .and_then(|hint| {
                projects
                    .iter()
                    .position(|project| same_path(&project.path, hint))
            })
            .unwrap_or(0usize);
        let current_project = projects
            .get(project_selected)
            .map(|p| p.path.clone())
            .unwrap_or_else(|| root_ws.clone());
        ensure_project_layout(&current_project)?;
        let _ = write_active_project_hint(&root_ws, &current_project);

        let filter = StatusFilter::All;
        let result_kind_filter = ResultKindFilter::All;
        let result_failed_first = false;
        let result_query = String::new();
        let all_tasks = load_tasks(current_project.clone())?;
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

        let mut state = Self {
            root_ws,
            pane: MainPane::Dashboard,
            filter,
            task_tab: TaskTab::Overview,
            result_kind_filter,
            result_failed_first,
            input_mode: InputMode::Normal,
            project_template: ProjectTemplate::Minimal,
            main_layout: MainLayout::Single,
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
            script_output_serial: 1,
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
            cmd_cursor: 0,
            cmd_undo_stack: Vec::new(),
            cmd_redo_stack: Vec::new(),
            cmd_history: Vec::new(),
            cmd_history_idx: None,
            cmd_history_scratch: None,
            cmd_completion: Vec::new(),
            cmd_completion_idx: None,
            cmd_completion_seed: String::new(),
            project_new_buffer: String::new(),
            project_import_buffer: String::new(),
            project_copy_buffer: String::new(),
            project_rename_buffer: String::new(),
            mini_console_visible: !zellij_managed,
            mini_console_layout: MiniConsoleLayout::DockRightBottom,
            mini_float_x_pct: 52,
            mini_float_y_pct: 58,
            mini_float_w_pct: 46,
            mini_float_h_pct: 36,
            mini_popup_mode: false,
            mini_popup_saved_geom: None,
            mini_console_tab: MiniConsoleTab::Output,
            mini_console_scroll: 0,
            mini_terminal_lines,
            mini_terminal_serial: 1,
            terminal_screen_lines: Vec::new(),
            terminal_view_serial: 0,
            terminal_cursor: None,
            terminal_blink_on: true,
            terminal_last_blink: std::time::Instant::now(),
            terminal_scroll_offset: 0,
            terminal_selecting: false,
            terminal_sel_start: None,
            terminal_sel_end: None,
            terminal_last_size: None,
            terminal_dirty: true,
            terminal_partial_line: String::new(),
            terminal_input_buffer: String::new(),
            terminal_session: None,
            last_status_pushed: String::new(),
            status_line,
            last_task_refresh: std::time::Instant::now(),
            task_refresh_interval: std::time::Duration::from_millis(1200),
            perf_last_refresh: std::time::Instant::now(),
            perf_refresh_interval: std::time::Duration::from_millis(1000),
            perf_cpu_pct: None,
            perf_mem_used_mb: 0,
            perf_mem_total_mb: 0,
            perf_proc_rss_mb: 0,
            perf_loadavg: "-".to_string(),
            last_cpu_total: 0,
            last_cpu_idle: 0,
            task_poll_serial: 0,
            dashboard_cache_key: None,
            dashboard_lines: Vec::new(),
            result_indices_cache_key: None,
            task_detail_cache_key: None,
            task_detail_lines: Vec::new(),
            result_detail_cache_key: None,
            result_detail_lines: Vec::new(),
            mini_console_cache_key: None,
            mini_console_lines: Vec::new(),
            mini_console_render_serial: 0,
            task_pane_cache_key: None,
            task_table_rows: Vec::new(),
            task_compact_items: Vec::new(),
            task_pane_render_serial: 0,
            result_list_cache_key: None,
            result_list_items: Vec::new(),
            result_list_render_serial: 0,
            scripts_pane_cache_key: None,
            script_file_items: Vec::new(),
            script_output_lines: Vec::new(),
            scripts_pane_render_serial: 0,
            projects_pane_cache_key: None,
            project_list_items: Vec::new(),
            project_detail_lines: Vec::new(),
            projects_pane_render_serial: 0,
            launcher_pane_cache_key: None,
            launcher_list_items: Vec::new(),
            launcher_detail_lines: Vec::new(),
            launcher_pane_render_serial: 0,
            dashboard_render_serial: 0,
            task_detail_render_serial: 0,
            result_detail_render_serial: 0,
            ui_tick: 0,
            last_ui_tick_advance: std::time::Instant::now(),
            last_frame_signature: None,
        };
        state.refresh_render_caches()?;
        Ok(state)
    }
}
