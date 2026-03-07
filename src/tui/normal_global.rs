use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyModifiers};

use super::models::{
    InputMode, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectEntry, StatusFilter, TaskView,
};
use super::project_store::load_projects;
use super::script_runtime::{load_script_files, read_script_text};
use super::task_store::{apply_filter, load_tasks};
use crate::errors::RustpenError;

pub(crate) enum GlobalNormalAction {
    Handled,
    Unhandled,
    Quit,
}

pub(crate) struct GlobalNormalCtx<'a> {
    pub(crate) pane: &'a mut MainPane,
    pub(crate) detail_scroll: &'a mut u16,
    pub(crate) effect_scroll: &'a mut u16,

    pub(crate) input_mode: &'a mut InputMode,
    pub(crate) cmd_buffer: &'a mut String,
    pub(crate) status_line: &'a mut String,

    pub(crate) mini_console_visible: &'a mut bool,
    pub(crate) mini_console_layout: &'a mut MiniConsoleLayout,
    pub(crate) mini_popup_mode: &'a mut bool,
    pub(crate) mini_popup_saved_geom: &'a mut Option<(u16, u16, u16, u16)>,
    pub(crate) mini_float_x_pct: &'a mut u16,
    pub(crate) mini_float_y_pct: &'a mut u16,
    pub(crate) mini_float_w_pct: &'a mut u16,
    pub(crate) mini_float_h_pct: &'a mut u16,
    pub(crate) mini_console_tab: &'a mut MiniConsoleTab,
    pub(crate) mini_console_scroll: &'a mut u16,

    pub(crate) root_ws: &'a PathBuf,
    pub(crate) current_project: &'a PathBuf,
    pub(crate) scripts_dir: &'a PathBuf,
    pub(crate) filter: StatusFilter,
    pub(crate) script_dirty: bool,
    pub(crate) script_buffer: &'a mut String,

    pub(crate) projects: &'a mut Vec<ProjectEntry>,
    pub(crate) project_selected: &'a mut usize,
    pub(crate) all_tasks: &'a mut Vec<TaskView>,
    pub(crate) tasks: &'a mut Vec<TaskView>,
    pub(crate) scripts: &'a mut Vec<PathBuf>,
    pub(crate) task_selected: &'a mut usize,
    pub(crate) result_selected: &'a mut usize,
    pub(crate) script_selected: &'a mut usize,
}

pub(crate) fn handle_global_normal_key(
    key: KeyCode,
    modifiers: KeyModifiers,
    ctx: &mut GlobalNormalCtx<'_>,
) -> Result<GlobalNormalAction, RustpenError> {
    match key {
        KeyCode::Char('q') => return Ok(GlobalNormalAction::Quit),
        KeyCode::Char('1') => {
            *ctx.pane = MainPane::Dashboard;
            *ctx.detail_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('2') => {
            *ctx.pane = MainPane::Tasks;
            *ctx.detail_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('3') => {
            *ctx.pane = MainPane::Launcher;
            *ctx.detail_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('4') => {
            *ctx.pane = MainPane::Scripts;
            *ctx.detail_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('5') => {
            *ctx.pane = MainPane::Results;
            *ctx.effect_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('6') => {
            *ctx.pane = MainPane::Projects;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('[') if *ctx.mini_console_visible => {
            *ctx.mini_console_tab = ctx.mini_console_tab.prev();
            *ctx.mini_console_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char(']') if *ctx.mini_console_visible => {
            *ctx.mini_console_tab = ctx.mini_console_tab.next();
            *ctx.mini_console_scroll = 0;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('K') | KeyCode::Char('k') if *ctx.mini_console_visible => {
            *ctx.mini_console_scroll = ctx.mini_console_scroll.saturating_sub(3);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('J') | KeyCode::Char('j') if *ctx.mini_console_visible => {
            *ctx.mini_console_scroll = ctx.mini_console_scroll.saturating_add(3);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('v') => {
            *ctx.mini_console_visible = !*ctx.mini_console_visible;
            *ctx.status_line = if *ctx.mini_console_visible {
                "mini console: on".to_string()
            } else {
                "mini console: off".to_string()
            };
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('b') => {
            *ctx.mini_console_layout = ctx.mini_console_layout.next();
            if *ctx.mini_console_layout != MiniConsoleLayout::Floating {
                *ctx.mini_popup_mode = false;
                *ctx.mini_popup_saved_geom = None;
            }
            *ctx.status_line = format!("mini console layout: {}", ctx.mini_console_layout.label());
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('z') => {
            *ctx.mini_console_layout = match *ctx.mini_console_layout {
                MiniConsoleLayout::DockRightBottom => MiniConsoleLayout::DockLeftBottom,
                MiniConsoleLayout::DockLeftBottom => MiniConsoleLayout::DockRightBottom,
                MiniConsoleLayout::Floating => MiniConsoleLayout::DockRightBottom,
            };
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.status_line = format!("mini console dock: {}", ctx.mini_console_layout.label());
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('p') => {
            if !*ctx.mini_console_visible {
                *ctx.mini_console_visible = true;
            }
            if *ctx.mini_console_layout != MiniConsoleLayout::Floating {
                *ctx.mini_console_layout = MiniConsoleLayout::Floating;
            }
            if *ctx.mini_popup_mode {
                if let Some((x, y, w, h)) = ctx.mini_popup_saved_geom.take() {
                    *ctx.mini_float_x_pct = x;
                    *ctx.mini_float_y_pct = y;
                    *ctx.mini_float_w_pct = w;
                    *ctx.mini_float_h_pct = h;
                } else {
                    *ctx.mini_float_x_pct = 52;
                    *ctx.mini_float_y_pct = 58;
                    *ctx.mini_float_w_pct = 46;
                    *ctx.mini_float_h_pct = 36;
                }
                *ctx.mini_popup_mode = false;
                *ctx.status_line = "mini console popup: off".to_string();
            } else {
                *ctx.mini_popup_saved_geom = Some((
                    *ctx.mini_float_x_pct,
                    *ctx.mini_float_y_pct,
                    *ctx.mini_float_w_pct,
                    *ctx.mini_float_h_pct,
                ));
                *ctx.mini_float_x_pct = 4;
                *ctx.mini_float_y_pct = 6;
                *ctx.mini_float_w_pct = 92;
                *ctx.mini_float_h_pct = 84;
                *ctx.mini_popup_mode = true;
                *ctx.status_line = "mini console popup: on".to_string();
            }
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('0')
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating =>
        {
            *ctx.mini_float_x_pct = 52;
            *ctx.mini_float_y_pct = 58;
            *ctx.mini_float_w_pct = 46;
            *ctx.mini_float_h_pct = 36;
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.status_line = "mini console float geometry reset".to_string();
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Left
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::CONTROL) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_x_pct = ctx.mini_float_x_pct.saturating_sub(5);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Right
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::CONTROL) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_x_pct = (*ctx.mini_float_x_pct + 5).min(100);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Up
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::CONTROL) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_y_pct = ctx.mini_float_y_pct.saturating_sub(5);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Down
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::CONTROL) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_y_pct = (*ctx.mini_float_y_pct + 5).min(100);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Left
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::ALT) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_w_pct = ctx.mini_float_w_pct.saturating_sub(5).max(25);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Right
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::ALT) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_w_pct = (*ctx.mini_float_w_pct + 5).min(90);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Up
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::ALT) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_h_pct = ctx.mini_float_h_pct.saturating_sub(5).max(20);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Down
            if *ctx.mini_console_visible
                && *ctx.mini_console_layout == MiniConsoleLayout::Floating
                && modifiers.contains(KeyModifiers::ALT) =>
        {
            *ctx.mini_popup_mode = false;
            *ctx.mini_popup_saved_geom = None;
            *ctx.mini_float_h_pct = (*ctx.mini_float_h_pct + 5).min(90);
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char(':') => {
            ctx.cmd_buffer.clear();
            *ctx.input_mode = InputMode::CommandInput;
            return Ok(GlobalNormalAction::Handled);
        }
        KeyCode::Char('r') => {
            *ctx.projects = load_projects(ctx.root_ws)?;
            *ctx.project_selected =
                (*ctx.project_selected).min(ctx.projects.len().saturating_sub(1));
            *ctx.all_tasks = load_tasks(ctx.current_project.join("tasks"))?;
            *ctx.tasks = apply_filter(ctx.all_tasks, ctx.filter);
            *ctx.scripts = load_script_files(ctx.scripts_dir)?;
            *ctx.task_selected = (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
            *ctx.result_selected =
                (*ctx.result_selected).min(ctx.all_tasks.len().saturating_sub(1));
            *ctx.script_selected = (*ctx.script_selected).min(ctx.scripts.len().saturating_sub(1));
            if let Some(path) = ctx.scripts.get(*ctx.script_selected)
                && !ctx.script_dirty
            {
                *ctx.script_buffer = read_script_text(path);
            }
            return Ok(GlobalNormalAction::Handled);
        }
        _ => {}
    }

    Ok(GlobalNormalAction::Unhandled)
}
