use std::fs;

use crossterm::event::KeyCode;

use super::{PaneNormalAction, PaneNormalCtx};
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::project_store::{
    delete_local_project, ensure_project_layout, export_project_snapshot, load_projects,
    project_name_from_path, remove_imported_project,
};
use crate::tui::reverse_workbench_support::write_active_project_hint;
use crate::tui::script_runtime::{load_script_files, read_script_text};
use crate::tui::task_store::{apply_filter, load_tasks};

pub(super) fn handle_projects_key(
    key: KeyCode,
    ctx: &mut PaneNormalCtx<'_>,
) -> Result<PaneNormalAction, RustpenError> {
    match key {
        KeyCode::Up => {
            if !ctx.projects.is_empty() {
                *ctx.project_selected = ctx.project_selected.saturating_sub(1);
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Down => {
            if !ctx.projects.is_empty() {
                *ctx.project_selected =
                    (*ctx.project_selected + 1).min(ctx.projects.len().saturating_sub(1));
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('N') | KeyCode::Char('n') => {
            ctx.project_new_buffer.clear();
            *ctx.input_mode = InputMode::ProjectNewInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('I') | KeyCode::Char('i') => {
            ctx.project_import_buffer.clear();
            *ctx.input_mode = InputMode::ProjectImportInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('C') | KeyCode::Char('c') => {
            ctx.project_copy_buffer.clear();
            *ctx.input_mode = InputMode::ProjectCopyInput;
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('M') | KeyCode::Char('m') => {
            if let Some(sel) = ctx.projects.get(*ctx.project_selected) {
                if sel.imported {
                    *ctx.status_line = "导入项目不能直接重命名，可先复制为本地项目".to_string();
                } else {
                    *ctx.project_rename_buffer = project_name_from_path(&sel.path);
                    *ctx.input_mode = InputMode::ProjectRenameInput;
                }
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('T') | KeyCode::Char('t') => {
            *ctx.project_template = ctx.project_template.next();
            *ctx.status_line = format!("新建项目模板已切换: {}", ctx.project_template.label());
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('E') | KeyCode::Char('e') => {
            if let Some(sel) = ctx.projects.get(*ctx.project_selected) {
                match export_project_snapshot(ctx.root_ws, &sel.path) {
                    Ok(out) => {
                        *ctx.status_line = format!("项目已导出快照: {}", out.display());
                    }
                    Err(e) => {
                        *ctx.status_line = format!("项目导出失败: {}", e);
                    }
                }
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Char('D') | KeyCode::Char('d') => {
            if let Some(sel) = ctx.projects.get(*ctx.project_selected).cloned() {
                if sel.path == *ctx.current_project {
                    *ctx.status_line = "当前激活项目不能删除/移除，请先切换到其他项目".to_string();
                } else if sel.imported {
                    remove_imported_project(ctx.root_ws, &sel.path)?;
                    *ctx.projects = load_projects(ctx.root_ws)?;
                    *ctx.project_selected =
                        (*ctx.project_selected).min(ctx.projects.len().saturating_sub(1));
                    *ctx.status_line = format!("已移除导入项目: {}", sel.path.display());
                } else {
                    delete_local_project(ctx.root_ws, &sel.path)?;
                    *ctx.projects = load_projects(ctx.root_ws)?;
                    *ctx.project_selected =
                        (*ctx.project_selected).min(ctx.projects.len().saturating_sub(1));
                    *ctx.status_line = format!("已删除项目: {}", sel.path.display());
                }
            }
            Ok(PaneNormalAction::Handled)
        }
        KeyCode::Enter => {
            if *ctx.script_running {
                *ctx.status_line = "脚本正在运行，暂不可切换项目".to_string();
            } else if let Some(sel) = ctx.projects.get(*ctx.project_selected).cloned() {
                *ctx.current_project = sel.path;
                ensure_project_layout(ctx.current_project)?;
                *ctx.scripts_dir = ctx.current_project.join("scripts");
                let _ = fs::create_dir_all(&*ctx.scripts_dir);
                *ctx.all_tasks = load_tasks(ctx.current_project.clone())?;
                *ctx.tasks = apply_filter(ctx.all_tasks, *ctx.filter);
                *ctx.scripts = load_script_files(ctx.scripts_dir)?;
                *ctx.task_selected = (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
                *ctx.result_selected =
                    (*ctx.result_selected).min(ctx.all_tasks.len().saturating_sub(1));
                *ctx.script_selected =
                    (*ctx.script_selected).min(ctx.scripts.len().saturating_sub(1));
                if !*ctx.script_dirty {
                    if let Some(path) = ctx.scripts.get(*ctx.script_selected) {
                        *ctx.script_buffer = read_script_text(path);
                    } else {
                        ctx.script_buffer.clear();
                    }
                }
                let _ = write_active_project_hint(ctx.root_ws, ctx.current_project);
                *ctx.status_line = format!("已切换项目: {}", ctx.current_project.display());
            }
            Ok(PaneNormalAction::Handled)
        }
        _ => Ok(PaneNormalAction::Unhandled),
    }
}
