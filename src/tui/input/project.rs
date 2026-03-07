use std::fs;
use std::path::PathBuf;

use crossterm::event::KeyCode;

use super::NonNormalInputCtx;
use crate::errors::RustpenError;
use crate::tui::models::InputMode;
use crate::tui::project_store::{
    copy_project_to_local, create_local_project, import_project, load_projects,
    rename_local_project, same_path,
};
use crate::tui::script_runtime::{load_script_files, read_script_text};
use crate::tui::task_store::{apply_filter, load_tasks};

pub(super) fn handle_project_new_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.project_new_buffer.clear();
        }
        KeyCode::Enter => {
            let name = ctx.project_new_buffer.trim().to_string();
            if name.is_empty() {
                *ctx.status_line = "项目名不能为空".to_string();
            } else {
                match create_local_project(ctx.root_ws, &name, ctx.project_template) {
                    Ok(path) => {
                        *ctx.projects = load_projects(ctx.root_ws)?;
                        if let Some(pos) = ctx.projects.iter().position(|p| p.path == path) {
                            *ctx.project_selected = pos;
                        }
                        *ctx.status_line = format!("已创建项目: {}", path.display());
                    }
                    Err(e) => {
                        *ctx.status_line = format!("创建项目失败: {}", e);
                    }
                }
            }
            ctx.project_new_buffer.clear();
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.project_new_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.project_new_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn handle_project_import_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.project_import_buffer.clear();
        }
        KeyCode::Enter => {
            let raw = ctx.project_import_buffer.trim().to_string();
            if raw.is_empty() {
                *ctx.status_line = "导入路径不能为空".to_string();
            } else {
                let path = PathBuf::from(raw);
                match import_project(ctx.root_ws, &path) {
                    Ok(imported) => {
                        *ctx.projects = load_projects(ctx.root_ws)?;
                        if let Some(pos) = ctx
                            .projects
                            .iter()
                            .position(|p| same_path(&p.path, &imported))
                        {
                            *ctx.project_selected = pos;
                        }
                        *ctx.status_line = format!("导入成功: {}", imported.display());
                    }
                    Err(e) => {
                        *ctx.status_line = format!("导入项目失败: {}", e);
                    }
                }
            }
            ctx.project_import_buffer.clear();
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.project_import_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.project_import_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn handle_project_copy_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.project_copy_buffer.clear();
        }
        KeyCode::Enter => {
            let name = ctx.project_copy_buffer.trim().to_string();
            if name.is_empty() {
                *ctx.status_line = "复制项目名不能为空".to_string();
            } else if let Some(sel) = ctx.projects.get(*ctx.project_selected).cloned() {
                match copy_project_to_local(ctx.root_ws, &sel.path, &name) {
                    Ok(new_path) => {
                        *ctx.projects = load_projects(ctx.root_ws)?;
                        if let Some(pos) = ctx
                            .projects
                            .iter()
                            .position(|p| same_path(&p.path, &new_path))
                        {
                            *ctx.project_selected = pos;
                        }
                        *ctx.status_line = format!("项目复制完成: {}", new_path.display());
                    }
                    Err(e) => {
                        *ctx.status_line = format!("复制项目失败: {}", e);
                    }
                }
            }
            ctx.project_copy_buffer.clear();
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.project_copy_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.project_copy_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}

pub(super) fn handle_project_rename_input(
    key: KeyCode,
    ctx: &mut NonNormalInputCtx<'_>,
) -> Result<(), RustpenError> {
    match key {
        KeyCode::Esc => {
            *ctx.input_mode = InputMode::Normal;
            ctx.project_rename_buffer.clear();
        }
        KeyCode::Enter => {
            let name = ctx.project_rename_buffer.trim().to_string();
            if name.is_empty() {
                *ctx.status_line = "重命名项目名不能为空".to_string();
            } else if let Some(sel) = ctx.projects.get(*ctx.project_selected).cloned() {
                if sel.imported {
                    *ctx.status_line = "导入项目不能直接重命名，可先复制为本地项目".to_string();
                } else if ctx.script_running && sel.path == *ctx.current_project {
                    *ctx.status_line = "脚本运行中，暂不可重命名当前项目".to_string();
                } else if *ctx.script_dirty && sel.path == *ctx.current_project {
                    *ctx.status_line = "当前脚本有未保存内容，先保存再重命名项目".to_string();
                } else {
                    match rename_local_project(ctx.root_ws, &sel.path, &name) {
                        Ok(new_path) => {
                            if same_path(ctx.current_project, &sel.path) {
                                *ctx.current_project = new_path.clone();
                                *ctx.scripts_dir = ctx.current_project.join("scripts");
                                let _ = fs::create_dir_all(&*ctx.scripts_dir);
                                *ctx.all_tasks = load_tasks(ctx.current_project.join("tasks"))?;
                                *ctx.tasks = apply_filter(ctx.all_tasks, ctx.filter);
                                *ctx.scripts = load_script_files(ctx.scripts_dir)?;
                                *ctx.task_selected =
                                    (*ctx.task_selected).min(ctx.tasks.len().saturating_sub(1));
                                *ctx.script_selected =
                                    (*ctx.script_selected).min(ctx.scripts.len().saturating_sub(1));
                                if let Some(path) = ctx.scripts.get(*ctx.script_selected) {
                                    *ctx.script_buffer = read_script_text(path);
                                } else {
                                    ctx.script_buffer.clear();
                                }
                            }
                            *ctx.projects = load_projects(ctx.root_ws)?;
                            if let Some(pos) = ctx
                                .projects
                                .iter()
                                .position(|p| same_path(&p.path, &new_path))
                            {
                                *ctx.project_selected = pos;
                            }
                            *ctx.status_line = format!("项目重命名完成: {}", new_path.display());
                        }
                        Err(e) => {
                            *ctx.status_line = format!("重命名项目失败: {}", e);
                        }
                    }
                }
            }
            ctx.project_rename_buffer.clear();
            *ctx.input_mode = InputMode::Normal;
        }
        KeyCode::Backspace => {
            ctx.project_rename_buffer.pop();
        }
        KeyCode::Char(c) => {
            ctx.project_rename_buffer.push(c);
        }
        _ => {}
    }

    Ok(())
}
