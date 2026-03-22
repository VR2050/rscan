use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};

use crate::errors::RustpenError;

use super::models::{ProjectEntry, StatusFilter, TaskView};
use super::project_store::{ensure_project_layout, load_projects, same_path};
use super::reverse_workbench_support::{
    read_active_project_hint, shorten_id, write_active_project_hint,
};
use super::task_actions::{open_task_artifacts_by_id, open_task_logs_by_id, open_task_shell_by_id};
use super::task_store::apply_filter;

#[path = "native_hubs_support.rs"]
mod support;
#[path = "native_hubs_view.rs"]
mod view;

use support::{
    build_task_detail_lines, build_task_preview_lines, edge_index, focus_lower_shell,
    load_recent_scripts, load_recent_tasks, open_project_shell, resolve_project, run_inspect_hub,
    run_script_in_work_tab, run_work_hub, shell_quote, shifted_index, task_detail_cache_signature,
};

const AUTO_REFRESH_INTERVAL: Duration = Duration::from_millis(1400);
const MAX_RECENT_TASKS: usize = 12;
const MAX_RECENT_SCRIPTS: usize = 10;
const LOG_TAIL_MAX_BYTES: u64 = 8192;
const LOG_TAIL_MAX_LINES: usize = 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WorkFocus {
    Projects,
    Tasks,
    Scripts,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InspectFocus {
    Projects,
    Tasks,
}

struct WorkHubState {
    root_ws: PathBuf,
    projects: Vec<ProjectEntry>,
    active_project: PathBuf,
    selected_project: usize,
    tasks: Vec<TaskView>,
    selected_task: usize,
    scripts: Vec<PathBuf>,
    selected_script: usize,
    focus: WorkFocus,
    message: String,
    last_refresh: Instant,
}

struct InspectHubState {
    root_ws: PathBuf,
    projects: Vec<ProjectEntry>,
    active_project: PathBuf,
    selected_project: usize,
    tasks: Vec<TaskView>,
    selected_task: usize,
    focus: InspectFocus,
    status_filter: StatusFilter,
    detail_lines: Vec<String>,
    preview_lines: Vec<String>,
    detail_cache_signature: Option<u64>,
    message: String,
    last_refresh: Instant,
}

pub(crate) fn run_work_hub_entry(workspace: Option<PathBuf>) -> Result<(), RustpenError> {
    let root_ws =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    run_work_hub(root_ws)
}

pub(crate) fn run_inspect_hub_entry(workspace: Option<PathBuf>) -> Result<(), RustpenError> {
    let root_ws =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    run_inspect_hub(root_ws)
}

pub(crate) fn build_work_hub_command(exe: &str, workspace: &Path) -> String {
    format!(
        "{} pane --kind work --workspace {}",
        shell_quote(exe),
        shell_quote(&workspace.display().to_string())
    )
}

pub(crate) fn build_inspect_hub_command(exe: &str, workspace: &Path) -> String {
    format!(
        "{} pane --kind inspect --workspace {}",
        shell_quote(exe),
        shell_quote(&workspace.display().to_string())
    )
}

impl WorkHubState {
    fn new(root_ws: PathBuf) -> Result<Self, RustpenError> {
        let active_project = resolve_project(&root_ws)?;
        let mut state = Self {
            root_ws,
            projects: Vec::new(),
            active_project,
            selected_project: 0,
            tasks: Vec::new(),
            selected_task: 0,
            scripts: Vec::new(),
            selected_script: 0,
            focus: WorkFocus::Tasks,
            message: "Enter=执行当前焦点动作  h/l=切焦点  b=跳下方 shell".to_string(),
            last_refresh: Instant::now() - AUTO_REFRESH_INTERVAL,
        };
        state.refresh(true)?;
        Ok(state)
    }

    fn refresh(&mut self, force: bool) -> Result<(), RustpenError> {
        if !force && self.last_refresh.elapsed() < AUTO_REFRESH_INTERVAL {
            return Ok(());
        }
        let preferred_task = self.selected_task_id();
        let preferred_script = self.selected_script_path();
        self.projects = load_projects(&self.root_ws)?;
        self.sync_active_project();

        let tasks = load_recent_tasks(&self.active_project);
        self.selected_task = preferred_task
            .and_then(|id| tasks.iter().position(|task| task.meta.id == id))
            .unwrap_or(self.selected_task.min(tasks.len().saturating_sub(1)));
        self.tasks = tasks;

        let scripts = load_recent_scripts(&self.active_project);
        self.selected_script = preferred_script
            .and_then(|path| scripts.iter().position(|item| same_path(item, &path)))
            .unwrap_or(self.selected_script.min(scripts.len().saturating_sub(1)));
        self.scripts = scripts;
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.message = "Work hub 已刷新".to_string();
            }
            KeyCode::Char('b') => self.message = focus_lower_shell(),
            KeyCode::Left | KeyCode::Char('h') => self.focus = self.focus.prev(),
            KeyCode::Right | KeyCode::Char('l') => self.focus = self.focus.next(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1)?,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1)?,
            KeyCode::PageUp => self.move_selection(-5)?,
            KeyCode::PageDown => self.move_selection(5)?,
            KeyCode::Home | KeyCode::Char('g') => self.move_to_edge(true)?,
            KeyCode::End | KeyCode::Char('G') => self.move_to_edge(false)?,
            KeyCode::Enter => self.open_focused_item(),
            _ => {}
        }
        Ok(false)
    }

    fn move_selection(&mut self, delta: isize) -> Result<(), RustpenError> {
        match self.focus {
            WorkFocus::Projects => {
                self.selected_project =
                    shifted_index(self.selected_project, self.projects.len(), delta);
                self.activate_selected_project()?;
            }
            WorkFocus::Tasks => {
                self.selected_task = shifted_index(self.selected_task, self.tasks.len(), delta)
            }
            WorkFocus::Scripts => {
                self.selected_script =
                    shifted_index(self.selected_script, self.scripts.len(), delta)
            }
        }
        Ok(())
    }

    fn move_to_edge(&mut self, top: bool) -> Result<(), RustpenError> {
        match self.focus {
            WorkFocus::Projects => {
                self.selected_project = edge_index(self.projects.len(), top);
                self.activate_selected_project()?;
            }
            WorkFocus::Tasks => self.selected_task = edge_index(self.tasks.len(), top),
            WorkFocus::Scripts => self.selected_script = edge_index(self.scripts.len(), top),
        }
        Ok(())
    }

    fn open_focused_item(&mut self) {
        self.message = match self.focus {
            WorkFocus::Projects => open_project_shell(&self.active_project),
            WorkFocus::Tasks => self
                .selected_task_id()
                .map(|id| open_task_shell_by_id(&self.active_project, &id))
                .unwrap_or_else(|| "当前 project 没有 recent task".to_string()),
            WorkFocus::Scripts => self
                .selected_script_path()
                .map(|path| run_script_in_work_tab(&self.active_project, &path))
                .unwrap_or_else(|| "当前 project 没有可运行脚本".to_string()),
        };
    }

    fn sync_active_project(&mut self) {
        if self.projects.is_empty() {
            self.active_project = self.root_ws.clone();
            let _ = ensure_project_layout(&self.active_project);
            self.selected_project = 0;
            return;
        }
        let preferred =
            read_active_project_hint(&self.root_ws).unwrap_or_else(|| self.active_project.clone());
        let selected = self
            .projects
            .iter()
            .position(|project| same_path(&project.path, &preferred))
            .or_else(|| {
                self.projects
                    .iter()
                    .position(|project| same_path(&project.path, &self.active_project))
            })
            .unwrap_or(0);
        self.selected_project = selected;
        self.active_project = self.projects[selected].path.clone();
        let _ = ensure_project_layout(&self.active_project);
        let _ = write_active_project_hint(&self.root_ws, &self.active_project);
    }

    fn activate_selected_project(&mut self) -> Result<(), RustpenError> {
        if let Some(project) = self.projects.get(self.selected_project)
            && !same_path(&self.active_project, &project.path)
        {
            self.active_project = project.path.clone();
            ensure_project_layout(&self.active_project)?;
            let _ = write_active_project_hint(&self.root_ws, &self.active_project);
            self.selected_task = 0;
            self.selected_script = 0;
            self.message = format!("active project -> {}", self.active_project.display());
            self.refresh(true)?;
        }
        Ok(())
    }

    fn selected_task_id(&self) -> Option<String> {
        self.tasks
            .get(self.selected_task)
            .map(|task| task.meta.id.clone())
    }

    fn selected_script_path(&self) -> Option<PathBuf> {
        self.scripts.get(self.selected_script).cloned()
    }
}

impl InspectHubState {
    fn new(root_ws: PathBuf) -> Result<Self, RustpenError> {
        let active_project = resolve_project(&root_ws)?;
        let mut state = Self {
            root_ws,
            projects: Vec::new(),
            active_project,
            selected_project: 0,
            tasks: Vec::new(),
            selected_task: 0,
            focus: InspectFocus::Tasks,
            status_filter: StatusFilter::All,
            detail_lines: Vec::new(),
            preview_lines: Vec::new(),
            detail_cache_signature: None,
            message: "Enter/L=开日志  A=artifacts  W=shell  F=状态过滤".to_string(),
            last_refresh: Instant::now() - AUTO_REFRESH_INTERVAL,
        };
        state.refresh(true)?;
        Ok(state)
    }

    fn refresh(&mut self, force: bool) -> Result<(), RustpenError> {
        if !force && self.last_refresh.elapsed() < AUTO_REFRESH_INTERVAL {
            return Ok(());
        }
        let preferred_task = self.selected_task_id();
        self.projects = load_projects(&self.root_ws)?;
        self.sync_active_project();

        let filtered = apply_filter(&load_recent_tasks(&self.active_project), self.status_filter);
        self.selected_task = preferred_task
            .and_then(|id| filtered.iter().position(|task| task.meta.id == id))
            .unwrap_or(self.selected_task.min(filtered.len().saturating_sub(1)));
        self.tasks = filtered;
        self.rebuild_detail_cache();
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.message = "Inspect hub 已刷新".to_string();
            }
            KeyCode::Char('b') => self.message = focus_lower_shell(),
            KeyCode::Char('f') => {
                self.status_filter = self.status_filter.next();
                self.selected_task = 0;
                self.refresh(true)?;
                self.message = format!("status filter -> {}", self.status_filter.label());
            }
            KeyCode::Left | KeyCode::Char('h') => self.focus = self.focus.prev(),
            KeyCode::Right => {
                if self.focus == InspectFocus::Tasks {
                    self.open_logs();
                } else {
                    self.focus = self.focus.next();
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1)?,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1)?,
            KeyCode::PageUp => self.move_selection(-5)?,
            KeyCode::PageDown => self.move_selection(5)?,
            KeyCode::Home | KeyCode::Char('g') => self.move_to_edge(true)?,
            KeyCode::End | KeyCode::Char('G') => self.move_to_edge(false)?,
            KeyCode::Enter | KeyCode::Char('L') | KeyCode::Char('l') => self.open_logs(),
            KeyCode::Char('a') | KeyCode::Char('A') => self.open_artifacts(),
            KeyCode::Char('w') | KeyCode::Char('W') => self.open_shell(),
            _ => {}
        }
        Ok(false)
    }

    fn move_selection(&mut self, delta: isize) -> Result<(), RustpenError> {
        match self.focus {
            InspectFocus::Projects => {
                self.selected_project =
                    shifted_index(self.selected_project, self.projects.len(), delta);
                self.activate_selected_project()?;
            }
            InspectFocus::Tasks => {
                self.selected_task = shifted_index(self.selected_task, self.tasks.len(), delta);
                self.rebuild_detail_cache();
            }
        }
        Ok(())
    }

    fn move_to_edge(&mut self, top: bool) -> Result<(), RustpenError> {
        match self.focus {
            InspectFocus::Projects => {
                self.selected_project = edge_index(self.projects.len(), top);
                self.activate_selected_project()?;
            }
            InspectFocus::Tasks => {
                self.selected_task = edge_index(self.tasks.len(), top);
                self.rebuild_detail_cache();
            }
        }
        Ok(())
    }

    fn open_logs(&mut self) {
        self.message = self
            .selected_task_id()
            .map(|id| open_task_logs_by_id(&self.active_project, &id))
            .unwrap_or_else(|| "当前过滤条件下没有可查看的任务".to_string());
    }

    fn open_artifacts(&mut self) {
        self.message = self
            .selected_task_id()
            .map(|id| open_task_artifacts_by_id(&self.active_project, &id))
            .unwrap_or_else(|| "当前过滤条件下没有 artifact 可开".to_string());
    }

    fn open_shell(&mut self) {
        self.message = self
            .selected_task_id()
            .map(|id| open_task_shell_by_id(&self.active_project, &id))
            .unwrap_or_else(|| "当前过滤条件下没有 shell 可开".to_string());
    }

    fn sync_active_project(&mut self) {
        if self.projects.is_empty() {
            self.active_project = self.root_ws.clone();
            let _ = ensure_project_layout(&self.active_project);
            self.selected_project = 0;
            return;
        }
        let preferred =
            read_active_project_hint(&self.root_ws).unwrap_or_else(|| self.active_project.clone());
        let selected = self
            .projects
            .iter()
            .position(|project| same_path(&project.path, &preferred))
            .or_else(|| {
                self.projects
                    .iter()
                    .position(|project| same_path(&project.path, &self.active_project))
            })
            .unwrap_or(0);
        self.selected_project = selected;
        self.active_project = self.projects[selected].path.clone();
        let _ = ensure_project_layout(&self.active_project);
        let _ = write_active_project_hint(&self.root_ws, &self.active_project);
    }

    fn activate_selected_project(&mut self) -> Result<(), RustpenError> {
        if let Some(project) = self.projects.get(self.selected_project)
            && !same_path(&self.active_project, &project.path)
        {
            self.active_project = project.path.clone();
            ensure_project_layout(&self.active_project)?;
            let _ = write_active_project_hint(&self.root_ws, &self.active_project);
            self.selected_task = 0;
            self.message = format!("active project -> {}", self.active_project.display());
            self.refresh(true)?;
        }
        Ok(())
    }

    fn rebuild_detail_cache(&mut self) {
        if let Some(task) = self.tasks.get(self.selected_task) {
            let signature = task_detail_cache_signature(task);
            if self.detail_cache_signature == Some(signature) {
                return;
            }
            self.detail_lines = build_task_detail_lines(&self.active_project, task);
            self.preview_lines = build_task_preview_lines(task);
            self.detail_cache_signature = Some(signature);
        } else {
            self.detail_lines = vec![
                "no task selected".to_string(),
                "当前 project / filter 下没有可展示任务".to_string(),
            ];
            self.preview_lines = vec!["no log preview".to_string()];
            self.detail_cache_signature = Some(0);
        }
    }

    fn selected_task_id(&self) -> Option<String> {
        self.tasks
            .get(self.selected_task)
            .map(|task| task.meta.id.clone())
    }
}

impl WorkFocus {
    fn next(self) -> Self {
        match self {
            WorkFocus::Projects => WorkFocus::Tasks,
            WorkFocus::Tasks => WorkFocus::Scripts,
            WorkFocus::Scripts => WorkFocus::Projects,
        }
    }

    fn prev(self) -> Self {
        match self {
            WorkFocus::Projects => WorkFocus::Scripts,
            WorkFocus::Tasks => WorkFocus::Projects,
            WorkFocus::Scripts => WorkFocus::Tasks,
        }
    }
}

impl InspectFocus {
    fn next(self) -> Self {
        match self {
            InspectFocus::Projects => InspectFocus::Tasks,
            InspectFocus::Tasks => InspectFocus::Projects,
        }
    }

    fn prev(self) -> Self {
        self.next()
    }
}
