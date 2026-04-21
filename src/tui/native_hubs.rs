use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;

use crate::errors::RustpenError;
use crate::tui::command_catalog::{completion_heads, launcher_commands};
use crate::tui::command_exec::execute_short_command;
use crate::tui::script_runtime::{create_script_file, open_script_in_helix};

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
    build_task_detail_lines, build_task_preview_lines, build_work_result_lines, edge_index,
    focus_lower_shell, load_recent_scripts, load_recent_tasks, open_project_shell, resolve_project,
    run_inspect_hub, run_script_in_work_tab, run_work_hub, shell_quote, shifted_index,
    task_detail_cache_signature,
};

const AUTO_REFRESH_INTERVAL: Duration = Duration::from_millis(350);
const MAX_RECENT_TASKS: usize = 12;
const MAX_RECENT_SCRIPTS: usize = 10;
const LOG_TAIL_MAX_BYTES: u64 = 8192;
const LOG_TAIL_MAX_LINES: usize = 10;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WorkFocus {
    Projects,
    Tasks,
    Scripts,
    Results,
    Templates,
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
    result_scroll: usize,
    focus: WorkFocus,
    command_mode: bool,
    command_buffer: String,
    command_candidates: Vec<String>,
    command_candidate_idx: usize,
    script_new_mode: bool,
    script_new_buffer: String,
    launcher_items: Vec<(&'static str, &'static str)>,
    selected_template: usize,
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
            result_scroll: 0,
            focus: WorkFocus::Tasks,
            command_mode: false,
            command_buffer: String::new(),
            command_candidates: Vec::new(),
            command_candidate_idx: 0,
            script_new_mode: false,
            script_new_buffer: String::new(),
            launcher_items: launcher_commands(),
            selected_template: 0,
            message:
                "Enter=执行当前焦点动作  :=任务命令(Tab补全)  1=模板区  2=脚本编辑区  3=结果区  N=新建脚本  E=编辑脚本  h/l/tab=切焦点  b=下方shell"
                    .to_string(),
            last_refresh: Instant::now() - AUTO_REFRESH_INTERVAL,
        };
        state.refresh(true)?;
        Ok(state)
    }

    fn refresh(&mut self, force: bool) -> Result<(), RustpenError> {
        if !force && self.last_refresh.elapsed() < AUTO_REFRESH_INTERVAL {
            return Ok(());
        }
        let previous_task = self.selected_task_id();
        let preferred_task = self.selected_task_id();
        let preferred_script = self.selected_script_path();
        self.projects = load_projects(&self.root_ws)?;
        self.sync_active_project();

        let tasks = load_recent_tasks(&self.active_project);
        self.selected_task = preferred_task
            .and_then(|id| tasks.iter().position(|task| task.meta.id == id))
            .unwrap_or(self.selected_task.min(tasks.len().saturating_sub(1)));
        self.tasks = tasks;
        if self.selected_task_id() != previous_task {
            self.result_scroll = 0;
        }
        self.clamp_result_scroll();

        let scripts = load_recent_scripts(&self.active_project);
        self.selected_script = preferred_script
            .and_then(|path| scripts.iter().position(|item| same_path(item, &path)))
            .unwrap_or(self.selected_script.min(scripts.len().saturating_sub(1)));
        self.scripts = scripts;
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        // In normal mode only react to key press; in input modes accept repeat too.
        if !self.command_mode && !self.script_new_mode && key.kind != KeyEventKind::Press {
            return Ok(false);
        }
        if has_reserved_modifiers(key.modifiers) {
            return Ok(false);
        }
        if self.command_mode {
            self.handle_command_input(key)?;
            return Ok(false);
        }
        if self.script_new_mode {
            self.handle_script_new_input(key)?;
            return Ok(false);
        }
        match key.code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.message = "Work hub 已刷新".to_string();
            }
            KeyCode::Char('1') => self.focus = WorkFocus::Templates,
            KeyCode::Char('2') => {
                self.focus = WorkFocus::Scripts;
                self.prepare_script_workspace()?;
            }
            KeyCode::Char('3') => self.focus = WorkFocus::Results,
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::Char(':') => self.enter_command_mode(),
            KeyCode::Char('i') | KeyCode::Char('I') => self.enter_command_mode(),
            KeyCode::Char('N') | KeyCode::Char('n') => {
                self.script_new_mode = true;
                self.script_new_buffer.clear();
                self.focus = WorkFocus::Scripts;
                self.message = "work.script.new> 输入脚本名(.rs 可省略)，Enter 创建".to_string();
            }
            KeyCode::Char('E') | KeyCode::Char('e') => self.open_selected_script_editor(),
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

    fn handle_mouse(&mut self, mouse: MouseEvent, area: Rect) {
        if self.command_mode || self.script_new_mode {
            return;
        }
        if let Some(hit) = view::work_focus_at(area, mouse.column, mouse.row) {
            match mouse.kind {
                MouseEventKind::Down(MouseButton::Left) => {
                    self.focus = hit;
                }
                MouseEventKind::ScrollUp => {
                    if hit == WorkFocus::Results {
                        self.focus = WorkFocus::Results;
                        self.shift_result_scroll(-3);
                    }
                }
                MouseEventKind::ScrollDown => {
                    if hit == WorkFocus::Results {
                        self.focus = WorkFocus::Results;
                        self.shift_result_scroll(3);
                    }
                }
                _ => {}
            }
        } else if matches!(
            mouse.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) && self.focus == WorkFocus::Results
        {
            if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                self.shift_result_scroll(-3);
            } else {
                self.shift_result_scroll(3);
            }
        }
    }

    fn run_work_command(&mut self, cmd: &str) -> Result<(), RustpenError> {
        let exec = execute_short_command(&self.active_project, cmd);
        self.refresh(true)?;
        if let Some(task_id) = exec.task_id.as_deref() {
            if let Some(pos) = self.tasks.iter().position(|task| task.meta.id == task_id) {
                self.selected_task = pos;
                self.focus = WorkFocus::Tasks;
                self.result_scroll = 0;
            } else {
                self.selected_task = self.selected_task.min(self.tasks.len().saturating_sub(1));
                self.clamp_result_scroll();
            }
        }
        self.message = format!("work.cmd> {}", exec.status_line);
        Ok(())
    }

    fn handle_command_input(&mut self, key: KeyEvent) -> Result<(), RustpenError> {
        if has_reserved_modifiers(key.modifiers) {
            return Ok(());
        }
        match key.code {
            KeyCode::Esc => {
                self.command_mode = false;
                self.command_candidates.clear();
                self.command_candidate_idx = 0;
                self.message = "work.cmd 已取消".to_string();
            }
            KeyCode::Enter => {
                let cmd = self.command_buffer.trim().to_string();
                self.command_mode = false;
                self.command_buffer.clear();
                self.command_candidates.clear();
                self.command_candidate_idx = 0;
                if cmd.is_empty() {
                    self.message = "work.cmd 为空，已取消".to_string();
                } else {
                    self.run_work_command(&cmd)?;
                }
            }
            KeyCode::Tab => {
                self.refresh_command_candidates();
                if self.command_candidates.is_empty() {
                    self.message = "work.cmd 无可用补全".to_string();
                } else {
                    self.command_candidate_idx =
                        (self.command_candidate_idx + 1) % self.command_candidates.len();
                    if let Some(candidate) = self.command_candidates.get(self.command_candidate_idx)
                    {
                        self.command_buffer = candidate.clone();
                        self.message = format!("work.cmd 补全 -> {candidate}");
                    }
                }
            }
            KeyCode::Backspace => {
                self.command_buffer.pop();
                self.command_candidate_idx = 0;
            }
            KeyCode::Char(ch) => {
                self.command_buffer.push(ch);
                self.command_candidate_idx = 0;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_script_new_input(&mut self, key: KeyEvent) -> Result<(), RustpenError> {
        if has_reserved_modifiers(key.modifiers) {
            return Ok(());
        }
        match key.code {
            KeyCode::Esc => {
                self.script_new_mode = false;
                self.message = "work.script.new 已取消".to_string();
            }
            KeyCode::Enter => {
                let raw_name = self.script_new_buffer.trim().to_string();
                self.script_new_mode = false;
                self.script_new_buffer.clear();
                if raw_name.is_empty() {
                    self.message = "脚本名不能为空".to_string();
                    return Ok(());
                }
                let scripts_dir = self.active_project.join("scripts");
                std::fs::create_dir_all(&scripts_dir).map_err(RustpenError::Io)?;
                match create_script_file(&scripts_dir, &raw_name) {
                    Ok(path) => {
                        self.refresh(true)?;
                        if let Some(pos) = self.scripts.iter().position(|p| same_path(p, &path)) {
                            self.selected_script = pos;
                            self.focus = WorkFocus::Scripts;
                        }
                        self.message = format!("脚本已创建: {}", path.display());
                    }
                    Err(e) => {
                        self.message = format!("脚本创建失败: {e}");
                    }
                }
            }
            KeyCode::Backspace => {
                self.script_new_buffer.pop();
            }
            KeyCode::Char(ch) => {
                self.script_new_buffer.push(ch);
            }
            _ => {}
        }
        Ok(())
    }

    fn open_selected_script_editor(&mut self) {
        let Some(path) = self.selected_script_path() else {
            self.message = "当前没有可编辑脚本；先按 N 创建".to_string();
            return;
        };
        self.message = match open_script_in_helix(&path, &self.active_project) {
            Ok(msg) => msg,
            Err(e) => format!("打开脚本编辑器失败: {e}"),
        };
    }

    fn move_selection(&mut self, delta: isize) -> Result<(), RustpenError> {
        match self.focus {
            WorkFocus::Projects => {
                self.selected_project =
                    shifted_index(self.selected_project, self.projects.len(), delta);
                self.activate_selected_project()?;
            }
            WorkFocus::Tasks => {
                self.selected_task = shifted_index(self.selected_task, self.tasks.len(), delta);
                self.result_scroll = 0;
            }
            WorkFocus::Scripts => {
                self.selected_script =
                    shifted_index(self.selected_script, self.scripts.len(), delta)
            }
            WorkFocus::Results => self.shift_result_scroll(delta),
            WorkFocus::Templates => {
                self.selected_template =
                    shifted_index(self.selected_template, self.template_item_count(), delta)
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
            WorkFocus::Tasks => {
                self.selected_task = edge_index(self.tasks.len(), top);
                self.result_scroll = 0;
            }
            WorkFocus::Scripts => self.selected_script = edge_index(self.scripts.len(), top),
            WorkFocus::Results => {
                self.result_scroll = if top { 0 } else { self.max_result_scroll() };
            }
            WorkFocus::Templates => {
                self.selected_template = edge_index(self.template_item_count(), top)
            }
        }
        Ok(())
    }

    fn open_focused_item(&mut self) {
        if self.focus == WorkFocus::Templates {
            if self.template_is_custom_command() {
                self.enter_command_mode();
                return;
            }
            if let Some((name, cmd)) = self.template_item().copied() {
                let _ = self.run_work_command(cmd);
                self.message = format!("模板已执行: {name}");
            } else {
                self.message = "当前没有可用任务模板".to_string();
            }
            return;
        }
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
            WorkFocus::Results => self
                .selected_task_id()
                .map(|id| open_task_logs_by_id(&self.active_project, &id))
                .unwrap_or_else(|| "当前没有可查看结果的任务".to_string()),
            WorkFocus::Templates => "当前没有可用任务模板".to_string(),
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
            self.result_scroll = 0;
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

    fn max_result_scroll(&self) -> usize {
        build_work_result_lines(self).len().saturating_sub(1)
    }

    fn clamp_result_scroll(&mut self) {
        self.result_scroll = self.result_scroll.min(self.max_result_scroll());
    }

    fn shift_result_scroll(&mut self, delta: isize) {
        self.result_scroll = shifted_index(self.result_scroll, self.max_result_scroll() + 1, delta);
    }

    fn refresh_command_candidates(&mut self) {
        let mut out = smart_command_candidates(&self.command_buffer);
        if out.is_empty() {
            let prefix = self.command_buffer.trim();
            for (_, cmd) in &self.launcher_items {
                if cmd.starts_with(prefix) {
                    out.push((*cmd).to_string());
                }
            }
            for head in completion_heads() {
                if head.starts_with(prefix) {
                    out.push((*head).to_string());
                }
            }
            out.sort();
            out.dedup();
        }
        self.command_candidates = out;
    }

    fn prepare_script_workspace(&mut self) -> Result<(), RustpenError> {
        let main_rs = support::ensure_work_script_project(&self.active_project)?;
        self.refresh(true)?;
        if let Some(pos) = self.scripts.iter().position(|p| same_path(p, &main_rs)) {
            self.selected_script = pos;
        }
        self.message = format!("脚本工程已就绪: {} | 可按 E 打开编辑", main_rs.display());
        Ok(())
    }

    fn enter_command_mode(&mut self) {
        self.command_mode = true;
        self.command_buffer.clear();
        self.command_candidates.clear();
        self.command_candidate_idx = 0;
        self.message = "work.cmd> 输入任务命令，Tab 补全，Enter 执行，Esc 取消".to_string();
    }

    fn template_item_count(&self) -> usize {
        self.launcher_items.len() + 1
    }

    fn template_is_custom_command(&self) -> bool {
        self.selected_template >= self.launcher_items.len()
    }

    fn template_item(&self) -> Option<&(&'static str, &'static str)> {
        self.launcher_items.get(self.selected_template)
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
            WorkFocus::Scripts => WorkFocus::Results,
            WorkFocus::Results => WorkFocus::Templates,
            WorkFocus::Templates => WorkFocus::Projects,
        }
    }

    fn prev(self) -> Self {
        match self {
            WorkFocus::Projects => WorkFocus::Templates,
            WorkFocus::Tasks => WorkFocus::Projects,
            WorkFocus::Scripts => WorkFocus::Tasks,
            WorkFocus::Results => WorkFocus::Scripts,
            WorkFocus::Templates => WorkFocus::Results,
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

fn has_reserved_modifiers(mods: KeyModifiers) -> bool {
    mods.intersects(KeyModifiers::ALT | KeyModifiers::CONTROL | KeyModifiers::SUPER)
}

fn smart_command_candidates(input: &str) -> Vec<String> {
    let trailing_ws = input.chars().last().is_some_and(char::is_whitespace);
    let raw_tokens: Vec<&str> = input.split_whitespace().collect();
    let mut stable_tokens = raw_tokens.clone();
    let current_prefix = if trailing_ws {
        ""
    } else {
        stable_tokens.pop().unwrap_or("")
    };
    let arg_index = stable_tokens.len();
    let mut out = BTreeSet::<String>::new();

    if arg_index == 0 {
        push_prefixed(&mut out, "", current_prefix, root_heads());
        return out.into_iter().collect();
    }

    let base = stable_tokens.join(" ");
    let head = raw_tokens.first().copied().unwrap_or_default();
    match head {
        "host" => suggest_host_long(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            raw_tokens.get(1).copied(),
        ),
        "web" => suggest_web_long(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            raw_tokens.get(1).copied(),
        ),
        "vuln" => suggest_vuln_long(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            raw_tokens.get(1).copied(),
        ),
        "reverse" => suggest_reverse_long(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            raw_tokens.get(1).copied(),
        ),
        "h.quick" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<host>",
            host_flags_quick(),
        ),
        "h.tcp" | "h.udp" => suggest_alias_host_ports(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            host_flags_tcp_udp_syn(),
        ),
        "h.syn" => {
            suggest_alias_host_ports(&mut out, &base, current_prefix, arg_index, host_flags_syn())
        }
        "h.arp" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<cidr>",
            host_flags_arp(),
        ),
        "w.dir" => suggest_alias_web(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<base_url>",
            "<paths_csv>",
            web_flags_dir(),
        ),
        "w.fuzz" => suggest_alias_web(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<url_with_FUZZ>",
            "<keywords_csv>",
            web_flags_fuzz(),
        ),
        "w.dns" => suggest_alias_web(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<domain>",
            "<words_csv>",
            web_flags_dns(),
        ),
        "w.crawl" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<seed_url>"]);
            } else {
                push_prefixed(&mut out, &base, current_prefix, web_flags_crawl());
            }
        }
        "w.live" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<url_csv>"]);
            } else {
                push_prefixed(&mut out, &base, current_prefix, web_flags_common());
            }
        }
        "v.lint" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<templates_path>",
            no_flags(),
        ),
        "v.scan" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<target_url>"]);
            } else if arg_index == 2 {
                push_prefixed(&mut out, &base, current_prefix, ["[templates_dir]"]);
                push_prefixed(&mut out, &base, current_prefix, vuln_scan_flags());
            } else {
                push_prefixed(&mut out, &base, current_prefix, vuln_scan_flags());
            }
        }
        "v.ca" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<manifests_path>",
            no_flags(),
        ),
        "v.sg" => {}
        "v.sc" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<target_url>",
            vuln_stealth_flags(),
        ),
        "v.fa" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<target_url>",
            vuln_fragment_flags(),
        ),
        "r.analyze" => suggest_alias_simple(
            &mut out,
            &base,
            current_prefix,
            arg_index,
            "<input_file>",
            reverse_analyze_flags(),
        ),
        "r.plan" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<input_file>"]);
            } else if arg_index == 2 {
                push_prefixed(
                    &mut out,
                    &base,
                    current_prefix,
                    ["[engine]", "objdump", "radare2", "ghidra", "jadx"],
                );
            } else {
                push_prefixed(&mut out, &base, current_prefix, reverse_plan_flags());
            }
        }
        "r.run" => suggest_reverse_run(&mut out, &base, current_prefix, arg_index),
        "r.jobs" => {}
        "r.status" | "r.artifacts" | "r.funcs" | "r.doctor" => {
            push_prefixed(&mut out, &base, current_prefix, ["<job_id>"])
        }
        "r.logs" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<job_id>"]);
            } else {
                push_prefixed(
                    &mut out,
                    &base,
                    current_prefix,
                    ["--stream", "stdout", "stderr", "both"],
                );
            }
        }
        "r.show" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<job_id>"]);
            } else {
                push_prefixed(&mut out, &base, current_prefix, ["<function>"]);
            }
        }
        "r.search" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<job_id>"]);
            } else if arg_index == 2 {
                push_prefixed(&mut out, &base, current_prefix, ["<keyword>"]);
            } else {
                push_prefixed(&mut out, &base, current_prefix, ["--max"]);
            }
        }
        "r.clear" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<job_id>", "--all"]);
            } else {
                push_prefixed(&mut out, &base, current_prefix, ["--all"]);
            }
        }
        "r.prune" => push_prefixed(&mut out, &base, current_prefix, reverse_prune_flags()),
        "r.debug" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<input_file>"]);
            } else if arg_index == 2 {
                push_prefixed(&mut out, &base, current_prefix, ["<script_out>"]);
            } else if arg_index == 3 {
                push_prefixed(
                    &mut out,
                    &base,
                    current_prefix,
                    ["[profile]", "pwngdb", "pwndbg"],
                );
            } else {
                push_prefixed(
                    &mut out,
                    &base,
                    current_prefix,
                    ["--pwndbg-init", "--profile"],
                );
            }
        }
        "zrun" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<shell_command...>"]);
            }
        }
        "zlogs" | "zshell" | "zart" => {
            if arg_index == 1 {
                push_prefixed(&mut out, &base, current_prefix, ["<task_id>"]);
            }
        }
        "zfocus" => {
            if arg_index == 1 {
                push_prefixed(
                    &mut out,
                    &base,
                    current_prefix,
                    ["control", "work", "inspect", "reverse"],
                );
            }
        }
        _ => {
            push_prefixed(&mut out, "", current_prefix, root_heads());
        }
    }
    out.into_iter().collect()
}

fn push_prefixed<I, T>(out: &mut BTreeSet<String>, base: &str, current_prefix: &str, choices: I)
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    for choice in choices {
        let choice = choice.as_ref();
        if choice.starts_with(current_prefix) {
            if base.is_empty() {
                out.insert(choice.to_string());
            } else {
                out.insert(format!("{base} {choice}"));
            }
        }
    }
}

fn suggest_alias_simple<I, T>(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    positional: &'static str,
    flags: I,
) where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    if arg_index == 1 {
        push_prefixed(out, base, prefix, [positional]);
    } else {
        push_prefixed(out, base, prefix, flags);
    }
}

fn suggest_alias_host_ports<I, T>(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    flags: I,
) where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    if arg_index == 1 {
        push_prefixed(out, base, prefix, ["<host>"]);
    } else if arg_index == 2 {
        push_prefixed(out, base, prefix, ["<ports_csv>"]);
    } else {
        push_prefixed(out, base, prefix, flags);
    }
}

fn suggest_alias_web<I, T>(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    first_pos: &'static str,
    second_pos: &'static str,
    flags: I,
) where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    if arg_index == 1 {
        push_prefixed(out, base, prefix, [first_pos]);
    } else if arg_index == 2 {
        push_prefixed(out, base, prefix, [second_pos]);
    } else {
        push_prefixed(out, base, prefix, flags);
    }
}

fn suggest_host_long(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    sub: Option<&str>,
) {
    if arg_index == 1 {
        push_prefixed(out, base, prefix, ["quick", "tcp", "udp", "syn", "arp"]);
        return;
    }
    match sub.unwrap_or_default() {
        "quick" => suggest_alias_simple(out, base, prefix, arg_index, "<host>", host_flags_quick()),
        "tcp" | "udp" => {
            suggest_alias_host_ports(out, base, prefix, arg_index, host_flags_tcp_udp_syn())
        }
        "syn" => suggest_alias_host_ports(out, base, prefix, arg_index, host_flags_syn()),
        "arp" => suggest_alias_simple(out, base, prefix, arg_index, "<cidr>", host_flags_arp()),
        _ => {}
    }
}

fn suggest_web_long(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    sub: Option<&str>,
) {
    if arg_index == 1 {
        push_prefixed(out, base, prefix, ["dir", "fuzz", "dns", "crawl", "live"]);
        return;
    }
    match sub.unwrap_or_default() {
        "dir" => suggest_alias_web(
            out,
            base,
            prefix,
            arg_index,
            "<base_url>",
            "<paths_csv>",
            web_flags_dir(),
        ),
        "fuzz" => suggest_alias_web(
            out,
            base,
            prefix,
            arg_index,
            "<url_with_FUZZ>",
            "<keywords_csv>",
            web_flags_fuzz(),
        ),
        "dns" => suggest_alias_web(
            out,
            base,
            prefix,
            arg_index,
            "<domain>",
            "<words_csv>",
            web_flags_dns(),
        ),
        "crawl" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<seed_url>"]);
            } else {
                push_prefixed(out, base, prefix, web_flags_crawl());
            }
        }
        "live" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<url_csv>"]);
            } else {
                push_prefixed(out, base, prefix, web_flags_common());
            }
        }
        _ => {}
    }
}

fn suggest_vuln_long(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    sub: Option<&str>,
) {
    if arg_index == 1 {
        push_prefixed(
            out,
            base,
            prefix,
            [
                "lint",
                "scan",
                "container-audit",
                "system-guard",
                "stealth-check",
                "fragment-audit",
            ],
        );
        return;
    }
    match sub.unwrap_or_default() {
        "lint" => {
            suggest_alias_simple(out, base, prefix, arg_index, "<templates_path>", no_flags())
        }
        "scan" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<target_url>"]);
            } else if arg_index == 3 {
                push_prefixed(out, base, prefix, ["[templates_dir]"]);
                push_prefixed(out, base, prefix, vuln_scan_flags());
            } else {
                push_prefixed(out, base, prefix, vuln_scan_flags());
            }
        }
        "container-audit" => {
            suggest_alias_simple(out, base, prefix, arg_index, "<manifests_path>", no_flags())
        }
        "system-guard" => {}
        "stealth-check" => suggest_alias_simple(
            out,
            base,
            prefix,
            arg_index,
            "<target_url>",
            vuln_stealth_flags(),
        ),
        "fragment-audit" => suggest_alias_simple(
            out,
            base,
            prefix,
            arg_index,
            "<target_url>",
            vuln_fragment_flags(),
        ),
        _ => {}
    }
}

fn suggest_reverse_long(
    out: &mut BTreeSet<String>,
    base: &str,
    prefix: &str,
    arg_index: usize,
    sub: Option<&str>,
) {
    if arg_index == 1 {
        push_prefixed(
            out,
            base,
            prefix,
            [
                "analyze",
                "plan",
                "run",
                "jobs",
                "job-status",
                "job-logs",
                "job-artifacts",
                "job-functions",
                "job-show",
                "job-search",
                "job-clear",
                "job-prune",
                "job-doctor",
                "debug-script",
            ],
        );
        return;
    }
    match sub.unwrap_or_default() {
        "analyze" => suggest_alias_simple(
            out,
            base,
            prefix,
            arg_index,
            "<input_file>",
            reverse_analyze_flags(),
        ),
        "plan" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<input_file>"]);
            } else if arg_index == 3 {
                push_prefixed(
                    out,
                    base,
                    prefix,
                    ["[engine]", "objdump", "radare2", "ghidra", "jadx"],
                );
            } else {
                push_prefixed(out, base, prefix, reverse_plan_flags());
            }
        }
        "run" => suggest_reverse_run(out, base, prefix, arg_index),
        "jobs" => {}
        "job-status" | "job-artifacts" | "job-functions" | "job-doctor" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<job_id>"]);
            }
        }
        "job-logs" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<job_id>"]);
            } else {
                push_prefixed(out, base, prefix, ["--stream", "stdout", "stderr", "both"]);
            }
        }
        "job-show" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<job_id>"]);
            } else if arg_index == 3 {
                push_prefixed(out, base, prefix, ["<function>"]);
            }
        }
        "job-search" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<job_id>"]);
            } else if arg_index == 3 {
                push_prefixed(out, base, prefix, ["<keyword>"]);
            } else {
                push_prefixed(out, base, prefix, ["--max"]);
            }
        }
        "job-clear" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<job_id>", "--all"]);
            } else {
                push_prefixed(out, base, prefix, ["--all"]);
            }
        }
        "job-prune" => push_prefixed(out, base, prefix, reverse_prune_flags()),
        "debug-script" => {
            if arg_index == 2 {
                push_prefixed(out, base, prefix, ["<input_file>"]);
            } else if arg_index == 3 {
                push_prefixed(out, base, prefix, ["<script_out>"]);
            } else if arg_index == 4 {
                push_prefixed(out, base, prefix, ["[profile]", "pwngdb", "pwndbg"]);
            } else {
                push_prefixed(out, base, prefix, ["--pwndbg-init", "--profile"]);
            }
        }
        _ => {}
    }
}

fn suggest_reverse_run(out: &mut BTreeSet<String>, base: &str, prefix: &str, arg_index: usize) {
    if arg_index == 2 || arg_index == 1 {
        push_prefixed(out, base, prefix, ["<input_file>"]);
    } else if arg_index == 3 {
        push_prefixed(
            out,
            base,
            prefix,
            [
                "[engine]",
                "auto",
                "objdump",
                "radare2",
                "ghidra",
                "jadx",
                "rust",
                "rust-asm",
                "rust-index",
            ],
        );
    } else if arg_index == 4 {
        push_prefixed(out, base, prefix, ["[mode]", "full", "index", "function"]);
    } else if arg_index == 5 {
        push_prefixed(out, base, prefix, ["[function_if_mode_function]"]);
    } else {
        push_prefixed(out, base, prefix, reverse_run_flags());
    }
}

fn root_heads() -> &'static [&'static str] {
    &[
        "host",
        "web",
        "vuln",
        "reverse",
        "h.quick",
        "h.tcp",
        "h.udp",
        "h.syn",
        "h.arp",
        "w.dir",
        "w.fuzz",
        "w.dns",
        "w.crawl",
        "w.live",
        "v.lint",
        "v.scan",
        "v.ca",
        "v.sg",
        "v.sc",
        "v.fa",
        "r.analyze",
        "r.plan",
        "r.run",
        "r.jobs",
        "r.status",
        "r.logs",
        "r.artifacts",
        "r.funcs",
        "r.show",
        "r.search",
        "r.clear",
        "r.prune",
        "r.doctor",
        "r.debug",
        "zrun",
        "zlogs",
        "zshell",
        "zart",
        "zrev",
        "zfocus",
    ]
}

fn no_flags() -> &'static [&'static str] {
    &[]
}

fn host_flags_quick() -> &'static [&'static str] {
    &["--profile"]
}

fn host_flags_tcp_udp_syn() -> &'static [&'static str] {
    &["--profile", "--service-detect", "--probes-file"]
}

fn host_flags_syn() -> &'static [&'static str] {
    &[
        "--profile",
        "--service-detect",
        "--probes-file",
        "--syn-mode",
    ]
}

fn host_flags_arp() -> &'static [&'static str] {
    &["--profile"]
}

fn web_flags_common() -> &'static [&'static str] {
    &[
        "--profile",
        "--concurrency",
        "--timeout-ms",
        "--max-retries",
        "--header",
        "--status-min",
        "--status-max",
        "--method",
    ]
}

fn web_flags_dir() -> &'static [&'static str] {
    &[
        "--profile",
        "--concurrency",
        "--timeout-ms",
        "--max-retries",
        "--header",
        "--status-min",
        "--status-max",
        "--method",
        "--recursive",
        "--recursive-depth",
    ]
}

fn web_flags_fuzz() -> &'static [&'static str] {
    &[
        "--profile",
        "--concurrency",
        "--timeout-ms",
        "--max-retries",
        "--header",
        "--status-min",
        "--status-max",
        "--method",
        "--keywords-file",
    ]
}

fn web_flags_dns() -> &'static [&'static str] {
    &[
        "--profile",
        "--concurrency",
        "--timeout-ms",
        "--max-retries",
        "--header",
        "--status-min",
        "--status-max",
        "--method",
        "--words-file",
        "--discovery-mode",
    ]
}

fn web_flags_crawl() -> &'static [&'static str] {
    &[
        "--profile",
        "--concurrency",
        "--timeout-ms",
        "--max-retries",
        "--header",
        "--status-min",
        "--status-max",
        "--method",
        "--max-depth",
        "--max-pages",
        "--obey-robots",
    ]
}

fn vuln_scan_flags() -> &'static [&'static str] {
    &[
        "--severity",
        "--tag",
        "--concurrency",
        "--timeout-ms",
        "--findings-only",
        "--success-only",
    ]
}

fn vuln_stealth_flags() -> &'static [&'static str] {
    &[
        "--timeout-ms",
        "--burst-concurrency",
        "--low-noise-requests",
        "--burst-requests",
    ]
}

fn vuln_fragment_flags() -> &'static [&'static str] {
    &[
        "--timeout-ms",
        "--concurrency",
        "--requests-per-tier",
        "--payload-min-bytes",
        "--payload-max-bytes",
        "--payload-step-bytes",
    ]
}

fn reverse_analyze_flags() -> &'static [&'static str] {
    &[
        "--rules-file",
        "--dynamic",
        "--dynamic-timeout-ms",
        "--dynamic-syscalls",
        "--dynamic-blocklist",
    ]
}

fn reverse_plan_flags() -> &'static [&'static str] {
    &["--output-dir"]
}

fn reverse_run_flags() -> &'static [&'static str] {
    &[
        "--deep",
        "--rust-first",
        "--no-rust-first",
        "--timeout-secs",
    ]
}

fn reverse_prune_flags() -> &'static [&'static str] {
    &["--keep", "--older-than-days", "--include-running"]
}

#[cfg(test)]
mod tests {
    use super::smart_command_candidates;

    #[test]
    fn completion_branches_from_parent_to_subcommand() {
        let got = smart_command_candidates("host ");
        assert!(got.contains(&"host quick".to_string()));
        assert!(got.contains(&"host tcp".to_string()));
        assert!(got.contains(&"host syn".to_string()));
    }

    #[test]
    fn completion_suggests_subcommand_flags() {
        let got = smart_command_candidates("vuln scan https://x ");
        assert!(got.contains(&"vuln scan https://x --severity".to_string()));
        assert!(got.contains(&"vuln scan https://x --findings-only".to_string()));
    }

    #[test]
    fn completion_supports_reverse_alias_tree() {
        let got = smart_command_candidates("r.logs task-1 ");
        assert!(got.contains(&"r.logs task-1 --stream".to_string()));
        assert!(got.contains(&"r.logs task-1 stdout".to_string()));
    }
}
