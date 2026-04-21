use std::io::{IsTerminal, stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::errors::RustpenError;
use crate::modules::reverse::{ReverseJobMeta, ReverseJobStatus, list_jobs};

use super::project_store::ensure_project_layout;
use super::reverse_workbench_support::{
    ReverseBrowserEntry, ZellijFilepickerHandle, abort_zellij_filepicker, canonical_or_clone,
    discover_binary_candidates, ensure_reverse_project_for_input, load_reverse_browser_entries,
    poll_zellij_filepicker as poll_native_filepicker, preferred_picker_root,
    read_active_target_hint, relative_or_full, request_reverse_viewer_open, resolve_active_project,
    run_analyze_now, shorten_id, spawn_reverse_job, spawn_zellij_filepicker,
    write_active_project_hint, write_active_target_hint, zellij_filepicker_is_visible,
};

#[path = "reverse_picker_view.rs"]
mod view;
use view::draw_picker;

const AUTO_REFRESH_INTERVAL: Duration = Duration::from_millis(1200);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(120);
const MAX_BROWSER_ENTRIES: usize = 256;
const NATIVE_PICKER_TRIGGER_DEBOUNCE: Duration = Duration::from_millis(180);
const FILEPICKER_WAIT_TIMEOUT: Duration = Duration::from_secs(90);
const FILEPICKER_HIDDEN_ABORT_GRACE: Duration = Duration::from_millis(500);
const AUTO_OPEN_VIEWER_ENV: &str = "RSCAN_REVERSE_AUTO_OPEN";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PickerLauncherMode {
    LocalBrowser,
    ZellijNative,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PickerRootMode {
    Project,
    Filesystem,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PickerInputMode {
    Browse,
    Filter,
    Path,
}

struct ReversePickerState {
    root_ws: PathBuf,
    project_override: Option<PathBuf>,
    active_project: PathBuf,
    launcher_mode: PickerLauncherMode,
    bootstrap_native_picker: bool,
    root_mode: PickerRootMode,
    current_dir: PathBuf,
    entries: Vec<ReverseBrowserEntry>,
    selected: usize,
    filter: String,
    path_input: String,
    path_status: String,
    path_preview_dir: Option<PathBuf>,
    path_preview_filter: String,
    path_preview_target: Option<PathBuf>,
    input_mode: PickerInputMode,
    message: String,
    native_picker_not_before: Option<Instant>,
    native_picker_handle: Option<ZellijFilepickerHandle>,
    native_picker_started_at: Option<Instant>,
    native_picker_seen_visible_once: bool,
    native_picker_hidden_since: Option<Instant>,
    last_refresh: Instant,
}

pub(crate) fn run_reverse_picker(
    root_ws: PathBuf,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(RustpenError::Generic(
            "reverse picker 需要交互式终端(tty)".to_string(),
        ));
    }

    let mut state = ReversePickerState::new(root_ws, project)?;

    enable_raw_mode().map_err(RustpenError::Io)?;
    let mut out = stdout();
    crossterm::execute!(out, crossterm::terminal::EnterAlternateScreen)
        .map_err(RustpenError::Io)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).map_err(RustpenError::Io)?;
    let res = (|| -> Result<(), RustpenError> {
        loop {
            state.refresh(false)?;
            terminal
                .draw(|f| draw_picker(f, &state))
                .map_err(RustpenError::Io)?;
            if state.consume_bootstrap_native_picker() {
                state.start_zellij_filepicker();
            }
            state.poll_zellij_filepicker()?;

            if !event::poll(EVENT_POLL_INTERVAL).map_err(RustpenError::Io)? {
                continue;
            }
            let Event::Key(key) = event::read().map_err(RustpenError::Io)? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if state.handle_key(key)? {
                return Ok(());
            }
        }
    })();

    disable_raw_mode().map_err(RustpenError::Io)?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )
    .map_err(RustpenError::Io)?;
    terminal.show_cursor().ok();
    res
}

impl ReversePickerState {
    fn new(root_ws: PathBuf, project_override: Option<PathBuf>) -> Result<Self, RustpenError> {
        let active_project = resolve_active_project(&root_ws, project_override.as_ref())?;
        ensure_project_layout(&active_project)?;
        let _ = write_active_project_hint(&root_ws, &active_project);
        let current_dir = initial_picker_dir(&root_ws, &active_project);
        let launcher_mode = default_launcher_mode();
        let mut state = Self {
            root_ws,
            project_override,
            active_project,
            launcher_mode,
            bootstrap_native_picker: false,
            root_mode: PickerRootMode::Project,
            current_dir,
            entries: Vec::new(),
            selected: 0,
            filter: String::new(),
            path_input: String::new(),
            path_status: "输入绝对/相对路径后，列表会实时预览".to_string(),
            path_preview_dir: None,
            path_preview_filter: String::new(),
            path_preview_target: None,
            input_mode: PickerInputMode::Browse,
            message: initial_picker_message(launcher_mode),
            native_picker_not_before: None,
            native_picker_handle: None,
            native_picker_started_at: None,
            native_picker_seen_visible_once: false,
            native_picker_hidden_since: None,
            last_refresh: Instant::now() - AUTO_REFRESH_INTERVAL,
        };
        state.refresh(true)?;
        Ok(state)
    }

    fn refresh(&mut self, force: bool) -> Result<(), RustpenError> {
        if !force && self.last_refresh.elapsed() < AUTO_REFRESH_INTERVAL {
            return Ok(());
        }
        let resolved_project =
            resolve_active_project(&self.root_ws, self.project_override.as_ref())?;
        let project_changed =
            canonical_or_clone(&resolved_project) != canonical_or_clone(&self.active_project);
        if project_changed {
            self.active_project = resolved_project;
            self.current_dir = initial_picker_dir(&self.root_ws, &self.active_project);
            self.selected = 0;
            self.message = format!("active project -> {}", self.active_project.display());
        }

        ensure_project_layout(&self.active_project)?;
        let _ = write_active_project_hint(&self.root_ws, &self.active_project);

        self.ensure_current_dir();
        self.refresh_path_preview();

        let browse_root = self.browser_root();
        let browse_dir = self.browser_dir();
        let browse_filter = self.browser_filter();
        let preferred = self
            .browser_preferred_path()
            .or_else(|| self.selected_entry().map(|entry| entry.path.clone()))
            .or_else(|| read_active_target_hint(&self.root_ws));
        self.entries = build_browser_entries(
            &self.active_project,
            &browse_root,
            &browse_dir,
            browse_filter,
            self.browser_project_mode(),
        );
        self.sync_selection(preferred.as_deref());
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        if matches!(key.code, KeyCode::Char('p'))
            && key.modifiers == KeyModifiers::NONE
            && self.native_picker_handle.is_some()
        {
            self.cancel_zellij_filepicker()?;
            return Ok(false);
        }
        match self.input_mode {
            PickerInputMode::Browse => self.handle_browse_key(key),
            PickerInputMode::Filter => self.handle_filter_key(key),
            PickerInputMode::Path => self.handle_path_key(key),
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        if is_native_picker_hotkey(key) {
            self.schedule_zellij_filepicker_open();
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Ok(true),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-8),
            KeyCode::PageDown => self.move_selection(8),
            KeyCode::Home | KeyCode::Char('g') => self.selected = 0,
            KeyCode::End | KeyCode::Char('G') => {
                self.selected = self.entries.len().saturating_sub(1);
            }
            KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.go_parent()?;
            }
            KeyCode::Enter => {
                if self.launcher_mode == PickerLauncherMode::ZellijNative {
                    // In zellij-native mode, prioritize the currently highlighted entry.
                    // This avoids the "can't select file" feeling when Enter always re-opens
                    // filepicker instead of acting on the visible browser list.
                    if self.selected_entry().is_some() {
                        self.open_selected()?;
                    } else {
                        self.schedule_zellij_filepicker_open();
                    }
                } else {
                    self.import_selected()?;
                }
            }
            KeyCode::Right | KeyCode::Char('o') => {
                self.open_selected()?;
            }
            KeyCode::Char('f') => {
                self.full_selected()?;
            }
            KeyCode::Char('a') => {
                self.analyze_selected()?;
            }
            KeyCode::Char('i') => {
                self.index_selected()?;
            }
            KeyCode::Char('s') => {
                self.sync_selected_target()?;
            }
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.message = "reverse picker 已刷新".to_string();
            }
            KeyCode::Char('R') => {
                self.toggle_root_mode()?;
            }
            KeyCode::Char('b') => {
                self.launcher_mode = PickerLauncherMode::LocalBrowser;
                self.bootstrap_native_picker = false;
                self.native_picker_not_before = None;
                self.message =
                    "launcher -> local browser | Enter/o 打开选中项，Alt+f 可调 zellij filepicker"
                        .to_string();
            }
            KeyCode::Char('Z') => {
                if zellij_picker_available() {
                    self.launcher_mode = PickerLauncherMode::ZellijNative;
                    self.bootstrap_native_picker = false;
                    self.native_picker_not_before = None;
                    self.message =
                        "launcher -> zellij native | Enter/Alt+f 直接打开 zellij filepicker"
                            .to_string();
                } else {
                    self.message = "当前不在 zellij session，无法切到 zellij native".to_string();
                }
            }
            KeyCode::Char('/') => {
                self.input_mode = PickerInputMode::Filter;
            }
            KeyCode::F(2) | KeyCode::Char(':') => {
                self.enter_path_mode();
            }
            KeyCode::Char(c) if !c.is_whitespace() && !c.is_control() => {
                self.start_inline_filter(c)?;
            }
            _ => {}
        }
        Ok(false)
    }

    fn consume_bootstrap_native_picker(&mut self) -> bool {
        let should_open = self.bootstrap_native_picker
            && self
                .native_picker_not_before
                .map(|deadline| Instant::now() >= deadline)
                .unwrap_or(true);
        if should_open {
            self.bootstrap_native_picker = false;
            self.native_picker_not_before = None;
        }
        should_open
    }

    fn schedule_zellij_filepicker_open(&mut self) {
        if self.native_picker_handle.is_some() {
            self.message = "zellij filepicker 已在运行中".to_string();
            return;
        }
        if !zellij_picker_available() {
            self.message = "当前不在 zellij session，无法打开 zellij filepicker".to_string();
            return;
        }
        self.bootstrap_native_picker = true;
        self.native_picker_not_before = Some(Instant::now() + NATIVE_PICKER_TRIGGER_DEBOUNCE);
        self.message = "正在打开 zellij filepicker...".to_string();
    }

    fn start_zellij_filepicker(&mut self) {
        if self.native_picker_handle.is_some() {
            return;
        }
        let start = self.browser_dir();
        match spawn_zellij_filepicker(Some(&start), "rscan reverse picker") {
            Ok(handle) => {
                self.native_picker_handle = Some(handle);
                self.native_picker_started_at = Some(Instant::now());
                self.native_picker_seen_visible_once = false;
                self.native_picker_hidden_since = None;
                self.message = "zellij filepicker 已打开（Alt+f 可重开，p 关闭面板）".to_string();
            }
            Err(err) => {
                if matches!(self.input_mode, PickerInputMode::Path) {
                    self.path_status = format!("zellij filepicker: {}", err);
                } else {
                    self.message = format!("zellij filepicker: {}", err);
                }
            }
        }
    }

    fn poll_zellij_filepicker(&mut self) -> Result<(), RustpenError> {
        let Some(mut handle) = self.native_picker_handle.take() else {
            return Ok(());
        };

        if let Some(result) = poll_native_filepicker(&mut handle).map_err(RustpenError::Generic)? {
            self.native_picker_started_at = None;
            self.native_picker_seen_visible_once = false;
            self.native_picker_hidden_since = None;
            match result {
                Ok(path) => {
                    let msg = self.import_target_with_default_index(&path)?;
                    self.leave_path_mode(&msg);
                    self.message = format!("zellij filepicker -> {}", msg);
                }
                Err(err) => {
                    if matches!(self.input_mode, PickerInputMode::Path) {
                        self.path_status = format!("zellij filepicker: {}", err);
                    } else {
                        self.message = format!("zellij filepicker: {}", err);
                    }
                }
            }
            return Ok(());
        }

        if self
            .native_picker_started_at
            .map(|started| started.elapsed() >= FILEPICKER_WAIT_TIMEOUT)
            .unwrap_or(false)
        {
            let _ = abort_zellij_filepicker(&mut handle);
            self.native_picker_started_at = None;
            self.native_picker_seen_visible_once = false;
            self.native_picker_hidden_since = None;
            self.message = "zellij filepicker 等待超时，已自动取消".to_string();
            return Ok(());
        }

        match zellij_filepicker_is_visible(&handle) {
            Ok(true) => {
                self.native_picker_seen_visible_once = true;
                self.native_picker_hidden_since = None;
            }
            Ok(false) if self.native_picker_seen_visible_once => {
                let since = self
                    .native_picker_hidden_since
                    .get_or_insert_with(Instant::now);
                if since.elapsed() >= FILEPICKER_HIDDEN_ABORT_GRACE {
                    let _ = abort_zellij_filepicker(&mut handle);
                    self.native_picker_started_at = None;
                    self.native_picker_seen_visible_once = false;
                    self.native_picker_hidden_since = None;
                    self.message = "zellij filepicker 已关闭/取消".to_string();
                    return Ok(());
                }
            }
            _ => {}
        }

        self.native_picker_handle = Some(handle);
        Ok(())
    }

    fn cancel_zellij_filepicker(&mut self) -> Result<(), RustpenError> {
        let Some(mut handle) = self.native_picker_handle.take() else {
            self.message = "zellij filepicker 当前未打开".to_string();
            return Ok(());
        };
        abort_zellij_filepicker(&mut handle).map_err(RustpenError::Generic)?;
        self.native_picker_started_at = None;
        self.native_picker_seen_visible_once = false;
        self.native_picker_hidden_since = None;
        self.message = "zellij filepicker 已关闭（p）".to_string();
        Ok(())
    }

    fn start_inline_filter(&mut self, first: char) -> Result<(), RustpenError> {
        self.input_mode = PickerInputMode::Filter;
        self.filter.push(first);
        self.refresh(true)?;
        Ok(())
    }

    fn handle_filter_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        if is_native_picker_hotkey(key) {
            self.schedule_zellij_filepicker_open();
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc => {
                self.input_mode = PickerInputMode::Browse;
            }
            KeyCode::Enter => {
                self.input_mode = PickerInputMode::Browse;
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.refresh(true)?;
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.refresh(true)?;
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_path_key(&mut self, key: KeyEvent) -> Result<bool, RustpenError> {
        if is_native_picker_hotkey(key) {
            self.schedule_zellij_filepicker_open();
            return Ok(false);
        }
        match key.code {
            KeyCode::Esc => {
                self.leave_path_mode("路径输入已取消");
                self.refresh(true)?;
            }
            KeyCode::Enter => {
                self.confirm_path_input()?;
            }
            KeyCode::Backspace => {
                self.path_input.pop();
                self.refresh(true)?;
            }
            KeyCode::Char(c) => {
                self.path_input.push(c);
                self.refresh(true)?;
            }
            _ => {}
        }
        Ok(false)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            self.selected = 0;
            return;
        }
        let upper = self.entries.len().saturating_sub(1) as isize;
        let next = (self.selected as isize + delta).clamp(0, upper);
        self.selected = next as usize;
    }

    fn go_parent(&mut self) -> Result<(), RustpenError> {
        if self.current_dir == self.root_dir() {
            self.message = match self.root_mode {
                PickerRootMode::Project => "已在当前 project 根目录".to_string(),
                PickerRootMode::Filesystem => "已在 filesystem 根目录".to_string(),
            };
            return Ok(());
        }
        let Some(parent) = self.current_dir.parent() else {
            return Ok(());
        };
        if !parent.starts_with(self.root_dir()) {
            self.current_dir = self.root_dir().to_path_buf();
        } else {
            self.current_dir = parent.to_path_buf();
        }
        self.selected = 0;
        self.refresh(true)?;
        Ok(())
    }

    fn open_selected(&mut self) -> Result<(), RustpenError> {
        let Some(entry) = self.selected_entry().cloned() else {
            self.message = "当前目录没有可操作目标".to_string();
            return Ok(());
        };
        if entry.is_dir {
            self.current_dir = entry.path;
            self.selected = 0;
            self.refresh(true)?;
            return Ok(());
        }
        let (_, _, msg) = self.bind_selected_file(&entry.path, true)?;
        self.message = msg;
        Ok(())
    }

    fn import_selected(&mut self) -> Result<(), RustpenError> {
        let Some(entry) = self.selected_entry().cloned() else {
            self.message = "当前目录没有可操作目标".to_string();
            return Ok(());
        };
        if entry.is_dir {
            self.current_dir = entry.path;
            self.selected = 0;
            self.refresh(true)?;
            return Ok(());
        }
        self.message = self.import_target_with_default_index(&entry.path)?;
        Ok(())
    }

    fn analyze_selected(&mut self) -> Result<(), RustpenError> {
        let Some(selected) = self.selected_file_path() else {
            self.message = "请选择一个文件目标，再执行 analyze".to_string();
            return Ok(());
        };
        let (project, target, bind_msg) = self.bind_selected_file(&selected, false)?;
        let analyze_msg = run_analyze_now(&project, &target)?;
        self.message = format!("{bind_msg} | {analyze_msg}");
        Ok(())
    }

    fn index_selected(&mut self) -> Result<(), RustpenError> {
        let Some(selected) = self.selected_file_path() else {
            self.message = "请选择一个文件目标，再执行 index".to_string();
            return Ok(());
        };
        let (project, target, bind_msg) = self.bind_selected_file(&selected, true)?;
        let job_msg = spawn_reverse_job(&project, &target, "auto", "index")?;
        self.message = format!("{bind_msg} | {job_msg}");
        Ok(())
    }

    fn sync_selected_target(&mut self) -> Result<(), RustpenError> {
        if self.selected_file_path().is_none() {
            self.message = "当前选中项不是文件，无法同步为目标".to_string();
            return Ok(());
        }
        self.message = self.prepare_selected_file(false)?;
        Ok(())
    }

    fn full_selected(&mut self) -> Result<(), RustpenError> {
        let Some(selected) = self.selected_file_path() else {
            self.message = "请选择一个文件目标，再执行 full".to_string();
            return Ok(());
        };
        let (project, target, bind_msg) = self.bind_selected_file(&selected, true)?;
        let job_msg = spawn_reverse_job(&project, &target, "ghidra", "full")?;
        self.message = format!("{bind_msg} | {job_msg}");
        Ok(())
    }

    fn prepare_selected_file(&mut self, open_viewer: bool) -> Result<String, RustpenError> {
        let Some(selected) = self.selected_file_path() else {
            return Ok("当前选中项不是文件，无法同步为目标".to_string());
        };
        let (_, _, msg) = self.bind_selected_file(&selected, open_viewer)?;
        Ok(msg)
    }

    fn import_target_with_default_index(
        &mut self,
        selected: &Path,
    ) -> Result<String, RustpenError> {
        let (project, target, bind_msg) =
            self.bind_selected_file(selected, auto_open_viewer_enabled())?;
        if let Some(job) = reusable_analysis_job(&project, &target) {
            return Ok(format!("{bind_msg} | {}", describe_reused_job(&job)));
        }
        let job_msg = spawn_reverse_job(&project, &target, "auto", "index")?;
        Ok(format!("{bind_msg} | auto-index -> {job_msg}"))
    }

    fn bind_selected_file(
        &mut self,
        selected: &Path,
        open_viewer: bool,
    ) -> Result<(PathBuf, PathBuf, String), RustpenError> {
        let prepared = ensure_reverse_project_for_input(&self.root_ws, selected)?;
        self.project_override = Some(prepared.project.clone());
        self.active_project = prepared.project.clone();
        self.current_dir = preferred_picker_root(&self.active_project);
        self.selected = 0;
        write_active_project_hint(&self.root_ws, &prepared.project)?;
        write_active_target_hint(&self.root_ws, &prepared.target)?;
        if open_viewer {
            request_reverse_viewer_open(&self.root_ws, &prepared.target)?;
        }
        self.refresh(true)?;

        let mut flags = Vec::new();
        if prepared.created_project {
            flags.push("new-project");
        }
        if prepared.staged_input {
            flags.push("staged-input");
        }
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", flags.join(","))
        };
        let action = if open_viewer {
            "viewer 请求已发出"
        } else {
            "目标已同步"
        };
        Ok((
            prepared.project.clone(),
            prepared.target.clone(),
            format!(
                "{} -> project={} | target={}{}",
                action,
                prepared.project.display(),
                prepared.target.display(),
                flags
            ),
        ))
    }

    fn selected_entry(&self) -> Option<&ReverseBrowserEntry> {
        self.entries.get(self.selected)
    }

    fn selected_file_path(&self) -> Option<PathBuf> {
        let entry = self.selected_entry()?;
        if entry.is_dir {
            None
        } else {
            Some(entry.path.clone())
        }
    }

    fn sync_selection(&mut self, preferred: Option<&Path>) {
        if self.entries.is_empty() {
            self.selected = 0;
            return;
        }
        if let Some(path) = preferred {
            let path = canonical_or_clone(path);
            if let Some(idx) = self
                .entries
                .iter()
                .position(|entry| canonical_or_clone(&entry.path) == path)
            {
                self.selected = idx;
                return;
            }
        }
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }

    fn toggle_root_mode(&mut self) -> Result<(), RustpenError> {
        self.root_mode = match self.root_mode {
            PickerRootMode::Project => PickerRootMode::Filesystem,
            PickerRootMode::Filesystem => PickerRootMode::Project,
        };
        self.current_dir = match self.root_mode {
            PickerRootMode::Project => initial_picker_dir(&self.root_ws, &self.active_project),
            PickerRootMode::Filesystem => {
                let target_parent = read_active_target_hint(&self.root_ws)
                    .and_then(|target| target.parent().map(|parent| parent.to_path_buf()));
                target_parent
                    .filter(|path| path.is_dir())
                    .unwrap_or_else(filesystem_root_dir)
            }
        };
        self.selected = 0;
        self.refresh(true)?;
        self.message = match self.root_mode {
            PickerRootMode::Project => {
                format!("root mode -> project ({})", self.active_project.display())
            }
            PickerRootMode::Filesystem => {
                format!("root mode -> filesystem ({})", self.current_dir.display())
            }
        };
        Ok(())
    }

    fn enter_path_mode(&mut self) {
        self.input_mode = PickerInputMode::Path;
        if self.path_input.is_empty() {
            self.path_status = "输入绝对/相对路径；列表会实时预览，Enter 确认".to_string();
        }
        self.refresh_path_preview();
    }

    fn leave_path_mode(&mut self, status: &str) {
        self.input_mode = PickerInputMode::Browse;
        self.path_input.clear();
        self.path_status = status.to_string();
        self.path_preview_dir = None;
        self.path_preview_filter.clear();
        self.path_preview_target = None;
    }

    fn refresh_path_preview(&mut self) {
        if self.input_mode != PickerInputMode::Path {
            self.path_preview_dir = None;
            self.path_preview_filter.clear();
            self.path_preview_target = None;
            return;
        }
        let preview = build_path_preview(&self.current_dir, &self.path_input);
        self.path_status = preview.status;
        self.path_preview_dir = Some(preview.browser_dir);
        self.path_preview_filter = preview.browser_filter;
        self.path_preview_target = preview.exact_target;
    }

    fn browser_root(&self) -> PathBuf {
        match self.input_mode {
            PickerInputMode::Path => filesystem_root_dir(),
            _ => self.root_dir().to_path_buf(),
        }
    }

    fn browser_dir(&self) -> PathBuf {
        match self.input_mode {
            PickerInputMode::Path => self
                .path_preview_dir
                .clone()
                .unwrap_or_else(|| self.current_dir.clone()),
            _ => self.current_dir.clone(),
        }
    }

    fn browser_filter(&self) -> &str {
        match self.input_mode {
            PickerInputMode::Path => &self.path_preview_filter,
            _ => &self.filter,
        }
    }

    fn browser_project_mode(&self) -> bool {
        !matches!(self.input_mode, PickerInputMode::Path)
            && self.root_mode == PickerRootMode::Project
    }

    fn browser_preferred_path(&self) -> Option<PathBuf> {
        match self.input_mode {
            PickerInputMode::Path => self
                .path_preview_target
                .as_ref()
                .filter(|path| path.is_file())
                .cloned(),
            _ => None,
        }
    }

    fn confirm_path_input(&mut self) -> Result<(), RustpenError> {
        let preview = build_path_preview(&self.current_dir, &self.path_input);
        let typed = self.path_input.trim().to_string();
        if typed.is_empty() {
            self.leave_path_mode("路径输入为空，已返回浏览模式");
            self.refresh(true)?;
            return Ok(());
        }

        if let Some(target) = preview.exact_target {
            if target.is_file() {
                let msg = self.import_target_with_default_index(&target)?;
                self.leave_path_mode(&msg);
                self.message = msg;
                return Ok(());
            }
            if target.is_dir() {
                self.current_dir = target.clone();
                self.root_mode = if target.starts_with(&self.active_project) {
                    PickerRootMode::Project
                } else {
                    PickerRootMode::Filesystem
                };
                self.selected = 0;
                self.leave_path_mode(&format!("cwd -> {}", self.current_dir.display()));
                self.refresh(true)?;
                self.message = format!("cwd -> {}", self.current_dir.display());
                return Ok(());
            }
        }

        self.current_dir = preview.browser_dir.clone();
        if !self.current_dir.starts_with(&self.active_project) {
            self.root_mode = PickerRootMode::Filesystem;
        }
        self.filter = preview.browser_filter.clone();
        self.selected = 0;
        self.leave_path_mode(&format!(
            "路径未命中目标，切到 {} 继续浏览",
            self.current_dir.display()
        ));
        self.refresh(true)?;
        self.message = format!(
            "路径未命中目标，切到 {} 继续浏览",
            self.current_dir.display()
        );
        Ok(())
    }

    fn display_dir(&self) -> &Path {
        match self.input_mode {
            PickerInputMode::Path => self
                .path_preview_dir
                .as_deref()
                .unwrap_or(&self.current_dir),
            _ => &self.current_dir,
        }
    }

    fn ensure_current_dir(&mut self) {
        let root = self.root_dir();
        if !self.current_dir.is_dir() || !self.current_dir.starts_with(root) {
            self.current_dir = match self.root_mode {
                PickerRootMode::Project => preferred_picker_root(&self.active_project),
                PickerRootMode::Filesystem => filesystem_root_dir(),
            };
        }
    }

    fn root_dir(&self) -> &Path {
        match self.root_mode {
            PickerRootMode::Project => &self.active_project,
            PickerRootMode::Filesystem => Path::new("/"),
        }
    }
}

fn is_native_picker_hotkey(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('f') | KeyCode::Char('F'))
        && key.modifiers.contains(KeyModifiers::ALT)
}

fn auto_open_viewer_enabled() -> bool {
    std::env::var(AUTO_OPEN_VIEWER_ENV)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on"
        })
        .unwrap_or(false)
}

fn build_browser_entries(
    project: &Path,
    browse_root: &Path,
    current_dir: &Path,
    filter: &str,
    project_mode: bool,
) -> Vec<ReverseBrowserEntry> {
    let mut entries = Vec::new();
    if current_dir != browse_root
        && let Some(parent) = current_dir.parent()
    {
        entries.push(ReverseBrowserEntry {
            path: parent.to_path_buf(),
            is_dir: true,
            label: "../".to_string(),
            detail: "parent".to_string(),
        });
    }
    let mut discovered = load_reverse_browser_entries(
        browse_root,
        current_dir,
        filter,
        MAX_BROWSER_ENTRIES,
        project_mode,
    );
    entries.append(&mut discovered);
    if entries.is_empty() && filter.trim().is_empty() && project_mode {
        for path in discover_binary_candidates(project, 24) {
            let label = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("target")
                .to_string();
            entries.push(ReverseBrowserEntry {
                detail: relative_or_full(project, &path),
                path,
                is_dir: false,
                label,
            });
        }
    }
    entries
}

fn initial_picker_dir(root_ws: &Path, active_project: &Path) -> PathBuf {
    if let Some(target) = read_active_target_hint(root_ws)
        && target.starts_with(active_project)
        && let Some(parent) = target.parent()
    {
        return parent.to_path_buf();
    }
    preferred_picker_root(active_project)
}

fn filesystem_root_dir() -> PathBuf {
    PathBuf::from("/")
}

fn default_launcher_mode() -> PickerLauncherMode {
    let zellij = std::env::var("ZELLIJ").ok();
    let session = std::env::var("ZELLIJ_SESSION_NAME").ok();
    default_launcher_mode_for_env(zellij.as_deref(), session.as_deref())
}

fn default_launcher_mode_for_env(
    zellij: Option<&str>,
    session: Option<&str>,
) -> PickerLauncherMode {
    if zellij_picker_available_for_env(zellij, session) {
        PickerLauncherMode::ZellijNative
    } else {
        PickerLauncherMode::LocalBrowser
    }
}

fn zellij_picker_available() -> bool {
    let zellij = std::env::var("ZELLIJ").ok();
    let session = std::env::var("ZELLIJ_SESSION_NAME").ok();
    zellij_picker_available_for_env(zellij.as_deref(), session.as_deref())
}

fn zellij_picker_available_for_env(zellij: Option<&str>, session: Option<&str>) -> bool {
    zellij.is_some() || session.is_some()
}

fn initial_picker_message(mode: PickerLauncherMode) -> String {
    match mode {
        PickerLauncherMode::ZellijNative => {
            "Enter 优先处理当前选中项；可直接键入过滤（或按 /）；Alt+f 打开 zellij filepicker，p 关闭"
                .to_string()
        }
        PickerLauncherMode::LocalBrowser => {
            "Enter=import+index+open viewer  o=open only  f=full  i=index  a=analyze  s=sync target  /或直接键入=过滤"
                .to_string()
        }
    }
}

fn reusable_analysis_job(project: &Path, target: &Path) -> Option<ReverseJobMeta> {
    let target = canonical_or_clone(target);
    let mut jobs: Vec<ReverseJobMeta> = list_jobs(project)
        .unwrap_or_default()
        .into_iter()
        .filter(|job| canonical_or_clone(&job.target) == target)
        .filter(is_reusable_analysis_job)
        .collect();
    jobs.sort_by_key(reusable_analysis_job_priority);
    jobs.pop()
}

fn is_reusable_analysis_job(job: &ReverseJobMeta) -> bool {
    matches!(
        job.status,
        ReverseJobStatus::Queued | ReverseJobStatus::Running | ReverseJobStatus::Succeeded
    ) && matches!(
        job.mode.as_deref().map(str::trim),
        Some(mode) if mode.eq_ignore_ascii_case("index") || mode.eq_ignore_ascii_case("full")
    )
}

fn reusable_analysis_job_priority(job: &ReverseJobMeta) -> (u8, u8, u64) {
    (
        reusable_analysis_job_mode_rank(job),
        reusable_analysis_job_status_rank(&job.status),
        job.created_at,
    )
}

fn reusable_analysis_job_mode_rank(job: &ReverseJobMeta) -> u8 {
    match job.mode.as_deref().map(str::trim) {
        Some(mode) if mode.eq_ignore_ascii_case("full") => 2,
        Some(mode) if mode.eq_ignore_ascii_case("index") => 1,
        _ => 0,
    }
}

fn reusable_analysis_job_status_rank(status: &ReverseJobStatus) -> u8 {
    match status {
        ReverseJobStatus::Succeeded => 3,
        ReverseJobStatus::Running => 2,
        ReverseJobStatus::Queued => 1,
        ReverseJobStatus::Failed => 0,
    }
}

fn describe_reused_job(job: &ReverseJobMeta) -> String {
    let mode = job.mode.as_deref().unwrap_or("analysis");
    let status = match job.status {
        ReverseJobStatus::Queued => "queued",
        ReverseJobStatus::Running => "running",
        ReverseJobStatus::Succeeded => "ready",
        ReverseJobStatus::Failed => "failed",
    };
    format!("复用现有 {mode} job {} ({status})", shorten_id(&job.id, 18))
}

#[derive(Debug, Clone)]
struct PickerPathPreview {
    browser_dir: PathBuf,
    browser_filter: String,
    exact_target: Option<PathBuf>,
    status: String,
}

fn build_path_preview(current_dir: &Path, raw: &str) -> PickerPathPreview {
    let typed = raw.trim();
    if typed.is_empty() {
        return PickerPathPreview {
            browser_dir: current_dir.to_path_buf(),
            browser_filter: String::new(),
            exact_target: None,
            status: "输入绝对/相对路径；列表会实时预览".to_string(),
        };
    }

    let candidate = resolve_picker_path(current_dir, typed);
    if candidate.is_file() {
        return PickerPathPreview {
            browser_dir: candidate
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(filesystem_root_dir),
            browser_filter: String::new(),
            exact_target: Some(candidate.clone()),
            status: format!("文件就绪: {}", candidate.display()),
        };
    }
    if candidate.is_dir() {
        return PickerPathPreview {
            browser_dir: candidate.clone(),
            browser_filter: String::new(),
            exact_target: Some(candidate.clone()),
            status: format!("目录预览: {}", candidate.display()),
        };
    }

    let (browser_dir, browser_filter) = nearest_existing_dir_with_filter(&candidate)
        .unwrap_or_else(|| (filesystem_root_dir(), file_name_or_empty(&candidate)));
    let suffix = if browser_filter.is_empty() {
        "<none>".to_string()
    } else {
        browser_filter.clone()
    };
    PickerPathPreview {
        browser_dir: browser_dir.clone(),
        browser_filter,
        exact_target: None,
        status: format!(
            "未命中 {} | preview={} | filter={}",
            candidate.display(),
            browser_dir.display(),
            suffix
        ),
    }
}

fn resolve_picker_path(current_dir: &Path, raw: &str) -> PathBuf {
    let expanded = expand_tilde_path(raw);
    if expanded.is_absolute() {
        expanded
    } else {
        current_dir.join(expanded)
    }
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    if raw == "~" {
        return std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(raw));
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn nearest_existing_dir_with_filter(candidate: &Path) -> Option<(PathBuf, String)> {
    let mut cursor = candidate.to_path_buf();
    let mut leaf = String::new();
    loop {
        if cursor.is_dir() {
            return Some((cursor, leaf));
        }
        let next_leaf = file_name_or_empty(&cursor);
        if leaf.is_empty() {
            leaf = next_leaf;
        }
        let parent = cursor.parent()?.to_path_buf();
        cursor = parent;
    }
}

fn file_name_or_empty(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::reverse::ReverseJobStatus;
    use crate::tui::reverse_workbench_support::unix_now_secs;

    #[test]
    fn path_preview_selects_existing_file_parent() {
        let root = std::env::temp_dir().join("rscan_picker_path_test_file");
        let dir = root.join("binaries");
        let file = dir.join("demo.bin");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&file, b"\x7fELF").unwrap();

        let preview = build_path_preview(&root, &file.display().to_string());
        assert_eq!(preview.exact_target, Some(file.clone()));
        assert_eq!(preview.browser_dir, dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn path_preview_falls_back_to_existing_parent() {
        let root = std::env::temp_dir().join("rscan_picker_path_test_parent");
        let dir = root.join("samples");
        std::fs::create_dir_all(&dir).unwrap();

        let preview = build_path_preview(&root, &dir.join("ea").display().to_string());
        assert_eq!(preview.browser_dir, dir);
        assert_eq!(preview.browser_filter, "ea".to_string());
        assert!(preview.exact_target.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn default_launcher_prefers_zellij_inside_session() {
        assert_eq!(
            default_launcher_mode_for_env(Some("1"), None),
            PickerLauncherMode::ZellijNative
        );
    }

    #[test]
    fn default_launcher_falls_back_outside_session() {
        assert_eq!(
            default_launcher_mode_for_env(None, None),
            PickerLauncherMode::LocalBrowser
        );
    }

    #[test]
    fn scheduled_native_picker_waits_for_debounce() {
        let mut state = fake_picker_state();
        state.schedule_zellij_filepicker_open();

        assert!(!state.consume_bootstrap_native_picker());
        std::thread::sleep(NATIVE_PICKER_TRIGGER_DEBOUNCE + Duration::from_millis(30));
        assert!(state.consume_bootstrap_native_picker());
    }

    #[test]
    fn browse_mode_direct_char_starts_filter_input() {
        let mut state = fake_picker_state();
        state.input_mode = PickerInputMode::Browse;
        state.filter.clear();

        let quit = state
            .handle_browse_key(KeyEvent::new(KeyCode::Char('x'), event::KeyModifiers::NONE))
            .unwrap();

        assert!(!quit);
        assert_eq!(state.input_mode, PickerInputMode::Filter);
        assert_eq!(state.filter, "x");
    }

    #[test]
    fn alt_f_schedules_native_filepicker() {
        let mut state = fake_picker_state();
        state.input_mode = PickerInputMode::Browse;
        state.bootstrap_native_picker = false;

        let quit = state
            .handle_browse_key(KeyEvent::new(KeyCode::Char('f'), event::KeyModifiers::ALT))
            .unwrap();

        assert!(!quit);
        assert!(state.bootstrap_native_picker);
    }

    #[test]
    fn native_picker_hotkey_detects_alt_f_only() {
        assert!(is_native_picker_hotkey(KeyEvent::new(
            KeyCode::Char('f'),
            event::KeyModifiers::ALT
        )));
        assert!(is_native_picker_hotkey(KeyEvent::new(
            KeyCode::Char('F'),
            event::KeyModifiers::ALT
        )));
        assert!(!is_native_picker_hotkey(KeyEvent::new(
            KeyCode::Char('f'),
            event::KeyModifiers::NONE
        )));
        assert!(!is_native_picker_hotkey(KeyEvent::new(
            KeyCode::F(4),
            event::KeyModifiers::NONE
        )));
    }

    #[test]
    fn esc_quits_in_browse_mode() {
        let mut state = fake_picker_state();
        state.input_mode = PickerInputMode::Browse;
        let quit = state
            .handle_browse_key(KeyEvent::new(KeyCode::Esc, event::KeyModifiers::NONE))
            .unwrap();
        assert!(quit);
    }

    #[test]
    fn enter_in_native_mode_uses_selected_file_instead_of_reopening_filepicker() {
        let root =
            std::env::temp_dir().join(format!("rscan_picker_enter_select_{}", unix_now_secs()));
        let src = root.join("fixtures").join("sample.bin");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        std::fs::write(&src, b"\x7fELF").unwrap();

        let mut state = fake_picker_state();
        state.root_ws = root.clone();
        state.active_project = root.join("projects").join("default");
        std::fs::create_dir_all(&state.active_project).unwrap();
        state.current_dir = src.parent().unwrap().to_path_buf();
        state.entries = vec![ReverseBrowserEntry {
            path: src.clone(),
            is_dir: false,
            label: "sample.bin".to_string(),
            detail: "4 B | bin".to_string(),
        }];
        state.selected = 0;

        let quit = state
            .handle_browse_key(KeyEvent::new(KeyCode::Enter, event::KeyModifiers::NONE))
            .unwrap();
        assert!(!quit);
        assert!(!state.bootstrap_native_picker);
        assert!(state.message.contains("project="));
        assert!(
            state.message.contains("viewer 请求已发出") || state.message.contains("目标已同步")
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reusable_analysis_job_prefers_succeeded_full_over_running_index() {
        let target = PathBuf::from("/tmp/sample.bin");
        let jobs = vec![
            fake_job(
                "job-index-running",
                "index",
                ReverseJobStatus::Running,
                10,
                &target,
            ),
            fake_job(
                "job-full-ok",
                "full",
                ReverseJobStatus::Succeeded,
                20,
                &target,
            ),
        ];

        let picked = jobs
            .into_iter()
            .filter(is_reusable_analysis_job)
            .max_by_key(reusable_analysis_job_priority)
            .unwrap();
        assert_eq!(picked.id, "job-full-ok");
    }

    #[test]
    fn failed_jobs_are_not_reusable() {
        let job = fake_job(
            "job-full-failed",
            "full",
            ReverseJobStatus::Failed,
            42,
            &PathBuf::from("/tmp/sample.bin"),
        );
        assert!(!is_reusable_analysis_job(&job));
    }

    fn fake_job(
        id: &str,
        mode: &str,
        status: ReverseJobStatus,
        created_at: u64,
        target: &Path,
    ) -> ReverseJobMeta {
        ReverseJobMeta {
            id: id.to_string(),
            kind: "reverse".to_string(),
            backend: "ghidra".to_string(),
            mode: Some(mode.to_string()),
            function: None,
            target: target.to_path_buf(),
            workspace: PathBuf::from("/tmp/project"),
            status,
            created_at,
            started_at: None,
            ended_at: None,
            exit_code: None,
            program: "rscan".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: Vec::new(),
            error: None,
        }
    }

    fn fake_picker_state() -> ReversePickerState {
        ReversePickerState {
            root_ws: PathBuf::from("/tmp/root"),
            project_override: None,
            active_project: PathBuf::from("/tmp/project"),
            launcher_mode: PickerLauncherMode::ZellijNative,
            bootstrap_native_picker: false,
            root_mode: PickerRootMode::Project,
            current_dir: PathBuf::from("/tmp/project"),
            entries: Vec::new(),
            selected: 0,
            filter: String::new(),
            path_input: String::new(),
            path_status: String::new(),
            path_preview_dir: None,
            path_preview_filter: String::new(),
            path_preview_target: None,
            input_mode: PickerInputMode::Browse,
            message: String::new(),
            native_picker_not_before: None,
            native_picker_handle: None,
            native_picker_started_at: None,
            native_picker_seen_visible_once: false,
            native_picker_hidden_since: None,
            last_refresh: Instant::now(),
        }
    }
}
