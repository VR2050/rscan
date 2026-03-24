use std::io::{IsTerminal, stdin};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::errors::RustpenError;
use crate::modules::reverse::{
    ReverseConsoleConfig, ReverseJobMeta, ReverseJobStatus, list_jobs, list_primary_sample_jobs,
    run_reverse_tui,
};

use super::project_store::ensure_project_layout;
use super::reverse_native_runtime::{ensure_tty, enter_alt_terminal, leave_alt_terminal};
use super::reverse_workbench_support::{
    ViewerLaunchRequest, ZellijFilepickerHandle, abort_zellij_filepicker, canonical_or_clone,
    clear_active_target_hint, clear_reverse_viewer_request, discover_binary_candidates,
    ensure_reverse_project_for_input, poll_zellij_filepicker, preferred_picker_root,
    read_active_target_hint, read_reverse_viewer_request, relative_or_full,
    request_reverse_viewer_open, resolve_active_project, run_analyze_now, shorten_id,
    spawn_reverse_job, spawn_zellij_filepicker, target_belongs_to_project,
    write_active_project_hint, write_active_target_hint, zellij_filepicker_is_visible,
};

const AUTO_REFRESH_INTERVAL: Duration = Duration::from_millis(900);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(140);
const MAX_DISCOVERED_INPUTS: usize = 8;
const MAX_RECENT_JOBS: usize = 8;
const NATIVE_PICKER_LAUNCH_SETTLE: Duration = Duration::from_millis(90);
const NATIVE_PICKER_TRIGGER_DEBOUNCE: Duration = Duration::from_millis(180);
const NATIVE_PICKER_CLOSE_GRACE: Duration = Duration::from_millis(240);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SurfaceAction {
    None,
    Launch,
    PickTarget,
    Quit,
}

struct ReverseSurfaceState {
    root_ws: PathBuf,
    project_override: Option<PathBuf>,
    active_project: PathBuf,
    selected_target: Option<PathBuf>,
    selected_job_id: Option<String>,
    discovered_inputs: Vec<PathBuf>,
    recent_jobs: Vec<ReverseJobMeta>,
    status_line: String,
    last_viewer_request_ns: u128,
    last_refresh: Instant,
    native_picker_not_before: Option<Instant>,
    pending_filepicker: Option<PendingFilepicker>,
}

struct PendingFilepicker {
    handle: ZellijFilepickerHandle,
    opened_at: Instant,
    seen_visible: bool,
}

pub(crate) fn run_reverse_surface(
    root_ws: PathBuf,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    ensure_tty("reverse surface")?;

    let mut state = ReverseSurfaceState::new(root_ws, project)?;
    let mut terminal = enter_alt_terminal()?;
    update_surface_lock_status(&mut state);

    let res = loop {
        state.poll_pending_filepicker()?;
        state.refresh(false)?;
        if state.should_auto_launch() {
            leave_alt_terminal(&mut terminal)?;
            let launch_result = state.launch_selected_target();
            terminal = enter_alt_terminal()?;
            update_surface_lock_status(&mut state);
            if let Err(err) = launch_result {
                state.status_line = format!("reverse viewer 启动失败: {err}");
            }
            continue;
        }

        terminal
            .draw(|f| draw_surface(f, &state))
            .map_err(RustpenError::Io)?;

        if state.consume_scheduled_picker_open() {
            drain_pending_terminal_events();
            let pick_result = state.pick_target_with_zellij_filepicker();
            if let Err(err) = pick_result {
                state.status_line = format!("zellij filepicker 失败: {err}");
            }
            continue;
        }

        if !event::poll(EVENT_POLL_INTERVAL).map_err(RustpenError::Io)? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(RustpenError::Io)? else {
            continue;
        };
        match state.handle_key(key)? {
            SurfaceAction::None => {}
            SurfaceAction::Quit => break Ok(()),
            SurfaceAction::Launch => {
                leave_alt_terminal(&mut terminal)?;
                let launch_result = state.launch_selected_target();
                terminal = enter_alt_terminal()?;
                update_surface_lock_status(&mut state);
                if let Err(err) = launch_result {
                    state.status_line = format!("reverse viewer 启动失败: {err}");
                }
            }
            SurfaceAction::PickTarget => state.schedule_target_picker_open(),
        }
    };

    leave_alt_terminal(&mut terminal).ok();
    res
}

impl ReverseSurfaceState {
    fn new(root_ws: PathBuf, project_override: Option<PathBuf>) -> Result<Self, RustpenError> {
        let active_project = resolve_active_project(&root_ws, project_override.as_ref())?;
        ensure_project_layout(&active_project)?;
        let _ = write_active_project_hint(&root_ws, &active_project);

        let mut state = Self {
            root_ws,
            project_override,
            active_project,
            selected_target: None,
            selected_job_id: None,
            discovered_inputs: Vec::new(),
            recent_jobs: Vec::new(),
            status_line: "等待 Enter / p / F4 打开 zellij filepicker 选择样本；选中后会先绑定 project，分析由你手动发起。"
                .to_string(),
            last_viewer_request_ns: 0,
            last_refresh: Instant::now() - AUTO_REFRESH_INTERVAL,
            native_picker_not_before: None,
            pending_filepicker: None,
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
        if canonical_or_clone(&resolved_project) != canonical_or_clone(&self.active_project) {
            self.active_project = resolved_project;
            self.status_line = format!("active project -> {}", self.active_project.display());
        }

        ensure_project_layout(&self.active_project)?;
        let _ = write_active_project_hint(&self.root_ws, &self.active_project);

        let previous_target = self.selected_target.clone();
        let mut invalid_hint: Option<PathBuf> = None;
        let hinted = read_active_target_hint(&self.root_ws);
        match hinted {
            Some(path)
                if path.is_file() && target_belongs_to_project(&self.active_project, &path) =>
            {
                self.selected_target = Some(path);
            }
            Some(path) => {
                self.selected_target = None;
                let _ = clear_active_target_hint(&self.root_ws);
                let _ = clear_reverse_viewer_request(&self.root_ws);
                invalid_hint = Some(path);
            }
            None => {
                self.selected_target = None;
            }
        }

        if self.selected_target.is_none()
            && let Some((recovered, source)) = self.recover_target_without_hint()
        {
            let changed = previous_target
                .as_ref()
                .map(|path| canonical_or_clone(path))
                .as_ref()
                != Some(&canonical_or_clone(&recovered));
            self.selected_target = Some(recovered.clone());
            let _ = write_active_target_hint(&self.root_ws, &recovered);
            if changed {
                let recovered_label = relative_or_full(&self.active_project, &recovered);
                self.status_line = if let Some(stale) = invalid_hint {
                    format!(
                        "旧 target 已失效: {} | 已从{source}回填 -> {}",
                        stale.display(),
                        recovered_label
                    )
                } else {
                    format!("未找到 target hint；已从{source}回填 -> {recovered_label}")
                };
            }
        } else if let Some(stale) = invalid_hint {
            self.status_line = format!("目标已失效，已清空: {}", stale.display());
        }

        self.discovered_inputs =
            discover_binary_candidates(&self.active_project, MAX_DISCOVERED_INPUTS);
        self.recent_jobs = load_recent_jobs(&self.active_project, MAX_RECENT_JOBS);
        self.sync_selected_job();
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn recover_target_without_hint(&self) -> Option<(PathBuf, &'static str)> {
        let mut jobs: Vec<_> = list_primary_sample_jobs(&self.active_project)
            .unwrap_or_default()
            .into_iter()
            .filter(|job| {
                job.target.is_file() && target_belongs_to_project(&self.active_project, &job.target)
            })
            .collect();
        if jobs.len() == 1 {
            return jobs.pop().map(|job| (job.target, "现有 reverse job"));
        }

        let mut candidates = discover_binary_candidates(&self.active_project, 2)
            .into_iter()
            .filter(|path| path.is_file() && target_belongs_to_project(&self.active_project, path))
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            return candidates.pop().map(|path| (path, "唯一样本"));
        }
        None
    }

    fn handle_key(&mut self, key: KeyEvent) -> Result<SurfaceAction, RustpenError> {
        if key.kind != KeyEventKind::Press {
            return Ok(SurfaceAction::None);
        }
        match key.code {
            KeyCode::Char('q') => Ok(SurfaceAction::Quit),
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.status_line = "reverse surface 已刷新".to_string();
                Ok(SurfaceAction::None)
            }
            KeyCode::Char('p') | KeyCode::F(4) => Ok(SurfaceAction::PickTarget),
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_job_selection(1);
                Ok(SurfaceAction::None)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_job_selection(-1);
                Ok(SurfaceAction::None)
            }
            KeyCode::Char('f') | KeyCode::Char('d') => {
                self.spawn_job_for_target("ghidra", "full", true)?;
                Ok(SurfaceAction::None)
            }
            KeyCode::Char('i') => {
                self.spawn_job_for_target("auto", "index", true)?;
                Ok(SurfaceAction::None)
            }
            KeyCode::Char('a') => {
                self.analyze_target()?;
                Ok(SurfaceAction::None)
            }
            KeyCode::Char('t') => {
                self.activate_selected_job_target()?;
                Ok(SurfaceAction::None)
            }
            KeyCode::Enter => self.enter_key_action(),
            KeyCode::Char('o') | KeyCode::Char('v') => {
                if self.selected_target.is_none() {
                    self.status_line =
                        "尚未选择目标；请按 Enter / p / F4 打开 zellij filepicker。".to_string();
                    Ok(SurfaceAction::None)
                } else {
                    Ok(SurfaceAction::Launch)
                }
            }
            KeyCode::Char('c') => {
                clear_active_target_hint(&self.root_ws)?;
                self.selected_target = None;
                self.native_picker_not_before = None;
                self.status_line = "已清空当前目标；可按 Enter / p / F4 重新选择。".to_string();
                Ok(SurfaceAction::None)
            }
            _ => Ok(SurfaceAction::None),
        }
    }

    fn enter_key_action(&mut self) -> Result<SurfaceAction, RustpenError> {
        if self.selected_target.is_none() {
            if self.selected_job().is_some() {
                self.activate_selected_job_target()?;
                return Ok(SurfaceAction::None);
            }
            return Ok(SurfaceAction::PickTarget);
        }
        if self.selected_job_differs_from_target() {
            self.activate_selected_job_target()?;
            return Ok(SurfaceAction::None);
        }
        Ok(SurfaceAction::Launch)
    }

    fn schedule_target_picker_open(&mut self) {
        self.native_picker_not_before = Some(Instant::now() + NATIVE_PICKER_TRIGGER_DEBOUNCE);
        self.status_line = "正在打开 zellij filepicker...".to_string();
    }

    fn consume_scheduled_picker_open(&mut self) -> bool {
        let Some(deadline) = self.native_picker_not_before else {
            return false;
        };
        if Instant::now() < deadline {
            return false;
        }
        self.native_picker_not_before = None;
        true
    }

    fn pick_target_with_zellij_filepicker(&mut self) -> Result<(), RustpenError> {
        if self.pending_filepicker.is_some() {
            self.status_line =
                "zellij filepicker 正在运行；若要收起，直接再按一次 F4。".to_string();
            return Ok(());
        }
        let start = self
            .selected_target
            .clone()
            .unwrap_or_else(|| preferred_picker_root(&self.active_project));
        let _ = switch_zellij_mode_for_filepicker();
        flush_tty_stdin_input();
        std::thread::sleep(NATIVE_PICKER_LAUNCH_SETTLE);
        flush_tty_stdin_input();
        let handle = spawn_zellij_filepicker(Some(&start), "rscan reverse target")
            .map_err(RustpenError::ParseError)?;
        let seen_visible = zellij_filepicker_is_visible(&handle).unwrap_or(false);
        self.pending_filepicker = Some(PendingFilepicker {
            handle,
            opened_at: Instant::now(),
            seen_visible,
        });
        self.status_line = if seen_visible {
            "zellij filepicker 已打开；选中文件后会自动绑定并补 index，F4 可关闭。".to_string()
        } else {
            "正在打开 zellij filepicker...".to_string()
        };
        Ok(())
    }

    fn poll_pending_filepicker(&mut self) -> Result<(), RustpenError> {
        let Some(mut pending) = self.pending_filepicker.take() else {
            return Ok(());
        };

        if let Some(result) =
            poll_zellij_filepicker(&mut pending.handle).map_err(RustpenError::ParseError)?
        {
            let _ = auto_lock_zellij_for_surface();
            match result {
                Ok(path) => {
                    let msg = self.import_target_with_default_index(&path)?;
                    self.refresh(true)?;
                    self.status_line = format!("zellij filepicker -> {msg}");
                }
                Err(err) => {
                    self.status_line = if is_filepicker_closed_message(&err) {
                        "zellij filepicker 已关闭".to_string()
                    } else {
                        format!("zellij filepicker: {err}")
                    };
                }
            }
            return Ok(());
        }

        let visible = zellij_filepicker_is_visible(&pending.handle).unwrap_or(false);
        pending.seen_visible |= visible;
        if pending.seen_visible
            && !visible
            && pending.opened_at.elapsed() >= NATIVE_PICKER_CLOSE_GRACE
        {
            let _ = abort_zellij_filepicker(&mut pending.handle);
            let _ = auto_lock_zellij_for_surface();
            self.status_line = "zellij filepicker 已关闭".to_string();
            return Ok(());
        }

        if visible {
            self.status_line =
                "zellij filepicker 已打开；选中文件后会自动绑定并补 index，F4 可关闭。".to_string();
        }

        self.pending_filepicker = Some(pending);
        Ok(())
    }

    fn should_auto_launch(&self) -> bool {
        self.pending_viewer_request().is_some()
    }

    fn launch_selected_target(&mut self) -> Result<(), RustpenError> {
        let Some(target) = self.selected_target.clone() else {
            self.status_line =
                "尚未选择目标；请按 Enter / p / F4 打开 zellij filepicker。".to_string();
            return Ok(());
        };
        let display = relative_or_full(&self.active_project, &target);
        let cfg = ReverseConsoleConfig {
            input: target.clone(),
            workspace: self.active_project.clone(),
            pwndbg_init: None,
        };

        self.mark_pending_viewer_request_seen();
        let result = run_reverse_tui(cfg);
        self.refresh(true)?;
        self.status_line = match result {
            Ok(()) => format!(
                "reverse viewer 已退出 -> {} | 如需再次打开，可直接按 Enter / o / v。",
                display
            ),
            Err(err) => format!("reverse viewer 运行失败 -> {} | {}", display, err),
        };
        Ok(())
    }

    fn analyze_target(&mut self) -> Result<(), RustpenError> {
        let Some(target) = self.selected_target.clone() else {
            self.status_line = "尚未选择目标；无法执行 analyze。".to_string();
            return Ok(());
        };
        self.status_line = run_analyze_now(&self.active_project, &target)?;
        self.refresh(true)?;
        Ok(())
    }

    fn sync_selected_job(&mut self) {
        if self.recent_jobs.is_empty() {
            self.selected_job_id = None;
            return;
        }
        if let Some(selected) = self.selected_job_id.as_ref()
            && self.recent_jobs.iter().any(|job| &job.id == selected)
        {
            return;
        }
        if let Some(target) = self.selected_target.as_ref()
            && let Some(job) = self
                .recent_jobs
                .iter()
                .find(|job| canonical_or_clone(&job.target) == canonical_or_clone(target))
        {
            self.selected_job_id = Some(job.id.clone());
            return;
        }
        self.selected_job_id = self.recent_jobs.first().map(|job| job.id.clone());
    }

    fn selected_job(&self) -> Option<&ReverseJobMeta> {
        let selected = self.selected_job_id.as_ref()?;
        self.recent_jobs.iter().find(|job| &job.id == selected)
    }

    fn selected_job_index(&self) -> usize {
        let Some(selected) = self.selected_job_id.as_ref() else {
            return 0;
        };
        self.recent_jobs
            .iter()
            .position(|job| &job.id == selected)
            .unwrap_or(0)
    }

    fn move_job_selection(&mut self, delta: isize) {
        if self.recent_jobs.is_empty() {
            self.status_line = "当前没有 reverse job 可选".to_string();
            return;
        }
        let upper = self.recent_jobs.len().saturating_sub(1) as isize;
        let next = (self.selected_job_index() as isize + delta).clamp(0, upper) as usize;
        let job = &self.recent_jobs[next];
        self.selected_job_id = Some(job.id.clone());
        self.status_line = format!(
            "selected job -> {} ({})",
            shorten_id(&job.id, 18),
            relative_or_full(&self.active_project, &job.target)
        );
    }

    fn selected_job_differs_from_target(&self) -> bool {
        let Some(target) = self.selected_target.as_ref() else {
            return false;
        };
        let Some(job) = self.selected_job() else {
            return false;
        };
        canonical_or_clone(&job.target) != canonical_or_clone(target)
    }

    fn activate_selected_job_target(&mut self) -> Result<(), RustpenError> {
        let Some(job) = self.selected_job().cloned() else {
            self.status_line = "当前没有可跟随的 reverse job".to_string();
            return Ok(());
        };
        write_active_target_hint(&self.root_ws, &job.target)?;
        self.selected_target = Some(job.target.clone());
        self.status_line = format!(
            "当前文件 -> {} | job {}",
            relative_or_full(&self.active_project, &job.target),
            shorten_id(&job.id, 18)
        );
        Ok(())
    }

    fn spawn_job_for_target(
        &mut self,
        engine: &str,
        mode: &str,
        open_viewer: bool,
    ) -> Result<(), RustpenError> {
        let Some(target) = self.selected_target.clone() else {
            self.status_line = format!("尚未选择目标；无法执行 {mode}。");
            return Ok(());
        };
        if open_viewer {
            request_reverse_viewer_open(&self.root_ws, &target)?;
        }
        self.status_line = spawn_reverse_job(&self.active_project, &target, engine, mode)?;
        self.refresh(true)?;
        Ok(())
    }

    fn import_target_with_default_index(
        &mut self,
        selected: &Path,
    ) -> Result<String, RustpenError> {
        let (project, target, bind_msg) = self.bind_selected_file(selected, true)?;
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
        self.selected_target = Some(prepared.target.clone());
        write_active_project_hint(&self.root_ws, &prepared.project)?;
        write_active_target_hint(&self.root_ws, &prepared.target)?;
        if open_viewer {
            request_reverse_viewer_open(&self.root_ws, &prepared.target)?;
        }

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

    fn pending_viewer_request(&self) -> Option<ViewerLaunchRequest> {
        let selected = self.selected_target.as_ref()?;
        let request = read_reverse_viewer_request(&self.root_ws)?;
        if request.request_ns <= self.last_viewer_request_ns {
            return None;
        }
        if canonical_or_clone(&request.target) != canonical_or_clone(selected) {
            return None;
        }
        Some(request)
    }

    fn mark_pending_viewer_request_seen(&mut self) {
        if let Some(request) = self.pending_viewer_request() {
            self.last_viewer_request_ns = request.request_ns;
            let _ = clear_reverse_viewer_request(&self.root_ws);
        }
    }
}

fn draw_surface(f: &mut ratatui::Frame<'_>, state: &ReverseSurfaceState) {
    let size = f.size();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(4),
                Constraint::Min(8),
                Constraint::Length(5),
            ]
            .as_ref(),
        )
        .split(size);

    let target_label = state
        .selected_target
        .as_ref()
        .map(|path| relative_or_full(&state.active_project, path))
        .unwrap_or_else(|| "<等待 zellij filepicker 选择目标>".to_string());
    let launch_state = if state.should_auto_launch() {
        "pending"
    } else {
        "manual"
    };
    let header = Paragraph::new(Text::from(vec![
        Line::from(vec![
            Span::styled("project: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.active_project.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("file: ", Style::default().fg(Color::Yellow)),
            if state.selected_target.is_some() {
                Span::styled(
                    target_label,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw(target_label)
            },
        ]),
        Line::from(vec![
            Span::styled("viewer: ", Style::default().fg(Color::Yellow)),
            Span::raw(launch_state),
            Span::raw("  "),
            Span::styled("jobs: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.recent_jobs.len().to_string()),
        ]),
    ]))
    .block(
        Block::default()
            .title("rscan reverse surface")
            .borders(Borders::ALL),
    )
    .wrap(Wrap { trim: false });
    f.render_widget(header, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)].as_ref())
        .split(rows[1]);

    let left = Paragraph::new(build_file_panel_text(state))
        .block(Block::default().title("Current File").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(left, cols[0]);

    let jobs = List::new(build_jobs_items(state))
        .block(Block::default().title("Jobs").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    f.render_stateful_widget(jobs, cols[1], &mut list_state(state.selected_job_index()));

    let footer = Paragraph::new(Text::from(vec![
        Line::from(state.status_line.clone()),
        Line::from("Enter=follow selected job / open viewer  p/F4=picker  t=follow job"),
        Line::from("j/k=select job  i=index  f/d=full  a=analyze  c=clear  r=refresh  q=quit"),
    ]))
    .block(Block::default().title("Bridge").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    f.render_widget(footer, rows[2]);
}

fn build_file_panel_text(state: &ReverseSurfaceState) -> Text<'static> {
    let mut lines = Vec::new();
    if let Some(target) = &state.selected_target {
        lines.push(Line::from(vec![
            Span::styled("current", Style::default().fg(Color::Yellow)),
            Span::raw(format!(
                "  {}",
                relative_or_full(&state.active_project, target)
            )),
        ]));
        if let Some(job) = state
            .recent_jobs
            .iter()
            .find(|job| canonical_or_clone(&job.target) == canonical_or_clone(target))
        {
            lines.push(Line::from(format!(
                "job: {}  {}  {}",
                shorten_id(&job.id, 12),
                format!("{:?}", job.status).to_ascii_lowercase(),
                job.mode.as_deref().unwrap_or("-")
            )));
        } else {
            lines.push(Line::from("job: <none yet>"));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("p/F4 打开文件目录"));
        lines.push(Line::from("picker 开着时再按 F4 关闭"));
        lines.push(Line::from("Enter 打开当前 viewer"));
        lines.push(Line::from("i=auto-index  f/d=ghidra-full  a=analyze"));
    } else {
        lines.push(Line::from("当前未选文件"));
        lines.push(Line::from(""));
        lines.push(Line::from("p/F4 打开 zellij filepicker"));
        lines.push(Line::from("picker 开着时再按 F4 关闭"));
        lines.push(Line::from("Enter 若有高亮 job 就先跟随该文件"));
        lines.push(Line::from("没有 job 时 Enter 直接选文件"));
    }

    Text::from(lines)
}

fn build_jobs_items(state: &ReverseSurfaceState) -> Vec<ListItem<'static>> {
    if state.recent_jobs.is_empty() {
        return vec![ListItem::new("<none> | 先选文件，再发起 index/full job。")];
    }
    state
        .recent_jobs
        .iter()
        .map(|job| {
            let current_marker = state
                .selected_target
                .as_ref()
                .map(|target| canonical_or_clone(target) == canonical_or_clone(&job.target))
                .unwrap_or(false);
            let marker = if current_marker { "*" } else { " " };
            let status = format!("{:?}", job.status).to_ascii_lowercase();
            let target = job
                .target
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| relative_or_full(&state.active_project, &job.target));
            ListItem::new(format!(
                "{}{} {:<9} {:<8} {}",
                marker,
                shorten_id(&job.id, 10),
                status,
                job.mode.as_deref().unwrap_or("-"),
                target,
            ))
        })
        .collect()
}

fn list_state(selected: usize) -> ListState {
    let mut state = ListState::default();
    state.select(Some(selected));
    state
}

fn load_recent_jobs(project: &Path, limit: usize) -> Vec<ReverseJobMeta> {
    let mut jobs = list_primary_sample_jobs(project).unwrap_or_default();
    jobs.truncate(limit);
    jobs
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

fn update_surface_lock_status(state: &mut ReverseSurfaceState) {
    if let Err(err) = auto_lock_zellij_for_surface() {
        state.status_line =
            format!("zellij locked 自动切换失败: {err} | 如按键被吞，可手动 Ctrl-g");
    } else if std::env::var("ZELLIJ").is_ok() || std::env::var("ZELLIJ_SESSION_NAME").is_ok() {
        state.status_line =
            "reverse surface 已自动切到 zellij Locked mode；Enter / p / F4 现在会直达当前 pane。"
                .to_string();
    }
}

fn auto_lock_zellij_for_surface() -> Result<(), String> {
    switch_zellij_mode("locked")
}

fn switch_zellij_mode_for_filepicker() -> Result<(), String> {
    switch_zellij_mode("pane")
}

fn switch_zellij_mode(mode: &str) -> Result<(), String> {
    if std::env::var("ZELLIJ").is_err() && std::env::var("ZELLIJ_SESSION_NAME").is_err() {
        return Ok(());
    }
    let status = Command::new("zellij")
        .args(["action", "switch-mode", mode])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij switch-mode {mode} 失败: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("zellij switch-mode {mode} 返回失败"))
    }
}

fn is_filepicker_closed_message(err: &str) -> bool {
    matches!(err.trim(), "未选择任何文件" | "zellij filepicker 返回失败")
}

fn drain_pending_terminal_events() {
    while event::poll(Duration::ZERO).unwrap_or(false) {
        if event::read().is_err() {
            break;
        }
    }
}

#[cfg(unix)]
fn flush_tty_stdin_input() {
    if !stdin().is_terminal() {
        return;
    }
    unsafe {
        libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
    }
}

#[cfg(not(unix))]
fn flush_tty_stdin_input() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_root(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_reverse_surface_{name}_{stamp:x}"))
    }

    fn write_job_meta(project: &Path, target: &Path) {
        let job = ReverseJobMeta {
            id: "job-test".to_string(),
            kind: "decompile".to_string(),
            backend: "rust-index".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: target.to_path_buf(),
            workspace: project.to_path_buf(),
            status: ReverseJobStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            exit_code: Some(0),
            program: "rust-index".to_string(),
            args: Vec::new(),
            note: "test".to_string(),
            artifacts: Vec::new(),
            error: None,
        };
        let meta_path = project.join("jobs").join(&job.id).join("meta.json");
        fs::create_dir_all(meta_path.parent().unwrap()).unwrap();
        fs::write(meta_path, serde_json::to_vec_pretty(&job).unwrap()).unwrap();
    }

    fn fake_job(id: &str, project: &Path, target: &Path) -> ReverseJobMeta {
        ReverseJobMeta {
            id: id.to_string(),
            kind: "decompile".to_string(),
            backend: "rust-index".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: target.to_path_buf(),
            workspace: project.to_path_buf(),
            status: ReverseJobStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            exit_code: Some(0),
            program: "rust-index".to_string(),
            args: Vec::new(),
            note: "test".to_string(),
            artifacts: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn refresh_recovers_target_from_single_job_when_hint_missing() {
        let root = temp_root("recover_job");
        let project = root.join("projects").join("sample");
        let staged = project.join("binaries").join("sample.bin");
        let real = root.join("fixtures").join("sample.bin");
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(&real, b"\x7fELF").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &staged).unwrap();
        #[cfg(not(unix))]
        fs::copy(&real, &staged).unwrap();

        write_job_meta(&project, &staged);

        let state = ReverseSurfaceState::new(root.clone(), Some(project.clone())).unwrap();
        assert_eq!(state.selected_target.as_deref(), Some(staged.as_path()));
        assert_eq!(
            read_active_target_hint(&root).as_deref(),
            Some(staged.as_path())
        );
        assert!(state.status_line.contains("回填"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn enter_on_highlighted_other_job_switches_current_target() {
        let root = temp_root("follow_job");
        let project = root.join("projects").join("sample");
        let target_a = project.join("binaries").join("a.bin");
        let target_b = project.join("binaries").join("b.bin");
        fs::create_dir_all(target_a.parent().unwrap()).unwrap();
        fs::write(&target_a, b"\x7fELF").unwrap();
        fs::write(&target_b, b"\x7fELF").unwrap();

        let mut state = ReverseSurfaceState {
            root_ws: root.clone(),
            project_override: Some(project.clone()),
            active_project: project.clone(),
            selected_target: Some(target_a.clone()),
            selected_job_id: Some("job-b".to_string()),
            discovered_inputs: Vec::new(),
            recent_jobs: vec![
                fake_job("job-a", &project, &target_a),
                fake_job("job-b", &project, &target_b),
            ],
            status_line: String::new(),
            last_viewer_request_ns: 0,
            last_refresh: Instant::now(),
            native_picker_not_before: None,
            pending_filepicker: None,
        };

        let action = state.enter_key_action().unwrap();
        assert_eq!(action, SurfaceAction::None);
        assert_eq!(state.selected_target.as_deref(), Some(target_b.as_path()));
        assert_eq!(
            read_active_target_hint(&root).as_deref(),
            Some(target_b.as_path())
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn filepicker_close_messages_are_treated_as_benign() {
        assert!(is_filepicker_closed_message("未选择任何文件"));
        assert!(is_filepicker_closed_message("zellij filepicker 返回失败"));
        assert!(!is_filepicker_closed_message(
            "zellij pipe(filepicker) 调用失败"
        ));
    }
}
