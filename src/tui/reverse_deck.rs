use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};

use crate::errors::RustpenError;
use crate::modules::reverse::ReverseJobMeta;

use super::project_store::ensure_project_layout;
use super::reverse_native_runtime::{ensure_tty, enter_alt_terminal, leave_alt_terminal};
use super::reverse_workbench_support::{
    canonical_or_clone, load_visible_reverse_jobs, read_active_target_hint, relative_or_full,
    resolve_active_project, shorten_id, target_belongs_to_project, write_active_project_hint,
    write_active_target_hint,
};
#[path = "reverse_deck_actions.rs"]
mod actions;
#[path = "reverse_deck_support.rs"]
mod support;

#[path = "reverse_deck_view.rs"]
mod view;
use actions::{
    open_reverse_job_artifacts_pane, open_reverse_job_logs_pane, open_reverse_job_shell_pane,
};
use support::{
    DeckTargetRevision, ReverseArtifactSummary, load_job_artifact_summary, read_last_lines_fast,
    target_revision,
};
use view::draw_deck;

const AUTO_REFRESH_INTERVAL: Duration = Duration::from_millis(1100);
const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(180);
const MAX_RECENT_JOBS: usize = 8;
const LOG_PREVIEW_LINES: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileRevision {
    path: PathBuf,
    modified_ms: u128,
    len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LogRevision {
    job_id: String,
    stdout: Option<FileRevision>,
    stderr: Option<FileRevision>,
    mode: DeckLogMode,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DeckDetailMode {
    Logs,
    Artifacts,
    Meta,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DeckLogMode {
    Both,
    Stdout,
    Stderr,
}

impl DeckDetailMode {
    fn next(self) -> Self {
        match self {
            Self::Logs => Self::Artifacts,
            Self::Artifacts => Self::Meta,
            Self::Meta => Self::Logs,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Logs => "Log",
            Self::Artifacts => "Artifacts",
            Self::Meta => "Meta",
        }
    }
}

impl DeckLogMode {
    fn next(self) -> Self {
        match self {
            Self::Both => Self::Stdout,
            Self::Stdout => Self::Stderr,
            Self::Stderr => Self::Both,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

struct ReverseDeckState {
    root_ws: PathBuf,
    project_override: Option<PathBuf>,
    active_project: PathBuf,
    selected_target: Option<PathBuf>,
    selected_target_revision: Option<DeckTargetRevision>,
    recent_jobs: Vec<ReverseJobMeta>,
    preview_job_id: Option<String>,
    detail_mode: DeckDetailMode,
    log_mode: DeckLogMode,
    log_revision: Option<LogRevision>,
    log_preview: Vec<String>,
    artifact_summary: ReverseArtifactSummary,
    status_line: String,
    last_refresh: Instant,
}

pub(crate) fn run_reverse_deck(
    root_ws: PathBuf,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    ensure_tty("reverse deck")?;

    let mut state = ReverseDeckState::new(root_ws, project)?;
    let mut terminal = enter_alt_terminal()?;

    let res = loop {
        state.refresh(false)?;
        terminal
            .draw(|f| draw_deck(f, &state))
            .map_err(RustpenError::Io)?;

        if !event::poll(EVENT_POLL_INTERVAL).map_err(RustpenError::Io)? {
            continue;
        }
        let Event::Key(key) = event::read().map_err(RustpenError::Io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if state.handle_key(key.code)? {
            break Ok(());
        }
    };

    leave_alt_terminal(&mut terminal).ok();
    res
}

impl ReverseDeckState {
    fn new(root_ws: PathBuf, project_override: Option<PathBuf>) -> Result<Self, RustpenError> {
        let active_project = resolve_active_project(&root_ws, project_override.as_ref())?;
        ensure_project_layout(&active_project)?;
        let _ = write_active_project_hint(&root_ws, &active_project);

        let mut state = Self {
            root_ws,
            project_override,
            active_project,
            selected_target: None,
            selected_target_revision: None,
            recent_jobs: Vec::new(),
            preview_job_id: None,
            detail_mode: DeckDetailMode::Logs,
            log_mode: DeckLogMode::Both,
            log_revision: None,
            log_preview: vec!["<waiting for reverse jobs>".to_string()],
            artifact_summary: ReverseArtifactSummary::default(),
            status_line: "reverse deck 正在承接旧独立 reverse 面板的辅助区。".to_string(),
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
        if canonical_or_clone(&resolved_project) != canonical_or_clone(&self.active_project) {
            self.active_project = resolved_project;
            self.status_line = format!("active project -> {}", self.active_project.display());
        }

        ensure_project_layout(&self.active_project)?;
        let _ = write_active_project_hint(&self.root_ws, &self.active_project);
        let previous_target_revision = self.selected_target_revision.clone();
        self.selected_target = read_active_target_hint(&self.root_ws)
            .filter(|path| path.is_file() && target_belongs_to_project(&self.active_project, path));
        self.selected_target_revision = self
            .selected_target
            .as_deref()
            .map(|path| target_revision(&self.root_ws, path));
        self.recent_jobs = load_recent_jobs(
            &self.active_project,
            self.selected_target.as_deref(),
            MAX_RECENT_JOBS,
        );
        self.sync_preview_job(previous_target_revision);
        self.refresh_artifact_summary();
        self.refresh_log_preview();
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn handle_key(&mut self, code: KeyCode) -> Result<bool, RustpenError> {
        match code {
            KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('r') => {
                self.refresh(true)?;
                self.status_line = "reverse deck 已刷新".to_string();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home | KeyCode::Char('g') => self.select_first_job(),
            KeyCode::End | KeyCode::Char('G') => self.select_last_job(),
            KeyCode::Enter | KeyCode::Char('o') => {
                self.activate_preview_target()?;
            }
            KeyCode::Tab => {
                self.detail_mode = self.detail_mode.next();
                self.status_line = format!("detail mode -> {}", self.detail_mode.title());
            }
            KeyCode::Char('1') => {
                self.detail_mode = DeckDetailMode::Logs;
                self.status_line = "detail mode -> Log".to_string();
            }
            KeyCode::Char('2') | KeyCode::Char('a') => {
                self.detail_mode = DeckDetailMode::Artifacts;
                self.status_line = "detail mode -> Artifacts".to_string();
            }
            KeyCode::Char('3') | KeyCode::Char('m') => {
                self.detail_mode = DeckDetailMode::Meta;
                self.status_line = "detail mode -> Meta".to_string();
            }
            KeyCode::Char('l') => {
                self.log_mode = self.log_mode.next();
                self.log_revision = None;
                self.refresh_log_preview();
                self.status_line = format!("log mode -> {}", self.log_mode.label());
            }
            KeyCode::Char('L') => self.open_logs_pane(),
            KeyCode::Char('A') => self.open_artifacts_pane(),
            KeyCode::Char('W') => self.open_shell_pane(),
            KeyCode::Char('t') => self.select_job_for_current_target(),
            _ => {}
        }
        Ok(false)
    }

    fn sync_preview_job(&mut self, previous_target_revision: Option<DeckTargetRevision>) {
        let target_changed = self.selected_target_revision != previous_target_revision;
        let previous_preview = self.preview_job_id.clone();
        if target_changed {
            let next_job = select_preview_job(&self.recent_jobs, self.selected_target.as_deref());
            let next_job_id = next_job.map(|job| job.id.clone());
            let status_line = self.describe_target_follow_status(next_job);
            self.preview_job_id = next_job_id;
            if self.preview_job_id != previous_preview {
                self.log_revision = None;
            }
            self.status_line = status_line;
            return;
        }

        if let Some(current_id) = self.preview_job_id.as_deref()
            && self.recent_jobs.iter().any(|job| job.id == current_id)
        {
            return;
        }
        self.preview_job_id =
            select_preview_job(&self.recent_jobs, self.selected_target.as_deref())
                .map(|job| job.id.clone());
        if self.preview_job_id != previous_preview {
            self.log_revision = None;
        }
    }

    fn refresh_log_preview(&mut self) {
        let Some(job) = self.preview_job() else {
            self.log_preview = vec!["<no reverse jobs yet>".to_string()];
            self.log_revision = None;
            return;
        };
        let revision = log_revision(job, self.log_mode);
        if self.log_revision.as_ref() == Some(&revision) {
            return;
        }
        self.log_preview = build_log_preview(job, LOG_PREVIEW_LINES, self.log_mode);
        self.log_revision = Some(revision);
    }

    fn refresh_artifact_summary(&mut self) {
        self.artifact_summary = self
            .preview_job()
            .map(load_job_artifact_summary)
            .unwrap_or_default();
    }

    fn preview_job(&self) -> Option<&ReverseJobMeta> {
        let id = self.preview_job_id.as_deref()?;
        self.recent_jobs.iter().find(|job| job.id == id)
    }

    fn preview_index(&self) -> usize {
        self.preview_job_id
            .as_deref()
            .and_then(|id| self.recent_jobs.iter().position(|job| job.id == id))
            .unwrap_or(0)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.recent_jobs.is_empty() {
            self.preview_job_id = None;
            self.status_line = "当前没有 reverse job 可选".to_string();
            return;
        }
        let upper = self.recent_jobs.len().saturating_sub(1) as isize;
        let next = (self.preview_index() as isize + delta).clamp(0, upper) as usize;
        let job_id = self.recent_jobs[next].id.clone();
        let job_mode = self.recent_jobs[next]
            .mode
            .as_deref()
            .unwrap_or("-")
            .to_string();
        self.preview_job_id = Some(job_id.clone());
        self.log_revision = None;
        self.refresh_artifact_summary();
        self.refresh_log_preview();
        self.status_line = format!("selected job -> {} ({})", shorten_id(&job_id, 18), job_mode);
    }

    fn select_first_job(&mut self) {
        if self.recent_jobs.is_empty() {
            return;
        }
        self.preview_job_id = self.recent_jobs.first().map(|job| job.id.clone());
        self.log_revision = None;
        self.refresh_artifact_summary();
        self.refresh_log_preview();
    }

    fn select_last_job(&mut self) {
        if self.recent_jobs.is_empty() {
            return;
        }
        self.preview_job_id = self.recent_jobs.last().map(|job| job.id.clone());
        self.log_revision = None;
        self.refresh_artifact_summary();
        self.refresh_log_preview();
    }

    fn activate_preview_target(&mut self) -> Result<(), RustpenError> {
        let Some(job) = self.preview_job().cloned() else {
            self.status_line = "当前没有可激活的 reverse job".to_string();
            return Ok(());
        };
        write_active_target_hint(&self.root_ws, &job.target)?;
        self.selected_target = Some(job.target.clone());
        self.status_line = format!(
            "已同步 job target -> {} | 右上 viewer 将切到该目标",
            relative_or_full(&self.active_project, &job.target)
        );
        Ok(())
    }

    fn select_job_for_current_target(&mut self) {
        let Some(job) = select_preview_job(&self.recent_jobs, self.selected_target.as_deref())
        else {
            self.status_line = "当前 target 没有命中的 reverse job".to_string();
            return;
        };
        let job_id = job.id.clone();
        self.preview_job_id = Some(job_id.clone());
        self.log_revision = None;
        self.refresh_artifact_summary();
        self.refresh_log_preview();
        self.status_line = format!("已回对当前 target 的 job -> {}", shorten_id(&job_id, 18));
    }

    fn open_logs_pane(&mut self) {
        let Some(job) = self.preview_job().cloned() else {
            self.status_line = "当前没有可打开日志的 reverse job".to_string();
            return;
        };
        self.status_line = open_reverse_job_logs_pane(&job, self.log_mode);
    }

    fn open_artifacts_pane(&mut self) {
        let Some(job) = self.preview_job().cloned() else {
            self.status_line = "当前没有可打开 artifacts 的 reverse job".to_string();
            return;
        };
        self.status_line = open_reverse_job_artifacts_pane(&job);
    }

    fn open_shell_pane(&mut self) {
        let Some(job) = self.preview_job().cloned() else {
            self.status_line = "当前没有可打开 shell 的 reverse job".to_string();
            return;
        };
        self.status_line = open_reverse_job_shell_pane(&job);
    }

    fn describe_target_follow_status(&self, next_job: Option<&ReverseJobMeta>) -> String {
        match (self.selected_target.as_ref(), next_job) {
            (Some(target), Some(job))
                if canonical_or_clone(target) == canonical_or_clone(&job.target) =>
            {
                format!(
                    "deck 已跟随当前 target -> {} | job {}",
                    relative_or_full(&self.active_project, target),
                    shorten_id(&job.id, 18)
                )
            }
            (Some(target), Some(job)) => format!(
                "target 已切换 -> {} | 暂无匹配 job，回退显示 {}",
                relative_or_full(&self.active_project, target),
                shorten_id(&job.id, 18)
            ),
            (Some(target), None) => format!(
                "target 已切换 -> {} | 当前还没有 reverse job",
                relative_or_full(&self.active_project, target)
            ),
            (None, Some(job)) => format!(
                "当前 target 已清空 | deck 回退到最近 job {}",
                shorten_id(&job.id, 18)
            ),
            (None, None) => "当前 target 已清空 | 暂无 reverse job".to_string(),
        }
    }
}

fn load_recent_jobs(project: &Path, target: Option<&Path>, limit: usize) -> Vec<ReverseJobMeta> {
    load_visible_reverse_jobs(project, target, limit)
}

fn select_preview_job<'a>(
    jobs: &'a [ReverseJobMeta],
    target: Option<&Path>,
) -> Option<&'a ReverseJobMeta> {
    let target = target.map(canonical_or_clone);
    if let Some(target) = target
        && let Some(job) = jobs
            .iter()
            .find(|job| canonical_or_clone(&job.target) == target)
    {
        return Some(job);
    }
    jobs.first()
}

fn log_revision(job: &ReverseJobMeta, mode: DeckLogMode) -> LogRevision {
    let (stdout_log, stderr_log) = job_log_paths(job);
    LogRevision {
        job_id: job.id.clone(),
        stdout: file_revision(&stdout_log),
        stderr: file_revision(&stderr_log),
        mode,
    }
}

fn file_revision(path: &Path) -> Option<FileRevision> {
    let meta = fs::metadata(path).ok()?;
    let modified_ms = meta
        .modified()
        .ok()
        .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    Some(FileRevision {
        path: path.to_path_buf(),
        modified_ms,
        len: meta.len(),
    })
}

fn build_log_preview(job: &ReverseJobMeta, max_lines: usize, mode: DeckLogMode) -> Vec<String> {
    let chunk = if matches!(mode, DeckLogMode::Both) {
        (max_lines / 2).max(1)
    } else {
        max_lines.max(1)
    };
    let (stdout_log, stderr_log) = job_log_paths(job);
    let stdout_lines = read_last_lines(&stdout_log, chunk);
    let stderr_lines = read_last_lines(&stderr_log, chunk);
    if stdout_lines.is_empty() && stderr_lines.is_empty() {
        return vec!["<stdout/stderr 仍为空>".to_string()];
    }

    let mut lines = Vec::new();
    if matches!(mode, DeckLogMode::Both | DeckLogMode::Stdout) && !stdout_lines.is_empty() {
        lines.push("[stdout]".to_string());
        lines.extend(stdout_lines);
    }
    if matches!(mode, DeckLogMode::Both | DeckLogMode::Stderr) && !stderr_lines.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("[stderr]".to_string());
        lines.extend(stderr_lines);
    }
    lines
}

fn job_log_paths(job: &ReverseJobMeta) -> (PathBuf, PathBuf) {
    let job_dir = job.workspace.join("jobs").join(&job.id);
    (job_dir.join("stdout.log"), job_dir.join("stderr.log"))
}

fn read_last_lines(path: &Path, limit: usize) -> Vec<String> {
    read_last_lines_fast(path, limit)
}
