use std::cmp::Reverse;
use std::fs::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use super::models::ProjectTemplate;
use super::project_store::{create_local_project, ensure_project_layout, load_projects};
use crate::errors::RustpenError;
use crate::modules::reverse::{ReverseJobMeta, list_primary_jobs, list_primary_sample_jobs};

#[path = "reverse_workbench_fs.rs"]
mod fs_support;
use fs_support::{
    collect_candidate_files, file_mtime, human_size, is_probable_reverse_input, should_skip_dir,
};

const ACTIVE_PROJECT_HINT_FILE: &str = "active_project.txt";
const ACTIVE_TARGET_HINT_FILE: &str = "selected_target.txt";
const VIEWER_REQUEST_HINT_FILE: &str = "open_viewer.txt";
const MAX_REVERSE_PROJECT_ATTEMPTS: usize = 32;
const FILEPICKER_PLUGIN_WAIT_TIMEOUT: Duration = Duration::from_millis(750);
const FILEPICKER_PLUGIN_WAIT_STEP: Duration = Duration::from_millis(25);

#[derive(Clone, Debug)]
pub(crate) struct ReverseBrowserEntry {
    pub(crate) path: PathBuf,
    pub(crate) is_dir: bool,
    pub(crate) label: String,
    pub(crate) detail: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedReverseTarget {
    pub(crate) project: PathBuf,
    pub(crate) target: PathBuf,
    pub(crate) created_project: bool,
    pub(crate) staged_input: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ViewerLaunchRequest {
    pub(crate) target: PathBuf,
    pub(crate) request_ns: u128,
}

pub(crate) struct ZellijFilepickerHandle {
    child: Option<std::process::Child>,
    session_name: Option<String>,
    revealed_hidden_floating: bool,
}

pub(crate) fn active_project_hint_path(root_ws: &Path) -> PathBuf {
    reverse_hint_dir(root_ws).join(ACTIVE_PROJECT_HINT_FILE)
}

pub(crate) fn active_target_hint_path(root_ws: &Path) -> PathBuf {
    reverse_hint_dir(root_ws).join(ACTIVE_TARGET_HINT_FILE)
}

pub(crate) fn active_viewer_request_path(root_ws: &Path) -> PathBuf {
    reverse_hint_dir(root_ws).join(VIEWER_REQUEST_HINT_FILE)
}

fn reverse_hint_dir(root_ws: &Path) -> PathBuf {
    root_ws.join(".rscan").join("reverse")
}

pub(crate) fn write_active_project_hint(
    root_ws: &Path,
    project: &Path,
) -> Result<(), RustpenError> {
    let hint_path = active_project_hint_path(root_ws);
    if let Some(parent) = hint_path.parent() {
        fs::create_dir_all(parent).map_err(RustpenError::Io)?;
    }
    let project = canonical_or_clone(project);
    fs::write(&hint_path, project.display().to_string()).map_err(RustpenError::Io)?;
    reconcile_reverse_hints_for_project(root_ws, &project)?;
    Ok(())
}

pub(crate) fn read_active_project_hint(root_ws: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(active_project_hint_path(root_ws)).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let path = PathBuf::from(text);
    if path.is_dir() { Some(path) } else { None }
}

pub(crate) fn write_active_target_hint(root_ws: &Path, input: &Path) -> Result<(), RustpenError> {
    let hint_path = active_target_hint_path(root_ws);
    if let Some(parent) = hint_path.parent() {
        fs::create_dir_all(parent).map_err(RustpenError::Io)?;
    }
    let input = absolute_or_clone(input);
    fs::write(&hint_path, input.display().to_string()).map_err(RustpenError::Io)?;
    Ok(())
}

pub(crate) fn clear_active_target_hint(root_ws: &Path) -> Result<(), RustpenError> {
    let hint_path = active_target_hint_path(root_ws);
    match fs::remove_file(&hint_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(RustpenError::Io(e)),
    }
}

pub(crate) fn clear_reverse_viewer_request(root_ws: &Path) -> Result<(), RustpenError> {
    let hint_path = active_viewer_request_path(root_ws);
    match fs::remove_file(&hint_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(RustpenError::Io(e)),
    }
}

pub(crate) fn read_active_target_hint(root_ws: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(active_target_hint_path(root_ws)).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let path = PathBuf::from(text);
    if path.is_file() { Some(path) } else { None }
}

pub(crate) fn request_reverse_viewer_open(
    root_ws: &Path,
    input: &Path,
) -> Result<(), RustpenError> {
    let hint_path = active_viewer_request_path(root_ws);
    if let Some(parent) = hint_path.parent() {
        fs::create_dir_all(parent).map_err(RustpenError::Io)?;
    }
    let input = absolute_or_clone(input);
    fs::write(&hint_path, input.display().to_string()).map_err(RustpenError::Io)?;
    Ok(())
}

pub(crate) fn read_reverse_viewer_request(root_ws: &Path) -> Option<ViewerLaunchRequest> {
    let hint_path = active_viewer_request_path(root_ws);
    let text = fs::read_to_string(&hint_path).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let request_ns = fs::metadata(&hint_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Some(ViewerLaunchRequest {
        target: PathBuf::from(text),
        request_ns,
    })
}

pub(crate) fn target_belongs_to_project(project: &Path, target: &Path) -> bool {
    absolute_or_clone(target).starts_with(absolute_or_clone(project))
}

fn reconcile_reverse_hints_for_project(root_ws: &Path, project: &Path) -> Result<(), RustpenError> {
    if let Some(target) = read_active_target_hint(root_ws)
        && !target_belongs_to_project(project, &target)
    {
        clear_active_target_hint(root_ws)?;
    }
    if let Some(request) = read_reverse_viewer_request(root_ws)
        && !target_belongs_to_project(project, &request.target)
    {
        clear_reverse_viewer_request(root_ws)?;
    }
    Ok(())
}

pub(crate) fn build_reverse_surface_command(exe: &str, workspace: &Path) -> String {
    format!(
        "{} reverse surface --workspace {}",
        shell_quote(exe),
        shell_quote(&workspace.display().to_string())
    )
}

#[allow(dead_code)]
pub(crate) fn build_reverse_deck_command(exe: &str, workspace: &Path) -> String {
    format!(
        "{} reverse deck --workspace {}",
        shell_quote(exe),
        shell_quote(&workspace.display().to_string())
    )
}

pub(crate) fn resolve_active_project(
    root_ws: &Path,
    project_override: Option<&PathBuf>,
) -> Result<PathBuf, RustpenError> {
    if let Some(project) = project_override {
        return Ok(normalize_project_path(root_ws, project));
    }
    if let Some(project) = read_active_project_hint(root_ws) {
        return Ok(project);
    }
    let projects = load_projects(&root_ws.to_path_buf())?;
    if let Some(project) = projects.first() {
        return Ok(project.path.clone());
    }
    Ok(root_ws.to_path_buf())
}

pub(crate) fn normalize_project_path(root_ws: &Path, raw: &Path) -> PathBuf {
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        root_ws.join(raw)
    };
    canonical_or_clone(&candidate)
}

pub(crate) fn discover_binary_candidates(project: &Path, limit: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let roots = [
        project.join("binaries"),
        project.join("samples"),
        project.join("inputs"),
        project.to_path_buf(),
    ];
    for root in roots {
        let max_depth = if root == project { 1 } else { 2 };
        collect_candidate_files(&root, max_depth, &mut files);
    }
    files.sort();
    files.dedup();
    files.sort_by_key(|path| Reverse(file_mtime(path)));
    files.truncate(limit);
    files
}

pub(crate) fn preferred_picker_root(project: &Path) -> PathBuf {
    for candidate in [
        project.join("binaries"),
        project.join("samples"),
        project.to_path_buf(),
    ] {
        if candidate.is_dir() {
            return candidate;
        }
    }
    project.to_path_buf()
}

pub(crate) fn load_reverse_browser_entries(
    project: &Path,
    dir: &Path,
    filter: &str,
    limit: usize,
    restrict_to_project: bool,
) -> Vec<ReverseBrowserEntry> {
    let filter = filter.trim().to_ascii_lowercase();
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let project_root = canonical_or_clone(project);
    for entry in entries.flatten() {
        let child = entry.path();
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let label = child
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        if label.is_empty() || label.starts_with('.') {
            continue;
        }
        if !filter.is_empty() && !label.to_ascii_lowercase().contains(&filter) {
            continue;
        }
        if metadata.is_dir() {
            if should_skip_dir(&child) {
                continue;
            }
            if restrict_to_project && !canonical_or_clone(&child).starts_with(&project_root) {
                continue;
            }
            dirs.push(ReverseBrowserEntry {
                path: child,
                is_dir: true,
                label: format!("{label}/"),
                detail: "dir".to_string(),
            });
            continue;
        }
        if !is_probable_reverse_input(&child, &metadata) {
            continue;
        }
        let ext = child
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("-");
        let ext = ext.to_string();
        files.push(ReverseBrowserEntry {
            path: child,
            is_dir: false,
            label,
            detail: format!("{} | {}", human_size(metadata.len()), ext),
        });
    }
    dirs.sort_by(|a, b| {
        a.label
            .to_ascii_lowercase()
            .cmp(&b.label.to_ascii_lowercase())
    });
    files.sort_by_key(|entry| Reverse(file_mtime(&entry.path)));
    dirs.extend(files);
    dirs.truncate(limit);
    dirs
}

pub(crate) fn relative_or_full(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .map(|value| value.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

pub(crate) fn shorten_id(id: &str, max: usize) -> String {
    if id.len() <= max {
        id.to_string()
    } else {
        id[..max].to_string()
    }
}

pub(crate) fn canonical_or_clone(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn absolute_or_clone(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

pub(crate) fn ensure_reverse_project_for_input(
    root_ws: &Path,
    input: &Path,
) -> Result<PreparedReverseTarget, RustpenError> {
    let source = canonical_or_clone(input);
    if !source.is_file() {
        return Err(RustpenError::ParseError(format!(
            "reverse target is not a file: {}",
            source.display()
        )));
    }

    let base_name = sanitize_reverse_project_name(
        source
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("reverse_sample"),
    );
    let base_name = if base_name.is_empty() {
        "reverse_sample".to_string()
    } else {
        base_name
    };
    let file_name = source
        .file_name()
        .map(|value| value.to_owned())
        .unwrap_or_else(|| "sample.bin".into());
    let root_ws_buf = root_ws.to_path_buf();

    for attempt in 0..MAX_REVERSE_PROJECT_ATTEMPTS {
        let project_name = if attempt == 0 {
            base_name.clone()
        } else {
            format!("{base_name}_{attempt}")
        };
        let project_path = root_ws.join("projects").join(&project_name);
        let created_project = if !project_path.exists() {
            create_local_project(&root_ws_buf, &project_name, ProjectTemplate::Reverse)?;
            true
        } else {
            false
        };
        let project_path_buf = project_path.clone();
        ensure_project_layout(&project_path_buf)?;
        let staged_target = project_path.join("binaries").join(&file_name);
        match ensure_reverse_input_staged(&source, &staged_target)? {
            Some(staged_input) => {
                return Ok(PreparedReverseTarget {
                    project: project_path,
                    target: staged_target,
                    created_project,
                    staged_input,
                });
            }
            None => continue,
        }
    }

    Err(RustpenError::ParseError(format!(
        "unable to assign reverse project for target {}",
        source.display()
    )))
}

fn sanitize_reverse_project_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || ch == '.' {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string()
}

fn ensure_reverse_input_staged(source: &Path, target: &Path) -> Result<Option<bool>, RustpenError> {
    if target.exists() {
        if canonical_or_clone(target) == canonical_or_clone(source) {
            return Ok(Some(false));
        }
        return Ok(None);
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(RustpenError::Io)?;
    }

    #[cfg(unix)]
    {
        if std::os::unix::fs::symlink(source, target).is_ok() {
            return Ok(Some(true));
        }
    }

    fs::copy(source, target).map_err(RustpenError::Io)?;
    Ok(Some(true))
}

pub(crate) fn load_visible_reverse_jobs(
    project: &Path,
    target: Option<&Path>,
    limit: usize,
) -> Vec<ReverseJobMeta> {
    if let Some(target) = target {
        let target = canonical_or_clone(target);
        let mut jobs: Vec<_> = list_primary_jobs(project)
            .unwrap_or_default()
            .into_iter()
            .filter(|job| canonical_or_clone(&job.target) == target)
            .collect();
        jobs.truncate(limit);
        return jobs;
    }
    let mut jobs = list_primary_sample_jobs(project).unwrap_or_default();
    jobs.truncate(limit);
    jobs
}

pub(crate) fn run_analyze_now(project: &Path, input: &Path) -> Result<String, RustpenError> {
    let exe = std::env::current_exe().map_err(RustpenError::Io)?;
    let analysis_dir = project.join("analysis");
    fs::create_dir_all(&analysis_dir).map_err(RustpenError::Io)?;
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("target");
    let out_path = analysis_dir.join(format!("{stem}-analyze-{}.json", unix_now_secs()));
    let status = Command::new(exe)
        .args([
            "reverse",
            "analyze",
            "--input",
            &input.display().to_string(),
            "--output",
            "json",
            "--out",
            &out_path.display().to_string(),
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(RustpenError::Io)?;
    if status.success() {
        Ok(format!(
            "analyze 完成 -> {} | 可在 Inspect 中打开或直接查看 JSON",
            out_path.display()
        ))
    } else {
        Ok("analyze 失败；请检查输入文件或 reverse backend 状态".to_string())
    }
}

pub(crate) fn run_zellij_filepicker(
    preferred_start: Option<&Path>,
    title: &str,
) -> Result<PathBuf, String> {
    let mut handle = spawn_zellij_filepicker(preferred_start, title)?;
    loop {
        if let Some(result) = poll_zellij_filepicker(&mut handle)? {
            return result;
        }
        thread::sleep(FILEPICKER_PLUGIN_WAIT_STEP);
    }
}

pub(crate) fn spawn_zellij_filepicker(
    preferred_start: Option<&Path>,
    _title: &str,
) -> Result<ZellijFilepickerHandle, String> {
    let session_name = std::env::var("ZELLIJ_SESSION_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if std::env::var("ZELLIJ").is_err() && session_name.is_none() {
        return Err("当前不在 zellij session 内".to_string());
    }
    let floating_panes_hidden = zellij_current_tab_hides_floating_panes(session_name.as_deref())?;
    let picker_root = std::env::var("RSCAN_REVERSE_FILEPICKER_ROOT")
        .ok()
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .or_else(|| normalize_filepicker_start(preferred_start))
        .unwrap_or_else(|| PathBuf::from("/"));

    // 官方 filepicker contract 要求 CLI 侧通过 `zellij pipe -p filepicker`
    // 发起，让插件自己 block/unblock CLI pipe input 并回传 stdout。
    let config = format!("cwd={}", picker_root.display());
    let mut command = zellij_command_for_session(session_name.as_deref());
    let mut child = command
        .args(["pipe", "-p", "filepicker", "-c", config.as_str(), "--", ""])
        .env_remove("ZELLIJ")
        .env_remove("ZELLIJ_PANE_ID")
        .env_remove("ZELLIJ_TAB_POSITION")
        .env_remove("ZELLIJ_TAB_NAME")
        .env_remove("ZELLIJ_SESSION_NAME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("zellij pipe(filepicker) 调用失败: {e}"))?;

    let mut revealed_hidden_floating = false;
    if floating_panes_hidden
        && wait_for_focused_tab_floating_pane(session_name.as_deref(), &mut child)?
        && toggle_zellij_floating_panes(session_name.as_deref()).is_ok()
    {
        revealed_hidden_floating = true;
    }

    Ok(ZellijFilepickerHandle {
        child: Some(child),
        session_name,
        revealed_hidden_floating,
    })
}

pub(crate) fn poll_zellij_filepicker(
    handle: &mut ZellijFilepickerHandle,
) -> Result<Option<Result<PathBuf, String>>, String> {
    let Some(child) = handle.child.as_mut() else {
        return Ok(Some(Err("zellij filepicker handle 已结束".to_string())));
    };
    if child
        .try_wait()
        .map_err(|e| format!("等待 filepicker 进程状态失败: {e}"))?
        .is_none()
    {
        return Ok(None);
    }

    finalize_zellij_filepicker(handle).map(Some)
}

pub(crate) fn abort_zellij_filepicker(handle: &mut ZellijFilepickerHandle) -> Result<(), String> {
    if let Some(child) = handle.child.as_mut() {
        let _ = child.kill();
    }
    let _ = finalize_zellij_filepicker(handle);
    Ok(())
}

pub(crate) fn zellij_filepicker_is_visible(
    handle: &ZellijFilepickerHandle,
) -> Result<bool, String> {
    let output = zellij_command_for_session(handle.session_name.as_deref())
        .args(["action", "dump-layout"])
        .output()
        .map_err(|e| format!("zellij dump-layout 失败: {e}"))?;
    if !output.status.success() {
        return Err("zellij dump-layout 返回失败".to_string());
    }
    Ok(parse_focused_tab_shows_floating_panes(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn finalize_zellij_filepicker(
    handle: &mut ZellijFilepickerHandle,
) -> Result<Result<PathBuf, String>, String> {
    let Some(child) = handle.child.take() else {
        return Ok(Err("zellij filepicker handle 已结束".to_string()));
    };
    let output = child
        .wait_with_output()
        .map_err(|e| format!("zellij pipe(filepicker) 调用失败: {e}"))?;
    restore_filepicker_floating_visibility(handle);
    Ok(parse_filepicker_output(output))
}

fn restore_filepicker_floating_visibility(handle: &mut ZellijFilepickerHandle) {
    if handle.revealed_hidden_floating {
        let _ = toggle_zellij_floating_panes(handle.session_name.as_deref());
        handle.revealed_hidden_floating = false;
    }
}

fn parse_filepicker_output(output: std::process::Output) -> Result<PathBuf, String> {
    if !output.status.success() {
        return Err("zellij filepicker 返回失败".to_string());
    }
    let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if selected.is_empty() {
        return Err("未选择任何文件".to_string());
    }
    let path = PathBuf::from(selected);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("选择结果不是普通文件: {}", path.display()))
    }
}

fn zellij_command_for_session(session_name: Option<&str>) -> Command {
    let mut command = Command::new("zellij");
    if let Some(session_name) = session_name {
        command.arg("--session").arg(session_name);
    }
    command
}

fn toggle_zellij_floating_panes(session_name: Option<&str>) -> Result<(), String> {
    let status = zellij_command_for_session(session_name)
        .args(["action", "toggle-floating-panes"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij toggle-floating-panes 失败: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("zellij toggle-floating-panes 返回失败".to_string())
    }
}

fn zellij_current_tab_hides_floating_panes(session_name: Option<&str>) -> Result<bool, String> {
    let output = zellij_command_for_session(session_name)
        .args(["action", "dump-layout"])
        .output()
        .map_err(|e| format!("zellij dump-layout 失败: {e}"))?;
    if !output.status.success() {
        return Err("zellij dump-layout 返回失败".to_string());
    }
    Ok(parse_focused_tab_hides_floating_panes(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn wait_for_focused_tab_floating_pane(
    session_name: Option<&str>,
    child: &mut std::process::Child,
) -> Result<bool, String> {
    let start = std::time::Instant::now();
    while start.elapsed() < FILEPICKER_PLUGIN_WAIT_TIMEOUT {
        if child
            .try_wait()
            .map_err(|e| format!("等待 filepicker 进程状态失败: {e}"))?
            .is_some()
        {
            return Ok(false);
        }
        if focused_tab_has_floating_panes(session_name)? {
            return Ok(true);
        }
        thread::sleep(FILEPICKER_PLUGIN_WAIT_STEP);
    }
    Ok(false)
}

fn focused_tab_has_floating_panes(session_name: Option<&str>) -> Result<bool, String> {
    let output = zellij_command_for_session(session_name)
        .args(["action", "dump-layout"])
        .output()
        .map_err(|e| format!("zellij dump-layout 失败: {e}"))?;
    if !output.status.success() {
        return Err("zellij dump-layout 返回失败".to_string());
    }
    Ok(parse_focused_tab_has_floating_panes(
        &String::from_utf8_lossy(&output.stdout),
    ))
}

fn parse_focused_tab_hides_floating_panes(layout: &str) -> bool {
    for line in layout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("tab ") && trimmed.contains("focus=true") {
            return trimmed.contains("hide_floating_panes=true");
        }
    }
    false
}

fn parse_focused_tab_has_floating_panes(layout: &str) -> bool {
    let mut in_focused_tab = false;
    let mut tab_depth = 0_i32;

    for line in layout.lines() {
        let trimmed = line.trim();
        let opens = trimmed.matches('{').count() as i32;
        let closes = trimmed.matches('}').count() as i32;

        if trimmed.starts_with("tab ") {
            in_focused_tab = trimmed.contains("focus=true");
            tab_depth = opens - closes;
            continue;
        }

        if !in_focused_tab {
            continue;
        }

        if trimmed.starts_with("floating_panes") {
            return true;
        }

        tab_depth += opens - closes;
        if tab_depth <= 0 {
            in_focused_tab = false;
            tab_depth = 0;
        }
    }

    false
}

fn parse_focused_tab_shows_floating_panes(layout: &str) -> bool {
    parse_focused_tab_has_floating_panes(layout) && !parse_focused_tab_hides_floating_panes(layout)
}

fn normalize_filepicker_start(preferred_start: Option<&Path>) -> Option<PathBuf> {
    let start = preferred_start?;
    if start.is_dir() {
        return Some(start.to_path_buf());
    }
    start
        .parent()
        .map(Path::to_path_buf)
        .filter(|path| path.is_dir())
}

pub(crate) fn spawn_reverse_job(
    project: &Path,
    input: &Path,
    engine: &str,
    mode: &str,
) -> Result<String, RustpenError> {
    let exe = std::env::current_exe().map_err(RustpenError::Io)?;
    let logs_dir = project.join("analysis").join("workbench");
    fs::create_dir_all(&logs_dir).map_err(RustpenError::Io)?;
    let stamp = unix_now_secs();
    let stdout_path = logs_dir.join(format!("launch-{stamp}-{mode}.stdout.log"));
    let stderr_path = logs_dir.join(format!("launch-{stamp}-{mode}.stderr.log"));
    let stdout = fs::File::create(&stdout_path).map_err(RustpenError::Io)?;
    let stderr = fs::File::create(&stderr_path).map_err(RustpenError::Io)?;

    let child = Command::new(exe)
        .args([
            "reverse",
            "decompile-run",
            "--input",
            &input.display().to_string(),
            "--engine",
            engine,
            "--mode",
            mode,
            "--workspace",
            &project.display().to_string(),
            "--output",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(RustpenError::Io)?;

    Ok(format!(
        "reverse {mode} job 已后台发出 (pid={}) | target={} | logs={} | Control 的 Tasks/Results 会自动回流",
        child.id(),
        input.display(),
        stdout_path.display()
    ))
}

pub(crate) fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn shell_quote(input: &str) -> String {
    let escaped = input.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_project_hint_roundtrip() {
        let root = std::env::temp_dir().join(format!("rscan_hint_test_{}", unix_now_secs()));
        let project = root.join("projects").join("default");
        fs::create_dir_all(&project).unwrap();
        write_active_project_hint(&root, &project).unwrap();
        let loaded = read_active_project_hint(&root).unwrap();
        assert_eq!(canonical_or_clone(&loaded), canonical_or_clone(&project));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_target_hint_roundtrip() {
        let root = std::env::temp_dir().join(format!("rscan_target_hint_test_{}", unix_now_secs()));
        let project = root.join("projects").join("default");
        let input = project.join("binaries").join("sample.bin");
        fs::create_dir_all(input.parent().unwrap()).unwrap();
        fs::write(&input, b"\x7fELF").unwrap();
        write_active_target_hint(&root, &input).unwrap();
        let loaded = read_active_target_hint(&root).unwrap();
        assert_eq!(canonical_or_clone(&loaded), canonical_or_clone(&input));
        clear_active_target_hint(&root).unwrap();
        assert!(read_active_target_hint(&root).is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_symlink_target_hint_preserves_project_local_path() {
        let root =
            std::env::temp_dir().join(format!("rscan_target_hint_symlink_{}", unix_now_secs()));
        let project = root.join("projects").join("default");
        let real = root.join("fixtures").join("sample.bin");
        let staged = project.join("binaries").join("sample.bin");
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(&real, b"\x7fELF").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &staged).unwrap();
        #[cfg(not(unix))]
        fs::copy(&real, &staged).unwrap();

        write_active_target_hint(&root, &staged).unwrap();
        let loaded = read_active_target_hint(&root).unwrap();
        assert_eq!(loaded, staged);
        assert!(target_belongs_to_project(&project, &loaded));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_symlink_viewer_request_preserves_project_local_path() {
        let root =
            std::env::temp_dir().join(format!("rscan_viewer_hint_symlink_{}", unix_now_secs()));
        let project = root.join("projects").join("default");
        let real = root.join("fixtures").join("sample.bin");
        let staged = project.join("binaries").join("sample.bin");
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(&real, b"\x7fELF").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &staged).unwrap();
        #[cfg(not(unix))]
        fs::copy(&real, &staged).unwrap();

        request_reverse_viewer_open(&root, &staged).unwrap();
        let request = read_reverse_viewer_request(&root).unwrap();
        assert_eq!(request.target, staged);
        assert!(target_belongs_to_project(&project, &request.target));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn switching_project_clears_stale_reverse_target_and_viewer_request() {
        let root =
            std::env::temp_dir().join(format!("rscan_reverse_hint_sync_{}", unix_now_secs()));
        let old_project = root.join("projects").join("old");
        let new_project = root.join("projects").join("new");
        let old_target = old_project.join("binaries").join("sample.bin");
        fs::create_dir_all(old_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&new_project).unwrap();
        fs::write(&old_target, b"\x7fELF").unwrap();

        write_active_target_hint(&root, &old_target).unwrap();
        request_reverse_viewer_open(&root, &old_target).unwrap();
        write_active_project_hint(&root, &new_project).unwrap();

        assert!(read_active_target_hint(&root).is_none());
        assert!(read_reverse_viewer_request(&root).is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discover_binary_candidates_prefers_reverse_inputs() {
        let root = std::env::temp_dir().join(format!("rscan_inputs_test_{}", unix_now_secs()));
        let project = root.join("project");
        fs::create_dir_all(project.join("binaries")).unwrap();
        fs::create_dir_all(project.join("scripts")).unwrap();
        fs::write(project.join("binaries").join("sample.bin"), b"\x7fELF").unwrap();
        fs::write(project.join("scripts").join("ignore.py"), b"print('hi')").unwrap();

        let found = discover_binary_candidates(&project, 8);
        assert!(found.iter().any(|path| path.ends_with("sample.bin")));
        assert!(!found.iter().any(|path| path.ends_with("ignore.py")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reverse_surface_command_targets_reverse_subcommand() {
        let cmd = build_reverse_surface_command("/tmp/rscan", Path::new("/tmp/ws"));
        assert!(cmd.contains("reverse surface --workspace"));
    }

    #[test]
    fn reverse_deck_command_targets_reverse_subcommand() {
        let cmd = build_reverse_deck_command("/tmp/rscan", Path::new("/tmp/ws"));
        assert!(cmd.contains("reverse deck --workspace"));
    }

    #[test]
    fn normalize_filepicker_start_prefers_parent_for_file() {
        let root = std::env::temp_dir().join(format!("rscan_filepicker_start_{}", unix_now_secs()));
        let dir = root.join("bin");
        let file = dir.join("a.out");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, b"\x7fELF").unwrap();
        assert_eq!(normalize_filepicker_start(Some(&file)), Some(dir.clone()));
        assert_eq!(normalize_filepicker_start(Some(&dir)), Some(dir));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn browser_entries_allow_filesystem_dirs_when_unrestricted() {
        let root = std::env::temp_dir().join(format!("rscan_browser_test_{}", unix_now_secs()));
        let project = root.join("projects").join("default");
        let outside = root.join("outside");
        fs::create_dir_all(project.join("binaries")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sample.bin"), b"\x7fELF").unwrap();

        let restricted = load_reverse_browser_entries(&project, &root, "", 32, true);
        assert!(!restricted.iter().any(|entry| entry.path == outside));

        let unrestricted = load_reverse_browser_entries(&project, &root, "", 32, false);
        assert!(unrestricted.iter().any(|entry| entry.path == outside));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parse_focused_tab_hides_floating_panes_detects_hidden_focus_tab() {
        let layout = r#"
layout {
    tab name="Tab #1" focus=true hide_floating_panes=true {
    }
}
"#;
        assert!(parse_focused_tab_hides_floating_panes(layout));
    }

    #[test]
    fn parse_focused_tab_hides_floating_panes_ignores_visible_focus_tab() {
        let layout = r#"
layout {
    tab name="Tab #1" focus=true {
    }
}
"#;
        assert!(!parse_focused_tab_hides_floating_panes(layout));
    }

    #[test]
    fn parse_focused_tab_has_floating_panes_detects_plugin_overlay() {
        let layout = r#"
layout {
    tab name="Tab #1" focus=true hide_floating_panes=true {
        pane
        floating_panes {
            pane {
                plugin location="zellij:strider" {
                    cwd "/tmp"
                }
            }
        }
    }
}
"#;
        assert!(parse_focused_tab_has_floating_panes(layout));
    }

    #[test]
    fn parse_focused_tab_has_floating_panes_ignores_other_tabs() {
        let layout = r#"
layout {
    tab name="Tab #1" focus=true {
        pane
    }
    tab name="Tab #2" hide_floating_panes=true {
        pane
        floating_panes {
            pane
        }
    }
}
"#;
        assert!(!parse_focused_tab_has_floating_panes(layout));
    }

    #[test]
    fn parse_focused_tab_shows_floating_panes_respects_hide_flag() {
        let hidden = r#"
layout {
    tab name="Tab #1" focus=true hide_floating_panes=true {
        pane
        floating_panes {
            pane
        }
    }
}
"#;
        assert!(!parse_focused_tab_shows_floating_panes(hidden));

        let visible = r#"
layout {
    tab name="Tab #1" focus=true {
        pane
        floating_panes {
            pane
        }
    }
}
"#;
        assert!(parse_focused_tab_shows_floating_panes(visible));
    }
}
