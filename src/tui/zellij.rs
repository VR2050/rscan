use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::zellij_layout::{
    LayoutAssets, default_shell, single_tab_layout_path, write_layout_assets,
};
use super::zellij_query::{
    PaneLookupSource, SessionState, resolve_named_pane_tab, session_state, session_tab_names,
};

pub(crate) const CONTROL_TAB: &str = "Control";
pub(crate) const WORK_TAB: &str = "Work";
pub(crate) const INSPECT_TAB: &str = "Inspect";
pub(crate) const REVERSE_TAB: &str = "Reverse";
const MANAGED_TABS: [&str; 4] = [CONTROL_TAB, WORK_TAB, INSPECT_TAB, REVERSE_TAB];

pub(crate) struct ZellijConfig {
    pub(crate) session: String,
}

pub(crate) enum EnsureResult {
    Inside,
    Existing,
    Spawned,
}

pub(crate) enum BootstrapResult {
    Continue,
    Launched,
}

pub(crate) fn is_enabled() -> bool {
    match std::env::var("RSCAN_ZELLIJ") {
        Ok(v) => v != "0" && v.to_ascii_lowercase() != "false",
        Err(_) => true,
    }
}

pub(crate) fn config() -> ZellijConfig {
    let session = match std::env::var("RSCAN_ZELLIJ_SESSION") {
        Ok(v) => v,
        Err(_) => std::env::var("ZELLIJ_SESSION_NAME").unwrap_or_else(|_| "rscan".to_string()),
    };
    ZellijConfig { session }
}

fn inside_zellij() -> bool {
    std::env::var("ZELLIJ").is_ok() || std::env::var("ZELLIJ_SESSION_NAME").is_ok()
}

pub(crate) fn is_managed_runtime() -> bool {
    is_enabled() && inside_zellij()
}

pub(crate) fn session_name() -> Option<String> {
    if !is_managed_runtime() {
        return None;
    }
    Some(config().session)
}

pub(crate) fn managed_tabs() -> &'static [&'static str] {
    &MANAGED_TABS
}

pub(crate) fn ensure_session(cfg: &ZellijConfig) -> Result<EnsureResult, String> {
    if inside_zellij() {
        return Ok(EnsureResult::Inside);
    }
    match session_state(&cfg.session) {
        SessionState::Active => Ok(EnsureResult::Existing),
        SessionState::Exited => {
            delete_session(cfg)?;
            Ok(EnsureResult::Spawned)
        }
        SessionState::Missing => Ok(EnsureResult::Spawned),
    }
}

pub(crate) fn open_pane(
    cmd: &str,
    workspace: &PathBuf,
    name: Option<String>,
) -> Result<String, String> {
    open_command_pane_in_tab(WORK_TAB, workspace, cmd, workspace, name)
}

pub(crate) fn open_command_pane_in_tab(
    tab: &str,
    workspace: &PathBuf,
    cmd: &str,
    cwd: &PathBuf,
    name: Option<String>,
) -> Result<String, String> {
    open_tab_pane(tab, workspace, cwd, name, Some(cmd))
}

pub(crate) fn open_shell_pane_in_tab(
    tab: &str,
    workspace: &PathBuf,
    cwd: &PathBuf,
    name: Option<String>,
) -> Result<String, String> {
    open_tab_pane(tab, workspace, cwd, name, None)
}

fn open_tab_pane(
    tab: &str,
    workspace: &PathBuf,
    cwd: &PathBuf,
    name: Option<String>,
    cmd: Option<&str>,
) -> Result<String, String> {
    let cfg = config();
    match ensure_session(&cfg)? {
        EnsureResult::Spawned => match bootstrap_layout(workspace, None)? {
            BootstrapResult::Continue | BootstrapResult::Launched => {}
        },
        EnsureResult::Inside | EnsureResult::Existing => {
            ensure_managed_tabs(&cfg, workspace, None)?;
        }
    }

    if let Some(name) = name.as_deref()
        && let Some(hit) = resolve_named_pane_tab(workspace, &cfg.session, name)
    {
        focus_tab(&cfg, &hit.tab)?;
        let hint = match hit.source {
            PaneLookupSource::LiveLayout => format!("复用 pane {name}"),
            PaneLookupSource::Registry => format!("命中 pane registry: {name}"),
        };
        return Ok(format!("zellij -> {} | {}", hit.tab, hint));
    }

    focus_tab(&cfg, tab)?;
    let mut args = vec![
        "--session".to_string(),
        cfg.session.clone(),
        "action".to_string(),
        "new-pane".to_string(),
        "--cwd".to_string(),
        cwd.display().to_string(),
    ];
    if let Some(name) = name {
        args.push("--name".to_string());
        args.push(name);
    }
    if let Some(cmd) = cmd {
        args.push("--".to_string());
        args.push(default_shell());
        args.push("-lc".to_string());
        args.push(cmd.to_string());
    }

    let status = Command::new("zellij")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij new-pane 失败: {e}"))?;

    if !status.success() {
        return Err("zellij new-pane 失败".to_string());
    }
    Ok(format!("zellij -> {tab}"))
}

pub(crate) fn focus_managed_tab(workspace: &PathBuf, tab: &str) -> Result<String, String> {
    let tab = normalize_managed_tab_name(tab)
        .ok_or_else(|| format!("未知 zellij tab: {tab}，可选 control|work|inspect|reverse"))?;
    let cfg = config();
    match ensure_session(&cfg)? {
        EnsureResult::Spawned => match bootstrap_layout(workspace, None)? {
            BootstrapResult::Continue | BootstrapResult::Launched => {}
        },
        EnsureResult::Inside | EnsureResult::Existing => {
            ensure_managed_tabs(&cfg, workspace, None)?;
        }
    }
    focus_tab(&cfg, tab)?;
    Ok(format!("zellij -> {tab}"))
}

pub(crate) fn bootstrap_layout(
    workspace: &Path,
    refresh_ms: Option<u64>,
) -> Result<BootstrapResult, String> {
    let cfg = config();
    let assets = write_layout_assets(workspace, refresh_ms, managed_tabs())?;

    match ensure_session(&cfg)? {
        EnsureResult::Inside => {
            ensure_managed_tabs_with_assets(&cfg, workspace, refresh_ms, &assets)?;
            let _ = focus_tab(&cfg, CONTROL_TAB);
            Ok(BootstrapResult::Continue)
        }
        EnsureResult::Existing => {
            ensure_managed_tabs_with_assets(&cfg, workspace, refresh_ms, &assets)?;
            let _ = focus_tab(&cfg, CONTROL_TAB);
            attach_session(&cfg)?;
            Ok(BootstrapResult::Launched)
        }
        EnsureResult::Spawned => {
            let status = Command::new("zellij")
                .arg("-c")
                .arg(&assets.config)
                .args([
                    "attach",
                    "--create",
                    &cfg.session,
                    "options",
                    "--default-layout",
                    assets.full.to_str().unwrap_or("zellij/rscan.kdl"),
                ])
                .status()
                .map_err(|e| format!("zellij 启动失败: {e}"))?;
            if status.success() {
                Ok(BootstrapResult::Launched)
            } else {
                Err("zellij 启动失败".to_string())
            }
        }
    }
}

pub(crate) fn focus_control_shell_pane(cwd: &PathBuf) -> Result<String, String> {
    open_shell_pane_in_tab(CONTROL_TAB, cwd, cwd, Some("control-workspace".to_string()))
        .map(|msg| format!("{msg} | Control shell 已打开"))
}

fn ensure_managed_tabs(
    cfg: &ZellijConfig,
    workspace: &Path,
    refresh_ms: Option<u64>,
) -> Result<(), String> {
    let assets = write_layout_assets(workspace, refresh_ms, managed_tabs())?;
    ensure_managed_tabs_with_assets(cfg, workspace, refresh_ms, &assets)
}

fn ensure_managed_tabs_with_assets(
    cfg: &ZellijConfig,
    workspace: &Path,
    refresh_ms: Option<u64>,
    assets: &LayoutAssets,
) -> Result<(), String> {
    let names = session_tab_names(&cfg.session).unwrap_or_default();
    let existing = names.into_iter().collect::<BTreeSet<_>>();
    for tab in MANAGED_TABS {
        if existing.contains(tab) {
            continue;
        }
        let layout = if tab == CONTROL_TAB {
            assets.control.clone()
        } else {
            single_tab_layout_path(workspace, tab)
        };
        let status = Command::new("zellij")
            .args(["--session", &cfg.session, "action", "new-tab", "--layout"])
            .arg(layout)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("zellij new-tab 失败: {e}"))?;
        if !status.success() {
            return Err(format!("zellij new-tab 失败: {tab}"));
        }
        if tab == CONTROL_TAB {
            let _ = focus_tab(cfg, CONTROL_TAB);
            // Reuse the current binary for the control surface after adding the layout tab.
            let _ = refresh_ms;
        }
    }
    ensure_control_surface_present(cfg, workspace, refresh_ms)?;
    Ok(())
}

fn ensure_control_surface_present(
    cfg: &ZellijConfig,
    workspace: &Path,
    refresh_ms: Option<u64>,
) -> Result<(), String> {
    if resolve_named_pane_tab(workspace, &cfg.session, "rscan-control").is_some() {
        return Ok(());
    }
    focus_tab(cfg, CONTROL_TAB)?;
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("rscan"))
        .display()
        .to_string();
    let refresh = refresh_ms.unwrap_or(220);
    let ws = shell_quote(&workspace.display().to_string());
    let cmd = format!(
        "RSCAN_ZELLIJ_BOOTSTRAP=1 RSCAN_ZELLIJ_ACTIVE_TAB={} {} tui --refresh-ms {} --workspace {}",
        CONTROL_TAB,
        shell_quote(&exe),
        refresh,
        ws
    );
    let status = Command::new("zellij")
        .args([
            "--session",
            &cfg.session,
            "action",
            "new-pane",
            "--cwd",
            &workspace.display().to_string(),
            "--name",
            "rscan-control",
            "--",
        ])
        .arg(default_shell())
        .args(["-lc", &cmd])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij 重建 Control pane 失败: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("zellij 重建 Control pane 失败".to_string())
    }
}

fn attach_session(cfg: &ZellijConfig) -> Result<(), String> {
    let status = Command::new("zellij")
        .args(["attach", &cfg.session])
        .status()
        .map_err(|e| format!("zellij attach 失败: {e}"))?;
    if status.success() {
        return Ok(());
    }
    Err("zellij attach 失败".to_string())
}

fn delete_session(cfg: &ZellijConfig) -> Result<(), String> {
    let status = Command::new("zellij")
        .args(["delete-session", &cfg.session])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij delete-session 失败: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("zellij delete-session 失败".to_string())
    }
}

fn focus_tab(cfg: &ZellijConfig, tab: &str) -> Result<(), String> {
    let status = Command::new("zellij")
        .args([
            "--session",
            &cfg.session,
            "action",
            "go-to-tab-name",
            "--create",
            tab,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("zellij 切换 tab 失败: {e}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!("zellij 切换 tab 失败: {tab}"))
}

fn normalize_managed_tab_name(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "control" | "ctl" | "ctrl" | "c" => Some(CONTROL_TAB),
        "work" | "w" => Some(WORK_TAB),
        "inspect" | "insp" | "i" => Some(INSPECT_TAB),
        "reverse" | "rev" | "r" => Some(REVERSE_TAB),
        _ => None,
    }
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_managed_tab_aliases() {
        assert_eq!(normalize_managed_tab_name("control"), Some(CONTROL_TAB));
        assert_eq!(normalize_managed_tab_name("ctl"), Some(CONTROL_TAB));
        assert_eq!(normalize_managed_tab_name("work"), Some(WORK_TAB));
        assert_eq!(normalize_managed_tab_name("inspect"), Some(INSPECT_TAB));
        assert_eq!(normalize_managed_tab_name("rev"), Some(REVERSE_TAB));
        assert_eq!(normalize_managed_tab_name("unknown"), None);
    }
}
