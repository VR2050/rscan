use std::path::Path;
use std::process::{Command, Stdio};

use crate::tui::zellij_registry;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionState {
    Missing,
    Active,
    Exited,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PaneLookupSource {
    LiveLayout,
    Registry,
}

pub(crate) struct PaneLookup {
    pub(crate) tab: String,
    pub(crate) source: PaneLookupSource,
}

pub(crate) fn session_state(session: &str) -> SessionState {
    let out = Command::new("zellij")
        .args(["list-sessions"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(out) = out else {
        return SessionState::Missing;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let clean = strip_ansi(line).trim().to_string();
        if clean.is_empty() {
            continue;
        }
        let name = clean.split_whitespace().next().unwrap_or("");
        if name != session {
            continue;
        }
        return if clean.contains("(EXITED") {
            SessionState::Exited
        } else {
            SessionState::Active
        };
    }
    SessionState::Missing
}

pub(crate) fn session_tab_names(session: &str) -> Result<Vec<String>, String> {
    let out = Command::new("zellij")
        .args(["--session", session, "action", "query-tab-names"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("zellij query-tab-names 失败: {e}"))?;
    if !out.status.success() {
        return Err("zellij query-tab-names 失败".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect())
}

pub(crate) fn resolve_named_pane_tab(
    workspace: &Path,
    session: &str,
    pane_name: &str,
) -> Option<PaneLookup> {
    if let Some(tab) = find_named_pane_tab(session, pane_name) {
        return Some(PaneLookup {
            tab,
            source: PaneLookupSource::LiveLayout,
        });
    }
    zellij_registry::find_recorded_pane(workspace, pane_name).map(|entry| PaneLookup {
        tab: entry.tab,
        source: PaneLookupSource::Registry,
    })
}

fn find_named_pane_tab(session: &str, pane_name: &str) -> Option<String> {
    let layout = session_layout_text(session).ok()?;
    zellij_registry::find_named_pane_tab_in_layout(&layout, pane_name)
}

fn session_layout_text(session: &str) -> Result<String, String> {
    let out = Command::new("zellij")
        .args(["--session", session, "action", "dump-layout"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("zellij dump-layout 失败: {e}"))?;
    if !out.status.success() {
        return Err("zellij dump-layout 失败".to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && matches!(chars.peek().copied(), Some('[')) {
            let _ = chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_sequences() {
        assert_eq!(strip_ansi("\u{1b}[32mhello\u{1b}[0m"), "hello");
        assert_eq!(strip_ansi("plain"), "plain");
    }
}
