use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cores::engine::task::now_epoch_secs;
use crate::errors::RustpenError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PaneRegistryEntry {
    pub(crate) name: String,
    pub(crate) tab: String,
    pub(crate) cwd: PathBuf,
    #[serde(default)]
    pub(crate) role: Option<String>,
    #[serde(default)]
    pub(crate) command: Option<String>,
    pub(crate) updated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PaneRegistry {
    #[serde(default)]
    panes: Vec<PaneRegistryEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PaneRegistrySummary {
    pub(crate) total: usize,
    pub(crate) tab_counts: Vec<(String, usize)>,
    pub(crate) recent: Vec<PaneRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedPane {
    tab: String,
    name: String,
}

pub(crate) fn record_pane(
    workspace: &Path,
    name: String,
    tab: String,
    cwd: PathBuf,
    role: Option<String>,
    command: Option<String>,
) -> Result<(), RustpenError> {
    let mut registry = load_registry(workspace)?;
    registry.panes.retain(|pane| pane.name != name);
    registry.panes.push(PaneRegistryEntry {
        name,
        tab,
        cwd,
        role,
        command,
        updated_at: now_epoch_secs(),
    });
    registry.panes.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
    });
    save_registry(workspace, &registry)
}

pub(crate) fn load_entries(workspace: &Path) -> Result<Vec<PaneRegistryEntry>, RustpenError> {
    Ok(load_registry(workspace)?.panes)
}

pub(crate) fn find_recorded_pane(workspace: &Path, name: &str) -> Option<PaneRegistryEntry> {
    load_entries(workspace)
        .ok()?
        .into_iter()
        .find(|pane| pane.name == name)
}

pub(crate) fn summarize_registry(
    workspace: &Path,
    recent_limit: usize,
) -> Result<PaneRegistrySummary, RustpenError> {
    let mut panes = load_entries(workspace)?;
    let total = panes.len();

    let mut tab_counts = BTreeMap::new();
    for pane in &panes {
        *tab_counts.entry(pane.tab.clone()).or_insert(0usize) += 1;
    }

    panes.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(PaneRegistrySummary {
        total,
        tab_counts: tab_counts.into_iter().collect(),
        recent: panes.into_iter().take(recent_limit).collect(),
    })
}

pub(crate) fn registry_signature(workspace: &Path) -> u64 {
    let path = registry_path(workspace);
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };

    let modified = meta
        .modified()
        .ok()
        .and_then(|ts| ts.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_default();

    let mut hasher = DefaultHasher::new();
    meta.len().hash(&mut hasher);
    modified.hash(&mut hasher);
    hasher.finish()
}

pub(crate) fn find_named_pane_tab_in_layout(layout: &str, pane_name: &str) -> Option<String> {
    parse_named_panes_from_layout(layout)
        .into_iter()
        .find(|pane| pane.name == pane_name)
        .map(|pane| pane.tab)
}

fn registry_path(workspace: &Path) -> PathBuf {
    workspace.join(".rscan").join("zellij").join("panes.json")
}

fn load_registry(workspace: &Path) -> Result<PaneRegistry, RustpenError> {
    let path = registry_path(workspace);
    if !path.is_file() {
        return Ok(PaneRegistry::default());
    }
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))
}

fn save_registry(workspace: &Path, registry: &PaneRegistry) -> Result<(), RustpenError> {
    let path = registry_path(workspace);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(registry)
        .map_err(|e| RustpenError::ParseError(e.to_string()))?;
    std::fs::write(path, text)?;
    Ok(())
}

fn parse_named_panes_from_layout(layout: &str) -> Vec<NamedPane> {
    let mut out = Vec::new();
    let mut current_tab: Option<String> = None;
    for line in layout.lines() {
        let line = line.trim();
        if line.starts_with("tab")
            && let Some(name) = extract_kdl_string_attr(line, "name")
        {
            current_tab = Some(name);
            continue;
        }
        if line.starts_with("pane")
            && let Some(name) = extract_kdl_string_attr(line, "name")
            && let Some(tab) = current_tab.clone()
        {
            out.push(NamedPane { tab, name });
        }
    }
    out
}

fn extract_kdl_string_attr(line: &str, key: &str) -> Option<String> {
    let needle = format!(r#"{key}=""#);
    let start = line.find(&needle)? + needle.len();
    let rest = line.get(start..)?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace(name: &str) -> PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_zellij_registry_{name}_{ns:x}"))
    }

    #[test]
    fn find_named_pane_tab_from_layout() {
        let layout = r#"
layout {
    tab name="Control" {
        pane name="rscan-control"
    }
    tab name="Inspect" {
        pane name="logs-abc123"
    }
}
"#;
        assert_eq!(
            find_named_pane_tab_in_layout(layout, "logs-abc123").as_deref(),
            Some("Inspect")
        );
        assert_eq!(find_named_pane_tab_in_layout(layout, "missing"), None);
    }

    #[test]
    fn record_pane_persists_latest_entry() {
        let ws = temp_workspace("record");
        record_pane(
            &ws,
            "logs-task".to_string(),
            "Inspect".to_string(),
            ws.join("tasks").join("task-1"),
            Some("inspect-logs".to_string()),
            Some("tail -F".to_string()),
        )
        .unwrap();
        record_pane(
            &ws,
            "logs-task".to_string(),
            "Inspect".to_string(),
            ws.join("tasks").join("task-1-new"),
            Some("inspect-logs".to_string()),
            Some("tail -F".to_string()),
        )
        .unwrap();
        let registry = load_registry(&ws).unwrap();
        assert_eq!(registry.panes.len(), 1);
        assert!(registry.panes[0].cwd.ends_with("task-1-new"));
        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn summarize_registry_counts_tabs() {
        let ws = temp_workspace("summary");
        record_pane(
            &ws,
            "logs-task".to_string(),
            "Inspect".to_string(),
            ws.join("tasks").join("task-1"),
            Some("inspect-logs".to_string()),
            Some("tail -F".to_string()),
        )
        .unwrap();
        record_pane(
            &ws,
            "shell-task".to_string(),
            "Work".to_string(),
            ws.join("tasks").join("task-2"),
            Some("task-shell".to_string()),
            None,
        )
        .unwrap();

        let summary = summarize_registry(&ws, 8).unwrap();
        assert_eq!(summary.total, 2);
        assert!(
            summary
                .tab_counts
                .iter()
                .any(|(tab, count)| tab == "Inspect" && *count == 1)
        );
        assert!(
            summary
                .tab_counts
                .iter()
                .any(|(tab, count)| tab == "Work" && *count == 1)
        );
        let _ = std::fs::remove_dir_all(ws);
    }
}
