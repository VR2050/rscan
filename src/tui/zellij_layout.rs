use std::path::{Path, PathBuf};

use crate::tui::native_hubs::{build_inspect_hub_command, build_work_hub_command};
use crate::tui::reverse_workbench_support::build_reverse_surface_command;
use crate::tui::zellij::{CONTROL_TAB, INSPECT_TAB, REVERSE_TAB, WORK_TAB};

pub(crate) struct LayoutAssets {
    pub(crate) full: PathBuf,
    pub(crate) control: PathBuf,
    pub(crate) config: PathBuf,
}

pub(crate) fn write_layout_assets(
    workspace: &Path,
    refresh_ms: Option<u64>,
    tabs: &[&str],
) -> Result<LayoutAssets, String> {
    let dir = layout_dir(workspace);
    std::fs::create_dir_all(&dir).map_err(|e| format!("写入 layout 目录失败: {e}"))?;
    prune_stale_layouts(&dir, tabs)?;

    let full = dir.join("rscan.kdl");
    let config = dir.join("config.kdl");
    std::fs::write(&full, build_layout_text(workspace, refresh_ms))
        .map_err(|e| format!("写入 layout 失败: {e}"))?;
    std::fs::write(&config, build_config_text())
        .map_err(|e| format!("写入 zellij config 失败: {e}"))?;
    for tab in tabs {
        write_single_tab_layout(workspace, tab, refresh_ms)?;
    }

    Ok(LayoutAssets {
        full,
        control: single_tab_layout_path(workspace, CONTROL_TAB),
        config,
    })
}

pub(crate) fn single_tab_layout_path(workspace: &Path, tab: &str) -> PathBuf {
    layout_dir(workspace).join(format!("{}.kdl", tab.to_ascii_lowercase()))
}

pub(crate) fn default_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "zsh".to_string())
}

fn write_single_tab_layout(
    workspace: &Path,
    tab: &str,
    refresh_ms: Option<u64>,
) -> Result<(), String> {
    let path = single_tab_layout_path(workspace, tab);
    std::fs::write(
        &path,
        build_single_tab_layout_text(workspace, tab, refresh_ms),
    )
    .map_err(|e| format!("写入 {tab} layout 失败: {e}"))
}

fn layout_dir(workspace: &Path) -> PathBuf {
    workspace.join(".rscan").join("zellij")
}

fn prune_stale_layouts(dir: &Path, tabs: &[&str]) -> Result<(), String> {
    let mut keep = vec!["rscan.kdl".to_string()];
    keep.extend(
        tabs.iter()
            .map(|tab| format!("{}.kdl", tab.to_ascii_lowercase())),
    );

    let entries = std::fs::read_dir(dir).map_err(|e| format!("读取 layout 目录失败: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("读取 layout 项失败: {e}"))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("kdl") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if keep.iter().any(|item| item == name) {
            continue;
        }
        std::fs::remove_file(&path)
            .map_err(|e| format!("清理旧 layout 失败 ({}): {e}", path.display()))?;
    }
    Ok(())
}

fn build_layout_text(workspace: &Path, refresh_ms: Option<u64>) -> String {
    let exe_raw = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("rscan"))
        .display()
        .to_string();
    let refresh = refresh_ms.unwrap_or(220);
    let ws = escape_kdl(workspace.display().to_string());
    let exe = escape_kdl(exe_raw.clone());
    let work_hub_cmd = escape_kdl(build_work_hub_command(&exe_raw, workspace));
    let inspect_hub_cmd = escape_kdl(build_inspect_hub_command(&exe_raw, workspace));
    let reverse_surface_cmd = escape_kdl(build_reverse_surface_command(&exe_raw, workspace));
    let control_cmd = escape_kdl(format!(
        concat!(
            "RSCAN_ZELLIJ_BOOTSTRAP=1 ",
            "RSCAN_ZELLIJ_ACTIVE_TAB={} ",
            "{} tui --refresh-ms {} --workspace {}",
        ),
        CONTROL_TAB, exe, refresh, ws
    ));

    format!(
        r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{CONTROL_TAB}" focus=true split_direction="vertical" {{
        pane name="rscan-control" command="{shell}" {{
            args "-lc" "{control_cmd}"
        }}
    }}
    tab name="{WORK_TAB}" split_direction="vertical" {{
        pane name="work-hub" command="{shell}" {{
            args "-lc" "{work_hub_cmd}"
        }}
    }}
    tab name="{INSPECT_TAB}" split_direction="vertical" {{
        pane name="inspect-hub" command="{shell}" {{
            args "-lc" "{inspect_hub_cmd}"
        }}
    }}
    tab name="{REVERSE_TAB}" {{
        pane name="reverse-surface" command="{shell}" {{
            args "-lc" "{reverse_surface_cmd}"
        }}
    }}
}}
"#,
        shell = escape_kdl(default_shell()),
    )
}

fn build_config_text() -> String {
    String::new()
}

fn build_single_tab_layout_text(workspace: &Path, tab: &str, refresh_ms: Option<u64>) -> String {
    let ws = escape_kdl(workspace.display().to_string());
    if tab == CONTROL_TAB {
        let exe = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("rscan"))
            .display()
            .to_string();
        let refresh = refresh_ms.unwrap_or(220);
        let control_cmd = escape_kdl(format!(
            "RSCAN_ZELLIJ_BOOTSTRAP=1 RSCAN_ZELLIJ_ACTIVE_TAB={} {} tui --refresh-ms {} --workspace {}",
            CONTROL_TAB, exe, refresh, ws
        ));
        return format!(
            r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{CONTROL_TAB}" focus=true split_direction="vertical" {{
        pane name="rscan-control" command="{shell}" {{
            args "-lc" "{control_cmd}"
        }}
    }}
}}
"#,
            shell = escape_kdl(default_shell()),
        );
    }

    if tab == REVERSE_TAB {
        let exe_raw = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("rscan"))
            .display()
            .to_string();
        let reverse_surface_cmd = escape_kdl(build_reverse_surface_command(&exe_raw, workspace));
        return format!(
            r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{REVERSE_TAB}" focus=true {{
        pane name="reverse-surface" command="{shell}" {{
            args "-lc" "{reverse_surface_cmd}"
        }}
    }}
}}
"#,
            shell = escape_kdl(default_shell()),
        );
    }

    if tab == WORK_TAB {
        let exe_raw = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("rscan"))
            .display()
            .to_string();
        let work_hub_cmd = escape_kdl(build_work_hub_command(&exe_raw, workspace));
        return format!(
            r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{WORK_TAB}" focus=true split_direction="vertical" {{
        pane name="work-hub" command="{shell}" {{
            args "-lc" "{work_hub_cmd}"
        }}
    }}
}}
"#,
            shell = escape_kdl(default_shell()),
        );
    }

    if tab == INSPECT_TAB {
        let exe_raw = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("rscan"))
            .display()
            .to_string();
        let inspect_hub_cmd = escape_kdl(build_inspect_hub_command(&exe_raw, workspace));
        return format!(
            r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{INSPECT_TAB}" focus=true split_direction="vertical" {{
        pane name="inspect-hub" command="{shell}" {{
            args "-lc" "{inspect_hub_cmd}"
        }}
    }}
}}
"#,
            shell = escape_kdl(default_shell()),
        );
    }

    let pane_name = escape_kdl(format!("{}-shell", tab.to_ascii_lowercase()));

    format!(
        r#"layout {{
    cwd "{ws}"
    default_tab_template {{
        pane size=1 borderless=true {{
            plugin location="zellij:tab-bar"
        }}
        children
        pane size=2 borderless=true {{
            plugin location="zellij:status-bar"
        }}
    }}
    tab name="{tab}" focus=true {{
        pane name="{pane_name}"
    }}
}}
"#
    )
}

fn escape_kdl<S: Into<String>>(input: S) -> String {
    input.into().replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_does_not_include_legacy_f4_binding() {
        let text = build_config_text();
        assert!(!text.contains("bind \"F4\""));
        assert!(!text.contains("ToggleFloatingPanes"));
    }

    #[test]
    fn generated_layout_does_not_include_default_shell_panes() {
        let text = build_layout_text(Path::new("/tmp/ws"), Some(220));
        assert!(!text.contains("workspace-shell"));
        assert!(!text.contains("work-shell"));
        assert!(!text.contains("inspect-shell"));
    }
}
