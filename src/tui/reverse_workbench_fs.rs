use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(super) fn collect_candidate_files(root: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    walk_candidate_files(root, 0, max_depth, out);
}

pub(super) fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git"
            | ".rscan"
            | "analysis"
            | "jobs"
            | "node_modules"
            | "reverse_out"
            | "scripts"
            | "target"
            | "tasks"
            | "vuln_templates"
    )
}

pub(super) fn is_probable_reverse_input(path: &Path, metadata: &Metadata) -> bool {
    if !metadata.is_file() || metadata.len() == 0 {
        return false;
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if file_name.starts_with('.') {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let likely_ext = matches!(
        ext.as_str(),
        "apk"
            | "apex"
            | "bin"
            | "class"
            | "dex"
            | "dll"
            | "dmp"
            | "elf"
            | "exe"
            | "img"
            | "ipa"
            | "jar"
            | "ko"
            | "o"
            | "so"
            | "sys"
            | "wasm"
    );
    if likely_ext {
        return true;
    }
    if matches!(
        path.parent()
            .and_then(|parent| parent.file_name())
            .and_then(|value| value.to_str()),
        Some("binaries" | "inputs" | "samples")
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 != 0 {
            return true;
        }
    }
    false
}

pub(super) fn file_mtime(path: &Path) -> u128 {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub(super) fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let value = bytes as f64;
    if value >= GB {
        format!("{:.1} GB", value / GB)
    } else if value >= MB {
        format!("{:.1} MB", value / MB)
    } else if value >= KB {
        format!("{:.1} KB", value / KB)
    } else {
        format!("{bytes} B")
    }
}

fn walk_candidate_files(path: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let child = entry.path();
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            if should_skip_dir(&child) {
                continue;
            }
            walk_candidate_files(&child, depth + 1, max_depth, out);
            continue;
        }
        if is_probable_reverse_input(&child, &metadata) {
            out.push(child);
        }
    }
}
