use std::fs;
use std::path::PathBuf;

use crate::cores::engine::task::now_epoch_secs;
use crate::errors::RustpenError;

use super::models::{ProjectEntry, ProjectTemplate};

pub(crate) fn project_name_from_path(path: &PathBuf) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

fn projects_root_dir(root_ws: &PathBuf) -> PathBuf {
    root_ws.join("projects")
}

fn project_registry_path(root_ws: &PathBuf) -> PathBuf {
    root_ws.join(".rscan_projects_imports.json")
}

pub(crate) fn ensure_project_layout(project_dir: &PathBuf) -> Result<(), RustpenError> {
    fs::create_dir_all(project_dir).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("tasks")).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("scripts")).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("vuln_templates")).map_err(RustpenError::Io)?;
    Ok(())
}

fn load_imported_project_paths(root_ws: &PathBuf) -> Result<Vec<PathBuf>, RustpenError> {
    let path = project_registry_path(root_ws);
    if !path.is_file() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(path).map_err(RustpenError::Io)?;
    let entries = serde_json::from_str::<Vec<String>>(&text).unwrap_or_default();
    Ok(entries.into_iter().map(PathBuf::from).collect())
}

fn save_imported_project_paths(root_ws: &PathBuf, paths: &[PathBuf]) -> Result<(), RustpenError> {
    let text = serde_json::to_string_pretty(
        &paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
    )
    .map_err(|e| RustpenError::ParseError(e.to_string()))?;
    fs::write(project_registry_path(root_ws), text).map_err(RustpenError::Io)?;
    Ok(())
}

pub(crate) fn same_path(a: &PathBuf, b: &PathBuf) -> bool {
    let ca = fs::canonicalize(a).unwrap_or_else(|_| a.clone());
    let cb = fs::canonicalize(b).unwrap_or_else(|_| b.clone());
    ca == cb
}

pub(crate) fn load_projects(root_ws: &PathBuf) -> Result<Vec<ProjectEntry>, RustpenError> {
    let project_root = projects_root_dir(root_ws);
    fs::create_dir_all(&project_root).map_err(RustpenError::Io)?;

    let mut out: Vec<ProjectEntry> = Vec::new();
    for entry in fs::read_dir(&project_root).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        ensure_project_layout(&p)?;
        out.push(ProjectEntry {
            name: project_name_from_path(&p),
            path: p,
            imported: false,
        });
    }

    if out.is_empty() {
        let default_path = project_root.join("default");
        ensure_project_layout(&default_path)?;
        init_project_template(&default_path, ProjectTemplate::Minimal)?;
        out.push(ProjectEntry {
            name: "default".to_string(),
            path: default_path,
            imported: false,
        });
    }

    for p in load_imported_project_paths(root_ws)? {
        if !p.is_dir() {
            continue;
        }
        if out.iter().any(|x| same_path(&x.path, &p)) {
            continue;
        }
        if ensure_project_layout(&p).is_err() {
            continue;
        }
        out.push(ProjectEntry {
            name: project_name_from_path(&p),
            path: p,
            imported: true,
        });
    }

    out.sort_by(|a, b| {
        a.imported
            .cmp(&b.imported)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

fn sanitize_project_name(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch);
        } else if ch.is_whitespace() {
            s.push('_');
        }
    }
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    s.trim_matches('_').to_string()
}

fn write_if_missing(path: &PathBuf, content: &str) -> Result<(), RustpenError> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(RustpenError::Io)?;
        }
        fs::write(path, content).map_err(RustpenError::Io)?;
    }
    Ok(())
}

fn init_project_template(
    project_path: &PathBuf,
    template: ProjectTemplate,
) -> Result<(), RustpenError> {
    let readme = match template {
        ProjectTemplate::Minimal => {
            "# rscan Project\n\nTemplate: minimal\n\n- tasks/\n- scripts/\n- vuln_templates/\n"
        }
        ProjectTemplate::Recon => {
            "# rscan Project\n\nTemplate: recon\n\n建议流程:\n1. host quick/tcp\n2. web dir/fuzz/dns\n3. vuln scan\n"
        }
        ProjectTemplate::Reverse => {
            "# rscan Project\n\nTemplate: reverse\n\n建议流程:\n1. reverse analyze\n2. reverse decompile-plan\n3. reverse jobs/console\n"
        }
    };
    write_if_missing(&project_path.join("README.md"), readme)?;

    match template {
        ProjectTemplate::Minimal => {
            write_if_missing(
                &project_path.join("scripts").join("hello.py"),
                "print('hello from project template: minimal')\n",
            )?;
        }
        ProjectTemplate::Recon => {
            write_if_missing(
                &project_path.join("scripts").join("recon.py"),
                "targets = ['127.0.0.1']\nfor t in targets:\n    print(f'recon target={t}')\n",
            )?;
            write_if_missing(
                &project_path.join("vuln_templates").join("basic_http.yaml"),
                "id: project-basic-http\ninfo:\n  name: Project Basic HTTP\n  severity: info\nhttp:\n  - method: GET\n    path: ['/', '/robots.txt']\n    matchers:\n      - type: status\n        status: [200,301,302,401,403]\n",
            )?;
        }
        ProjectTemplate::Reverse => {
            write_if_missing(
                &project_path.join("scripts").join("reverse_notes.rs"),
                "fn main() {\n    println!(\"reverse template project ready\");\n}\n",
            )?;
        }
    }
    Ok(())
}

pub(crate) fn create_local_project(
    root_ws: &PathBuf,
    raw_name: &str,
    template: ProjectTemplate,
) -> Result<PathBuf, RustpenError> {
    let name = sanitize_project_name(raw_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "project name contains no valid characters".to_string(),
        ));
    }
    let path = projects_root_dir(root_ws).join(name);
    if path.exists() {
        return Err(RustpenError::ParseError(format!(
            "project already exists: {}",
            path.display()
        )));
    }
    ensure_project_layout(&path)?;
    init_project_template(&path, template)?;
    Ok(path)
}

pub(crate) fn import_project(
    root_ws: &PathBuf,
    raw_path: &PathBuf,
) -> Result<PathBuf, RustpenError> {
    let path = if raw_path.is_absolute() {
        raw_path.clone()
    } else {
        std::env::current_dir()?.join(raw_path)
    };
    if !path.is_dir() {
        return Err(RustpenError::ParseError(format!(
            "project path not found: {}",
            path.display()
        )));
    }
    ensure_project_layout(&path)?;
    let mut imports = load_imported_project_paths(root_ws)?;
    if !imports.iter().any(|p| same_path(p, &path)) {
        imports.push(path.clone());
        save_imported_project_paths(root_ws, &imports)?;
    }
    Ok(path)
}

pub(crate) fn remove_imported_project(
    root_ws: &PathBuf,
    path: &PathBuf,
) -> Result<(), RustpenError> {
    let imports = load_imported_project_paths(root_ws)?;
    let kept = imports
        .into_iter()
        .filter(|p| !same_path(p, path))
        .collect::<Vec<_>>();
    save_imported_project_paths(root_ws, &kept)?;
    Ok(())
}

pub(crate) fn delete_local_project(root_ws: &PathBuf, path: &PathBuf) -> Result<(), RustpenError> {
    let root = projects_root_dir(root_ws);
    if !path.starts_with(&root) {
        return Err(RustpenError::ParseError(format!(
            "refuse deleting non-local project: {}",
            path.display()
        )));
    }
    if path.exists() {
        fs::remove_dir_all(path).map_err(RustpenError::Io)?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> Result<(), RustpenError> {
    if !src.is_dir() {
        return Err(RustpenError::ParseError(format!(
            "source is not directory: {}",
            src.display()
        )));
    }
    if dst.exists() {
        return Err(RustpenError::ParseError(format!(
            "destination already exists: {}",
            dst.display()
        )));
    }
    fs::create_dir_all(dst).map_err(RustpenError::Io)?;
    for entry in fs::read_dir(src).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if from.is_file() {
            fs::copy(&from, &to).map_err(RustpenError::Io)?;
        }
    }
    Ok(())
}

pub(crate) fn copy_project_to_local(
    root_ws: &PathBuf,
    source_project: &PathBuf,
    new_name: &str,
) -> Result<PathBuf, RustpenError> {
    let name = sanitize_project_name(new_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "copy project name contains no valid characters".to_string(),
        ));
    }
    let dst = projects_root_dir(root_ws).join(name);
    copy_dir_recursive(source_project, &dst)?;
    ensure_project_layout(&dst)?;
    Ok(dst)
}

pub(crate) fn rename_local_project(
    root_ws: &PathBuf,
    source_project: &PathBuf,
    new_name: &str,
) -> Result<PathBuf, RustpenError> {
    let root = projects_root_dir(root_ws);
    if !source_project.starts_with(&root) {
        return Err(RustpenError::ParseError(format!(
            "only local project can be renamed: {}",
            source_project.display()
        )));
    }
    let name = sanitize_project_name(new_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "rename target name contains no valid characters".to_string(),
        ));
    }
    let dst = root.join(name);
    if same_path(&dst, source_project) {
        return Ok(source_project.clone());
    }
    if dst.exists() {
        return Err(RustpenError::ParseError(format!(
            "target project already exists: {}",
            dst.display()
        )));
    }
    fs::rename(source_project, &dst).map_err(RustpenError::Io)?;
    Ok(dst)
}

pub(crate) fn export_project_snapshot(
    root_ws: &PathBuf,
    source_project: &PathBuf,
) -> Result<PathBuf, RustpenError> {
    let exports_dir = root_ws.join("exports");
    fs::create_dir_all(&exports_dir).map_err(RustpenError::Io)?;
    let name = sanitize_project_name(&project_name_from_path(source_project));
    let out = exports_dir.join(format!("{}_{}", name, now_epoch_secs()));
    copy_dir_recursive(source_project, &out)?;
    Ok(out)
}
