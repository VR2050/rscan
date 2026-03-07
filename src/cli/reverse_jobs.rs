use super::*;

pub(super) async fn handle_jobs(
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let jobs = list_jobs(&workspace)?;
    let s = to_json_or_raw(&jobs, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_status(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let info = load_job_by_id(&workspace, &job)?;
    let s = to_json_or_raw(&info, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_logs(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    stream: String,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let (stdout, stderr) = load_job_logs(&workspace, &job)?;
    match stream.to_ascii_lowercase().as_str() {
        "stdout" => print!("{}", stdout),
        "stderr" => print!("{}", stderr),
        "both" => {
            println!("--- stdout ---");
            print!("{}", stdout);
            println!("--- stderr ---");
            print!("{}", stderr);
        }
        _ => {
            return Err(RustpenError::ParseError(
                "invalid --stream. use stdout|stderr|both".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn handle_job_artifacts(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let info = load_job_by_id(&workspace, &job)?;
    let s = to_json_or_raw(&info.artifacts, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_functions(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let rows = load_job_pseudocode_rows(&workspace, &job)?;
    let funcs: Vec<_> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "ea": r.get("ea").and_then(|v| v.as_str()).unwrap_or(""),
                "name": r.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();
    let s = if output.eq_ignore_ascii_case("raw") {
        funcs
            .iter()
            .map(|f| format!("{} {}", f["ea"], f["name"]))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        to_json_or_raw(&funcs, &output)?
    };
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_show(
    job: Option<String>,
    job_pos: Option<String>,
    name: Option<String>,
    name_pos: Option<String>,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let name = required_name(name, name_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let rows = load_job_pseudocode_rows(&workspace, &job)?;
    let one = rows.into_iter().find(|r| {
        r.get("name").and_then(|v| v.as_str()) == Some(name.as_str())
            || r.get("ea").and_then(|v| v.as_str()) == Some(name.as_str())
    });
    let v = one.ok_or_else(|| {
        RustpenError::ScanError(format!("function '{}' not found in job {}", name, job))
    })?;
    let s = to_json_or_raw(&v, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_search(
    job: Option<String>,
    job_pos: Option<String>,
    keyword: Option<String>,
    keyword_pos: Option<String>,
    workspace: Option<PathBuf>,
    max: usize,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let keyword = required_keyword(keyword, keyword_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let kw = keyword.to_ascii_lowercase();
    let rows = load_job_pseudocode_rows(&workspace, &job)?;
    let mut hits = Vec::new();
    for r in rows {
        let name = r
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let ea = r
            .get("ea")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let code = r
            .get("pseudocode")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let matched = name.to_ascii_lowercase().contains(&kw)
            || code.to_ascii_lowercase().contains(&kw)
            || ea.to_ascii_lowercase().contains(&kw);
        if matched {
            hits.push(serde_json::json!({"ea": ea, "name": name}));
            if hits.len() >= max.max(1) {
                break;
            }
        }
    }
    let s = if output.eq_ignore_ascii_case("raw") {
        hits.iter()
            .map(|h| format!("{} {}", h["ea"], h["name"]))
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        to_json_or_raw(&hits, &output)?
    };
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_clear(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    all: bool,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = job.or(job_pos);
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let removed = if all {
        clear_jobs(&workspace, None)?
    } else {
        clear_jobs(&workspace, job.as_deref())?
    };
    let v = serde_json::json!({ "removed": removed, "all": all, "job": job });
    let s = to_json_or_raw(&v, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_prune(
    keep: usize,
    older_than_days: Option<u64>,
    include_running: bool,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let removed = prune_jobs(
        &workspace,
        crate::modules::reverse::JobPrunePolicy {
            keep_latest: Some(keep.max(1)),
            older_than_days,
            include_running,
        },
    )?;
    let v = serde_json::json!({
        "removed": removed,
        "keep": keep.max(1),
        "older_than_days": older_than_days,
        "include_running": include_running
    });
    let s = to_json_or_raw(&v, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_job_doctor(
    job: Option<String>,
    job_pos: Option<String>,
    workspace: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let job = required_job_id(job, job_pos)?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let health = inspect_job_health(&workspace, &job)?;
    let s = to_json_or_raw(&health, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

fn required_job_id(job: Option<String>, job_pos: Option<String>) -> Result<String, RustpenError> {
    job.or(job_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--job <id> or <JOB>".to_string(),
        })
}

fn required_name(name: Option<String>, name_pos: Option<String>) -> Result<String, RustpenError> {
    name.or(name_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--name <fn> or <NAME>".to_string(),
        })
}

fn required_keyword(
    keyword: Option<String>,
    keyword_pos: Option<String>,
) -> Result<String, RustpenError> {
    keyword
        .or(keyword_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--keyword <kw> or <KEYWORD>".to_string(),
        })
}
