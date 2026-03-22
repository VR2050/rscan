use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cores::engine::task::{
    TaskEvent, TaskMeta, TaskRuntimeBinding, TaskStatus, attach_task_runtime,
};
use crate::errors::RustpenError;
use crate::modules::reverse::{ReverseJobMeta, ReverseJobStatus, list_primary_sample_jobs};

use super::models::{ResultKindFilter, StatusFilter, TaskOrigin, TaskView};
use super::zellij;

pub(crate) const REVERSE_JOB_RUNTIME_FILE: &str = "task-runtime.json";

pub(crate) fn load_tasks(workspace: PathBuf) -> Result<Vec<TaskView>, RustpenError> {
    let mut metas = load_structured_tasks(workspace.join("tasks"))?;
    metas.extend(load_reverse_jobs_as_tasks(&workspace)?);
    metas.sort_by_key(|m| std::cmp::Reverse(m.meta.created_at));
    Ok(metas)
}

fn load_structured_tasks(dir: PathBuf) -> Result<Vec<TaskView>, RustpenError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut metas = Vec::new();
    for entry in fs::read_dir(&dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path().join("meta.json");
        if !p.is_file() {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&p)
            && let Ok(meta) = serde_json::from_str(&text)
        {
            metas.push(TaskView {
                meta,
                dir: entry.path(),
                origin: TaskOrigin::Task,
            });
        }
    }
    metas.sort_by_key(|m| std::cmp::Reverse(m.meta.created_at));
    Ok(metas)
}

fn load_reverse_jobs_as_tasks(workspace: &Path) -> Result<Vec<TaskView>, RustpenError> {
    Ok(list_primary_sample_jobs(workspace)?
        .into_iter()
        .map(|job| reverse_job_to_task_view(workspace, job))
        .collect())
}

fn reverse_job_to_task_view(workspace: &Path, job: ReverseJobMeta) -> TaskView {
    let job_dir = workspace.join("jobs").join(&job.id);
    let logs = vec![job_dir.join("stdout.log"), job_dir.join("stderr.log")];
    let mut meta = TaskMeta {
        id: job.id.clone(),
        kind: "reverse".to_string(),
        tags: reverse_job_tags(&job),
        status: reverse_status_to_task_status(&job.status),
        created_at: job.created_at,
        started_at: job.started_at,
        ended_at: job.ended_at,
        progress: Some(reverse_status_progress(&job.status)),
        note: reverse_job_note(&job),
        artifacts: reverse_job_artifacts(workspace, &job),
        logs,
        extra: None,
    };

    let runtime = load_reverse_job_runtime_binding(&job_dir)
        .unwrap_or_else(|| default_reverse_job_runtime(workspace, &job, &job_dir));
    attach_task_runtime(&mut meta, runtime);

    TaskView {
        meta,
        dir: job_dir,
        origin: TaskOrigin::ReverseJob,
    }
}

fn reverse_job_tags(job: &ReverseJobMeta) -> Vec<String> {
    let mut tags = vec![
        "reverse-job".to_string(),
        format!("job:{}", job.kind),
        format!("backend:{}", job.backend),
    ];
    if let Some(mode) = job.mode.as_ref().filter(|s| !s.trim().is_empty()) {
        tags.push(format!("mode:{mode}"));
    }
    if let Some(function) = job.function.as_ref().filter(|s| !s.trim().is_empty()) {
        tags.push(format!("function:{function}"));
    }
    tags.push(job.target.display().to_string());
    tags
}

fn reverse_status_to_task_status(status: &ReverseJobStatus) -> TaskStatus {
    match status {
        ReverseJobStatus::Queued => TaskStatus::Queued,
        ReverseJobStatus::Running => TaskStatus::Running,
        ReverseJobStatus::Succeeded => TaskStatus::Succeeded,
        ReverseJobStatus::Failed => TaskStatus::Failed,
    }
}

fn reverse_status_progress(status: &ReverseJobStatus) -> f32 {
    match status {
        ReverseJobStatus::Queued => 0.0,
        ReverseJobStatus::Running => 55.0,
        ReverseJobStatus::Succeeded | ReverseJobStatus::Failed => 100.0,
    }
}

fn reverse_job_note(job: &ReverseJobMeta) -> Option<String> {
    let mut parts = Vec::new();
    if !job.note.trim().is_empty() {
        parts.push(job.note.trim().to_string());
    }
    parts.push(format!("target={}", job.target.display()));
    if let Some(mode) = job.mode.as_ref().filter(|s| !s.trim().is_empty()) {
        parts.push(format!("mode={mode}"));
    }
    if let Some(function) = job.function.as_ref().filter(|s| !s.trim().is_empty()) {
        parts.push(format!("function={function}"));
    }
    if let Some(code) = job.exit_code {
        parts.push(format!("exit={code}"));
    }
    if let Some(error) = job.error.as_ref().filter(|s| !s.trim().is_empty()) {
        parts.push(format!("error={error}"));
    }
    (!parts.is_empty()).then(|| parts.join(" | "))
}

fn reverse_job_artifacts(workspace: &Path, job: &ReverseJobMeta) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut artifacts = Vec::new();
    for item in &job.artifacts {
        let path = normalize_reverse_path(workspace, item);
        if seen.insert(path.clone()) {
            artifacts.push(path);
        }
    }
    let out_dir = workspace.join("reverse_out").join(&job.id);
    if out_dir.exists() && seen.insert(out_dir.clone()) {
        artifacts.push(out_dir);
    }
    artifacts
}

fn normalize_reverse_path(workspace: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

fn default_reverse_job_runtime(
    workspace: &Path,
    job: &ReverseJobMeta,
    job_dir: &Path,
) -> TaskRuntimeBinding {
    let out_dir = workspace.join("reverse_out").join(&job.id);
    let cwd = if out_dir.exists() {
        out_dir
    } else {
        job_dir.to_path_buf()
    };
    TaskRuntimeBinding {
        backend: format!("reverse-job:{}", job.backend),
        session: std::env::var("ZELLIJ_SESSION_NAME").ok(),
        tab: Some(zellij::REVERSE_TAB.to_string()),
        pane_name: Some(short_reverse_job_pane_name(&job.id)),
        role: Some(format!("reverse-{}", job.kind)),
        cwd: Some(cwd),
        command: Some(join_command(&job.program, &job.args)),
    }
}

fn short_reverse_job_pane_name(job_id: &str) -> String {
    let short = job_id.trim_start_matches("job-");
    let short = &short[..short.len().min(10)];
    format!("rev-{short}")
}

fn join_command(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

fn load_reverse_job_runtime_binding(job_dir: &Path) -> Option<TaskRuntimeBinding> {
    let text = fs::read_to_string(job_dir.join(REVERSE_JOB_RUNTIME_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

pub(crate) fn apply_filter(all: &[TaskView], filter: StatusFilter) -> Vec<TaskView> {
    all.iter()
        .filter(|t| match filter {
            StatusFilter::All => true,
            StatusFilter::Running => t.meta.status == TaskStatus::Running,
            StatusFilter::Failed => t.meta.status == TaskStatus::Failed,
            StatusFilter::Succeeded => t.meta.status == TaskStatus::Succeeded,
        })
        .cloned()
        .collect()
}

fn task_matches_result_filter(task: &TaskView, filter: ResultKindFilter) -> bool {
    match filter {
        ResultKindFilter::All => true,
        ResultKindFilter::Host => task.meta.kind == "host",
        ResultKindFilter::Web => task.meta.kind == "web",
        ResultKindFilter::Vuln => task.meta.kind == "vuln",
        ResultKindFilter::Reverse => task.meta.kind == "reverse",
        ResultKindFilter::Script => task.meta.kind == "script",
    }
}

fn result_status_rank(status: &TaskStatus) -> u8 {
    match status {
        TaskStatus::Failed => 0,
        TaskStatus::Running => 1,
        TaskStatus::Succeeded => 2,
        TaskStatus::Queued => 3,
        TaskStatus::Canceled => 4,
    }
}

fn task_matches_result_query(task: &TaskView, query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }

    let meta = &task.meta;
    let mut hay = vec![
        meta.id.to_ascii_lowercase(),
        meta.kind.to_ascii_lowercase(),
        meta.status.to_string().to_ascii_lowercase(),
        meta.note.clone().unwrap_or_default().to_ascii_lowercase(),
        meta.tags.join(" ").to_ascii_lowercase(),
        meta.artifacts
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
        meta.logs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    ];
    if hay.iter().any(|h| h.contains(&q)) {
        return true;
    }

    let ev_join = load_events(&task.dir, 30)
        .into_iter()
        .map(|ev| {
            format!(
                "{} {:?} {} {}",
                ev.level,
                ev.kind,
                ev.message.unwrap_or_default(),
                ev.data.map(|v| v.to_string()).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    hay.push(ev_join);

    let out_join = load_log_tail(&task.dir, "stdout.log", 30)
        .into_iter()
        .chain(load_log_tail(&task.dir, "stderr.log", 30))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    hay.push(out_join);
    hay.iter().any(|h| h.contains(&q))
}

pub(crate) fn build_result_indices(
    all_tasks: &[TaskView],
    filter: ResultKindFilter,
    failed_first: bool,
    query: &str,
) -> Vec<usize> {
    let mut indices: Vec<usize> = all_tasks
        .iter()
        .enumerate()
        .filter_map(|(idx, t)| {
            (task_matches_result_filter(t, filter) && task_matches_result_query(t, query))
                .then_some(idx)
        })
        .collect();
    if failed_first {
        indices.sort_by(|a, b| {
            let ta = &all_tasks[*a];
            let tb = &all_tasks[*b];
            result_status_rank(&ta.meta.status)
                .cmp(&result_status_rank(&tb.meta.status))
                .then_with(|| tb.meta.created_at.cmp(&ta.meta.created_at))
        });
    }
    indices
}

pub(crate) fn load_events(task_dir: &PathBuf, limit: usize) -> Vec<TaskEvent> {
    let path = task_dir.join("events.jsonl");
    if !path.is_file() {
        return vec![];
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return vec![];
    };
    text.lines()
        .rev()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str::<TaskEvent>(line).ok()
        })
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
}

pub(crate) fn load_log_tail(task_dir: &PathBuf, filename: &str, limit: usize) -> Vec<String> {
    let path = task_dir.join(filename);
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = text
        .lines()
        .rev()
        .take(limit)
        .map(|s| s.to_string())
        .collect();
    lines.reverse();
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::reverse::{ReverseJobMeta, ReverseJobStatus};

    fn temp_workspace(name: &str) -> PathBuf {
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("rscan_task_store_{name}_{ns:x}"))
    }

    #[test]
    fn load_tasks_merges_structured_tasks_and_reverse_jobs() {
        let ws = temp_workspace("merge");
        let task_dir = ws.join("tasks").join("task-one");
        let job_dir = ws.join("jobs").join("job-one");
        let out_dir = ws.join("reverse_out").join("job-one");
        std::fs::create_dir_all(&task_dir).unwrap();
        std::fs::create_dir_all(&job_dir).unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();

        let task_meta = TaskMeta {
            id: "task-one".to_string(),
            kind: "host".to_string(),
            tags: vec!["127.0.0.1".to_string()],
            status: TaskStatus::Succeeded,
            created_at: 10,
            started_at: Some(10),
            ended_at: Some(11),
            progress: Some(100.0),
            note: Some("host finished".to_string()),
            artifacts: Vec::new(),
            logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
            extra: None,
        };
        std::fs::write(
            task_dir.join("meta.json"),
            serde_json::to_string_pretty(&task_meta).unwrap(),
        )
        .unwrap();

        let job_meta = ReverseJobMeta {
            id: "job-one".to_string(),
            kind: "decompile".to_string(),
            backend: "ghidra".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: ws.join("sample.bin"),
            workspace: ws.clone(),
            status: ReverseJobStatus::Succeeded,
            created_at: 20,
            started_at: Some(20),
            ended_at: Some(21),
            exit_code: Some(0),
            program: "analyzeHeadless".to_string(),
            args: vec!["proj".to_string()],
            note: "reverse done".to_string(),
            artifacts: vec![out_dir.join("index.jsonl").display().to_string()],
            error: None,
        };
        std::fs::write(
            job_dir.join("meta.json"),
            serde_json::to_string_pretty(&job_meta).unwrap(),
        )
        .unwrap();

        let tasks = load_tasks(ws.clone()).unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].meta.id, "job-one");
        assert_eq!(tasks[0].meta.kind, "reverse");
        assert_eq!(tasks[0].origin, TaskOrigin::ReverseJob);
        assert!(
            tasks[0]
                .meta
                .artifacts
                .iter()
                .any(|p| p.ends_with("reverse_out/job-one"))
        );
        assert_eq!(tasks[1].meta.id, "task-one");
        assert_eq!(tasks[1].origin, TaskOrigin::Task);

        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn reverse_job_runtime_sidecar_overrides_default_runtime() {
        let ws = temp_workspace("runtime");
        let job_dir = ws.join("jobs").join("job-two");
        std::fs::create_dir_all(&job_dir).unwrap();

        let job_meta = ReverseJobMeta {
            id: "job-two".to_string(),
            kind: "decompile".to_string(),
            backend: "jadx".to_string(),
            mode: Some("full".to_string()),
            function: None,
            target: ws.join("sample.apk"),
            workspace: ws.clone(),
            status: ReverseJobStatus::Running,
            created_at: 30,
            started_at: Some(30),
            ended_at: None,
            exit_code: None,
            program: "jadx".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: Vec::new(),
            error: None,
        };
        std::fs::write(
            job_dir.join("meta.json"),
            serde_json::to_string_pretty(&job_meta).unwrap(),
        )
        .unwrap();
        let sidecar = TaskRuntimeBinding {
            backend: "zellij".to_string(),
            session: Some("rscan".to_string()),
            tab: Some("Reverse".to_string()),
            pane_name: Some("rev-job-two".to_string()),
            role: Some("inspect-artifacts".to_string()),
            cwd: Some(job_dir.clone()),
            command: Some("ls -lah".to_string()),
        };
        std::fs::write(
            job_dir.join(REVERSE_JOB_RUNTIME_FILE),
            serde_json::to_string_pretty(&sidecar).unwrap(),
        )
        .unwrap();

        let tasks = load_tasks(ws.clone()).unwrap();
        let runtime =
            crate::cores::engine::task::task_runtime_binding_from_extra(&tasks[0].meta.extra)
                .unwrap();
        assert_eq!(runtime.backend, "zellij");
        assert_eq!(runtime.pane_name.as_deref(), Some("rev-job-two"));

        let _ = std::fs::remove_dir_all(ws);
    }
}
