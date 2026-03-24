use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader};
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
    let kind = task.meta.kind.as_str();
    match filter {
        ResultKindFilter::All => true,
        ResultKindFilter::Host => kind == "host" || kind.starts_with("host-"),
        ResultKindFilter::Web => kind == "web" || kind.starts_with("web-"),
        ResultKindFilter::Vuln => kind == "vuln" || kind.starts_with("vuln-"),
        ResultKindFilter::Reverse => kind == "reverse" || kind.starts_with("reverse-"),
        ResultKindFilter::Script => kind == "script" || kind.starts_with("script-"),
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
    if contains_case_insensitive(&meta.id, &q)
        || contains_case_insensitive(&meta.kind, &q)
        || contains_case_insensitive(&meta.status.to_string(), &q)
        || meta
            .note
            .as_deref()
            .is_some_and(|note| contains_case_insensitive(note, &q))
        || meta
            .tags
            .iter()
            .any(|tag| contains_case_insensitive(tag, &q))
        || meta
            .artifacts
            .iter()
            .any(|path| contains_path_case_insensitive(path, &q))
        || meta
            .logs
            .iter()
            .any(|path| contains_path_case_insensitive(path, &q))
    {
        return true;
    }

    if load_events(&task.dir, 30).into_iter().any(|ev| {
        contains_case_insensitive(&ev.level, &q)
            || contains_case_insensitive(&format!("{:?}", ev.kind), &q)
            || ev
                .message
                .as_deref()
                .is_some_and(|message| contains_case_insensitive(message, &q))
            || ev
                .data
                .as_ref()
                .is_some_and(|data| contains_case_insensitive(&data.to_string(), &q))
    }) {
        return true;
    }

    if load_text_artifact_snippets(task, 24, 3)
        .into_iter()
        .flat_map(|(_, lines)| lines.into_iter())
        .any(|line| contains_case_insensitive(&line, &q))
    {
        return true;
    }

    load_log_tail(&task.dir, "stdout.log", 30)
        .into_iter()
        .chain(load_log_tail(&task.dir, "stderr.log", 30))
        .any(|line| contains_case_insensitive(&line, &q))
}

fn contains_case_insensitive(text: &str, needle_lower: &str) -> bool {
    text.to_ascii_lowercase().contains(needle_lower)
}

fn contains_path_case_insensitive(path: &Path, needle_lower: &str) -> bool {
    contains_case_insensitive(&path.display().to_string(), needle_lower)
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
    tail_lines(&path, limit)
        .into_iter()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str::<TaskEvent>(line).ok()
        })
        .collect::<Vec<_>>()
}

pub(crate) fn load_log_tail(task_dir: &PathBuf, filename: &str, limit: usize) -> Vec<String> {
    let path = task_dir.join(filename);
    load_path_tail(&path, limit)
}

pub(crate) fn load_path_tail(path: &Path, limit: usize) -> Vec<String> {
    if !path.is_file() {
        return Vec::new();
    }
    tail_lines(path, limit)
}

pub(crate) fn load_text_artifact_snippets(
    task: &TaskView,
    limit_per_file: usize,
    max_files: usize,
) -> Vec<(PathBuf, Vec<String>)> {
    previewable_artifact_paths(task)
        .into_iter()
        .take(max_files.max(1))
        .map(|path| {
            let lines = load_path_tail(&path, limit_per_file);
            (path, lines)
        })
        .filter(|(_, lines)| !lines.is_empty())
        .collect()
}

pub(crate) fn preview_text_artifact(
    task: &TaskView,
    limit: usize,
) -> Option<(PathBuf, Vec<String>)> {
    previewable_artifact_paths(task)
        .into_iter()
        .next()
        .map(|path| {
            let lines = load_path_tail(&path, limit);
            (path, lines)
        })
}

fn previewable_artifact_paths(task: &TaskView) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for artifact in &task.meta.artifacts {
        collect_previewable_paths(artifact, 1, &mut seen, &mut out);
    }
    out
}

fn collect_previewable_paths(
    path: &Path,
    depth_left: usize,
    seen: &mut BTreeSet<PathBuf>,
    out: &mut Vec<PathBuf>,
) {
    if path.is_file() {
        let normalized = path.to_path_buf();
        if is_previewable_text_artifact(&normalized) && seen.insert(normalized.clone()) {
            out.push(normalized);
        }
        return;
    }

    if !path.is_dir() || depth_left == 0 {
        return;
    }

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    let mut entries = entries.filter_map(Result::ok).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        collect_previewable_paths(&entry.path(), depth_left.saturating_sub(1), seen, out);
    }
}

fn tail_lines(path: &Path, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut tail = VecDeque::with_capacity(limit.min(128));
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            continue;
        };
        if tail.len() == limit {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    tail.into_iter().collect()
}

fn is_previewable_text_artifact(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    matches!(
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase()),
        Some(ext)
            if matches!(
                ext.as_str(),
                "txt" | "log" | "json" | "jsonl" | "csv" | "tsv" | "md" | "html" | "htm" | "xml" | "yaml" | "yml"
            )
    )
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

    fn write_task_meta_file(task_dir: &Path, meta: &TaskMeta) {
        std::fs::create_dir_all(task_dir).unwrap();
        std::fs::write(
            task_dir.join("meta.json"),
            serde_json::to_string_pretty(meta).unwrap(),
        )
        .unwrap();
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

    #[test]
    fn load_text_artifact_snippets_reads_previewable_files_inside_artifact_dirs() {
        let ws = temp_workspace("artifact_snippets");
        let task_dir = ws.join("tasks").join("task-web");
        let artifact_dir = task_dir.join("artifacts");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(
            artifact_dir.join("web-dir-result.txt"),
            "OK 200 https://example.com/admin\nCLIENT 404 https://example.com/missing\n",
        )
        .unwrap();

        let meta = TaskMeta {
            id: "task-web".to_string(),
            kind: "web".to_string(),
            tags: vec!["https://example.com".to_string()],
            status: TaskStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            progress: Some(100.0),
            note: None,
            artifacts: vec![artifact_dir.clone()],
            logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
            extra: None,
        };
        write_task_meta_file(&task_dir, &meta);

        let tasks = load_tasks(ws.clone()).unwrap();
        let snippets = load_text_artifact_snippets(&tasks[0], 8, 2);
        assert_eq!(snippets.len(), 1);
        assert!(snippets[0].0.ends_with("web-dir-result.txt"));
        assert!(snippets[0].1.iter().any(|line| line.contains("/admin")));

        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn result_query_matches_artifact_content() {
        let ws = temp_workspace("artifact_query");
        let task_dir = ws.join("tasks").join("task-vuln");
        std::fs::create_dir_all(&task_dir).unwrap();
        let artifact_path = task_dir.join("vuln-scan-result.txt");
        std::fs::write(
            &artifact_path,
            "HIGH cvescan GET https://example.com/login\nmatched=word:body,status:code\n",
        )
        .unwrap();

        let meta = TaskMeta {
            id: "task-vuln".to_string(),
            kind: "vuln".to_string(),
            tags: vec!["https://example.com".to_string()],
            status: TaskStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            progress: Some(100.0),
            note: None,
            artifacts: vec![artifact_path],
            logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
            extra: None,
        };
        write_task_meta_file(&task_dir, &meta);

        let tasks = load_tasks(ws.clone()).unwrap();
        assert!(task_matches_result_query(&tasks[0], "cvescan"));
        assert!(task_matches_result_query(&tasks[0], "matched=word:body"));
        assert!(task_matches_result_query(&tasks[0], "/login"));
        assert!(!task_matches_result_query(&tasks[0], "totally-missing"));

        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn preview_text_artifact_prefers_sorted_previewable_file_in_directory() {
        let ws = temp_workspace("preview_sorted");
        let task_dir = ws.join("tasks").join("task-web");
        let artifact_dir = task_dir.join("artifacts");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("z-last.txt"), "zzz\n").unwrap();
        std::fs::write(artifact_dir.join("a-first.txt"), "aaa\n").unwrap();

        let meta = TaskMeta {
            id: "task-web".to_string(),
            kind: "web".to_string(),
            tags: vec!["https://example.com".to_string()],
            status: TaskStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            progress: Some(100.0),
            note: None,
            artifacts: vec![artifact_dir],
            logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
            extra: None,
        };
        write_task_meta_file(&task_dir, &meta);

        let tasks = load_tasks(ws.clone()).unwrap();
        let (path, lines) = preview_text_artifact(&tasks[0], 5).unwrap();
        assert!(path.ends_with("a-first.txt"));
        assert_eq!(lines.first().map(String::as_str), Some("aaa"));

        let _ = std::fs::remove_dir_all(ws);
    }

    #[test]
    fn load_text_artifact_snippets_respects_max_files_limit() {
        let ws = temp_workspace("artifact_limit");
        let task_dir = ws.join("tasks").join("task-web");
        let artifact_dir = task_dir.join("artifacts");
        std::fs::create_dir_all(&artifact_dir).unwrap();
        std::fs::write(artifact_dir.join("a.txt"), "one\n").unwrap();
        std::fs::write(artifact_dir.join("b.txt"), "two\n").unwrap();
        std::fs::write(artifact_dir.join("c.txt"), "three\n").unwrap();

        let meta = TaskMeta {
            id: "task-web".to_string(),
            kind: "web".to_string(),
            tags: vec!["https://example.com".to_string()],
            status: TaskStatus::Succeeded,
            created_at: 1,
            started_at: Some(1),
            ended_at: Some(2),
            progress: Some(100.0),
            note: None,
            artifacts: vec![artifact_dir],
            logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
            extra: None,
        };
        write_task_meta_file(&task_dir, &meta);

        let tasks = load_tasks(ws.clone()).unwrap();
        let snippets = load_text_artifact_snippets(&tasks[0], 5, 2);
        assert_eq!(snippets.len(), 2);
        assert!(snippets[0].0.ends_with("a.txt"));
        assert!(snippets[1].0.ends_with("b.txt"));

        let _ = std::fs::remove_dir_all(ws);
    }
}
