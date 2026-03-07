use std::fs;
use std::path::PathBuf;

use crate::cores::engine::task::{TaskEvent, TaskStatus};
use crate::errors::RustpenError;

use super::models::{ResultKindFilter, StatusFilter, TaskView};

pub(crate) fn load_tasks(dir: PathBuf) -> Result<Vec<TaskView>, RustpenError> {
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
            });
        }
    }
    metas.sort_by_key(|m| std::cmp::Reverse(m.meta.created_at));
    Ok(metas)
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
