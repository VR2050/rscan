use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::errors::RustpenError;

/// 统一的任务状态，用于 TUI / 事件流。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

impl Default for TaskStatus {
    fn default() -> Self {
        TaskStatus::Queued
    }
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TaskStatus::Queued => "queued",
            TaskStatus::Running => "running",
            TaskStatus::Succeeded => "succeeded",
            TaskStatus::Failed => "failed",
            TaskStatus::Canceled => "canceled",
        };
        write!(f, "{s}")
    }
}

/// 任务元数据，写入 `workspace/tasks/<id>/meta.json`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMeta {
    pub id: String,
    /// 模块类型：host/web/vuln/reverse/shell/other
    pub kind: String,
    /// 自定义标签，如 target host/domain
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub status: TaskStatus,
    pub created_at: u64,
    #[serde(default)]
    pub started_at: Option<u64>,
    #[serde(default)]
    pub ended_at: Option<u64>,
    /// 0.0~100.0 之间的进度，可选
    #[serde(default)]
    pub progress: Option<f32>,
    #[serde(default)]
    pub note: Option<String>,
    /// 产物路径（相对或绝对）
    #[serde(default)]
    pub artifacts: Vec<PathBuf>,
    /// 日志路径（stdout/stderr）
    #[serde(default)]
    pub logs: Vec<PathBuf>,
    /// 额外字段，便于模块扩展
    #[serde(default)]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskRuntimeBinding {
    pub backend: String,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub tab: Option<String>,
    #[serde(default)]
    pub pane_name: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub command: Option<String>,
}

/// 任务事件 JSONL：`workspace/tasks/<id>/events.jsonl`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEvent {
    pub ts: u64,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub kind: EventKind,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    #[default]
    Log,
    Progress,
    Metric,
    Control,
}

fn default_level() -> String {
    "info".to_string()
}

/// 生成任务 ID，格式 `task-<hex_nanos>`.
pub fn new_task_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("task-{ns:x}")
}

pub fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// 确保任务目录存在，返回绝对路径。
pub fn ensure_task_dir(workspace: &Path, task_id: &str) -> Result<PathBuf, RustpenError> {
    let dir = workspace.join("tasks").join(task_id);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// 写入 meta.json（覆盖）。
pub fn write_task_meta(dir: &Path, meta: &TaskMeta) -> Result<(), RustpenError> {
    let path = dir.join("meta.json");
    let text =
        serde_json::to_string_pretty(meta).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    std::fs::write(path, text)?;
    Ok(())
}

pub fn load_task_meta(dir: &Path) -> Result<TaskMeta, RustpenError> {
    let path = dir.join("meta.json");
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))
}

pub fn task_runtime_binding_from_extra(extra: &Option<Value>) -> Option<TaskRuntimeBinding> {
    let obj = extra.as_ref()?.as_object()?;
    let runtime = obj.get("runtime")?.clone();
    serde_json::from_value(runtime).ok()
}

pub fn attach_task_runtime(meta: &mut TaskMeta, binding: TaskRuntimeBinding) {
    let mut obj = match meta.extra.take() {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let runtime = serde_json::to_value(binding).unwrap_or(Value::Null);
    obj.insert("runtime".to_string(), runtime);
    meta.extra = Some(Value::Object(obj));
}

pub fn update_task_runtime_binding(
    dir: &Path,
    binding: TaskRuntimeBinding,
) -> Result<(), RustpenError> {
    let mut meta = load_task_meta(dir)?;
    attach_task_runtime(&mut meta, binding);
    write_task_meta(dir, &meta)
}

/// 追加事件到 events.jsonl。
pub fn append_task_event(dir: &Path, event: &TaskEvent) -> Result<(), RustpenError> {
    let path = dir.join("events.jsonl");
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(event).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// 简单事件写入器，便于模块持有。
#[derive(Clone)]
pub struct TaskEventWriter {
    dir: PathBuf,
    last_progress_bucket: Arc<Mutex<Option<u8>>>,
    write_lock: Arc<Mutex<()>>,
}

impl TaskEventWriter {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            last_progress_bucket: Arc::new(Mutex::new(None)),
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn log(
        &self,
        level: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<(), RustpenError> {
        let _write_guard = self.write_lock.lock().ok();
        let level = level.into();
        let message = message.into();
        let ev = TaskEvent {
            ts: now_epoch_secs(),
            level: level.clone(),
            kind: EventKind::Log,
            message: Some(message.clone()),
            data: None,
        };
        append_task_event(&self.dir, &ev)?;
        let filename = if level.eq_ignore_ascii_case("error") {
            "stderr.log"
        } else {
            "stdout.log"
        };
        self.append_file_line(filename, &message)
    }

    pub fn progress(&self, pct: f32, message: Option<String>) -> Result<(), RustpenError> {
        let _write_guard = self.write_lock.lock().ok();
        let pct = pct.clamp(0.0, 100.0);
        let bucket = pct.round() as u8;
        let mut should_emit = true;
        if let Ok(mut last) = self.last_progress_bucket.lock() {
            if last.as_ref().copied().is_some_and(|seen| bucket <= seen) {
                should_emit = false;
            } else {
                *last = Some(bucket);
            }
        }
        if !should_emit {
            return Ok(());
        }
        let ev = TaskEvent {
            ts: now_epoch_secs(),
            level: "info".to_string(),
            kind: EventKind::Progress,
            message,
            data: Some(Value::from(pct)),
        };
        append_task_event(&self.dir, &ev)?;
        let _ = self.update_meta_progress(pct);
        if let Some(msg) = ev.message.as_deref() {
            let _ = self.append_file_line("stdout.log", &format!("[progress {:>5.1}%] {msg}", pct));
        }
        Ok(())
    }

    fn update_meta_progress(&self, pct: f32) -> Result<(), RustpenError> {
        let mut meta = load_task_meta(&self.dir)?;
        meta.progress = Some(pct);
        write_task_meta(&self.dir, &meta)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn register_artifact(&self, path: impl Into<PathBuf>) -> Result<(), RustpenError> {
        let path = path.into();
        self.update_meta(|meta| {
            if !meta.artifacts.iter().any(|item| item == &path) {
                meta.artifacts.push(path.clone());
            }
        })
    }

    pub fn append_stdout(&self, text: &str) -> Result<(), RustpenError> {
        self.append_file_text("stdout.log", text)
    }

    pub fn append_stderr(&self, text: &str) -> Result<(), RustpenError> {
        self.append_file_text("stderr.log", text)
    }

    fn update_meta<F>(&self, mut f: F) -> Result<(), RustpenError>
    where
        F: FnMut(&mut TaskMeta),
    {
        let mut meta = load_task_meta(&self.dir)?;
        f(&mut meta);
        write_task_meta(&self.dir, &meta)
    }

    fn append_file_line(&self, filename: &str, line: &str) -> Result<(), RustpenError> {
        let mut owned = line.to_string();
        if !owned.ends_with('\n') {
            owned.push('\n');
        }
        self.append_file_text(filename, &owned)
    }

    fn append_file_text(&self, filename: &str, text: &str) -> Result<(), RustpenError> {
        let path = self.dir.join(filename);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }
}
