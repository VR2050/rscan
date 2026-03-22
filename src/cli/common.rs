use super::*;

#[path = "common_host.rs"]
mod common_host;
pub(super) use common_host::*;

pub(super) fn parse_output(fmt: &str) -> OutputFormat {
    match fmt.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "csv" => OutputFormat::Csv,
        _ => OutputFormat::Raw,
    }
}

pub(super) fn normalize_filter_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub(super) fn load_keywords_file(path: &PathBuf) -> Result<Vec<String>, RustpenError> {
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        out.push(s.to_string());
    }
    Ok(out)
}

pub(super) fn percent_encode_non_unreserved(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(super) fn apply_kw_transform(s: &str, t: FuzzKeywordTransform) -> String {
    match t {
        FuzzKeywordTransform::Raw => s.to_string(),
        FuzzKeywordTransform::UrlEncode => percent_encode_non_unreserved(s),
        FuzzKeywordTransform::DoubleUrlEncode => {
            percent_encode_non_unreserved(&percent_encode_non_unreserved(s))
        }
        FuzzKeywordTransform::Lower => s.to_ascii_lowercase(),
        FuzzKeywordTransform::Upper => s.to_ascii_uppercase(),
        FuzzKeywordTransform::PathWrap => format!("/{}/", s.trim_matches('/')),
    }
}

pub(super) fn preset_default_transforms(preset: FuzzPreset) -> Vec<FuzzKeywordTransform> {
    match preset {
        FuzzPreset::Api => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::Lower,
            FuzzKeywordTransform::UrlEncode,
        ],
        FuzzPreset::Path => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::PathWrap,
            FuzzKeywordTransform::UrlEncode,
        ],
        FuzzPreset::Param => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::UrlEncode,
            FuzzKeywordTransform::DoubleUrlEncode,
        ],
    }
}

pub(super) fn expand_keywords_with_preset(
    words: Vec<String>,
    preset: Option<FuzzPreset>,
) -> Vec<String> {
    let Some(preset) = preset else { return words };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for kw in words {
        if kw.trim().is_empty() {
            continue;
        }
        let variants: Vec<String> = match preset {
            FuzzPreset::Api => vec![
                kw.clone(),
                format!("api/{kw}"),
                format!("v1/{kw}"),
                format!("{kw}.json"),
                format!("{kw}.xml"),
            ],
            FuzzPreset::Path => vec![
                kw.clone(),
                format!("{kw}/"),
                format!(".{kw}"),
                format!("{kw}.bak"),
                format!("{kw}.old"),
            ],
            FuzzPreset::Param => vec![
                kw.clone(),
                format!("{kw}=1"),
                format!("{kw}=test"),
                format!("{kw}[]="),
                format!("{kw}=%7B%7D"),
            ],
        };
        for v in variants {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

pub(super) fn build_fuzz_keywords(
    base_keywords: Vec<String>,
    transforms: &[FuzzKeywordTransform],
    prefix: Option<String>,
    suffix: Option<String>,
    max_len: Option<usize>,
) -> Vec<String> {
    let transform_set = if transforms.is_empty() {
        vec![FuzzKeywordTransform::Raw]
    } else {
        transforms.to_vec()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for kw in base_keywords {
        let trimmed = kw.trim();
        if trimmed.is_empty() {
            continue;
        }
        for t in &transform_set {
            let mut v = apply_kw_transform(trimmed, *t);
            if let Some(p) = prefix.as_ref() {
                v = format!("{p}{v}");
            }
            if let Some(s) = suffix.as_ref() {
                v.push_str(s);
            }
            if let Some(mx) = max_len
                && v.len() > mx
            {
                continue;
            }
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

pub(super) fn filter_vuln_templates(
    templates: Vec<SafeTemplate>,
    severities: &[String],
    tags: &[String],
) -> Vec<SafeTemplate> {
    let sev_set = normalize_filter_set(severities);
    let tag_set = normalize_filter_set(tags);
    if sev_set.is_empty() && tag_set.is_empty() {
        return templates;
    }

    templates
        .into_iter()
        .filter(|tpl| {
            let sev_ok = if sev_set.is_empty() {
                true
            } else {
                tpl.info
                    .severity
                    .as_ref()
                    .map(|s| sev_set.contains(&s.to_ascii_lowercase()))
                    .unwrap_or(false)
            };
            let tag_ok = if tag_set.is_empty() {
                true
            } else {
                tpl.info
                    .tags
                    .iter()
                    .any(|t| tag_set.contains(&t.to_ascii_lowercase()))
            };
            sev_ok && tag_ok
        })
        .collect()
}

pub(super) fn apply_web_profile(mcfg: &mut ModuleScanConfig, profile: ScanProfile) {
    match profile {
        ScanProfile::LowNoise => {
            mcfg.concurrency = 4;
            mcfg.timeout_ms = Some(8000);
            mcfg.max_retries = Some(2);
            mcfg.per_host_concurrency_override = Some(1);
            mcfg.adaptive_rate = true;
            mcfg.adaptive_initial_delay_ms = 120;
            mcfg.adaptive_max_delay_ms = 2200;
        }
        ScanProfile::Balanced => {
            mcfg.concurrency = 24;
            mcfg.timeout_ms = Some(5000);
            mcfg.max_retries = Some(0);
            mcfg.per_host_concurrency_override = Some(16);
        }
        ScanProfile::Aggressive => {
            mcfg.concurrency = 64;
            mcfg.timeout_ms = Some(2500);
            mcfg.max_retries = Some(0);
            mcfg.per_host_concurrency_override = Some(32);
            mcfg.adaptive_rate = false;
            mcfg.adaptive_initial_delay_ms = 0;
            mcfg.adaptive_max_delay_ms = 800;
        }
    }
}

pub(super) fn apply_web_smart_fast(
    mcfg: &mut ModuleScanConfig,
    status_min: Option<u16>,
    status_max: Option<u16>,
) {
    mcfg.follow_redirects = false;
    mcfg.wildcard_filter = true;
    mcfg.fingerprint_filter = true;
    // Keep user-provided status filter first. If not provided, use a practical default
    // that preserves common "interesting" ranges while reducing noisy 4xx/5xx tails.
    if status_min.is_none() && status_max.is_none() {
        mcfg.status_min = Some(200);
        mcfg.status_max = Some(403);
    }
}

pub(super) fn apply_web_smart_fast_strict(
    mcfg: &mut ModuleScanConfig,
    status_min: Option<u16>,
    status_max: Option<u16>,
) {
    mcfg.follow_redirects = false;
    mcfg.wildcard_filter = true;
    mcfg.wildcard_sample_count = 1;
    mcfg.wildcard_len_tolerance = 8;
    mcfg.fingerprint_filter = true;
    mcfg.fingerprint_distance_threshold = 3;
    mcfg.max_retries = Some(0);
    if status_min.is_none() && status_max.is_none() {
        mcfg.status_min = Some(200);
        mcfg.status_max = Some(399);
    }
}

pub(super) fn parse_http_method(method: &str) -> Result<reqwest::Method, RustpenError> {
    reqwest::Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
        .map_err(|e| RustpenError::ParseError(format!("invalid --method '{}': {}", method, e)))
}

pub(super) fn parse_request_headers(
    values: &[String],
) -> Result<reqwest::header::HeaderMap, RustpenError> {
    let mut map = reqwest::header::HeaderMap::new();
    for raw in values {
        let Some((name, value)) = raw.split_once(':') else {
            return Err(RustpenError::ParseError(format!(
                "invalid --header '{}', expected 'Name: Value'",
                raw
            )));
        };
        let name = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|e| RustpenError::ParseError(format!("invalid header name: {}", e)))?;
        let value = reqwest::header::HeaderValue::from_str(value.trim())
            .map_err(|e| RustpenError::ParseError(format!("invalid header value: {}", e)))?;
        map.insert(name, value);
    }
    Ok(map)
}

pub(super) fn apply_body_mode_default_content_type(
    headers: &mut reqwest::header::HeaderMap,
    mode: RequestBodyModeArg,
    has_body: bool,
) {
    if !has_body || headers.contains_key(reqwest::header::CONTENT_TYPE) {
        return;
    }
    let value = match mode {
        RequestBodyModeArg::Raw => return,
        RequestBodyModeArg::Form => "application/x-www-form-urlencoded",
        RequestBodyModeArg::Json => "application/json",
    };
    if let Ok(v) = reqwest::header::HeaderValue::from_str(value) {
        headers.insert(reqwest::header::CONTENT_TYPE, v);
    }
}

pub(super) fn parse_decompile_mode(mode: &str) -> Result<DecompileMode, RustpenError> {
    DecompileMode::parse(mode).ok_or_else(|| {
        RustpenError::ParseError("invalid --mode. use: full|index|function".to_string())
    })
}

pub(super) fn to_json_or_raw<T: serde::Serialize + std::fmt::Debug>(
    value: &T,
    fmt: &str,
) -> Result<String, RustpenError> {
    if fmt.eq_ignore_ascii_case("json") {
        serde_json::to_string_pretty(value).map_err(|e| RustpenError::ParseError(e.to_string()))
    } else {
        Ok(format!("{value:#?}"))
    }
}

pub(super) async fn write_host_output_to_file(mut file: File, s: &str) -> Result<(), RustpenError> {
    file.write_all(format!("{}\n", s).as_bytes())
        .await
        .map_err(RustpenError::Io)?;
    Ok(())
}

/// 轻量任务上下文，用于写 meta / 事件流，供 TUI 读取。
pub(super) struct TaskCtx {
    dir: PathBuf,
    meta: TaskMeta,
    writer: TaskEventWriter,
}

pub(super) fn init_task_ctx(
    cli: &Cli,
    kind: &str,
    tags: Vec<String>,
) -> Result<Option<TaskCtx>, RustpenError> {
    let workspace = match &cli.task_workspace {
        Some(w) => w.clone(),
        None => return Ok(None),
    };
    let id = cli.task_id.clone().unwrap_or_else(|| new_task_id());
    let dir = ensure_task_dir(&workspace, &id)?;
    let now = now_epoch_secs();
    let mut meta = TaskMeta {
        id: id.clone(),
        kind: kind.to_string(),
        tags,
        status: TaskStatus::Running,
        created_at: now,
        started_at: Some(now),
        ended_at: None,
        progress: Some(0.0),
        note: cli.task_note.clone(),
        artifacts: Vec::new(),
        logs: vec![dir.join("stdout.log"), dir.join("stderr.log")],
        extra: None,
    };
    crate::cores::engine::task::attach_task_runtime(
        &mut meta,
        crate::cores::engine::task::TaskRuntimeBinding {
            backend: if std::env::var("ZELLIJ").is_ok()
                || std::env::var("ZELLIJ_SESSION_NAME").is_ok()
            {
                "zellij-task-engine".to_string()
            } else {
                "task-engine".to_string()
            },
            session: std::env::var("ZELLIJ_SESSION_NAME").ok(),
            tab: std::env::var("RSCAN_ZELLIJ_ACTIVE_TAB").ok(),
            pane_name: Some("rscan-control".to_string()),
            role: Some("task-engine".to_string()),
            cwd: Some(workspace.clone()),
            command: None,
        },
    );
    write_task_meta(&dir, &meta)?;
    let writer = TaskEventWriter::new(dir.clone());
    let _ = writer.log("info", "task started");
    let ev = TaskEvent {
        ts: now,
        level: "info".to_string(),
        kind: EventKind::Progress,
        message: Some("start".to_string()),
        data: Some(0.0.into()),
    };
    let _ = crate::cores::engine::task::append_task_event(&dir, &ev);
    Ok(Some(TaskCtx { dir, meta, writer }))
}

pub(super) fn finalize_task_ctx(
    ctx: &mut Option<TaskCtx>,
    status: TaskStatus,
    note: Option<String>,
) -> Result<(), RustpenError> {
    if let Some(c) = ctx.as_mut() {
        c.meta.status = status;
        c.meta.ended_at = Some(now_epoch_secs());
        c.meta.progress = Some(100.0);
        if let Some(n) = note {
            match c.meta.note.as_mut() {
                Some(existing) => {
                    existing.push_str("; ");
                    existing.push_str(&n);
                }
                None => c.meta.note = Some(n),
            }
        }
        write_task_meta(&c.dir, &c.meta)?;
        let _ = c
            .writer
            .log("info", format!("task finished: {:?}", c.meta.status));
    }
    Ok(())
}

pub(super) async fn with_task<F, Fut, T>(
    cli: &Cli,
    kind: &str,
    tags: Vec<String>,
    f: F,
) -> Result<T, RustpenError>
where
    F: FnOnce(Option<TaskEventWriter>) -> Fut,
    Fut: std::future::Future<Output = Result<T, RustpenError>>,
{
    if cli.task_workspace.is_none() {
        return f(None).await;
    }
    let mut ctx = init_task_ctx(cli, kind, tags)?;
    let writer = ctx.as_ref().map(|c| c.writer.clone());
    let result = f(writer).await;
    match result {
        Ok(v) => {
            finalize_task_ctx(&mut ctx, TaskStatus::Succeeded, None)?;
            Ok(v)
        }
        Err(e) => {
            let _ = finalize_task_ctx(&mut ctx, TaskStatus::Failed, Some(e.to_string()));
            Err(e)
        }
    }
}
