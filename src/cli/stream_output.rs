use super::*;

fn all_errors_stream_failure(
    stage: &str,
    processed: usize,
    err_count: usize,
    first_error: Option<&RustpenError>,
) -> RustpenError {
    if err_count == 1
        && let Some(err) = first_error
    {
        return match err {
            RustpenError::ParseError(msg) => RustpenError::ParseError(msg.clone()),
            RustpenError::NetworkError(msg) => RustpenError::NetworkError(msg.clone()),
            RustpenError::ScanError(msg) => RustpenError::ScanError(msg.clone()),
            RustpenError::InvalidHost(msg) => RustpenError::InvalidHost(msg.clone()),
            _ => RustpenError::Generic(err.to_string()),
        };
    }
    RustpenError::Generic(format!(
        "{stage} failed for all stream items (errors={err_count}, total={processed}): {}",
        first_error
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn summary_lines_by_format(
    fmt: &OutputFormat,
    ranked: &[((u16, Option<u64>), usize)],
    shown: usize,
    err_count: usize,
) -> Vec<String> {
    match fmt {
        OutputFormat::Raw => {
            let mut lines = vec![format!(
                "summary clusters={} shown={} errors={}",
                ranked.len(),
                shown,
                err_count
            )];
            lines.extend(ranked.iter().take(shown).map(|((status, len), count)| {
                format!(
                    "cluster status={} content_len={} count={}",
                    status,
                    len.map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    count
                )
            }));
            lines
        }
        OutputFormat::Json => {
            let mut lines = vec![
                serde_json::json!({
                    "type": "summary",
                    "clusters": ranked.len(),
                    "shown": shown,
                    "errors": err_count,
                })
                .to_string(),
            ];
            lines.extend(ranked.iter().take(shown).map(|((status, len), count)| {
                serde_json::json!({
                    "type": "cluster",
                    "status": status,
                    "content_len": len,
                    "count": count,
                })
                .to_string()
            }));
            lines
        }
        OutputFormat::Csv => {
            let mut lines = vec![
                format!("__summary__,clusters,{}", ranked.len()),
                format!("__summary__,shown,{shown}"),
                format!("__summary__,errors,{err_count}"),
            ];
            lines.extend(ranked.iter().take(shown).map(|((status, len), count)| {
                format!(
                    "__cluster__,status={} content_len={},count={}",
                    status,
                    len.map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    count
                )
            }));
            lines
        }
    }
}

async fn start_json_array_output(
    output: &mut (Option<File>, bool),
    fmt: &OutputFormat,
) -> Result<Option<bool>, RustpenError> {
    if !matches!(fmt, OutputFormat::Json) {
        return Ok(None);
    }
    if let Some(file) = output.0.as_mut() {
        file.write_all(b"[\n").await.map_err(RustpenError::Io)?;
    } else if output.1 {
        println!("[");
    }
    Ok(Some(true))
}

async fn emit_stream_line(
    output: &mut (Option<File>, bool),
    fmt: &OutputFormat,
    json_first: &mut Option<bool>,
    line: &str,
) -> Result<(), RustpenError> {
    if matches!(fmt, OutputFormat::Json) {
        let first = json_first
            .as_mut()
            .ok_or_else(|| RustpenError::Generic("json stream state missing".to_string()))?;
        let chunk = if *first {
            *first = false;
            line.to_string()
        } else {
            format!(",\n{line}")
        };
        if let Some(file) = output.0.as_mut() {
            file.write_all(chunk.as_bytes())
                .await
                .map_err(RustpenError::Io)?;
        } else if output.1 {
            print!("{chunk}");
        }
        return Ok(());
    }

    if let Some(file) = output.0.as_mut() {
        file.write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(RustpenError::Io)?;
    } else if output.1 {
        println!("{line}");
    }
    Ok(())
}

async fn finish_json_array_output(
    output: &mut (Option<File>, bool),
    fmt: &OutputFormat,
    json_first: &Option<bool>,
) -> Result<(), RustpenError> {
    if !matches!(fmt, OutputFormat::Json) {
        return Ok(());
    }
    let suffix = if json_first.is_some_and(|first| first) {
        "]\n"
    } else {
        "\n]\n"
    };
    if let Some(file) = output.0.as_mut() {
        file.write_all(suffix.as_bytes())
            .await
            .map_err(RustpenError::Io)?;
    } else if output.1 {
        print!("{suffix}");
    }
    Ok(())
}

pub(super) fn stream_progress_pct(processed: usize, total_hint: Option<usize>) -> f32 {
    match total_hint {
        Some(total) if total > 0 => {
            let ratio = (processed.min(total) as f32) / (total as f32);
            (10.0 + ratio * 85.0).min(95.0)
        }
        _ => (10.0 + (processed as f32).ln_1p() * 18.0).min(95.0),
    }
}

pub(super) fn report_progress(
    events: &Option<TaskEventWriter>,
    pct: f32,
    message: impl Into<String>,
) {
    if let Some(w) = events.as_ref() {
        let _ = w.progress(pct, Some(message.into()));
    }
}

pub(super) fn report_log(events: &Option<TaskEventWriter>, message: impl Into<String>) {
    if let Some(w) = events.as_ref() {
        let _ = w.log("info", message.into());
    }
}

async fn prepare_stream_output(
    out_path: Option<PathBuf>,
    fmt: &OutputFormat,
    events: &Option<TaskEventWriter>,
    stage: &str,
) -> Result<(Option<File>, bool), RustpenError> {
    let resolved = if let Some(path) = out_path {
        Some(path)
    } else {
        events.as_ref().map(|writer| {
            writer.dir().join(format!(
                "{}-result.{}",
                stage.replace('.', "-"),
                match fmt {
                    OutputFormat::Json => "json",
                    OutputFormat::Csv => "csv",
                    OutputFormat::Raw => "txt",
                }
            ))
        })
    };

    if let Some(path) = resolved {
        let file = File::create(&path).await.map_err(RustpenError::Io)?;
        if let Some(writer) = events.as_ref() {
            let _ = writer.register_artifact(path.clone());
            let _ = writer.append_stdout(&format!("saved output -> {}\n", path.display()));
        }
        Ok((Some(file), false))
    } else {
        Ok((None, true))
    }
}

pub(super) async fn consume_module_stream(
    mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>,
    out_path: Option<PathBuf>,
    fmt: OutputFormat,
    events: Option<TaskEventWriter>,
    total_hint: Option<usize>,
    stage: &str,
) -> Result<(), RustpenError> {
    report_progress(&events, 12.0, format!("{stage}: start"));

    let mut output = prepare_stream_output(out_path, &fmt, &events, stage).await?;
    let mut json_first = start_json_array_output(&mut output, &fmt).await?;

    let mut processed = 0usize;
    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    let mut first_error = None::<RustpenError>;
    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                ok_count += 1;
                let line = format_scan_for_stdout(&m, &fmt);
                emit_stream_line(&mut output, &fmt, &mut json_first, &line).await?;
            }
            Err(e) => {
                err_count += 1;
                let err_line = format_scan_error_line(&e, &fmt);
                if first_error.is_none() {
                    first_error = Some(e);
                }
                emit_stream_line(&mut output, &fmt, &mut json_first, &err_line).await?;
            }
        }

        let pct = stream_progress_pct(processed, total_hint);
        let msg = match total_hint {
            Some(total) if total > 0 => format!("{stage}: processed {processed}/{total}"),
            _ => format!("{stage}: processed {processed}"),
        };
        report_progress(&events, pct, msg);
    }

    if processed == 0 {
        report_progress(&events, 95.0, format!("{stage}: no result"));
    }
    finish_json_array_output(&mut output, &fmt, &json_first).await?;
    if ok_count == 0 && err_count > 0 {
        return Err(all_errors_stream_failure(
            stage,
            processed,
            err_count,
            first_error.as_ref(),
        ));
    }
    Ok(())
}

pub(super) async fn consume_module_stream_with_summary(
    mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>,
    out_path: Option<PathBuf>,
    fmt: OutputFormat,
    events: Option<TaskEventWriter>,
    total_hint: Option<usize>,
    stage: &str,
    top_n: usize,
) -> Result<(), RustpenError> {
    report_progress(&events, 12.0, format!("{stage}: start"));

    let mut output = prepare_stream_output(out_path, &fmt, &events, stage).await?;
    let mut json_first = start_json_array_output(&mut output, &fmt).await?;

    let mut processed = 0usize;
    let mut ok_count = 0usize;
    let mut clusters: std::collections::BTreeMap<(u16, Option<u64>), usize> =
        std::collections::BTreeMap::new();
    let mut err_count = 0usize;
    let mut first_error = None::<RustpenError>;

    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                ok_count += 1;
                let key = (m.status, m.content_len);
                *clusters.entry(key).or_insert(0) += 1;
                let line = format_scan_for_stdout(&m, &fmt);
                emit_stream_line(&mut output, &fmt, &mut json_first, &line).await?;
            }
            Err(e) => {
                err_count += 1;
                let err_line = format_scan_error_line(&e, &fmt);
                if first_error.is_none() {
                    first_error = Some(e);
                }
                emit_stream_line(&mut output, &fmt, &mut json_first, &err_line).await?;
            }
        }

        let pct = stream_progress_pct(processed, total_hint);
        let msg = match total_hint {
            Some(total) if total > 0 => format!("{stage}: processed {processed}/{total}"),
            _ => format!("{stage}: processed {processed}"),
        };
        report_progress(&events, pct, msg);
    }

    let mut ranked: Vec<_> = clusters.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    let n = top_n.max(1);
    let shown = ranked.len().min(n);
    let summary_lines = summary_lines_by_format(&fmt, &ranked, shown, err_count);

    for ln in &summary_lines {
        emit_stream_line(&mut output, &fmt, &mut json_first, ln).await?;
    }

    if processed == 0 {
        report_progress(&events, 95.0, format!("{stage}: no result"));
    }
    finish_json_array_output(&mut output, &fmt, &json_first).await?;
    if ok_count == 0 && err_count > 0 {
        return Err(all_errors_stream_failure(
            stage,
            processed,
            err_count,
            first_error.as_ref(),
        ));
    }
    Ok(())
}
