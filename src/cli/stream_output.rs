use super::*;

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

    let mut processed = 0usize;
    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                if let Some(file) = output.0.as_mut() {
                    let line = format!("{}\n", format_scan_result(&m, &fmt));
                    file.write_all(line.as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else if output.1 {
                    println!("{}", format_scan_for_stdout(&m, &fmt));
                }
            }
            Err(e) => {
                let err_line = format_scan_error_line(&e, &fmt);
                if let Some(file) = output.0.as_mut() {
                    file.write_all(format!("{err_line}\n").as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else if output.1 {
                    println!("{err_line}");
                }
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

    let mut processed = 0usize;
    let mut clusters: std::collections::BTreeMap<(u16, Option<u64>), usize> =
        std::collections::BTreeMap::new();
    let mut err_count = 0usize;

    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                let key = (m.status, m.content_len);
                *clusters.entry(key).or_insert(0) += 1;
                if let Some(file) = output.0.as_mut() {
                    let line = format!("{}\n", format_scan_result(&m, &fmt));
                    file.write_all(line.as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else if output.1 {
                    println!("{}", format_scan_for_stdout(&m, &fmt));
                }
            }
            Err(e) => {
                err_count += 1;
                let err_line = format_scan_error_line(&e, &fmt);
                if let Some(file) = output.0.as_mut() {
                    file.write_all(format!("{err_line}\n").as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else if output.1 {
                    println!("{err_line}");
                }
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
    let summary_lines = ranked
        .iter()
        .take(n)
        .map(|((status, len), count)| {
            format!(
                "cluster status={} content_len={} count={}",
                status,
                len.map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                count
            )
        })
        .collect::<Vec<_>>();
    let summary_header = format!(
        "summary clusters={} shown={} errors={}",
        ranked.len(),
        summary_lines.len(),
        err_count
    );

    if let Some(file) = output.0.as_mut() {
        file.write_all(format!("{summary_header}\n").as_bytes())
            .await
            .map_err(RustpenError::Io)?;
        for ln in &summary_lines {
            file.write_all(format!("{ln}\n").as_bytes())
                .await
                .map_err(RustpenError::Io)?;
        }
    } else if output.1 {
        println!("{summary_header}");
        for ln in &summary_lines {
            println!("{ln}");
        }
    }

    if processed == 0 {
        report_progress(&events, 95.0, format!("{stage}: no result"));
    }
    Ok(())
}
