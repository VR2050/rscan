use super::*;

pub(super) async fn handle_analyze(
    cli: &Cli,
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    rules_file: Option<PathBuf>,
    dynamic: bool,
    dynamic_timeout_ms: Option<u64>,
    dynamic_syscalls: Option<String>,
    dynamic_blocklist: Option<String>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    if dynamic
        || dynamic_timeout_ms.is_some()
        || dynamic_syscalls.is_some()
        || dynamic_blocklist.is_some()
    {
        unsafe {
            std::env::set_var("RSCAN_REVERSE_DYNAMIC", "1");
        }
    }
    if let Some(v) = dynamic_timeout_ms {
        unsafe {
            std::env::set_var("RSCAN_REVERSE_DYNAMIC_TIMEOUT_MS", v.to_string());
        }
    }
    if let Some(v) = dynamic_syscalls {
        unsafe {
            std::env::set_var("RSCAN_REVERSE_DYNAMIC_SYSCALLS", v);
        }
    }
    if let Some(v) = dynamic_blocklist {
        unsafe {
            std::env::set_var("RSCAN_REVERSE_DYNAMIC_BLOCKLIST", v);
        }
    }

    with_task(
        cli,
        "reverse",
        vec![input.display().to_string()],
        |events| async move {
            report_progress(&events, 8.0, "reverse.analyze: preparing input");
            if let Some(ref w) = events {
                let _ = w.log("info", format!("reverse analyze {}", input.display()));
            }
            report_progress(&events, 18.0, "reverse.analyze: reading target");
            let bytes = std::fs::read(&input)?;
            let is_apk = bytes.len() >= 4
                && &bytes[0..4] == b"PK\x03\x04"
                && (bytes
                    .windows("AndroidManifest.xml".len())
                    .any(|w| w == b"AndroidManifest.xml")
                    || bytes
                        .windows("classes.dex".len())
                        .any(|w| w == b"classes.dex"));

            report_progress(&events, 35.0, "reverse.analyze: loading rules");
            let mut hot_rules = match rules_file {
                Some(path) => Some(RuleHotReloader::new(path)?),
                None => None,
            };
            let default_rules = RuleLibrary::default();
            let rules_ref = match hot_rules.as_mut() {
                Some(loader) => loader.rules()?,
                None => &default_rules,
            };

            report_progress(
                &events,
                52.0,
                if is_apk {
                    "reverse.analyze: analyzing apk"
                } else {
                    "reverse.analyze: analyzing binary"
                },
            );
            let s = if is_apk {
                let report = ReverseAnalyzer::analyze_apk_with_rules(&input, rules_ref)?;
                to_json_or_raw(&report, &output)?
            } else {
                let report = ReverseAnalyzer::analyze_binary_with_rules(&input, rules_ref)?;
                to_json_or_raw(&report, &output)?
            };

            report_progress(&events, 90.0, "reverse.analyze: rendering output");
            let _ = write_task_output(&events, out.as_ref(), "reverse-analyze-result", &output, &s)
                .await?;
            report_progress(&events, 98.0, "reverse.analyze: output done");
            Ok(())
        },
    )
    .await?;

    Ok(())
}

pub(super) async fn handle_decompile_plan(
    cli: &Cli,
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    engine: String,
    output_dir: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    let engine = DecompilerEngine::parse(&engine).ok_or_else(|| {
        RustpenError::ParseError("invalid --engine. use: objdump|radare2|ghidra|jadx".to_string())
    })?;
    with_task(
        cli,
        "reverse",
        vec![input.display().to_string()],
        |events| async move {
            report_progress(&events, 10.0, "reverse.decompile-plan: preparing");
            if let Some(ref w) = events {
                let _ = w.log(
                    "info",
                    format!("decompile-plan engine={engine:?} file={}", input.display()),
                );
            }
            let orchestrator = ReverseOrchestrator::detect();
            report_progress(&events, 50.0, "reverse.decompile-plan: building plan");
            let plan = orchestrator.build_decompile_plan(engine, &input, output_dir.as_deref())?;
            report_progress(&events, 90.0, "reverse.decompile-plan: rendering output");
            let s = to_json_or_raw(&plan, &output)?;
            let _ = write_task_output(
                &events,
                out.as_ref(),
                "reverse-decompile-plan-result",
                &output,
                &s,
            )
            .await?;
            report_progress(&events, 98.0, "reverse.decompile-plan: output done");
            Ok(())
        },
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_decompile_run(
    cli: &Cli,
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    engine: String,
    mode: String,
    function: Option<String>,
    deep: bool,
    rust_first: bool,
    no_rust_first: bool,
    workspace: Option<PathBuf>,
    timeout_secs: Option<u64>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let mode = parse_decompile_mode(&mode)?;
    let func = function.as_deref();
    if mode == DecompileMode::Function && func.is_none() {
        return Err(RustpenError::MissingArgument {
            arg: "--function".to_string(),
        });
    }
    let rust_first_enabled = rust_first && !no_rust_first;
    unsafe {
        std::env::set_var(
            "RSCAN_REVERSE_RUST_FIRST",
            if rust_first_enabled { "1" } else { "0" },
        );
        std::env::set_var("RSCAN_REVERSE_DEEP", if deep { "1" } else { "0" });
    }
    with_task(
        cli,
        "reverse",
        vec![input.display().to_string()],
        |events| async move {
            report_progress(&events, 10.0, "reverse.decompile-run: preparing job");
            if let Some(ref w) = events {
                let _ = w.log(
                    "info",
                    format!(
                        "decompile-run engine={} mode={:?} file={}",
                        engine,
                        mode,
                        input.display()
                    ),
                );
            }
            report_progress(&events, 35.0, "reverse.decompile-run: executing");
            let report = run_decompile_job(&input, &workspace, &engine, mode, func, timeout_secs)?;
            report_progress(&events, 90.0, "reverse.decompile-run: rendering output");
            let s = to_json_or_raw(&report, &output)?;
            let _ = write_task_output(
                &events,
                out.as_ref(),
                "reverse-decompile-run-result",
                &output,
                &s,
            )
            .await?;
            report_progress(&events, 98.0, "reverse.decompile-run: output done");
            Ok(())
        },
    )
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_decompile_batch(
    cli: &Cli,
    inputs: Vec<PathBuf>,
    inputs_pos: Vec<PathBuf>,
    engine: String,
    mode: String,
    function: Option<String>,
    deep: bool,
    rust_first: bool,
    no_rust_first: bool,
    workspace: Option<PathBuf>,
    timeout_secs: Option<u64>,
    parallel_jobs: usize,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let mut inputs = inputs;
    inputs.extend(inputs_pos);
    if inputs.is_empty() {
        return Err(RustpenError::MissingArgument {
            arg: "--inputs <paths> or <INPUTS...>".to_string(),
        });
    }
    let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
    let mode = parse_decompile_mode(&mode)?;
    let func = function.as_deref();
    if mode == DecompileMode::Function && func.is_none() {
        return Err(RustpenError::MissingArgument {
            arg: "--function".to_string(),
        });
    }
    let rust_first_enabled = rust_first && !no_rust_first;
    unsafe {
        std::env::set_var(
            "RSCAN_REVERSE_RUST_FIRST",
            if rust_first_enabled { "1" } else { "0" },
        );
        std::env::set_var("RSCAN_REVERSE_DEEP", if deep { "1" } else { "0" });
    }
    with_task(
        cli,
        "reverse",
        vec![format!("batch:{} files", inputs.len())],
        |events| async move {
            report_progress(&events, 10.0, "reverse.decompile-batch: preparing jobs");
            if let Some(ref w) = events {
                let _ = w.log(
                    "info",
                    format!(
                        "decompile-batch engine={} mode={:?} inputs={}",
                        engine,
                        mode,
                        inputs.len()
                    ),
                );
            }
            report_progress(
                &events,
                35.0,
                format!("reverse.decompile-batch: executing {} jobs", inputs.len()),
            );
            let report = run_decompile_batch(
                &inputs,
                &workspace,
                &engine,
                mode,
                func,
                timeout_secs,
                parallel_jobs,
            )?;
            report_progress(&events, 90.0, "reverse.decompile-batch: rendering output");
            let s = to_json_or_raw(&report, &output)?;
            let _ = write_task_output(
                &events,
                out.as_ref(),
                "reverse-decompile-batch-result",
                &output,
                &s,
            )
            .await?;
            report_progress(&events, 98.0, "reverse.decompile-batch: output done");
            Ok(())
        },
    )
    .await?;

    Ok(())
}
