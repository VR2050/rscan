use super::*;
use serde::{Deserialize, Serialize};

pub(super) async fn handle_vuln_command(
    cli: &Cli,
    action: VulnActions,
) -> Result<(), RustpenError> {
    match action {
        VulnActions::Lint {
            templates,
            output,
            out,
        } => {
            let (_templates, report) = load_safe_templates_from_path(&templates)?;
            let s = to_json_or_raw(&report, &output)?;
            if let Some(path) = out {
                let file = File::create(path).await.map_err(RustpenError::Io)?;
                write_host_output_to_file(file, &s).await?;
            } else {
                println!("{s}");
            }
        }
        VulnActions::Scan {
            targets,
            templates,
            severities,
            tags,
            concurrency,
            timeout_ms,
            output,
            findings_only,
            success_only,
            out,
        } => {
            with_task(&cli, "vuln", targets.clone(), |events| async move {
                report_log(
                    &events,
                    format!(
                        "vuln scan targets={} templates={} severity_filters={} tag_filters={}",
                        targets.len(),
                        templates.display(),
                        severities.len(),
                        tags.len(),
                    ),
                );
                report_progress(&events, 10.0, "vuln.scan: loading templates");
                let (templates, lint) = load_safe_templates_from_path(&templates)?;
                let templates = filter_vuln_templates(templates, &severities, &tags);
                if templates.is_empty() {
                    return Err(RustpenError::ParseError(format!(
                        "no usable templates loaded after filters (severity={:?}, tags={:?}): {:?}",
                        severities, tags, lint.errors
                    )));
                }
                let cfg = VulnScanConfig {
                    concurrency,
                    timeout_ms,
                };
                report_progress(
                    &events,
                    35.0,
                    format!(
                        "vuln.scan: scanning targets={} templates={}",
                        targets.len(),
                        templates.len()
                    ),
                );
                let report = vuln_scan_targets(&targets, &templates, cfg).await?;
                report_progress(
                    &events,
                    90.0,
                    format!(
                        "vuln.scan: findings={} errors={}",
                        report.findings.len(),
                        report.errors.len()
                    ),
                );
                let only_findings = findings_only || success_only;
                let s = if only_findings {
                    format_vuln_findings_only(&report, &output, color_enabled())
                } else if output.eq_ignore_ascii_case("json") {
                    to_json_or_raw(&report, &output)?
                } else {
                    format_vuln_report_pretty(&report, color_enabled())
                };
                let _ = write_task_output(&events, out.as_ref(), "vuln-scan-result", &output, &s)
                    .await?;
                report_progress(&events, 98.0, "vuln.scan: output done");
                Ok(())
            })
            .await?;
        }
        VulnActions::ContainerAudit {
            manifests,
            output,
            out,
        } => {
            with_task(
                &cli,
                "vuln-container-audit",
                vec![manifests.display().to_string()],
                |events| async move {
                    report_progress(&events, 10.0, "vuln.container-audit: loading manifests");
                    let report = audit_container_manifests_from_path(&manifests)?;
                    report_progress(
                        &events,
                        85.0,
                        format!(
                            "vuln.container-audit: findings={} errors={}",
                            report.findings.len(),
                            report.errors.len()
                        ),
                    );
                    let s = if output.eq_ignore_ascii_case("json") {
                        to_json_or_raw(&report, &output)?
                    } else {
                        format_container_audit_pretty(&report, color_enabled())
                    };
                    let _ = write_task_output(
                        &events,
                        out.as_ref(),
                        "vuln-container-audit-result",
                        &output,
                        &s,
                    )
                    .await?;
                    report_progress(&events, 98.0, "vuln.container-audit: output done");
                    Ok(())
                },
            )
            .await?;
        }
        VulnActions::SystemGuard { output, out } => {
            with_task(
                &cli,
                "vuln-system-guard",
                vec!["local-system".to_string()],
                |events| async move {
                    report_progress(&events, 10.0, "vuln.system-guard: collecting controls");
                    let report = audit_local_system_guard()?;
                    report_progress(
                        &events,
                        85.0,
                        format!(
                            "vuln.system-guard: controls={}/{} score={}",
                            report.controls_present, report.controls_total, report.score
                        ),
                    );
                    let s = if output.eq_ignore_ascii_case("json") {
                        to_json_or_raw(&report, &output)?
                    } else {
                        format_system_guard_pretty(&report, color_enabled())
                    };
                    let _ = write_task_output(
                        &events,
                        out.as_ref(),
                        "vuln-system-guard-result",
                        &output,
                        &s,
                    )
                    .await?;
                    report_progress(&events, 98.0, "vuln.system-guard: output done");
                    Ok(())
                },
            )
            .await?;
        }
        VulnActions::StealthCheck {
            target,
            low_noise_requests,
            low_noise_interval_ms,
            burst_requests,
            burst_concurrency,
            timeout_ms,
            advanced_checks,
            no_advanced_checks,
            variant_requests,
            variant_concurrency,
            output,
            out,
        } => {
            with_task(
                &cli,
                "vuln-stealth-check",
                vec![target.clone()],
                |events| async move {
                    report_progress(&events, 10.0, "vuln.stealth-check: probe planning");
                    let cfg = AntiScanConfig {
                        low_noise_requests,
                        low_noise_interval_ms,
                        burst_requests,
                        burst_concurrency,
                        timeout_ms,
                        advanced_checks: if no_advanced_checks {
                            false
                        } else {
                            advanced_checks
                        },
                        variant_requests,
                        variant_concurrency,
                    };
                    report_progress(
                        &events,
                        35.0,
                        format!(
                            "vuln.stealth-check: target={} low={} burst={}",
                            target, cfg.low_noise_requests, cfg.burst_requests
                        ),
                    );
                    let report = audit_http_anti_scan(&target, cfg).await?;
                    report_progress(
                        &events,
                        90.0,
                        format!(
                            "vuln.stealth-check: findings={} errors={}",
                            report.findings.len(),
                            report.errors.len()
                        ),
                    );
                    let s = if output.eq_ignore_ascii_case("json") {
                        to_json_or_raw(&report, &output)?
                    } else {
                        format_stealth_check_pretty(&report, color_enabled())
                    };
                    let _ = write_task_output(
                        &events,
                        out.as_ref(),
                        "vuln-stealth-check-result",
                        &output,
                        &s,
                    )
                    .await?;
                    report_progress(&events, 98.0, "vuln.stealth-check: output done");
                    Ok(())
                },
            )
            .await?;
        }
        VulnActions::FragmentAudit {
            target,
            requests_per_tier,
            concurrency,
            timeout_ms,
            payload_min_bytes,
            payload_max_bytes,
            payload_step_bytes,
            output,
            out,
        } => {
            with_task(
                &cli,
                "vuln-fragment-audit",
                vec![target.clone()],
                |events| async move {
                    report_progress(&events, 10.0, "vuln.fragment-audit: probe planning");
                    let cfg = FragmentAuditConfig {
                        requests_per_tier,
                        concurrency,
                        timeout_ms,
                        payload_min_bytes,
                        payload_max_bytes,
                        payload_step_bytes,
                    };
                    report_progress(
                        &events,
                        35.0,
                        format!(
                            "vuln.fragment-audit: target={} tiers={}..{} step={}",
                            target,
                            cfg.payload_min_bytes,
                            cfg.payload_max_bytes,
                            cfg.payload_step_bytes
                        ),
                    );
                    let report = audit_http_fragment_resilience(&target, cfg).await?;
                    report_progress(
                        &events,
                        90.0,
                        format!(
                            "vuln.fragment-audit: findings={} errors={}",
                            report.findings.len(),
                            report.errors.len()
                        ),
                    );
                    let s = if output.eq_ignore_ascii_case("json") {
                        to_json_or_raw(&report, &output)?
                    } else {
                        format_fragment_audit_pretty(&report, color_enabled())
                    };
                    let _ = write_task_output(
                        &events,
                        out.as_ref(),
                        "vuln-fragment-audit-result",
                        &output,
                        &s,
                    )
                    .await?;
                    report_progress(&events, 98.0, "vuln.fragment-audit: output done");
                    Ok(())
                },
            )
            .await?;
        }
        VulnActions::Fuzz {
            url,
            keywords,
            keywords_file,
            concurrency,
            timeout_ms,
            status_min,
            status_max,
            output,
            out,
        } => {
            with_task(&cli, "vuln-fuzz", vec![url.clone()], |events| async move {
                let mut words = keywords;
                if let Some(path) = keywords_file.as_ref() {
                    let from_file = load_keywords_file(path)?;
                    words.extend(from_file);
                }
                words = words
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                words.sort();
                words.dedup();
                if words.is_empty() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--keyword/--keywords-file".to_string(),
                    });
                }
                report_progress(
                    &events,
                    15.0,
                    format!("vuln.fuzz: loading keywords count={}", words.len()),
                );
                let cfg = FuzzAttackConfig {
                    concurrency,
                    timeout_ms,
                };
                report_progress(
                    &events,
                    35.0,
                    format!(
                        "vuln.fuzz: scanning url={} concurrency={} timeout_ms={}",
                        url, cfg.concurrency, cfg.timeout_ms
                    ),
                );
                let hits = run_simple_fuzz_attack(&url, &words, cfg).await?;
                let hits = hits
                    .into_iter()
                    .filter(|h| status_min.map(|v| h.status >= v).unwrap_or(true))
                    .filter(|h| status_max.map(|v| h.status <= v).unwrap_or(true))
                    .collect::<Vec<_>>();
                let report = FuzzAttackReport {
                    scanned_payloads: words.len(),
                    hits,
                    errors: Vec::new(),
                };
                report_progress(
                    &events,
                    90.0,
                    format!(
                        "vuln.fuzz: scanned={} hits={}",
                        report.scanned_payloads,
                        report.hits.len()
                    ),
                );
                let s = format_vuln_fuzz_output(&report, &output, color_enabled())?;
                let _ = write_task_output(&events, out.as_ref(), "vuln-fuzz-result", &output, &s)
                    .await?;
                report_progress(&events, 98.0, "vuln.fuzz: output done");
                Ok(())
            })
            .await?;
        }
        VulnActions::Poc {
            target,
            path,
            method,
            headers,
            body,
            timeout_ms,
            statuses,
            words,
            header_words,
            match_all,
            case_insensitive,
            output,
            out,
        } => {
            with_task(
                &cli,
                "vuln-poc",
                vec![target.clone()],
                |events| async move {
                    report_progress(&events, 10.0, "vuln.poc: preparing probe");
                    let _ = parse_http_method(&method)?;
                    let parsed_headers = parse_raw_headers(&headers)?;
                    let expect_status =
                        if statuses.is_empty() && words.is_empty() && header_words.is_empty() {
                            vec![200]
                        } else {
                            statuses
                        };
                    let cfg = PocHttpConfig {
                        method: method.to_ascii_uppercase(),
                        path,
                        headers: parsed_headers,
                        body,
                        timeout_ms,
                        expect_status: expect_status,
                        expect_body_words: words,
                        expect_header_words: header_words,
                        expect_all: match_all,
                        case_insensitive,
                    };
                    report_progress(
                        &events,
                        35.0,
                        format!("vuln.poc: target={} path={}", target, cfg.path),
                    );
                    let report = run_poc_http_probe(&target, cfg).await?;
                    report_progress(
                        &events,
                        90.0,
                        format!(
                            "vuln.poc: vulnerable={} matched={}",
                            report.vulnerable,
                            report.matched.len()
                        ),
                    );
                    let s = format_vuln_poc_output(&report, &output, color_enabled())?;
                    let _ =
                        write_task_output(&events, out.as_ref(), "vuln-poc-result", &output, &s)
                            .await?;
                    report_progress(&events, 98.0, "vuln.poc: output done");
                    Ok(())
                },
            )
            .await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuzzAttackReport {
    scanned_payloads: usize,
    hits: Vec<FuzzAttackHit>,
    errors: Vec<String>,
}

fn format_vuln_fuzz_output(
    report: &FuzzAttackReport,
    output: &str,
    color: bool,
) -> Result<String, RustpenError> {
    if output.eq_ignore_ascii_case("json") {
        return to_json_or_raw(report, output);
    }
    if output.eq_ignore_ascii_case("csv") {
        let mut lines = vec!["status,content_len,payload,url".to_string()];
        for h in &report.hits {
            lines.push(format!(
                "{},{},{},{}",
                h.status,
                h.content_len,
                h.payload.replace(',', " "),
                h.url.replace(',', " ")
            ));
        }
        return Ok(lines.join("\n"));
    }
    Ok(format_vuln_fuzz_pretty(report, color))
}

fn format_vuln_fuzz_pretty(report: &FuzzAttackReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "fuzz=ok scanned={} hits={} errors={}",
        report.scanned_payloads,
        report.hits.len(),
        report.errors.len()
    ));
    if report.hits.is_empty() {
        lines.push(colorize("no hits", "90", color));
        return lines.join("\n");
    }
    lines.push(format!(
        "{:>6} {:>10} {:<20} {}",
        "CODE", "LEN", "PAYLOAD", "URL"
    ));
    for h in &report.hits {
        let status_col = if (200..300).contains(&h.status) {
            "32"
        } else if (300..400).contains(&h.status) {
            "36"
        } else if (400..500).contains(&h.status) {
            "33"
        } else {
            "31"
        };
        lines.push(format!(
            "{} {:>10} {:<20} {}",
            colorize(&format!("{:>6}", h.status), status_col, color),
            h.content_len,
            h.payload,
            h.url
        ));
    }
    lines.join("\n")
}

fn format_vuln_poc_output(
    report: &PocHttpReport,
    output: &str,
    color: bool,
) -> Result<String, RustpenError> {
    if output.eq_ignore_ascii_case("json") {
        return to_json_or_raw(report, output);
    }
    if output.eq_ignore_ascii_case("csv") {
        let matched = report.matched.join("|").replace(',', " ");
        return Ok(format!(
            "vulnerable,status,method,url,response_time_ms,content_len,matched\n{},{},{},{},{},{},{}",
            report.vulnerable,
            report.status.unwrap_or_default(),
            report.method.replace(',', " "),
            report.url.replace(',', " "),
            report.response_time_ms,
            report.content_len,
            matched
        ));
    }
    Ok(format_vuln_poc_pretty(report, color))
}

fn format_vuln_poc_pretty(report: &PocHttpReport, color: bool) -> String {
    let verdict = if report.vulnerable {
        colorize("CONFIRMED", "31", color)
    } else {
        colorize("NOT_CONFIRMED", "90", color)
    };
    let mut lines = vec![
        format!("poc=ok target={} verdict={}", report.target, verdict),
        format!(
            "method={} status={} latency_ms={} content_len={}",
            report.method,
            report
                .status
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            report.response_time_ms,
            report.content_len
        ),
        format!("url={}", report.url),
    ];
    if report.matched.is_empty() {
        lines.push(colorize("matched=none", "90", color));
    } else {
        lines.push(format!("matched={}", report.matched.join(",")));
    }
    if !report.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for err in &report.errors {
            lines.push(format!("ERR {}", err.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

fn parse_raw_headers(values: &[String]) -> Result<Vec<(String, String)>, RustpenError> {
    let mut out = Vec::new();
    for raw in values {
        let Some((name, value)) = raw.split_once(':') else {
            return Err(RustpenError::ParseError(format!(
                "invalid --header '{}', expected 'Name: Value'",
                raw
            )));
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(RustpenError::ParseError(format!(
                "invalid --header '{}', empty header name",
                raw
            )));
        }
        out.push((name.to_string(), value.to_string()));
    }
    Ok(out)
}
