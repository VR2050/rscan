use super::*;

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
    }
    Ok(())
}
