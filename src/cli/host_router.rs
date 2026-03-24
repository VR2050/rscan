use super::*;
use crate::cores::host::ScanProgress;
use std::sync::Arc;

fn host_progress_callback(
    events: &Option<TaskEventWriter>,
    stage: &'static str,
) -> Option<crate::cores::host::ScanProgressCallback> {
    events.as_ref().map(|writer| {
        let writer = writer.clone();
        Arc::new(move |progress: ScanProgress| {
            let pct = if progress.total == 0 {
                35.0
            } else {
                (20.0 + (progress.scanned as f32 / progress.total as f32) * 70.0).min(90.0)
            };
            let msg = format!(
                "{stage}: scanned {}/{} open={}",
                progress.scanned, progress.total, progress.open
            );
            let _ = writer.progress(pct, Some(msg));
        }) as crate::cores::host::ScanProgressCallback
    })
}

pub(super) async fn handle_host_command(
    cli: &Cli,
    action: HostActions,
) -> Result<(), RustpenError> {
    match action {
        HostActions::Tcp {
            host,
            ports,
            output,
            out,
            service_detect,
            probes_file,
            profile,
            tcp_timeout_ms,
            tcp_concurrency,
            tcp_retries,
            tcp_max_rate,
            tcp_jitter_ms,
            tcp_scan_order,
            tcp_adaptive_backpressure,
            tcp_auto_tune,
            tcp_mode,
        } => {
            with_task(&cli, "host", vec![host.clone()], |events| async move {
                report_log(&events, format!("tcp scan host={} ports={:?}", host, ports));
                report_progress(&events, 8.0, "host.tcp: start");
                if service_detect {
                    report_progress(&events, 18.0, "host.tcp: parse ports");
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine =
                        load_probe_engine_if_requested(service_detect, probes_file)?;
                    if let Some(engine) = probe_engine.as_ref() {
                        report_log(&events, probe_engine_stats_line(engine));
                    }
                    report_progress(&events, 35.0, "host.tcp: scanning (service-detect)");
                    let rows = run_engine_host_scan(
                        &host,
                        &parsed,
                        ScanType::Connect,
                        probe_engine,
                        profile,
                        None,
                    )
                    .await?;
                    report_progress(&events, 88.0, format!("host.tcp: rows={}", rows.len()));
                    let s = format_engine_scan_results(&rows, &output);
                    let _ = write_task_output(&events, out.as_ref(), "host-tcp-result", &output, &s)
                        .await?;
                } else {
                    report_progress(&events, 18.0, "host.tcp: parse ports");
                    let mut base_cfg = tcp_config_with_overrides(
                        profile,
                        tcp_timeout_ms,
                        tcp_concurrency,
                        tcp_retries,
                        tcp_max_rate,
                        tcp_jitter_ms,
                        tcp_scan_order,
                        tcp_adaptive_backpressure,
                    );
                    let parsed = parse_ports_flags(&ports)?;
                    let progress_cb = host_progress_callback(&events, "host.tcp");
                    if tcp_auto_tune && parsed.len() >= 256 {
                        report_progress(&events, 24.0, "host.tcp: auto-tune sampling");
                        let sample_ports = sample_ports_for_autotune(&parsed, 2048);
                        if !sample_ports.is_empty() {
                            let mut candidates = Vec::new();
                            let rate_candidates: &[Option<u32>] = &[Some(8000), Some(9500)];
                            let jitter_candidates: &[Option<u64>] = &[Some(0), Some(2)];
                            for rate in rate_candidates {
                                for jitter in jitter_candidates {
                                    let mut c = base_cfg.clone();
                                    c.max_rate = *rate;
                                    c.jitter_ms = *jitter;
                                    c.scan_order = crate::cores::host::TcpScanOrder::Interleave;
                                    c.adaptive_backpressure = true;
                                    c.concurrency = c.concurrency.clamp(1024, 3072);
                                    candidates.push(c);
                                }
                            }
                            let mut best_cfg = base_cfg.clone();
                            let mut best_score = f64::MIN;
                            for (idx, cand) in candidates.into_iter().enumerate() {
                                let test_cfg = match tcp_mode {
                                    TcpMode::Turbo => turbo_phase1_config(cand.clone()),
                                    TcpMode::TurboAdaptive => turbo_phase1_config(cand.clone()),
                                    _ => cand.clone(),
                                };
                                let scanner = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(test_cfg),
                                );
                                let started = std::time::Instant::now();
                                let res = scanner.scan_tcp(&host, &sample_ports).await?;
                                let elapsed_ms = started.elapsed().as_millis().max(1) as f64;
                                let throughput = (sample_ports.len() as f64) / (elapsed_ms / 1000.0);
                                let filtered_ratio = (res.filtered_ports_count() as f64)
                                    / (res.total_scanned.max(1) as f64);
                                let score = throughput
                                    + (res.open_ports_count() as f64 * 120.0)
                                    - (filtered_ratio * 450.0);
                                report_log(
                                    &events,
                                    format!(
                                        "auto-tune[{idx}] rate={:?} jitter={:?} open={} filtered_ratio={:.3} throughput={:.1} score={:.1}",
                                        cand.max_rate,
                                        cand.jitter_ms,
                                        res.open_ports_count(),
                                        filtered_ratio,
                                        throughput,
                                        score
                                    ),
                                );
                                if score > best_score {
                                    best_score = score;
                                    best_cfg = cand;
                                }
                            }
                            base_cfg = best_cfg;
                            report_log(
                                &events,
                                format!(
                                    "auto-tune selected rate={:?} jitter={:?} concurrency={} scan_order=interleave adaptive_backpressure=true",
                                    base_cfg.max_rate,
                                    base_cfg.jitter_ms,
                                    base_cfg.concurrency
                                ),
                            );
                        }
                    }
                    let scan_started = std::time::Instant::now();
                    let mut res = match tcp_mode {
                        TcpMode::Standard => {
                            let scanner = HostScanner::with_manager(
                                crate::cores::host::ScanManager::new(base_cfg.clone()),
                            );
                            report_progress(&events, 35.0, "host.tcp: scanning (standard)");
                            scanner
                                .scan_tcp_with_progress(&host, &parsed, progress_cb.clone())
                                .await?
                        }
                        TcpMode::Turbo => {
                            let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                            let scanner = HostScanner::with_manager(
                                crate::cores::host::ScanManager::new(phase1_cfg),
                            );
                            report_progress(&events, 35.0, "host.tcp: scanning (turbo-pass1)");
                            scanner
                                .scan_tcp_with_progress(&host, &parsed, progress_cb.clone())
                                .await?
                        }
                        TcpMode::TurboVerify => {
                            let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                            let scanner1 = HostScanner::with_manager(
                                crate::cores::host::ScanManager::new(phase1_cfg),
                            );
                            report_progress(&events, 32.0, "host.tcp: scanning (turbo-pass1)");
                            let mut first = scanner1.scan_tcp(&host, &parsed).await?;
                            let filtered = first.filtered_ports();
                            if !filtered.is_empty() {
                                report_progress(
                                    &events,
                                    62.0,
                                    format!(
                                        "host.tcp: verify filtered ports={}",
                                        filtered.len()
                                    ),
                                );
                                let phase2_cfg = turbo_phase2_verify_config(base_cfg.clone());
                                let scanner2 = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(phase2_cfg),
                                );
                                let second = scanner2.scan_tcp(&host, &filtered).await?;
                                merge_verified_tcp_subset(&mut first, &second, &filtered);
                            }
                            first
                        }
                        TcpMode::TurboAdaptive => {
                            let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                            let scanner1 = HostScanner::with_manager(
                                crate::cores::host::ScanManager::new(phase1_cfg),
                            );
                            report_progress(
                                &events,
                                32.0,
                                "host.tcp: scanning (turbo-adaptive-pass1)",
                            );
                            let mut first = scanner1.scan_tcp(&host, &parsed).await?;
                            let filtered = first.filtered_ports();
                            if !filtered.is_empty() {
                                let priority_verify = prioritized_filtered_ports(&filtered);
                                if !priority_verify.is_empty() {
                                    report_progress(
                                        &events,
                                        46.0,
                                        format!(
                                            "host.tcp: adaptive-priority-verify ports={}",
                                            priority_verify.len()
                                        ),
                                    );
                                    let pri_cfg = turbo_phase2_verify_config_adaptive(
                                        base_cfg.clone(),
                                        (filtered.len() as f64) / (parsed.len().max(1) as f64),
                                    );
                                    let pri_scanner = HostScanner::with_manager(
                                        crate::cores::host::ScanManager::new(pri_cfg),
                                    );
                                    let pri_second =
                                        pri_scanner.scan_tcp(&host, &priority_verify).await?;
                                    merge_verified_tcp_subset(
                                        &mut first,
                                        &pri_second,
                                        &priority_verify,
                                    );
                                }
                                let filtered_ratio =
                                    (filtered.len() as f64) / (parsed.len().max(1) as f64);
                                let sample_cap = if filtered_ratio >= 0.7 {
                                    4096
                                } else if filtered_ratio >= 0.45 {
                                    2048
                                } else {
                                    1024
                                };
                                let sample_len = filtered.len().min(sample_cap);
                                let step = (filtered.len() / sample_len.max(1)).max(1);
                                let sample_ports: Vec<u16> = filtered
                                    .iter()
                                    .step_by(step)
                                    .take(sample_len)
                                    .copied()
                                    .collect();
                                report_progress(
                                    &events,
                                    58.0,
                                    format!(
                                        "host.tcp: adaptive-sample filtered={} sample={}",
                                        filtered.len(),
                                        sample_ports.len()
                                    ),
                                );
                                let phase2_cfg = turbo_phase2_verify_config_adaptive(
                                    base_cfg.clone(),
                                    filtered_ratio,
                                );
                                let scanner2 = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(phase2_cfg.clone()),
                                );
                                let sample_second = scanner2.scan_tcp(&host, &sample_ports).await?;
                                let sample_open = sample_ports
                                    .iter()
                                    .filter(|&&p| sample_second.is_port_open(p))
                                    .count();
                                let sample_open_rate =
                                    (sample_open as f64) / (sample_ports.len().max(1) as f64);
                                merge_verified_tcp_subset(
                                    &mut first,
                                    &sample_second,
                                    &sample_ports,
                                );
                                let verify_all = filtered.len() <= 4096 || sample_open_rate >= 0.01;
                                let verify_limit = 6000usize;
                                let should_verify_more = verify_all
                                    || (sample_open_rate >= 0.004
                                        && filtered.len() > sample_ports.len());
                                if should_verify_more {
                                    let sampled_set: BTreeSet<u16> =
                                        sample_ports.iter().copied().collect();
                                    let remaining: Vec<u16> = filtered
                                        .iter()
                                        .filter(|p| !sampled_set.contains(p))
                                        .copied()
                                        .collect();
                                    if !remaining.is_empty() {
                                        let to_verify: Vec<u16> = if verify_all {
                                            remaining
                                        } else {
                                            remaining.into_iter().take(verify_limit).collect()
                                        };
                                        report_progress(
                                            &events,
                                            70.0,
                                            format!(
                                                "host.tcp: adaptive-verify more={} open_rate={:.4}",
                                                to_verify.len(),
                                                sample_open_rate
                                            ),
                                        );
                                        let chunk_size = 1200usize;
                                        let mut since_last_open = 0usize;
                                        let mut offset = 0usize;
                                        while offset < to_verify.len() {
                                            let end = (offset + chunk_size).min(to_verify.len());
                                            let chunk = &to_verify[offset..end];
                                            let scanner3 = HostScanner::with_manager(
                                                crate::cores::host::ScanManager::new(
                                                    phase2_cfg.clone(),
                                                ),
                                            );
                                            let more_second = scanner3.scan_tcp(&host, chunk).await?;
                                            let new_open = chunk
                                                .iter()
                                                .filter(|&&p| more_second.is_port_open(p))
                                                .count();
                                            merge_verified_tcp_subset(&mut first, &more_second, chunk);
                                            if new_open == 0 {
                                                since_last_open += chunk.len();
                                            } else {
                                                since_last_open = 0;
                                            }
                                            if since_last_open >= 2400 && sample_open_rate < 0.01 {
                                                report_log(
                                                    &events,
                                                    format!(
                                                        "host.tcp: adaptive-verify early-stop at {}/{} (no new open in recent chunks)",
                                                        end,
                                                        to_verify.len()
                                                    ),
                                                );
                                                break;
                                            }
                                            offset = end;
                                        }
                                    }
                                }
                            }
                            first
                        }
                    };
                    res.scan_duration = scan_started.elapsed();
                    report_progress(
                        &events,
                        88.0,
                        format!(
                            "host.tcp: open_ports={} filtered={}",
                            res.open_ports_count(),
                            res.filtered_ports_count()
                        ),
                    );
                    let s = format_host_scan_result(&res, &output);
                    let _ = write_task_output(&events, out.as_ref(), "host-tcp-result", &output, &s)
                        .await?;
                }
                report_progress(&events, 98.0, "host.tcp: output done");
                Ok(())
            })
            .await?;
        }
        HostActions::Udp {
            host,
            ports,
            output,
            out,
            service_detect,
            probes_file,
            profile,
        } => {
            with_task(&cli, "host", vec![host.clone()], |events| async move {
                report_log(&events, format!("udp scan host={} ports={:?}", host, ports));
                report_progress(&events, 8.0, "host.udp: start");
                if service_detect {
                    report_progress(&events, 18.0, "host.udp: parse ports");
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine = load_probe_engine_if_requested(service_detect, probes_file)?;
                    if let Some(engine) = probe_engine.as_ref() {
                        report_log(&events, probe_engine_stats_line(engine));
                    }
                    report_progress(&events, 35.0, "host.udp: scanning (service-detect)");
                    let rows = run_engine_host_scan(
                        &host,
                        &parsed,
                        ScanType::UdpProbe,
                        probe_engine,
                        profile,
                        None,
                    )
                    .await?;
                    report_progress(&events, 88.0, format!("host.udp: rows={}", rows.len()));
                    let s = format_engine_scan_results(&rows, &output);
                    let _ =
                        write_task_output(&events, out.as_ref(), "host-udp-result", &output, &s)
                            .await?;
                } else {
                    report_progress(&events, 18.0, "host.udp: parse ports");
                    use crate::cores::host::ScanManager;
                    let manager = ScanManager::new_with_udp(
                        tcp_config_for_profile(profile),
                        Some(udp_config_for_profile(profile)),
                    );
                    let scanner = HostScanner::with_manager(manager);
                    let parsed = parse_ports_flags(&ports)?;
                    report_progress(&events, 35.0, "host.udp: scanning");
                    let res = scanner.scan_udp(&host, &parsed).await?;
                    report_progress(
                        &events,
                        88.0,
                        format!("host.udp: open_ports={}", res.open_ports_count()),
                    );
                    let s = format_host_scan_result(&res, &output);
                    let _ =
                        write_task_output(&events, out.as_ref(), "host-udp-result", &output, &s)
                            .await?;
                }
                report_progress(&events, 98.0, "host.udp: output done");
                Ok(())
            })
            .await?;
        }
        HostActions::Syn {
            host,
            ports,
            output,
            out,
            service_detect,
            probes_file,
            profile,
            syn_mode,
        } => {
            require_root_for_raw_scan("SYN scan")?;
            with_task(&cli, "host", vec![host.clone()], |events| async move {
                report_log(&events, format!("syn scan host={} ports={:?}", host, ports));
                report_progress(&events, 8.0, "host.syn: start");
                if service_detect {
                    report_progress(&events, 18.0, "host.syn: parse ports");
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine = load_probe_engine_if_requested(service_detect, probes_file)?;
                    if let Some(engine) = probe_engine.as_ref() {
                        report_log(&events, probe_engine_stats_line(engine));
                    }
                    report_progress(&events, 35.0, "host.syn: scanning (service-detect)");
                    let rows = run_engine_host_scan(
                        &host,
                        &parsed,
                        ScanType::Syn,
                        probe_engine,
                        profile,
                        Some(syn_mode),
                    )
                    .await?;
                    report_progress(&events, 88.0, format!("host.syn: rows={}", rows.len()));
                    let s = format_engine_scan_results(&rows, &output);
                    let _ =
                        write_task_output(&events, out.as_ref(), "host-syn-result", &output, &s)
                            .await?;
                } else {
                    report_progress(&events, 18.0, "host.syn: parse ports");
                    let parsed = parse_ports_flags(&ports)?;
                    report_progress(&events, 35.0, "host.syn: scanning (raw-engine)");
                    let rows = run_engine_host_scan(
                        &host,
                        &parsed,
                        ScanType::Syn,
                        None,
                        profile,
                        Some(syn_mode),
                    )
                    .await?;
                    let ip = resolve_target_ip(&host)?;
                    let res = engine_rows_to_host_result(
                        &host,
                        ip,
                        crate::cores::host::Protocol::Tcp,
                        &rows,
                    );
                    report_progress(
                        &events,
                        88.0,
                        format!("host.syn: open_ports={}", res.open_ports_count()),
                    );
                    let s = format_host_scan_result(&res, &output);
                    let _ =
                        write_task_output(&events, out.as_ref(), "host-syn-result", &output, &s)
                            .await?;
                }
                report_progress(&events, 98.0, "host.syn: output done");
                Ok(())
            })
            .await?;
        }
        HostActions::Quick {
            host,
            output,
            out,
            profile,
        } => {
            with_task(&cli, "host", vec![host.clone()], |events| async move {
                report_log(&events, format!("quick scan host={}", host));
                report_progress(&events, 10.0, "host.quick: start");
                let scanner = HostScanner::with_manager(crate::cores::host::ScanManager::new(
                    tcp_config_for_profile(profile),
                ));
                let progress_cb = host_progress_callback(&events, "host.quick");
                report_progress(&events, 35.0, "host.quick: scanning");
                let res = scanner.quick_tcp_with_progress(&host, progress_cb).await?;
                report_progress(
                    &events,
                    88.0,
                    format!("host.quick: open_ports={}", res.open_ports_count()),
                );
                let s = format_host_scan_result(&res, &output);
                let _ = write_task_output(&events, out.as_ref(), "host-quick-result", &output, &s)
                    .await?;
                report_progress(&events, 98.0, "host.quick: output done");
                Ok(())
            })
            .await?;
        }
        HostActions::Arp { cidr, output, out } => {
            require_root_for_raw_scan("ARP scan")?;
            with_task(&cli, "host", vec![cidr.clone()], |events| async move {
                report_log(&events, format!("arp scan cidr={}", cidr));
                report_progress(&events, 10.0, "host.arp: start");
                let scanner = HostScanner::default();
                report_progress(&events, 35.0, "host.arp: scanning");
                let res = scanner.arp_scan_cidr(&cidr).await?;
                report_progress(&events, 88.0, format!("host.arp: alive={}", res.len()));
                if output.to_lowercase() == "json" {
                    let json_vec: Vec<_> = res.iter().map(|h| serde_json::json!({"ip": h.ip, "mac": h.mac.to_string(), "interface": h.interface})).collect();
                    let s = serde_json::to_string(&json_vec)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?;
                    if let Some(path) = &out {
                        let mut file = File::create(path).await.map_err(RustpenError::Io)?;
                        file.write_all(format!("{}\n", s).as_bytes())
                            .await
                            .map_err(RustpenError::Io)?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    if let Some(path) = &out {
                        let mut file = File::create(path).await.map_err(RustpenError::Io)?;
                        for h in res {
                            let line = format!("{} {} {}\n", h.ip, h.mac, h.interface);
                            file.write_all(line.as_bytes())
                                .await
                                .map_err(RustpenError::Io)?;
                        }
                    } else {
                        for h in res {
                            let line = format!("{} {} {}\n", h.ip, h.mac, h.interface);
                            print!("{}", line);
                        }
                    }
                }
                report_progress(&events, 98.0, "host.arp: output done");
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}
