use super::*;

pub(super) async fn handle_web_command(cli: &Cli, action: WebActions) -> Result<(), RustpenError> {
    match action {
        WebActions::Dir {
            base,
            paths,
            stream_to,
            output,
            concurrency,
            timeout_ms,
            max_retries,
            headers,
            body,
            body_mode,
            per_host_concurrency,
            dedupe,
            no_dedupe,
            status_min,
            status_max,
            wildcard_filter,
            wildcard_samples,
            wildcard_len_tolerance,
            fingerprint_filter,
            fingerprint_distance,
            resume_file,
            adaptive_rate,
            adaptive_initial_delay_ms,
            adaptive_max_delay_ms,
            method,
            no_follow_redirect,
            smart_fast,
            smart_fast_strict,
            recursive,
            recursive_depth,
            profile,
        } => {
            with_task(&cli, "web", vec![base.clone()], |events| async move {
                report_log(
                    &events,
                    format!("web dir base={} paths={}", base, paths.len()),
                );
                report_progress(&events, 8.0, "web.dir: config building");
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig {
                    request_method: parse_http_method(&method)?,
                    recursive,
                    recursive_max_depth: recursive_depth.max(1),
                    ..Default::default()
                };
                apply_web_profile(&mut mcfg, profile);
                if let Some(c) = concurrency {
                    mcfg.concurrency = c;
                }
                if let Some(t) = timeout_ms {
                    mcfg.timeout_ms = Some(t);
                }
                if let Some(r) = max_retries {
                    mcfg.max_retries = Some(r);
                }
                let mut header_map = parse_request_headers(&headers)?;
                apply_body_mode_default_content_type(&mut header_map, body_mode, body.is_some());
                mcfg.request_headers = if header_map.is_empty() {
                    None
                } else {
                    Some(header_map)
                };
                mcfg.request_body_template = body.clone();
                mcfg.follow_redirects = !no_follow_redirect;
                if let Some(p) = per_host_concurrency {
                    mcfg.per_host_concurrency_override = Some(p);
                }
                mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;
                mcfg.wildcard_filter = wildcard_filter;
                if let Some(v) = wildcard_samples {
                    mcfg.wildcard_sample_count = v;
                }
                if let Some(v) = wildcard_len_tolerance {
                    mcfg.wildcard_len_tolerance = v;
                }
                mcfg.fingerprint_filter = fingerprint_filter;
                if let Some(v) = fingerprint_distance {
                    mcfg.fingerprint_distance_threshold = v;
                }
                mcfg.resume_file = resume_file;
                mcfg.adaptive_rate = adaptive_rate;
                if let Some(v) = adaptive_initial_delay_ms {
                    mcfg.adaptive_initial_delay_ms = v;
                }
                if let Some(v) = adaptive_max_delay_ms {
                    mcfg.adaptive_max_delay_ms = v;
                }
                if smart_fast {
                    apply_web_smart_fast(&mut mcfg, status_min, status_max);
                }
                if smart_fast_strict {
                    apply_web_smart_fast_strict(&mut mcfg, status_min, status_max);
                }
                let total_hint = if recursive { None } else { Some(paths.len()) };
                let rx = ws.dir_scan_stream(&base, paths, Some(mcfg));
                consume_module_stream(rx, stream_to, fmt, events.clone(), total_hint, "web.dir")
                    .await?;
                report_progress(&events, 98.0, "web.dir: output done");
                Ok(())
            })
            .await?;
        }
        WebActions::Fuzz {
            url,
            keywords,
            keywords_file,
            kw_transforms,
            preset,
            keyword_prefix,
            keyword_suffix,
            keyword_max_len,
            summary,
            summary_top,
            content_len_min,
            content_len_max,
            stream_to,
            output,
            concurrency,
            timeout_ms,
            max_retries,
            headers,
            body,
            body_mode,
            per_host_concurrency,
            dedupe,
            no_dedupe,
            status_min,
            status_max,
            wildcard_filter,
            wildcard_samples,
            wildcard_len_tolerance,
            fingerprint_filter,
            fingerprint_distance,
            resume_file,
            adaptive_rate,
            adaptive_initial_delay_ms,
            adaptive_max_delay_ms,
            method,
            no_follow_redirect,
            smart_fast,
            smart_fast_strict,
            profile,
        } => {
            with_task(&cli, "web", vec![url.clone()], |events| async move {
                let mut base_keywords = keywords.clone();
                if let Some(path) = keywords_file.as_ref() {
                    let mut from_file = load_keywords_file(path)?;
                    base_keywords.append(&mut from_file);
                }
                let base_keywords = expand_keywords_with_preset(base_keywords, preset);
                let eff_transforms = if kw_transforms.is_empty() {
                    if let Some(p) = preset {
                        preset_default_transforms(p)
                    } else {
                        vec![FuzzKeywordTransform::Raw]
                    }
                } else {
                    kw_transforms.clone()
                };
                let expanded_keywords = build_fuzz_keywords(
                    base_keywords,
                    &eff_transforms,
                    keyword_prefix.clone(),
                    keyword_suffix.clone(),
                    keyword_max_len,
                );
                if expanded_keywords.is_empty() {
                    return Err(RustpenError::ParseError(
                        "no fuzz keywords produced after transforms/filters".to_string(),
                    ));
                }
                report_log(
                    &events,
                    format!(
                        "web fuzz url={} base_words={} expanded_words={} transforms={}",
                        url,
                        keywords.len(),
                        expanded_keywords.len(),
                        eff_transforms
                            .iter()
                            .map(|x| format!("{x:?}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                );
                report_progress(&events, 8.0, "web.fuzz: config building");
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig {
                    request_method: parse_http_method(&method)?,
                    ..Default::default()
                };
                apply_web_profile(&mut mcfg, profile);
                if let Some(c) = concurrency {
                    mcfg.concurrency = c;
                }
                if let Some(t) = timeout_ms {
                    mcfg.timeout_ms = Some(t);
                }
                if let Some(r) = max_retries {
                    mcfg.max_retries = Some(r);
                }
                let mut header_map = parse_request_headers(&headers)?;
                apply_body_mode_default_content_type(&mut header_map, body_mode, body.is_some());
                mcfg.request_headers = if header_map.is_empty() {
                    None
                } else {
                    Some(header_map)
                };
                mcfg.request_body_template = body.clone();
                mcfg.follow_redirects = !no_follow_redirect;
                if let Some(p) = per_host_concurrency {
                    mcfg.per_host_concurrency_override = Some(p);
                }
                mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;
                mcfg.content_len_min = content_len_min;
                mcfg.content_len_max = content_len_max;
                mcfg.wildcard_filter = wildcard_filter;
                if let Some(v) = wildcard_samples {
                    mcfg.wildcard_sample_count = v;
                }
                if let Some(v) = wildcard_len_tolerance {
                    mcfg.wildcard_len_tolerance = v;
                }
                mcfg.fingerprint_filter = fingerprint_filter;
                if let Some(v) = fingerprint_distance {
                    mcfg.fingerprint_distance_threshold = v;
                }
                mcfg.resume_file = resume_file;
                mcfg.adaptive_rate = adaptive_rate;
                if let Some(v) = adaptive_initial_delay_ms {
                    mcfg.adaptive_initial_delay_ms = v;
                }
                if let Some(v) = adaptive_max_delay_ms {
                    mcfg.adaptive_max_delay_ms = v;
                }
                if smart_fast {
                    apply_web_smart_fast(&mut mcfg, status_min, status_max);
                }
                if smart_fast_strict {
                    apply_web_smart_fast_strict(&mut mcfg, status_min, status_max);
                }
                let total_hint = Some(expanded_keywords.len());
                let rx = ws.fuzz_scan_stream(&url, expanded_keywords, Some(mcfg));
                if summary {
                    consume_module_stream_with_summary(
                        rx,
                        stream_to,
                        fmt,
                        events.clone(),
                        total_hint,
                        "web.fuzz",
                        summary_top,
                    )
                    .await?;
                } else {
                    consume_module_stream(
                        rx,
                        stream_to,
                        fmt,
                        events.clone(),
                        total_hint,
                        "web.fuzz",
                    )
                    .await?;
                }
                report_progress(&events, 98.0, "web.fuzz: output done");
                Ok(())
            })
            .await?;
        }
        WebActions::Dns {
            domain,
            words,
            words_file,
            discovery_mode,
            stream_to,
            output,
            concurrency,
            timeout_ms,
            max_retries,
            per_host_concurrency,
            dedupe,
            no_dedupe,
            status_min,
            status_max,
            method,
            profile,
        } => {
            with_task(&cli, "web", vec![domain.clone()], |events| async move {
                let mut eff_words = words.clone();
                if let Some(path) = words_file.as_ref() {
                    let mut from_file = load_keywords_file(path)?;
                    eff_words.append(&mut from_file);
                }
                eff_words = eff_words
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>();
                if eff_words.is_empty() {
                    return Err(RustpenError::ParseError(
                        "web dns requires at least one word via --words or --words-file"
                            .to_string(),
                    ));
                }
                eff_words.sort();
                eff_words.dedup();
                report_log(
                    &events,
                    format!("web dns domain={} words={}", domain, eff_words.len()),
                );
                report_progress(&events, 8.0, "web.dns: config building");
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig {
                    request_method: parse_http_method(&method)?,
                    ..Default::default()
                };
                apply_web_profile(&mut mcfg, profile);
                if let Some(c) = concurrency {
                    mcfg.concurrency = c;
                }
                if let Some(t) = timeout_ms {
                    mcfg.timeout_ms = Some(t);
                }
                if let Some(r) = max_retries {
                    mcfg.max_retries = Some(r);
                }
                if let Some(p) = per_host_concurrency {
                    mcfg.per_host_concurrency_override = Some(p);
                }
                mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;
                mcfg.dns_http_verify = matches!(discovery_mode, DnsDiscoveryMode::Precise);
                let total_hint = Some(eff_words.len());
                let rx = ws.subdomain_burst_stream(&domain, eff_words, Some(mcfg));
                consume_module_stream(rx, stream_to, fmt, events.clone(), total_hint, "web.dns")
                    .await?;
                report_progress(&events, 98.0, "web.dns: output done");
                Ok(())
            })
            .await?;
        }
        WebActions::Crawl {
            seeds,
            max_depth,
            concurrency,
            max_pages,
            obey_robots,
            output,
            out,
        } => {
            with_task(&cli, "web", seeds.clone(), |events| async move {
                report_log(
                    &events,
                    format!("crawl seeds={} max_depth={}", seeds.len(), max_depth),
                );
                report_progress(&events, 10.0, "web.crawl: start");
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig {
                    max_depth,
                    concurrency,
                    max_pages,
                    obey_robots,
                    ..Default::default()
                })?;
                report_progress(&events, 20.0, "web.crawl: crawling");
                let crawled = ws.scan(seeds).await?;
                report_progress(&events, 90.0, format!("web.crawl: pages={}", crawled.len()));
                let s = if output.eq_ignore_ascii_case("json") {
                    serde_json::to_string_pretty(&crawled)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                } else {
                    crawled.join("\n")
                };
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
                report_progress(&events, 98.0, "web.crawl: output done");
                Ok(())
            })
            .await?;
        }
        WebActions::Live {
            urls,
            method,
            concurrency,
            output,
            out,
        } => {
            with_task(&cli, "web", urls.clone(), |events| async move {
                report_log(
                    &events,
                    format!("live check urls={} method={}", urls.len(), method),
                );
                report_progress(&events, 8.0, "web.live: start");
                let method = parse_http_method(&method)?;
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(false)
                    .build()
                    .map_err(|e| RustpenError::NetworkError(e.to_string()))?;
                let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
                let mut tasks = Vec::with_capacity(urls.len());
                for url in urls {
                    let sem = std::sync::Arc::clone(&sem);
                    let client = client.clone();
                    let method = method.clone();
                    tasks.push(tokio::spawn(async move {
                        let _permit = sem.acquire_owned().await.ok();
                        let r = live_ping(&client, &url, method).await;
                        (url, r)
                    }));
                }
                let mut rows: Vec<(String, Result<String, String>)> = Vec::new();
                let total = tasks.len().max(1);
                let mut done = 0usize;
                for t in tasks {
                    if let Ok((url, res)) = t.await {
                        match res {
                            Ok(msg) => rows.push((url, Ok(msg))),
                            Err(e) => rows.push((url, Err(e.to_string()))),
                        }
                        done += 1;
                        let pct = 15.0 + ((done as f32) / (total as f32)) * 75.0;
                        report_progress(
                            &events,
                            pct,
                            format!("web.live: processed {done}/{total}"),
                        );
                    }
                }
                let s = if output.eq_ignore_ascii_case("json") {
                    let json_rows: Vec<_> = rows
                        .iter()
                        .map(|(url, res)| match res {
                            Ok(msg) => serde_json::json!({"url": url, "result": msg}),
                            Err(e) => serde_json::json!({"url": url, "error": e}),
                        })
                        .collect();
                    serde_json::to_string_pretty(&json_rows)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?
                } else {
                    let color = color_enabled();
                    let mut out = Vec::new();
                    out.push(format!("{:>4} {:<7} {}", "LIVE", "METHOD", "URL"));
                    for (url, res) in rows {
                        match res {
                            Ok(msg) => {
                                let tag = colorize("OK", "32", color);
                                out.push(format!("{:>4} {:<7} {} {}", tag, method, url, msg));
                            }
                            Err(e) => {
                                let tag = colorize("ERR", "31", color);
                                out.push(format!("{:>4} {:<7} {} {}", tag, method, url, e));
                            }
                        }
                    }
                    out.join("\n")
                };
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
                report_progress(&events, 98.0, "web.live: output done");
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}
