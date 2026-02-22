// 模糊扫描：基于 core 的 Fetcher 对包含占位符 FUZZ 的 URL 做并行请求
use crate::cores::web::{FetchRequest, Fetcher};
use crate::errors::RustpenError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use warp::Filter;

    #[tokio::test]
    async fn fuzz_scan_basic() {
        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/FUZZ.html\">FUZZ</a>"));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = crate::modules::web_scan::ModuleScanConfig {
            fetcher: crate::cores::web::FetcherConfig {
                timeout: Duration::from_secs(5),
                user_agent: None,
                max_retries: 0,
                accept_invalid_certs: false,
                per_host_concurrency: 2,
                default_headers: None,
                honor_retry_after: true,
                backoff_base_ms: 100,
                backoff_max_ms: 10_000,
            },
            concurrency: 2,
            timeout_ms: Some(5000),
            max_retries: Some(0),
            status_min: None,
            status_max: None,
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            wildcard_filter: false,
            wildcard_sample_count: 2,
            wildcard_len_tolerance: 16,
            fingerprint_filter: false,
            fingerprint_distance_threshold: 6,
            resume_file: None,
            adaptive_rate: false,
            adaptive_initial_delay_ms: 0,
            adaptive_max_delay_ms: 2000,
            request_method: reqwest::Method::GET,
            recursive: false,
            recursive_max_depth: 2,
        };
        let res = run_fuzz_scan(&format!("{}/FUZZ.html", base), &["test", "a"], cfg)
            .await
            .unwrap();
        assert!(res.iter().any(|r| r.url.contains("FUZZ") == false));
    }

    #[tokio::test]
    async fn fuzz_scan_concurrency() {
        // server that sleeps and tracks concurrent handlers
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let cur = current.clone();
        let mx = max_seen.clone();
        let handler = warp::any().and_then(move || {
            let cur = cur.clone();
            let mx = mx.clone();
            async move {
                let v = cur.fetch_add(1, Ordering::SeqCst) + 1;
                loop {
                    let prev = mx.load(Ordering::SeqCst);
                    if v <= prev {
                        break;
                    }
                    if mx
                        .compare_exchange(prev, v, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(warp::reply::with_status(
                    "ok",
                    warp::http::StatusCode::OK,
                ))
            }
        });

        let (addr, server) = warp::serve(handler).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = crate::modules::web_scan::ModuleScanConfig {
            fetcher: crate::cores::web::FetcherConfig {
                timeout: Duration::from_secs(5),
                user_agent: None,
                max_retries: 0,
                accept_invalid_certs: false,
                per_host_concurrency: 10,
                default_headers: None,
                honor_retry_after: true,
                backoff_base_ms: 100,
                backoff_max_ms: 10_000,
            },
            concurrency: 5,
            timeout_ms: Some(2000),
            max_retries: Some(0),
            status_min: None,
            status_max: None,
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            wildcard_filter: false,
            wildcard_sample_count: 2,
            wildcard_len_tolerance: 16,
            fingerprint_filter: false,
            fingerprint_distance_threshold: 6,
            resume_file: None,
            adaptive_rate: false,
            adaptive_initial_delay_ms: 0,
            adaptive_max_delay_ms: 2000,
            request_method: reqwest::Method::GET,
            recursive: false,
            recursive_max_depth: 2,
        };
        let url = format!("{}/FUZZ.html", base);
        let _res = run_fuzz_scan(&url, &["a", "b", "c", "d", "e", "f"], cfg)
            .await
            .unwrap();
        let mv = max_seen.load(Ordering::SeqCst);
        assert!(mv > 1, "expected concurrent handlers > 1, got {}", mv);
    }
}
/// 尝试将 keywords 插入到包含 FUZZ 的 URL 中并发出请求
use crate::modules::web_scan::ModuleScanConfig;
use crate::modules::web_scan::common::{
    ResponseFingerprint, build_fingerprint, detect_fuzz_wildcard_signatures, is_near_duplicate,
    is_wildcard_match,
};
use crate::modules::web_scan::resume::{load_or_new, maybe_resume_path, save};

fn summarize_errors(total: usize, errors: usize, first: Option<&str>) -> RustpenError {
    let hint = first.unwrap_or("unknown error");
    RustpenError::NetworkError(format!(
        "fuzz scan failed for all requests (errors={errors}, total={total}): {hint}"
    ))
}

pub async fn run_fuzz_scan(
    url_with_fuzz: &str,
    keywords: &[&str],
    cfg: ModuleScanConfig,
) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override {
        fetch_cfg.per_host_concurrency = v;
    }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let wildcard_signatures = detect_fuzz_wildcard_signatures(&fetcher, url_with_fuzz, &cfg).await;
    let mut reqs = Vec::new();
    let mut seen_req = std::collections::HashSet::new();
    for kw in keywords {
        let url = url_with_fuzz.replace("FUZZ", kw);
        if !seen_req.insert(url.clone()) {
            continue;
        }
        let r = FetchRequest {
            url,
            method: cfg.request_method.clone(),
            headers: None,
            body: None,
            timeout_ms: cfg.timeout_ms,
            max_retries: cfg.max_retries,
        };
        reqs.push(r);
    }
    let mut resume_state = if let Some(path) = maybe_resume_path(&cfg.resume_file) {
        Some(load_or_new(path, "fuzz", url_with_fuzz)?)
    } else {
        None
    };
    if let Some(st) = &resume_state {
        reqs.retain(|r| !st.is_done(&r.url));
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut seen_fingerprints: Vec<ResponseFingerprint> = Vec::new();
    let mut adaptive_delay_ms = cfg.adaptive_initial_delay_ms;
    let mut error_count = 0usize;
    let mut first_error: Option<String> = None;
    for chunk in reqs.chunks(cfg.concurrency.max(1)) {
        if cfg.adaptive_rate && adaptive_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(adaptive_delay_ms)).await;
        }
        let results = fetcher
            .fetch_many(chunk.iter().cloned(), cfg.concurrency)
            .await;
        let mut throttle_hits = 0usize;
        let mut observed = 0usize;
        for r in results {
            match r {
                Ok(resp) => {
                    observed += 1;
                    if resp.status == 429 || resp.status >= 500 {
                        throttle_hits += 1;
                    }
                    if let Some(min) = cfg.status_min
                        && resp.status < min
                    {
                        continue;
                    }
                    if let Some(max) = cfg.status_max
                        && resp.status > max
                    {
                        continue;
                    }
                    if cfg.dedupe_results && !seen.insert(resp.url.clone()) {
                        continue;
                    }
                    let content_len = resp.body.len() as u64;
                    if is_wildcard_match(
                        resp.status,
                        content_len,
                        &wildcard_signatures,
                        cfg.wildcard_len_tolerance,
                    ) {
                        continue;
                    }
                    if cfg.fingerprint_filter {
                        let fp = build_fingerprint(resp.status, &resp.body);
                        if is_near_duplicate(
                            &fp,
                            &seen_fingerprints,
                            cfg.fingerprint_distance_threshold,
                        ) {
                            continue;
                        }
                        seen_fingerprints.push(fp);
                    }
                    if let Some(st) = resume_state.as_mut() {
                        st.mark_discovered(&resp.url);
                    }
                    out.push(crate::modules::web_scan::ModuleScanResult {
                        url: resp.url,
                        status: resp.status,
                        content_len: Some(content_len),
                    })
                }
                Err(e) => {
                    error_count += 1;
                    if first_error.is_none() {
                        first_error = Some(e.to_string());
                    }
                }
            }
        }
        if let Some(st) = resume_state.as_mut() {
            for req in chunk {
                st.mark_done(&req.url);
            }
            if let Some(path) = maybe_resume_path(&cfg.resume_file) {
                save(path, st)?;
            }
        }
        if cfg.adaptive_rate && observed > 0 {
            if throttle_hits * 3 >= observed {
                adaptive_delay_ms = (adaptive_delay_ms.saturating_mul(2).saturating_add(20))
                    .min(cfg.adaptive_max_delay_ms);
            } else {
                adaptive_delay_ms /= 2;
            }
        }
    }
    if out.is_empty() && error_count > 0 {
        return Err(summarize_errors(
            reqs.len(),
            error_count,
            first_error.as_deref(),
        ));
    }
    Ok(out)
}

/// 流式版本：返回一个 channel，发送每个结果（并行执行）
pub fn run_fuzz_scan_stream(
    url_with_fuzz: &str,
    keywords: Vec<String>,
    cfg: ModuleScanConfig,
) -> tokio::sync::mpsc::Receiver<Result<crate::modules::web_scan::ModuleScanResult, RustpenError>> {
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let cfg = cfg.clone();
    let url_template = url_with_fuzz.to_string();

    tokio::spawn(async move {
        let mut fetch_cfg = cfg.fetcher.clone();
        if let Some(v) = cfg.per_host_concurrency_override {
            fetch_cfg.per_host_concurrency = v;
        }
        let fetcher = match Fetcher::new(fetch_cfg) {
            Ok(f) => f,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        let wildcard_signatures =
            detect_fuzz_wildcard_signatures(&fetcher, &url_template, &cfg).await;
        let mut reqs = Vec::new();
        let mut seen_req = std::collections::HashSet::new();
        for kw in keywords.iter() {
            let url = url_template.replace("FUZZ", kw);
            if !seen_req.insert(url.clone()) {
                continue;
            }
            reqs.push(FetchRequest {
                url,
                method: cfg.request_method.clone(),
                headers: None,
                body: None,
                timeout_ms: cfg.timeout_ms,
                max_retries: cfg.max_retries,
            });
        }
        let mut resume_state = if let Some(path) = maybe_resume_path(&cfg.resume_file) {
            match load_or_new(path, "fuzz", &url_template) {
                Ok(st) => Some(st),
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        } else {
            None
        };
        if let Some(st) = &resume_state {
            reqs.retain(|r| !st.is_done(&r.url));
        }
        let mut seen = std::collections::HashSet::new();
        let mut seen_fingerprints: Vec<ResponseFingerprint> = Vec::new();
        let mut adaptive_delay_ms = cfg.adaptive_initial_delay_ms;
        for chunk in reqs.chunks(cfg.concurrency.max(1)) {
            if cfg.adaptive_rate && adaptive_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(adaptive_delay_ms)).await;
            }
            let results = fetcher
                .fetch_many(chunk.iter().cloned(), cfg.concurrency)
                .await;
            let mut throttle_hits = 0usize;
            let mut observed = 0usize;
            for r in results {
                match r {
                    Ok(resp) => {
                        observed += 1;
                        if resp.status == 429 || resp.status >= 500 {
                            throttle_hits += 1;
                        }
                        if let Some(min) = cfg.status_min
                            && resp.status < min
                        {
                            continue;
                        }
                        if let Some(max) = cfg.status_max
                            && resp.status > max
                        {
                            continue;
                        }
                        if cfg.dedupe_results && !seen.insert(resp.url.clone()) {
                            continue;
                        }
                        let content_len = resp.body.len() as u64;
                        if is_wildcard_match(
                            resp.status,
                            content_len,
                            &wildcard_signatures,
                            cfg.wildcard_len_tolerance,
                        ) {
                            continue;
                        }
                        if cfg.fingerprint_filter {
                            let fp = build_fingerprint(resp.status, &resp.body);
                            if is_near_duplicate(
                                &fp,
                                &seen_fingerprints,
                                cfg.fingerprint_distance_threshold,
                            ) {
                                continue;
                            }
                            seen_fingerprints.push(fp);
                        }
                        if let Some(st) = resume_state.as_mut() {
                            st.mark_discovered(&resp.url);
                        }
                        let _ = tx
                            .send(Ok(crate::modules::web_scan::ModuleScanResult {
                                url: resp.url.clone(),
                                status: resp.status,
                                content_len: Some(content_len),
                            }))
                            .await;
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                    }
                }
            }
            if let Some(st) = resume_state.as_mut() {
                for req in chunk {
                    st.mark_done(&req.url);
                }
                if let Some(path) = maybe_resume_path(&cfg.resume_file) {
                    let _ = save(path, st);
                }
            }
            if cfg.adaptive_rate && observed > 0 {
                if throttle_hits * 3 >= observed {
                    adaptive_delay_ms = (adaptive_delay_ms.saturating_mul(2).saturating_add(20))
                        .min(cfg.adaptive_max_delay_ms);
                } else {
                    adaptive_delay_ms /= 2;
                }
            }
        }
    });

    rx
}
