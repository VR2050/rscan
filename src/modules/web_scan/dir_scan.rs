use crate::cores::web::{FetchRequest, Fetcher};
use crate::errors::RustpenError;

use crate::modules::web_scan::common::{
    ResponseFingerprint, build_fingerprint, build_joined_url, detect_dir_wildcard_signatures,
    is_near_duplicate, is_wildcard_match,
};
use crate::modules::web_scan::resume::{load_or_new, maybe_resume_path, save};
/// 在 modules 层提供更易用的目录扫描函数，内部使用 cores::web::Fetcher
/// paths: 相对于 base 的路径列表（例如 ["/admin", "/login"]）
use crate::modules::web_scan::{ModuleScanConfig, ModuleScanResult, format_scan_result};
use tokio::sync::mpsc::{self, Receiver};

fn expand_recursive_words(paths: &[&str], max_depth: usize) -> Vec<String> {
    let mut words = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in paths {
        let w = p.trim().trim_start_matches('/').trim_end_matches('/');
        if w.is_empty() {
            continue;
        }
        if seen.insert(w.to_string()) {
            words.push(w.to_string());
        }
    }
    if words.is_empty() || max_depth == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut level = vec![String::new()];
    for _depth in 1..=max_depth {
        let mut next = Vec::new();
        for prefix in &level {
            for w in &words {
                let path = if prefix.is_empty() {
                    format!("/{}", w)
                } else {
                    format!("{}/{}", prefix, w)
                };
                out.push(path.clone());
                next.push(path);
            }
        }
        level = next;
    }
    out
}

fn summarize_errors(total: usize, errors: usize, first: Option<&str>) -> RustpenError {
    let hint = first.unwrap_or("unknown error");
    RustpenError::NetworkError(format!(
        "dir scan failed for all requests (errors={errors}, total={total}): {hint}"
    ))
}

pub async fn run_dir_scan(
    base: &str,
    paths: &[&str],
    cfg: ModuleScanConfig,
) -> Result<Vec<ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override {
        fetch_cfg.per_host_concurrency = v;
    }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let wildcard_signatures = detect_dir_wildcard_signatures(&fetcher, base, &cfg).await;
    let mut reqs = Vec::new();
    let mut seen_req = std::collections::HashSet::new();
    let effective_paths: Vec<String> = if cfg.recursive {
        let r = expand_recursive_words(paths, cfg.recursive_max_depth);
        if r.is_empty() {
            paths.iter().map(|s| s.to_string()).collect()
        } else {
            r
        }
    } else {
        paths.iter().map(|s| s.to_string()).collect()
    };

    for p in &effective_paths {
        let url = build_joined_url(base, p);
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
        Some(load_or_new(path, "dir", base)?)
    } else {
        None
    };
    if let Some(st) = &resume_state {
        reqs.retain(|r| !st.is_done(&r.url));
    }
    // 转换结果并按状态过滤/去重
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
                    let mr = ModuleScanResult {
                        url: resp.url.clone(),
                        status: resp.status,
                        content_len: Some(content_len),
                    };
                    if let Some(st) = resume_state.as_mut() {
                        st.mark_discovered(&mr.url);
                    }
                    if let Some(fmt) = &cfg.output_format {
                        let _s = format_scan_result(&mr, fmt);
                    }
                    out.push(mr);
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

/// 异步流式 API：返回一个 Receiver，按结果到达发送 ModuleScanResult
pub fn run_dir_scan_stream(
    base: &str,
    paths: Vec<String>,
    cfg: ModuleScanConfig,
) -> Receiver<Result<ModuleScanResult, RustpenError>> {
    let (tx, rx) = mpsc::channel(100);
    let base = base.to_string();
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
        let wildcard_signatures = detect_dir_wildcard_signatures(&fetcher, &base, &cfg).await;
        let mut reqs = Vec::new();
        let mut seen_req = std::collections::HashSet::new();
        let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
        let effective_paths: Vec<String> = if cfg.recursive {
            let r = expand_recursive_words(&path_refs, cfg.recursive_max_depth);
            if r.is_empty() { paths.clone() } else { r }
        } else {
            paths.clone()
        };
        for p in effective_paths.iter() {
            let url = build_joined_url(&base, p);
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
            match load_or_new(path, "dir", &base) {
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
                        let mr = ModuleScanResult {
                            url: resp.url.clone(),
                            status: resp.status,
                            content_len: Some(content_len),
                        };
                        let _ = tx.send(Ok(mr)).await;
                    }
                    Err(e) => {
                        error_count += 1;
                        if first_error.is_none() {
                            first_error = Some(e.to_string());
                        }
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
        if reqs.is_empty() {
            return;
        }
        if error_count == reqs.len() {
            let _ = tx
                .send(Err(summarize_errors(
                    reqs.len(),
                    error_count,
                    first_error.as_deref(),
                )))
                .await;
        }
    });
    rx
}

/// 支持回调的便利方法（给 CLI 使用）：回调在后台任务中被调用
pub fn run_dir_scan_with_callback<F>(
    base: &str,
    paths: Vec<String>,
    cfg: ModuleScanConfig,
    cb: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(ModuleScanResult) + Send + Sync + 'static,
{
    let cb = std::sync::Arc::new(cb);
    let base_owned = base.to_string();
    tokio::spawn(async move {
        let mut rx = run_dir_scan_stream(&base_owned, paths, cfg);
        while let Some(r) = rx.recv().await {
            if let Ok(m) = r {
                (cb)(m);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use warp::Filter;

    #[tokio::test]
    async fn dir_scan_basic() {
        let route =
            warp::path!(String).map(|s: String| warp::reply::html(format!("you asked {}", s)));
        let root = warp::path::end().map(|| warp::reply::html("root"));
        let (addr, server) = warp::serve(route.or(root)).bind_ephemeral(([127, 0, 0, 1], 0));
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
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            status_min: None,
            status_max: None,
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
        let res = run_dir_scan(&base, &["/a", "/b"], cfg).await.unwrap();
        assert!(res.iter().any(|r| r.url.contains("/a")
            || r.url.contains("/b")
            || r.url == base
            || r.url == format!("{}/", base)));
    }

    #[tokio::test]
    async fn dir_scan_timeout_and_retry() {
        // handler that sleeps on first hit for path "/slow" then returns quickly
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let handler = warp::path!(String).and_then(move |p: String| {
            let h = hits_clone.clone();
            async move {
                if p == "slow" {
                    let c = h.fetch_add(1, Ordering::SeqCst);
                    if c == 0 {
                        tokio::time::sleep(Duration::from_millis(250)).await; // ensure first attempt times out
                    }
                }
                Ok::<_, std::convert::Infallible>(warp::reply::with_status(
                    "ok",
                    warp::http::StatusCode::OK,
                ))
            }
        });

        let (addr, server) = warp::serve(handler).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        // small timeout to cause first attempt to time out, allow 1 retry
        // Note: tests can run concurrently; use a timeout that's small enough to fail the first try
        // but not so small that scheduling jitter breaks the retry.
        let cfg = crate::modules::web_scan::ModuleScanConfig {
            fetcher: crate::cores::web::FetcherConfig {
                timeout: Duration::from_secs(1),
                user_agent: None,
                max_retries: 1,
                accept_invalid_certs: false,
                per_host_concurrency: 2,
                default_headers: None,
                honor_retry_after: true,
                backoff_base_ms: 10,
                backoff_max_ms: 100,
            },
            concurrency: 2,
            timeout_ms: Some(120),
            max_retries: Some(1),
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            status_min: None,
            status_max: None,
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
        let res = run_dir_scan(&base, &["/slow"], cfg).await.unwrap();
        // since we allowed a retry the slow resource should eventually be fetched
        assert!(res.iter().any(|r| r.status == 200));
    }
}
