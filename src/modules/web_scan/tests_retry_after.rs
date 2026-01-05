#[cfg(test)]
mod tests {
    use crate::modules::web_scan::ModuleScanConfig;
    use crate::modules::web_scan::{run_dir_scan, run_fuzz_scan};
    use std::time::{Duration, SystemTime};
    use warp::Filter;
    use httpdate::fmt_http_date;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn dir_scan_honors_retry_after_seconds() {
        // first response 429 with Retry-After: 1, second response 200
        let cnt = Arc::new(AtomicUsize::new(0));
        let cnt_clone = cnt.clone();
        let handler = warp::path::end().map(move || {
            let c = cnt_clone.clone();
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let mut r = warp::reply::with_status("", warp::http::StatusCode::TOO_MANY_REQUESTS);
                r = warp::reply::with_header(r, "retry-after", "1");
                return r;
            }
            warp::reply::with_status("ok", warp::http::StatusCode::OK)
        });

        let (addr, server) = warp::serve(handler).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 5, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 10, backoff_max_ms: 1000 }, concurrency: 2, timeout_ms: Some(5000), max_retries: Some(5), per_host_concurrency_override: None, dedupe_results: true, status_min: None, status_max: None };
        let res = run_dir_scan(&base, &[], cfg).await.unwrap();
        assert!(res.iter().any(|(_, s, _)| *s == 200));
        assert!(cnt.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn dir_scan_honors_retry_after_httpdate() {
        let cnt = Arc::new(AtomicUsize::new(0));
        let cnt_clone = cnt.clone();
        let handler = warp::path::end().map(move || {
            let c = cnt_clone.clone();
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let when = SystemTime::now() + Duration::from_secs(1);
                let header = fmt_http_date(when);
                let mut r = warp::reply::with_status("", warp::http::StatusCode::TOO_MANY_REQUESTS);
                r = warp::reply::with_header(r, "retry-after", header.as_str());
                return r;
            }
            warp::reply::with_status("ok", warp::http::StatusCode::OK)
        });

        let (addr, server) = warp::serve(handler).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 5, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 10, backoff_max_ms: 2000 }, concurrency: 2, timeout_ms: Some(5000), max_retries: Some(5), per_host_concurrency_override: None, dedupe_results: true, status_min: None, status_max: None };
        let res = run_dir_scan(&base, &[], cfg).await.unwrap();
        assert!(res.iter().any(|(_, s, _)| *s == 200));
        assert!(cnt.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn fuzz_scan_respects_per_host_override() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

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
                    if v <= prev { break; }
                    if mx.compare_exchange(prev, v, Ordering::SeqCst, Ordering::SeqCst).is_ok() { break; }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });
        let (addr, server) = warp::serve(handler).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 10, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 10, timeout_ms: Some(2000), max_retries: Some(0), per_host_concurrency_override: Some(1), dedupe_results: false, status_min: None, status_max: None };
        let url = format!("{}/FUZZ.html", base);
        let res = run_fuzz_scan(&url, &["a","b","c","d","e","f"], cfg).await.unwrap();
        let mv = max_seen.load(Ordering::SeqCst);
        assert!(mv <= 1, "per-host override failed, max concurrent seen {}", mv);
    }
}