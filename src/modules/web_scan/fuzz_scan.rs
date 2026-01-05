// 模糊扫描：基于 core 的 Fetcher 对包含占位符 FUZZ 的 URL 做并行请求
use crate::errors::RustpenError;
use crate::cores::web_en::{Fetcher, FetcherConfig, FetchRequest};
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn fuzz_scan_basic() {
        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/FUZZ.html\">FUZZ</a>"));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = crate::modules::web_scan::ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 2, timeout_ms: Some(5000), max_retries: Some(0), status_min: None, status_max: None, per_host_concurrency_override: None, dedupe_results: true, output_format: None };
        let res = run_fuzz_scan(&format!("{}/FUZZ.html", base), &["test","a"], cfg).await.unwrap();
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

        let cfg = crate::modules::web_scan::ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 10, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 5, timeout_ms: Some(2000), max_retries: Some(0), status_min: None, status_max: None, per_host_concurrency_override: None, dedupe_results: true, output_format: None };
        let url = format!("{}/FUZZ.html", base);
        let res = run_fuzz_scan(&url, &["a","b","c","d","e","f"], cfg).await.unwrap();
        let mv = max_seen.load(Ordering::SeqCst);
        assert!(mv > 1, "expected concurrent handlers > 1, got {}", mv);
    }
}
/// 尝试将 keywords 插入到包含 FUZZ 的 URL 中并发出请求
use crate::modules::web_scan::ModuleScanConfig;

pub async fn run_fuzz_scan(url_with_fuzz: &str, keywords: &[&str], cfg: ModuleScanConfig) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override { fetch_cfg.per_host_concurrency = v; }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let mut reqs = Vec::new();
    for kw in keywords {
        let url = url_with_fuzz.replace("FUZZ", kw);
        let r = FetchRequest { url, method: reqwest::Method::GET, headers: None, body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries };
        reqs.push(r);
    }
    let results = fetcher.fetch_many(reqs.into_iter().map(|r| r), cfg.concurrency).await;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in results {
        match r {
            Ok(resp) => {
                if let Some(min) = cfg.status_min { if resp.status < min { continue; } }
                if let Some(max) = cfg.status_max { if resp.status > max { continue; } }
                if cfg.dedupe_results {
                    if !seen.insert(resp.url.clone()) { continue; }
                }
                out.push(crate::modules::web_scan::ModuleScanResult { url: resp.url, status: resp.status, content_len: Some(resp.body.len() as u64) })
            }
            Err(_) => { /* skip errors at module level */ }
        }
    }
    Ok(out)
}

/// 流式版本：返回一个 channel，发送每个结果（并行执行）
pub fn run_fuzz_scan_stream(url_with_fuzz: &str, keywords: Vec<String>, cfg: ModuleScanConfig) -> tokio::sync::mpsc::Receiver<Result<crate::modules::web_scan::ModuleScanResult, RustpenError>> {
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let cfg = cfg.clone();
    let url_template = url_with_fuzz.to_string();

    tokio::spawn(async move {
        let mut fetch_cfg = cfg.fetcher.clone();
        if let Some(v) = cfg.per_host_concurrency_override { fetch_cfg.per_host_concurrency = v; }
        let fetcher = match Fetcher::new(fetch_cfg) { Ok(f) => f, Err(e) => { let _ = tx.send(Err(e)).await; return; } };
        let mut reqs = Vec::new();
        for kw in keywords.iter() {
            let url = url_template.replace("FUZZ", kw);
            reqs.push(FetchRequest { url, method: reqwest::Method::GET, headers: None, body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries });
        }

        let results = fetcher.fetch_many(reqs.into_iter().map(|r| r), cfg.concurrency).await;
        let mut seen = std::collections::HashSet::new();
        for r in results {
            match r {
                Ok(resp) => {
                    if let Some(min) = cfg.status_min { if resp.status < min { continue; } }
                    if let Some(max) = cfg.status_max { if resp.status > max { continue; } }
                    if cfg.dedupe_results {
                        if !seen.insert(resp.url.clone()) { continue; }
                    }
                    let _ = tx.send(Ok(crate::modules::web_scan::ModuleScanResult { url: resp.url.clone(), status: resp.status, content_len: Some(resp.body.len() as u64) })).await;
                }
                Err(e) => { let _ = tx.send(Err(e)).await; }
            }
        }
    });

    rx
}

