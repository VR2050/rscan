use crate::errors::RustpenError;
use crate::cores::web_en::{Fetcher, FetcherConfig, FetchRequest};
use std::time::Duration;

/// 在 modules 层提供更易用的目录扫描函数，内部使用 cores::web_en::Fetcher
/// paths: 相对于 base 的路径列表（例如 ["/admin", "/login"]）
use crate::modules::web_scan::{ModuleScanConfig, ModuleScanResult, OutputFormat, format_scan_result};
use tokio::sync::mpsc::{self, Receiver};

pub async fn run_dir_scan(base: &str, paths: &[&str], cfg: ModuleScanConfig) -> Result<Vec<ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override { fetch_cfg.per_host_concurrency = v; }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let mut reqs = Vec::new();
    for p in paths {
        let url = if p.starts_with("/") { format!("{}{}", base.trim_end_matches('/'), p) } else { format!("{}/{}", base.trim_end_matches('/'), p) };
        let r = FetchRequest { url, method: reqwest::Method::GET, headers: None, body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries };
        reqs.push(r);
    }

    let results = fetcher.fetch_many(reqs.into_iter().map(|r| r), cfg.concurrency).await;
    // 转换结果并按状态过滤/去重
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in results {
        match r {
            Ok(resp) => {
                if let Some(min) = cfg.status_min { if resp.status < min { continue; } }
                if let Some(max) = cfg.status_max { if resp.status > max { continue; } }
                if cfg.dedupe_results { if !seen.insert(resp.url.clone()) { continue; } }
                let mr = ModuleScanResult { url: resp.url, status: resp.status, content_len: Some(resp.body.len() as u64) };
                if let Some(fmt) = &cfg.output_format { let _s = format_scan_result(&mr, fmt); /* user may fetch string by invoking format_scan_result themselves */ }
                out.push(mr);
            }
            Err(_) => { /* ignore errors in module-level return; caller can use streaming/callback for errors */ }
        }
    }
    Ok(out)
}

/// 异步流式 API：返回一个 Receiver，按结果到达发送 ModuleScanResult
pub fn run_dir_scan_stream(base: &str, paths: Vec<String>, cfg: ModuleScanConfig) -> Receiver<Result<ModuleScanResult, RustpenError>> {
    let (tx, rx) = mpsc::channel(100);
    let base = base.to_string();
    tokio::spawn(async move {
        let mut fetch_cfg = cfg.fetcher.clone();
        if let Some(v) = cfg.per_host_concurrency_override { fetch_cfg.per_host_concurrency = v; }
        let fetcher = match Fetcher::new(fetch_cfg) { Ok(f) => f, Err(e) => { let _ = tx.send(Err(e)).await; return; } };
        let mut reqs = Vec::new();
        for p in paths.iter() {
            let url = if p.starts_with("/") { format!("{}{}", base.trim_end_matches('/'), p) } else { format!("{}/{}", base.trim_end_matches('/'), p) };
            reqs.push(FetchRequest { url, method: reqwest::Method::GET, headers: None, body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries });
        }

        let results = fetcher.fetch_many(reqs.into_iter().map(|r| r), cfg.concurrency).await;
        let mut seen = std::collections::HashSet::new();
        for r in results {
            match r {
                Ok(resp) => {
                    if let Some(min) = cfg.status_min { if resp.status < min { continue; } }
                    if let Some(max) = cfg.status_max { if resp.status > max { continue; } }
                    if cfg.dedupe_results { if !seen.insert(resp.url.clone()) { continue; } }
                    let mr = ModuleScanResult { url: resp.url.clone(), status: resp.status, content_len: Some(resp.body.len() as u64) };
                    let _ = tx.send(Ok(mr)).await;
                }
                Err(e) => { let _ = tx.send(Err(e)).await; }
            }
        }
    });
    rx
}

/// 支持回调的便利方法（给 CLI 使用）：回调在后台任务中被调用
pub fn run_dir_scan_with_callback<F>(base: &str, paths: Vec<String>, cfg: ModuleScanConfig, cb: F) -> tokio::task::JoinHandle<()>
where
    F: Fn(ModuleScanResult) + Send + Sync + 'static,
{
    let cb = std::sync::Arc::new(cb);
    let base_owned = base.to_string();
    tokio::spawn(async move {
        let mut rx = run_dir_scan_stream(&base_owned, paths, cfg);
        while let Some(r) = rx.recv().await {
            if let Ok(m) = r { (cb)(m); }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;
    use std::time::Duration;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn dir_scan_basic() {
        let route = warp::path!(String).map(|s: String| warp::reply::html(format!("you asked {}", s)));
        let root = warp::path::end().map(|| warp::reply::html("root"));
        let (addr, server) = warp::serve(route.or(root)).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);
        let cfg = crate::modules::web_scan::ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 2, timeout_ms: Some(5000), max_retries: Some(0), per_host_concurrency_override: None, dedupe_results: true, output_format: None, status_min: None, status_max: None };
        let res = run_dir_scan(&base, &["/a","/b"], cfg).await.unwrap();
        assert!(res.iter().any(|r| r.url.contains("/a") || r.url.contains("/b") || r.url == base || r.url == format!("{}/", base)));
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
                        tokio::time::sleep(Duration::from_millis(200)).await; // cause timeout for small timeout cfg
                    }
                }
                Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });

        let (addr, server) = warp::serve(handler).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        // small timeout to cause first attempt to time out, allow 1 retry
        let cfg = crate::modules::web_scan::ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(1), user_agent: None, max_retries: 1, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 10, backoff_max_ms: 100 }, concurrency: 2, timeout_ms: Some(50), max_retries: Some(1), per_host_concurrency_override: None, dedupe_results: true, output_format: None, status_min: None, status_max: None };
        let res = run_dir_scan(&base, &["/slow"], cfg).await.unwrap();
        // since we allowed a retry the slow resource should eventually be fetched
        assert!(res.iter().any(|r| r.status == 200));
    }
}