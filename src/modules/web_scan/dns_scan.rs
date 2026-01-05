// 子域名爆破：使用 core Fetcher 对生成的子域名进行 HTTP 请求，成功响应则认为存活
use crate::errors::RustpenError;
use crate::cores::web_en::{Fetcher, FetcherConfig, FetchRequest};
use std::time::Duration;

use crate::modules::web_scan::ModuleScanConfig;

pub async fn run_subdomain_burst(base_domain: &str, words: &[&str], cfg: ModuleScanConfig) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override { fetch_cfg.per_host_concurrency = v; }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let mut reqs = Vec::new();
    // Try to parse base_domain as host[:port] so we can avoid DNS lookups for names like `a.127.0.0.1:PORT`.
    let parsed_domain = url::Url::parse(&format!("http://{}", base_domain.trim_end_matches('/')));
    for w in words {
        if let Ok(parsed) = &parsed_domain {
            if let Some(host) = parsed.host_str() {
                let port_part = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
                // Connect directly to numeric host:port to avoid DNS resolution, and set Host header to the subdomain
                let connect_url = format!("http://{}{}", host, port_part);
                let mut headers = reqwest::header::HeaderMap::new();
                let host_header_value = format!("{}.{}", w, base_domain.trim_end_matches('/'));
                headers.insert(reqwest::header::HOST, reqwest::header::HeaderValue::from_str(&host_header_value).unwrap());
                let r = FetchRequest { url: connect_url, method: reqwest::Method::GET, headers: Some(headers), body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries };
                reqs.push(r);
                continue;
            }
        }

        // fallback to default behavior
        let url = format!("http://{}.{}", w, base_domain.trim_end_matches('/'));
        let r = FetchRequest { url, method: reqwest::Method::GET, headers: None, body: None, timeout_ms: cfg.timeout_ms, max_retries: cfg.max_retries };
        reqs.push(r);
    }
    let results = fetcher.fetch_many(reqs.into_iter().map(|r| r), cfg.concurrency).await;
    let mut alive = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in results {
        if let Ok(resp) = r {
            let min_ok = cfg.status_min.unwrap_or(200);
            let max_ok = cfg.status_max.unwrap_or(399);
            if resp.status >= min_ok && resp.status <= max_ok {
                if cfg.dedupe_results {
                    if !seen.insert(resp.url.clone()) { continue; }
                }
                alive.push(crate::modules::web_scan::ModuleScanResult { url: resp.url, status: resp.status, content_len: Some(resp.body.len() as u64) });
            }
        }
    }
    Ok(alive)
}
