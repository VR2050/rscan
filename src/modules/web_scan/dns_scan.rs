// 子域名爆破：使用 core Fetcher 对生成的子域名进行 HTTP 请求，成功响应则认为存活
use crate::cores::web::{FetchRequest, Fetcher};
use crate::errors::RustpenError;

use crate::modules::web_scan::ModuleScanConfig;
use tokio::sync::mpsc::{self, Receiver};

fn sanitize_fragment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn build_subdomain_request(base_domain: &str, word: &str, cfg: &ModuleScanConfig) -> FetchRequest {
    // Try host[:port] direct-connect optimization for local test hosts like 127.0.0.1:PORT.
    if let Ok(parsed) = url::Url::parse(&format!("http://{}", base_domain.trim_end_matches('/')))
        && let Some(host) = parsed.host_str()
    {
        let port_part = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
        let virtual_host = format!("{}.{}", word, base_domain.trim_end_matches('/'));
        let marker = sanitize_fragment(&virtual_host);
        let connect_url = format!("http://{}{}#rscan-vhost={}", host, port_part, marker);
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&virtual_host) {
            headers.insert(reqwest::header::HOST, v);
            return FetchRequest {
                url: connect_url,
                method: cfg.request_method.clone(),
                headers: Some(headers),
                body: None,
                timeout_ms: cfg.timeout_ms,
                max_retries: cfg.max_retries,
            };
        }
    }

    FetchRequest {
        url: format!("http://{}.{}", word, base_domain.trim_end_matches('/')),
        method: cfg.request_method.clone(),
        headers: None,
        body: None,
        timeout_ms: cfg.timeout_ms,
        max_retries: cfg.max_retries,
    }
}

pub async fn run_subdomain_burst(
    base_domain: &str,
    words: &[&str],
    cfg: ModuleScanConfig,
) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override {
        fetch_cfg.per_host_concurrency = v;
    }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let mut reqs = Vec::new();
    for w in words {
        reqs.push(build_subdomain_request(base_domain, w, &cfg));
    }
    let results = fetcher.fetch_many(reqs, cfg.concurrency).await;
    let mut alive = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for resp in results.into_iter().flatten() {
        let min_ok = cfg.status_min.unwrap_or(200);
        let max_ok = cfg.status_max.unwrap_or(399);
        if resp.status >= min_ok && resp.status <= max_ok {
            if cfg.dedupe_results && !seen.insert(resp.url.clone()) {
                continue;
            }
            alive.push(crate::modules::web_scan::ModuleScanResult {
                url: resp.url,
                status: resp.status,
                content_len: Some(resp.body.len() as u64),
            });
        }
    }
    Ok(alive)
}

pub fn run_subdomain_burst_stream(
    base_domain: &str,
    words: Vec<String>,
    cfg: ModuleScanConfig,
) -> Receiver<Result<crate::modules::web_scan::ModuleScanResult, RustpenError>> {
    let (tx, rx) = mpsc::channel(100);
    let base_domain = base_domain.to_string();
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

        let mut reqs = Vec::new();
        for w in &words {
            reqs.push(build_subdomain_request(&base_domain, w, &cfg));
        }

        let mut seen = std::collections::HashSet::new();
        for chunk in reqs.chunks(cfg.concurrency.max(1)) {
            let results = fetcher
                .fetch_many(chunk.iter().cloned(), cfg.concurrency)
                .await;
            for r in results {
                match r {
                    Ok(resp) => {
                        let min_ok = cfg.status_min.unwrap_or(200);
                        let max_ok = cfg.status_max.unwrap_or(399);
                        if resp.status < min_ok || resp.status > max_ok {
                            continue;
                        }
                        if cfg.dedupe_results && !seen.insert(resp.url.clone()) {
                            continue;
                        }
                        let _ = tx
                            .send(Ok(crate::modules::web_scan::ModuleScanResult {
                                url: resp.url,
                                status: resp.status,
                                content_len: Some(resp.body.len() as u64),
                            }))
                            .await;
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                    }
                }
            }
        }
    });
    rx
}
