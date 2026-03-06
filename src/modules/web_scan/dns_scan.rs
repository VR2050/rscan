// 子域名爆破：先 DNS 解析，再对可解析子域发起 HTTP 请求并按状态码筛选。
use crate::cores::web::{FetchRequest, Fetcher};
use crate::errors::RustpenError;

use crate::modules::web_scan::ModuleScanConfig;
use crate::modules::web_scan::ModuleScanResult;
use crate::modules::web_scan::render_request_body;
use futures::stream::{self, StreamExt};
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

#[derive(Clone, Debug)]
struct DnsBaseTarget {
    host: String,
    port: Option<u16>,
    local_vhost_mode: bool,
}

fn parse_dns_base_target(base_domain: &str) -> DnsBaseTarget {
    let raw = base_domain.trim().trim_end_matches('/').to_ascii_lowercase();
    if let Ok(parsed) = url::Url::parse(&format!("http://{raw}"))
        && let Some(host) = parsed.host_str()
    {
        let local_vhost_mode = host.eq_ignore_ascii_case("localhost")
            || host.parse::<std::net::IpAddr>().is_ok();
        return DnsBaseTarget {
            host: host.to_string(),
            port: parsed.port(),
            local_vhost_mode,
        };
    }
    DnsBaseTarget {
        host: raw,
        port: None,
        local_vhost_mode: false,
    }
}

fn build_local_vhost_request(
    base: &DnsBaseTarget,
    fqdn: &str,
    word: &str,
    cfg: &ModuleScanConfig,
) -> Option<FetchRequest> {
    let port_part = base.port.map(|p| format!(":{p}")).unwrap_or_default();
    let marker = sanitize_fragment(fqdn);
    let connect_url = format!("http://{}{}#rscan-vhost={}", base.host, port_part, marker);
    let mut headers = reqwest::header::HeaderMap::new();
    let hv = reqwest::header::HeaderValue::from_str(fqdn).ok()?;
    headers.insert(reqwest::header::HOST, hv);
    Some(FetchRequest {
        url: connect_url,
        method: cfg.request_method.clone(),
        headers: {
            let mut merged = cfg.request_headers.clone().unwrap_or_default();
            for (k, v) in &headers {
                merged.insert(k, v.clone());
            }
            Some(merged)
        },
        body: render_request_body(&cfg.request_body_template, Some(word)),
        timeout_ms: cfg.timeout_ms,
        max_retries: cfg.max_retries,
        follow_redirects: Some(cfg.follow_redirects),
    })
}

fn build_dns_http_request(
    scheme: &str,
    fqdn: &str,
    port: Option<u16>,
    word: &str,
    cfg: &ModuleScanConfig,
) -> FetchRequest {
    let host_port = match port {
        Some(p) => format!("{fqdn}:{p}"),
        None => fqdn.to_string(),
    };
    FetchRequest {
        url: format!("{scheme}://{host_port}"),
        method: cfg.request_method.clone(),
        headers: cfg.request_headers.clone(),
        body: render_request_body(&cfg.request_body_template, Some(word)),
        timeout_ms: cfg.timeout_ms,
        max_retries: cfg.max_retries,
        follow_redirects: Some(cfg.follow_redirects),
    }
}

#[derive(Clone, Debug)]
enum ProbeCandidate {
    Local {
        fqdn: String,
        request: FetchRequest,
    },
    Remote { fqdn: String, word: String, port: Option<u16> },
}

async fn build_probe_candidates(
    base_domain: &str,
    words: &[String],
    cfg: &ModuleScanConfig,
) -> Vec<ProbeCandidate> {
    let base = parse_dns_base_target(base_domain);

    // Keep local/CTF compatibility for domains like 127.0.0.1:PORT used in tests.
    if base.local_vhost_mode {
        return words
            .iter()
            .filter_map(|w| {
                let fqdn = format!("{}.{}", w.trim(), base_domain.trim_end_matches('/'));
                build_local_vhost_request(&base, &fqdn, w, cfg).map(|request| {
                    ProbeCandidate::Local {
                        fqdn: fqdn.clone(),
                        request,
                    }
                })
            })
            .collect();
    }

    let resolve_port = base.port.unwrap_or(80);
    let conc = cfg.concurrency.max(1);
    let root_host = base.host.clone();
    let root_port = base.port;
    stream::iter(words.iter().cloned())
        .map(|w| {
            let fqdn = format!("{}.{}", w.trim(), root_host);
            async move {
                match tokio::net::lookup_host(format!("{fqdn}:{resolve_port}")).await {
                    Ok(mut iter) => {
                        if iter.next().is_some() {
                            Some(ProbeCandidate::Remote {
                                fqdn,
                                word: w,
                                port: root_port,
                            })
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(conc)
        .filter_map(|x| async move { x })
        .collect::<Vec<_>>()
        .await
}

fn status_in_scope(status: u16, cfg: &ModuleScanConfig) -> bool {
    let min_ok = cfg.status_min.unwrap_or(200);
    let max_ok = cfg.status_max.unwrap_or(399);
    status >= min_ok && status <= max_ok
}

fn to_module_result(resp: crate::cores::web::FetchResponse) -> ModuleScanResult {
    ModuleScanResult {
        url: resp.url,
        status: resp.status,
        content_len: Some(resp.body.len() as u64),
    }
}

fn candidate_discovery_url(cand: &ProbeCandidate) -> String {
    match cand {
        ProbeCandidate::Local { fqdn, .. } => format!("http://{fqdn}"),
        ProbeCandidate::Remote { fqdn, port, .. } => match port {
            Some(p) => format!("http://{fqdn}:{p}"),
            None => format!("http://{fqdn}"),
        },
    }
}

async fn probe_candidate(
    fetcher: &Fetcher,
    cfg: &ModuleScanConfig,
    cand: ProbeCandidate,
) -> Option<ModuleScanResult> {
    match cand {
        ProbeCandidate::Local { request, .. } => match fetcher.fetch_with_request(request).await {
            Ok(resp) if status_in_scope(resp.status, cfg) => Some(to_module_result(resp)),
            _ => None,
        },
        ProbeCandidate::Remote { fqdn, word, port } => {
            let req_http = build_dns_http_request("http", &fqdn, port, &word, cfg);
            match fetcher.fetch_with_request(req_http).await {
                Ok(resp) if status_in_scope(resp.status, cfg) => Some(to_module_result(resp)),
                Ok(_) => None,
                Err(_) => {
                    // Fallback to HTTPS when HTTP connection fails.
                    let req_https = build_dns_http_request("https", &fqdn, port, &word, cfg);
                    match fetcher.fetch_with_request(req_https).await {
                        Ok(resp) if status_in_scope(resp.status, cfg) => Some(to_module_result(resp)),
                        _ => None,
                    }
                }
            }
        }
    }
}

pub async fn run_subdomain_burst(
    base_domain: &str,
    words: &[&str],
    cfg: ModuleScanConfig,
) -> Result<Vec<ModuleScanResult>, RustpenError> {
    let mut fetch_cfg = cfg.fetcher.clone();
    if let Some(v) = cfg.per_host_concurrency_override {
        fetch_cfg.per_host_concurrency = v;
    }
    let fetcher = Fetcher::new(fetch_cfg)?;
    let word_vec: Vec<String> = words.iter().map(|x| x.to_string()).collect();
    let candidates = build_probe_candidates(base_domain, &word_vec, &cfg).await;
    let mut alive: Vec<ModuleScanResult> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if !cfg.dns_http_verify {
        for cand in candidates {
            let url = candidate_discovery_url(&cand);
            if cfg.dedupe_results && !seen.insert(url.clone()) {
                continue;
            }
            alive.push(ModuleScanResult {
                url,
                status: 200,
                content_len: None,
            });
        }
        return Ok(alive);
    }

    let results = stream::iter(candidates)
        .map(|cand| {
            let this = fetcher.clone();
            let cfg = cfg.clone();
            async move { probe_candidate(&this, &cfg, cand).await }
        })
        .buffer_unordered(cfg.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;
    for item in results.into_iter().flatten() {
        if cfg.dedupe_results && !seen.insert(item.url.clone()) {
            continue;
        }
        alive.push(item);
    }
    Ok(alive)
}

pub fn run_subdomain_burst_stream(
    base_domain: &str,
    words: Vec<String>,
    cfg: ModuleScanConfig,
) -> Receiver<Result<ModuleScanResult, RustpenError>> {
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

        let candidates = build_probe_candidates(&base_domain, &words, &cfg).await;

        let mut seen = std::collections::HashSet::new();
        if !cfg.dns_http_verify {
            for cand in candidates {
                let url = candidate_discovery_url(&cand);
                if cfg.dedupe_results && !seen.insert(url.clone()) {
                    continue;
                }
                let _ = tx
                    .send(Ok(ModuleScanResult {
                        url,
                        status: 200,
                        content_len: None,
                    }))
                    .await;
            }
            return;
        }

        let results = stream::iter(candidates)
            .map(|cand| {
                let this = fetcher.clone();
                let cfg = cfg.clone();
                async move { probe_candidate(&this, &cfg, cand).await }
            })
            .buffer_unordered(cfg.concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
        for item in results.into_iter().flatten() {
            if cfg.dedupe_results && !seen.insert(item.url.clone()) {
                continue;
            }
            let _ = tx.send(Ok(item)).await;
        }
    });
    rx
}
