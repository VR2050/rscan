use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

use super::safe_templates::{MatcherDef, SafeTemplate};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub template_id: String,
    pub template_name: Option<String>,
    pub severity: Option<String>,
    pub target: String,
    pub url: String,
    pub method: String,
    pub matched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanReport {
    pub scanned_requests: usize,
    pub findings: Vec<VulnFinding>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VulnScanConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for VulnScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 32,
            timeout_ms: 5000,
        }
    }
}

pub async fn vuln_scan_targets(
    targets: &[String],
    templates: &[SafeTemplate],
    cfg: VulnScanConfig,
) -> Result<VulnScanReport, RustpenError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let mut work_items = Vec::new();
    let mut errors = Vec::new();

    for t in targets {
        for tpl in templates {
            for req in &tpl.requests {
                if !is_allowed_method(&req.method) {
                    errors.push(format!(
                        "{}: method '{}' not allowed in safe scan",
                        tpl.id, req.method
                    ));
                    continue;
                }
                let method = reqwest::Method::from_bytes(req.method.as_bytes())
                    .unwrap_or(reqwest::Method::GET);
                for p in &req.paths {
                    let url = join_target_path(t, p);
                    work_items.push((tpl.clone(), req.clone(), method.clone(), url));
                }
            }
        }
    }

    let mut report = VulnScanReport {
        scanned_requests: 0,
        findings: Vec::new(),
        errors,
    };

    let mut in_flight = stream::iter(work_items.into_iter().map(|(tpl, req, method, url)| {
        let client = client.clone();
        async move {
            let resp = client.request(method, &url).send().await;
            (tpl, req, url, resp)
        }
    }))
    .buffer_unordered(cfg.concurrency.max(1));

    while let Some((tpl, req, url, resp)) = in_flight.next().await {
        report.scanned_requests += 1;
        match resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();
                let body = resp.bytes().await.unwrap_or_default();
                let body_s = String::from_utf8_lossy(&body).to_string();

                let mut matched = Vec::new();
                for m in &req.matchers {
                    if eval_matcher(m, status, &headers, &body_s) {
                        matched.push(format!("{}:{}", m.kind, m.part));
                    }
                }

                let hit = if req.matchers.is_empty() {
                    false
                } else if req.matchers_condition == "and" {
                    matched.len() == req.matchers.len()
                } else {
                    !matched.is_empty()
                };

                if hit {
                    report.findings.push(VulnFinding {
                        template_id: tpl.id.clone(),
                        template_name: tpl.info.name.clone(),
                        severity: tpl.info.severity.clone(),
                        target: extract_base_target(&url),
                        url,
                        method: req.method,
                        matched,
                    });
                }
            }
            Err(e) => report.errors.push(format!("{}: {}", url, e)),
        }
    }

    Ok(report)
}

fn eval_matcher(
    m: &MatcherDef,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> bool {
    match m.kind.as_str() {
        "status" => m.status.contains(&status),
        "word" => {
            let hay = if m.part == "header" {
                headers
                    .iter()
                    .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                body.to_string()
            };
            let h = if m.case_insensitive {
                hay.to_ascii_lowercase()
            } else {
                hay
            };
            if m.words.is_empty() {
                return false;
            }
            if m.condition == "and" {
                m.words.iter().all(|w| {
                    if m.case_insensitive {
                        h.contains(&w.to_ascii_lowercase())
                    } else {
                        h.contains(w)
                    }
                })
            } else {
                m.words.iter().any(|w| {
                    if m.case_insensitive {
                        h.contains(&w.to_ascii_lowercase())
                    } else {
                        h.contains(w)
                    }
                })
            }
        }
        "header" => {
            let h = headers
                .iter()
                .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\n");
            if m.words.is_empty() {
                return false;
            }
            let hay = if m.case_insensitive {
                h.to_ascii_lowercase()
            } else {
                h
            };
            if m.condition == "and" {
                m.words.iter().all(|w| {
                    if m.case_insensitive {
                        hay.contains(&w.to_ascii_lowercase())
                    } else {
                        hay.contains(w)
                    }
                })
            } else {
                m.words.iter().any(|w| {
                    if m.case_insensitive {
                        hay.contains(&w.to_ascii_lowercase())
                    } else {
                        hay.contains(w)
                    }
                })
            }
        }
        _ => false,
    }
}

fn join_target_path(target: &str, path: &str) -> String {
    let t = target.trim_end_matches('/');
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{}{}", t, path)
    } else {
        format!("{}/{}", t, path)
    }
}

fn extract_base_target(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        if let Some(host) = parsed.host_str() {
            let port = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
            return format!("{}://{}{}", scheme, host, port);
        }
    }
    url.to_string()
}

fn is_allowed_method(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD")
}
