use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

use super::safe_templates::{ExtractorDef, MatcherDef, SafeTemplate};

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
        .cookie_store(true)
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let mut work_items = Vec::new();
    let errors = Vec::new();
    let templates = Arc::new(templates.to_vec());

    for t in targets {
        for idx in 0..templates.len() {
            if templates[idx].requests.is_empty() {
                continue;
            }
            work_items.push((t.clone(), idx));
        }
    }

    let mut report = VulnScanReport {
        scanned_requests: 0,
        findings: Vec::new(),
        errors,
    };

    let mut in_flight = stream::iter(work_items.into_iter().map(|(target, idx)| {
        let client = client.clone();
        let templates = Arc::clone(&templates);
        async move { execute_template_on_target(&client, &target, &templates[idx]).await }
    }))
    .buffer_unordered(cfg.concurrency.max(1));

    while let Some(result) = in_flight.next().await {
        report.scanned_requests += result.scanned_requests;
        if let Some(finding) = result.finding {
            report.findings.push(finding);
        }
        report.errors.extend(result.errors);
    }

    Ok(report)
}

#[derive(Default)]
struct TemplateExecResult {
    scanned_requests: usize,
    finding: Option<VulnFinding>,
    errors: Vec<String>,
}

async fn execute_template_on_target(
    client: &reqwest::Client,
    target: &str,
    tpl: &SafeTemplate,
) -> TemplateExecResult {
    let mut out = TemplateExecResult::default();
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut last_url = target.to_string();
    let mut last_method = "GET".to_string();
    let mut all_matched_labels = Vec::new();
    let mut had_matcher_request = false;

    for req in &tpl.requests {
        let compiled_extractors = compile_extractors(&req.extractors);
        if !is_allowed_method(&req.method) {
            out.errors.push(format!(
                "{}: method '{}' not allowed in safe scan",
                tpl.id, req.method
            ));
            return out;
        }
        let mut req_hit = req.matchers.is_empty();
        if !req.matchers.is_empty() {
            had_matcher_request = true;
        }
        for raw_path in &req.paths {
            let rendered_path = render_runtime_vars(raw_path, &vars);
            let url = join_target_path(target, &rendered_path);
            if contains_unresolved_placeholders(&url) {
                out.errors
                    .push(format!("{}: unresolved variables in url '{}'", tpl.id, url));
                continue;
            }
            let method =
                reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
            let mut builder = client.request(method, &url);
            for (k, v) in &req.headers {
                let rv = render_runtime_vars(v, &vars);
                if contains_unresolved_placeholders(&rv) {
                    out.errors.push(format!(
                        "{}: unresolved variables in header '{}' for {}",
                        tpl.id, k, url
                    ));
                    continue;
                }
                builder = builder.header(k, rv);
            }
            if let Some(body) = req.body.as_ref() {
                let body = render_runtime_vars(body, &vars);
                if contains_unresolved_placeholders(&body) {
                    out.errors.push(format!(
                        "{}: unresolved variables in body for {}",
                        tpl.id, url
                    ));
                    continue;
                }
                builder = builder.body(body);
            }
            out.scanned_requests += 1;
            match builder.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let headers = resp.headers().clone();
                    let body = resp.bytes().await.unwrap_or_default();
                    let body_s = String::from_utf8_lossy(&body).to_string();
                    apply_extractors(&compiled_extractors, &headers, &body_s, &mut vars);
                    let header_text = headers
                        .iter()
                        .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or_default()))
                        .collect::<Vec<_>>()
                        .join("\n");
                    let body_lower = body_s.to_ascii_lowercase();
                    let header_lower = header_text.to_ascii_lowercase();
                    let mut matched = Vec::new();
                    for m in &req.matchers {
                        if eval_matcher(
                            m,
                            status,
                            &body_s,
                            &header_text,
                            &body_lower,
                            &header_lower,
                        ) {
                            matched.push(format!("{}:{}", m.kind, m.part));
                        }
                    }
                    let hit = if req.matchers.is_empty() {
                        true
                    } else if req.matchers_condition == "and" {
                        matched.len() == req.matchers.len()
                    } else {
                        !matched.is_empty()
                    };
                    if hit {
                        req_hit = true;
                        last_url = url.clone();
                        last_method = req.method.clone();
                        all_matched_labels.extend(matched);
                        break;
                    }
                }
                Err(e) => out.errors.push(format!("{}: {}", url, e)),
            }
        }
        if !req_hit {
            return out;
        }
    }

    if had_matcher_request {
        out.finding = Some(VulnFinding {
            template_id: tpl.id.clone(),
            template_name: tpl.info.name.clone(),
            severity: tpl.info.severity.clone(),
            target: extract_base_target(&last_url),
            url: last_url,
            method: last_method,
            matched: all_matched_labels,
        });
    }
    out
}

#[derive(Clone)]
struct CompiledExtractor {
    part: String,
    name: String,
    group: usize,
    regexes: Vec<Regex>,
}

fn compile_extractors(extractors: &[ExtractorDef]) -> Vec<CompiledExtractor> {
    let mut out = Vec::new();
    for ex in extractors {
        if !ex.internal {
            continue;
        }
        let Some(name) = ex.name.as_ref() else {
            continue;
        };
        let regexes = ex
            .regex
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect::<Vec<_>>();
        if regexes.is_empty() {
            continue;
        }
        out.push(CompiledExtractor {
            part: ex.part.clone(),
            name: name.clone(),
            group: ex.group,
            regexes,
        });
    }
    out
}

fn apply_extractors(
    extractors: &[CompiledExtractor],
    headers: &reqwest::header::HeaderMap,
    body: &str,
    vars: &mut HashMap<String, String>,
) {
    if extractors.is_empty() {
        return;
    }
    let header_text = headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n");
    for ex in extractors {
        let hay = if ex.part == "header" {
            &header_text
        } else {
            body
        };
        for re in &ex.regexes {
            let Some(caps) = re.captures(hay) else {
                continue;
            };
            let idx = ex.group;
            if let Some(value) = caps.get(idx).or_else(|| caps.get(0)) {
                vars.insert(ex.name.clone(), value.as_str().to_string());
                break;
            }
        }
    }
}

fn render_runtime_vars(input: &str, vars: &HashMap<String, String>) -> String {
    let mut out = input.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

fn contains_unresolved_placeholders(input: &str) -> bool {
    input.contains("{{") && input.contains("}}")
}

fn eval_matcher(
    m: &MatcherDef,
    status: u16,
    body: &str,
    header_text: &str,
    body_lower: &str,
    header_lower: &str,
) -> bool {
    match m.kind.as_str() {
        "status" => m.status.contains(&status),
        "word" => {
            let (hay, hay_lower) = if m.part == "header" {
                (header_text, header_lower)
            } else {
                (body, body_lower)
            };
            if m.words.is_empty() {
                return false;
            }
            if m.condition == "and" {
                m.words.iter().all(|w| {
                    if m.case_insensitive {
                        hay_lower.contains(&w.to_ascii_lowercase())
                    } else {
                        hay.contains(w)
                    }
                })
            } else {
                m.words.iter().any(|w| {
                    if m.case_insensitive {
                        hay_lower.contains(&w.to_ascii_lowercase())
                    } else {
                        hay.contains(w)
                    }
                })
            }
        }
        "header" => {
            if m.words.is_empty() {
                return false;
            }
            if m.condition == "and" {
                m.words.iter().all(|w| {
                    if m.case_insensitive {
                        header_lower.contains(&w.to_ascii_lowercase())
                    } else {
                        header_text.contains(w)
                    }
                })
            } else {
                m.words.iter().any(|w| {
                    if m.case_insensitive {
                        header_lower.contains(&w.to_ascii_lowercase())
                    } else {
                        header_text.contains(w)
                    }
                })
            }
        }
        _ => false,
    }
}

fn join_target_path(target: &str, path: &str) -> String {
    let t = target.trim_end_matches('/');
    let rendered = render_path_template(t, path);
    if rendered.starts_with("http://") || rendered.starts_with("https://") {
        rendered
    } else if rendered.starts_with('/') {
        format!("{}{}", t, rendered)
    } else {
        format!("{}/{}", t, rendered)
    }
}

fn render_path_template(target: &str, path: &str) -> String {
    let parsed = url::Url::parse(target).ok();
    let hostname = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or_default()
        .to_string();
    let host = parsed
        .as_ref()
        .and_then(|u| {
            u.host_str().map(|h| {
                if let Some(p) = u.port() {
                    format!("{h}:{p}")
                } else {
                    h.to_string()
                }
            })
        })
        .unwrap_or_else(|| hostname.clone());
    let port = parsed
        .as_ref()
        .and_then(|u| u.port_or_known_default())
        .map(|p| p.to_string())
        .unwrap_or_default();

    path.replace("{{BaseURL}}", target)
        .replace("{{RootURL}}", target)
        .replace("{{Hostname}}", &hostname)
        .replace("{{Host}}", &host)
        .replace("{{Port}}", &port)
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
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    )
}

#[cfg(test)]
mod tests {
    use super::{join_target_path, render_path_template};

    #[test]
    fn render_template_supports_common_nuclei_placeholders() {
        let rendered = render_path_template(
            "https://demo.test:8443",
            "{{BaseURL}}/login?host={{Host}}&name={{Hostname}}&port={{Port}}",
        );
        assert_eq!(
            rendered,
            "https://demo.test:8443/login?host=demo.test:8443&name=demo.test&port=8443"
        );
    }

    #[test]
    fn join_target_path_renders_relative_template() {
        let url = join_target_path("https://demo.test:8443", "/api/{{Hostname}}");
        assert_eq!(url, "https://demo.test:8443/api/demo.test");
    }
}
