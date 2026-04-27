use std::time::Instant;

use reqwest::{Response, header::HeaderMap};
use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

/// Generic PoC matcher container.
#[derive(Debug, Clone)]
pub struct PocScan<F, T>
where
    F: Fn(&Response, &T) -> bool,
{
    pub poc: HeaderMap,
    pub scan_func: F,
    pub scan_match: T,
}

impl<F, T> PocScan<F, T>
where
    F: Fn(&Response, &T) -> bool,
{
    pub fn new(poc: HeaderMap, scan_func: F, scan_match: T) -> Self {
        Self {
            poc,
            scan_func,
            scan_match,
        }
    }

    pub fn evaluate(&self, response: &Response) -> bool {
        (self.scan_func)(response, &self.scan_match)
    }
}

// Backward-compatible alias with original name.
pub type POCSCAN<F, T> = PocScan<F, T>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocHttpConfig {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout_ms: u64,
    pub expect_status: Vec<u16>,
    pub expect_body_words: Vec<String>,
    pub expect_header_words: Vec<String>,
    pub expect_all: bool,
    pub case_insensitive: bool,
}

impl Default for PocHttpConfig {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: None,
            timeout_ms: 5000,
            expect_status: vec![200],
            expect_body_words: Vec::new(),
            expect_header_words: Vec::new(),
            expect_all: false,
            case_insensitive: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocHttpReport {
    pub target: String,
    pub url: String,
    pub method: String,
    pub status: Option<u16>,
    pub content_len: u64,
    pub response_time_ms: u64,
    pub matched: Vec<String>,
    pub vulnerable: bool,
    pub errors: Vec<String>,
}

pub async fn run_poc_http_probe(
    target: &str,
    cfg: PocHttpConfig,
) -> Result<PocHttpReport, RustpenError> {
    let url = join_target_path(target, &cfg.path);
    let method = reqwest::Method::from_bytes(cfg.method.as_bytes())
        .map_err(|e| RustpenError::ParseError(format!("invalid method '{}': {}", cfg.method, e)))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let mut req = client.request(method, &url);
    for (k, v) in &cfg.headers {
        req = req.header(k, v);
    }
    if let Some(body) = cfg.body.as_ref() {
        req = req.body(body.clone());
    }

    let started = Instant::now();
    let resp = req
        .send()
        .await
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;
    let status = resp.status().as_u16();
    let headers = flatten_headers(resp.headers());
    let body = resp.bytes().await.unwrap_or_default();
    let body = String::from_utf8_lossy(&body).to_string();
    let response_time_ms = started.elapsed().as_millis() as u64;
    let content_len = body.len() as u64;
    let matched = collect_matches(status, &headers, &body, &cfg);

    let expected_total =
        cfg.expect_status.len() + cfg.expect_body_words.len() + cfg.expect_header_words.len();
    let vulnerable = if expected_total == 0 {
        false
    } else if cfg.expect_all {
        matched.len() == expected_total
    } else {
        !matched.is_empty()
    };

    Ok(PocHttpReport {
        target: target.to_string(),
        url,
        method: cfg.method,
        status: Some(status),
        content_len,
        response_time_ms,
        matched,
        vulnerable,
        errors: Vec::new(),
    })
}

fn join_target_path(target: &str, path: &str) -> String {
    let t = target.trim_end_matches('/');
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{t}{path}")
    } else {
        format!("{t}/{path}")
    }
}

fn flatten_headers(headers: &HeaderMap) -> String {
    headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.as_str(), v.to_str().unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_matches(status: u16, headers: &str, body: &str, cfg: &PocHttpConfig) -> Vec<String> {
    let mut out = Vec::new();
    if cfg.expect_status.contains(&status) {
        out.push(format!("status:{status}"));
    }
    let body_hay = if cfg.case_insensitive {
        body.to_ascii_lowercase()
    } else {
        String::new()
    };
    let headers_hay = if cfg.case_insensitive {
        headers.to_ascii_lowercase()
    } else {
        String::new()
    };
    for word in &cfg.expect_body_words {
        let hit = if cfg.case_insensitive {
            body_hay.contains(&word.to_ascii_lowercase())
        } else {
            body.contains(word)
        };
        if hit {
            out.push(format!("body:{word}"));
        }
    }
    for word in &cfg.expect_header_words {
        let hit = if cfg.case_insensitive {
            headers_hay.contains(&word.to_ascii_lowercase())
        } else {
            headers.contains(word)
        };
        if hit {
            out.push(format!("header:{word}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{PocHttpConfig, collect_matches, join_target_path};

    #[test]
    fn join_target_path_supports_relative_and_absolute() {
        assert_eq!(
            join_target_path("https://example.com/", "/login"),
            "https://example.com/login"
        );
        assert_eq!(
            join_target_path("https://example.com", "https://demo.test/x"),
            "https://demo.test/x"
        );
    }

    #[test]
    fn collect_matches_honors_case_insensitive() {
        let cfg = PocHttpConfig {
            expect_status: vec![200],
            expect_body_words: vec!["Token".to_string()],
            expect_header_words: vec!["Server: nginx".to_string()],
            case_insensitive: true,
            ..PocHttpConfig::default()
        };
        let matched = collect_matches(
            200,
            "server: NGINX\nx-powered-by:test",
            "csrf token found",
            &cfg,
        );
        assert!(matched.iter().any(|m| m == "status:200"));
        assert!(matched.iter().any(|m| m == "body:Token"));
        assert!(matched.iter().any(|m| m == "header:Server: nginx"));
    }
}
