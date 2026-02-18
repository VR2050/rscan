use std::path::Path;

use regex::bytes::Regex;

use crate::cores::engine::scan_result::ScanResult;
use crate::errors::RustpenError;

#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    pub service: String,
    pub version: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub banner: Option<String>,
    pub fingerprint: Option<ServiceFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ProbeSignature {
    pub protocol: ProbeProtocol,
    pub name: String,
    pub payload: Vec<u8>,
    pub ports: Vec<u16>,
    pub rarity: Option<u8>,
    pub fallback: Vec<String>,
}

#[derive(Debug, Clone)]
struct MatchRule {
    service: String,
    regex: Regex,
    version_hint: Option<String>,
    soft: bool,
    ports: Vec<u16>,
    rarity: Option<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct ProbeDatabase {
    pub probes: Vec<ProbeSignature>,
    rules: Vec<MatchRule>,
}

#[derive(Clone)]
pub struct ServiceProbeEngine {
    db: ProbeDatabase,
}

impl ServiceProbeEngine {
    pub fn new() -> Self {
        Self {
            db: ProbeDatabase::default(),
        }
    }

    pub fn from_nmap_file(path: impl AsRef<Path>) -> Result<Self, RustpenError> {
        let content = std::fs::read_to_string(path).map_err(RustpenError::Io)?;
        Self::from_nmap_text(&content)
    }

    pub fn from_nmap_text(input: &str) -> Result<Self, RustpenError> {
        let mut db = ProbeDatabase::default();
        let mut current_probe: Option<usize> = None;
        for raw in input.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with("Probe ") {
                let probe = parse_probe_line(line)?;
                db.probes.push(probe);
                current_probe = Some(db.probes.len() - 1);
                continue;
            }
            if line.starts_with("ports ") {
                if let Some(idx) = current_probe {
                    db.probes[idx].ports = parse_ports_directive(line)?;
                }
                continue;
            }
            if line.starts_with("rarity ") {
                if let Some(idx) = current_probe {
                    db.probes[idx].rarity = parse_rarity_directive(line)?;
                }
                continue;
            }
            if line.starts_with("fallback ") {
                if let Some(idx) = current_probe {
                    db.probes[idx].fallback = parse_fallback_directive(line);
                }
                continue;
            }
            if line.starts_with("match ") {
                let rule = parse_match_line(line, false)?;
                db.rules.push(rule);
                continue;
            }
            if line.starts_with("softmatch ") {
                let rule = parse_match_line(line, true)?;
                db.rules.push(rule);
            }
        }
        Ok(Self { db })
    }

    pub fn probes(&self) -> &[ProbeSignature] {
        &self.db.probes
    }

    pub fn identify(&self, data: &[u8]) -> Option<ServiceFingerprint> {
        self.identify_with_context(data, None)
    }

    pub fn identify_with_context(
        &self,
        data: &[u8],
        port: Option<u16>,
    ) -> Option<ServiceFingerprint> {
        // Prefer hard matches first, then softmatches.
        for rule in &self.db.rules {
            if rule.soft {
                continue;
            }
            if !port_allowed(&rule.ports, port) {
                continue;
            }
            if rule.regex.is_match(data) {
                return Some(ServiceFingerprint {
                    service: rule.service.clone(),
                    version: rule.version_hint.clone(),
                    confidence: confidence_for(false, rule.rarity),
                });
            }
        }
        for rule in &self.db.rules {
            if !rule.soft {
                continue;
            }
            if !port_allowed(&rule.ports, port) {
                continue;
            }
            if rule.regex.is_match(data) {
                return Some(ServiceFingerprint {
                    service: rule.service.clone(),
                    version: rule.version_hint.clone(),
                    confidence: confidence_for(true, rule.rarity),
                });
            }
        }
        None
    }

    pub fn probe(&self, data: &[u8]) -> ProbeResult {
        let banner = std::str::from_utf8(data).ok().map(|s| s.to_string());
        let fingerprint = self.identify(data);
        ProbeResult {
            banner,
            fingerprint,
        }
    }

    pub fn enrich_scan_result(&self, mut result: ScanResult) -> ScanResult {
        if let Some(resp) = &result.response {
            let banner = std::str::from_utf8(resp).ok().map(|s| s.to_string());
            let fingerprint = self.identify_with_context(resp, result.port);
            let p = ProbeResult {
                banner,
                fingerprint,
            };
            if let Some(fp) = p.fingerprint {
                result = result.with_meta("service", fp.service);
                if let Some(v) = fp.version {
                    result = result.with_meta("service_version", v);
                }
                result = result.with_meta("service_confidence", fp.confidence.to_string());
            }
            if let Some(banner) = p.banner {
                result = result.with_meta("banner_text", banner);
            }
        }
        result
    }
}

fn parse_probe_line(line: &str) -> Result<ProbeSignature, RustpenError> {
    // 例: Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
    let mut parts = line.splitn(4, ' ');
    let _probe_kw = parts.next();
    let proto = parts
        .next()
        .ok_or_else(|| RustpenError::ParseError("invalid Probe line (protocol)".to_string()))?;
    let name = parts
        .next()
        .ok_or_else(|| RustpenError::ParseError("invalid Probe line (name)".to_string()))?;
    let payload_part = parts
        .next()
        .ok_or_else(|| RustpenError::ParseError("invalid Probe line (payload)".to_string()))?;

    let protocol = match proto {
        "TCP" => ProbeProtocol::Tcp,
        "UDP" => ProbeProtocol::Udp,
        _ => {
            return Err(RustpenError::ParseError(format!(
                "unsupported probe protocol: {proto}"
            )));
        }
    };

    let payload = parse_quoted_payload(payload_part)?;
    Ok(ProbeSignature {
        protocol,
        name: name.to_string(),
        payload,
        ports: Vec::new(),
        rarity: None,
        fallback: Vec::new(),
    })
}

fn parse_match_line(line: &str, soft: bool) -> Result<MatchRule, RustpenError> {
    // 例: match http m|^HTTP/1\\.[01] \\d\\d\\d| p/Generic httpd/
    let prefix = if soft { "softmatch " } else { "match " };
    let after = line
        .strip_prefix(prefix)
        .ok_or_else(|| RustpenError::ParseError("invalid match line prefix".to_string()))?;
    let mut service_split = after.splitn(2, ' ');
    let service = service_split
        .next()
        .ok_or_else(|| RustpenError::ParseError("invalid match line (service)".to_string()))?;
    let rest = service_split
        .next()
        .ok_or_else(|| RustpenError::ParseError("invalid match line (pattern+attrs)".to_string()))?
        .trim_start();

    if !rest.starts_with('m') || rest.len() < 2 {
        return Err(RustpenError::ParseError(
            "invalid match pattern prefix".to_string(),
        ));
    }
    let delim = rest
        .chars()
        .nth(1)
        .ok_or_else(|| RustpenError::ParseError("invalid match delimiter".to_string()))?;
    let body_start = 2usize;
    let tail = &rest[body_start..];
    let body_end = tail
        .find(delim)
        .ok_or_else(|| RustpenError::ParseError("invalid match pattern body".to_string()))?;
    let pattern = tail[..body_end].to_string();
    let regex = Regex::new(&pattern)
        .map_err(|e| RustpenError::ParseError(format!("invalid regex: {e}")))?;

    let remaining = tail[body_end + 1..].trim_start();
    let version_hint = extract_tag_value(remaining, "p");
    let ports = extract_tag_value(remaining, "ports")
        .map(|s| parse_ports_field(&s))
        .transpose()?
        .unwrap_or_default();
    let rarity = extract_tag_value(remaining, "rarity").and_then(|s| s.parse::<u8>().ok());

    Ok(MatchRule {
        service: service.to_string(),
        regex,
        version_hint,
        soft,
        ports,
        rarity,
    })
}

fn parse_ports_directive(line: &str) -> Result<Vec<u16>, RustpenError> {
    let raw = line
        .strip_prefix("ports ")
        .ok_or_else(|| RustpenError::ParseError("invalid ports directive".to_string()))?;
    parse_ports_field(raw)
}

fn parse_rarity_directive(line: &str) -> Result<Option<u8>, RustpenError> {
    let raw = line
        .strip_prefix("rarity ")
        .ok_or_else(|| RustpenError::ParseError("invalid rarity directive".to_string()))?
        .trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let v = raw
        .parse::<u8>()
        .map_err(|e| RustpenError::ParseError(format!("invalid rarity: {e}")))?;
    Ok(Some(v))
}

fn parse_fallback_directive(line: &str) -> Vec<String> {
    let raw = line.strip_prefix("fallback ").unwrap_or("").trim();
    raw.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse_ports_field(raw: &str) -> Result<Vec<u16>, RustpenError> {
    let mut ports = Vec::new();
    for token in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = token.split_once('-') {
            let start = a
                .trim()
                .parse::<u16>()
                .map_err(|e| RustpenError::ParseError(format!("invalid port range start: {e}")))?;
            let end = b
                .trim()
                .parse::<u16>()
                .map_err(|e| RustpenError::ParseError(format!("invalid port range end: {e}")))?;
            if start > end {
                return Err(RustpenError::ParseError(
                    "invalid port range (start>end)".to_string(),
                ));
            }
            ports.extend(start..=end);
        } else {
            let p = token
                .parse::<u16>()
                .map_err(|e| RustpenError::ParseError(format!("invalid port: {e}")))?;
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn port_allowed(rule_ports: &[u16], port: Option<u16>) -> bool {
    if rule_ports.is_empty() {
        return true;
    }
    match port {
        Some(p) => rule_ports.binary_search(&p).is_ok(),
        None => true,
    }
}

fn confidence_for(soft: bool, rarity: Option<u8>) -> u8 {
    let base = if soft { 60u8 } else { 90u8 };
    let penalty = rarity.unwrap_or(0).min(40) / 2;
    base.saturating_sub(penalty)
}

fn parse_quoted_payload(payload_part: &str) -> Result<Vec<u8>, RustpenError> {
    let body = extract_delimited_body(payload_part, 'q')
        .ok_or_else(|| RustpenError::ParseError("invalid probe payload".to_string()))?;
    Ok(unescape_nmap_payload(&body))
}

fn extract_delimited_body(input: &str, prefix: char) -> Option<String> {
    // 支持 q|...| / m/.../ 等形式，分隔符为 prefix 后第一个字符
    let mut chars = input.chars();
    if chars.next()? != prefix {
        return None;
    }
    let delim = chars.next()?;
    let rest: String = chars.collect();
    let end = rest.rfind(delim)?;
    Some(rest[..end].to_string())
}

fn extract_tag_value(input: &str, tag: &str) -> Option<String> {
    // 例: p/Apache httpd/ 或 v/1.2.3/
    let pattern = format!("{tag}/");
    let start = input.find(&pattern)?;
    let from = start + pattern.len();
    let tail = &input[from..];
    let end = tail.find('/')?;
    Some(tail[..end].to_string())
}

fn unescape_nmap_payload(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'x' if i + 3 < bytes.len() => {
                    let hex = &s[i + 2..i + 4];
                    if let Ok(v) = u8::from_str_radix(hex, 16) {
                        out.push(v);
                        i += 4;
                        continue;
                    }
                }
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_probe_and_match_minimal() {
        let text = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d\d\d| p/Generic httpd/
"#;
        let engine = ServiceProbeEngine::from_nmap_text(text).unwrap();
        assert_eq!(engine.probes().len(), 1);
        let probe = &engine.probes()[0];
        assert_eq!(probe.protocol, ProbeProtocol::Tcp);
        assert!(probe.payload.starts_with(b"GET / HTTP/1.0"));

        let resp = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n";
        let fp = engine.identify(resp).unwrap();
        assert_eq!(fp.service, "http");
        assert_eq!(fp.version, Some("Generic httpd".to_string()));
    }

    #[test]
    fn parse_softmatch_ports_rarity_fallback() {
        let text = r#"
Probe TCP Hello q|HELLO\r\n|
ports 80,443,8000-8001
rarity 7
fallback GenericLines
match http m|^HTTP/1\.[01] \d\d\d| p/Generic httpd/ ports/80,443/ rarity/2/
softmatch http m|^HTTP/| p/soft/ ports/80,443/ rarity/8/
"#;
        let engine = ServiceProbeEngine::from_nmap_text(text).unwrap();
        assert_eq!(engine.probes().len(), 1);
        let p = &engine.probes()[0];
        assert_eq!(p.ports, vec![80, 443, 8000, 8001]);
        assert_eq!(p.rarity, Some(7));
        assert_eq!(p.fallback, vec!["GenericLines".to_string()]);

        // Hard match on allowed port.
        let fp = engine
            .identify_with_context(b"HTTP/1.1 200 OK\r\n\r\n", Some(80))
            .unwrap();
        assert_eq!(fp.service, "http");
        assert!(fp.confidence >= 80);

        // No match outside allowed ports.
        assert!(
            engine
                .identify_with_context(b"HTTP/1.1 200 OK\r\n\r\n", Some(1234))
                .is_none()
        );
    }
}
