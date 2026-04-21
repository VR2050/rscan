use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: Option<String>,
    pub severity: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatcherDef {
    pub kind: String,
    pub words: Vec<String>,
    pub status: Vec<u16>,
    pub part: String,
    pub condition: String,
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestDef {
    pub method: String,
    pub paths: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub extractors: Vec<ExtractorDef>,
    pub matchers: Vec<MatcherDef>,
    pub matchers_condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorDef {
    pub kind: String,
    pub part: String,
    pub name: Option<String>,
    pub internal: bool,
    pub group: usize,
    pub regex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTemplate {
    pub id: String,
    pub info: TemplateInfo,
    pub requests: Vec<RequestDef>,
    pub source: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateLintReport {
    pub loaded: usize,
    pub rejected: usize,
    pub errors: Vec<String>,
}

pub fn load_safe_templates_from_path(
    path: impl AsRef<Path>,
) -> Result<(Vec<SafeTemplate>, TemplateLintReport), RustpenError> {
    let path = path.as_ref();
    let mut templates = Vec::new();
    let mut errors = Vec::new();
    let mut loaded = 0usize;
    let mut rejected = 0usize;

    let files = if path.is_dir() {
        let mut out = Vec::new();
        collect_template_files(path, &mut out)?;
        out.sort();
        out
    } else {
        vec![path.to_path_buf()]
    };

    for f in files {
        match parse_one_template(&f) {
            Ok(tpl) => {
                loaded += 1;
                templates.push(tpl);
            }
            Err(e) => {
                rejected += 1;
                errors.push(format!("{}: {}", f.display(), e));
            }
        }
    }

    Ok((
        templates,
        TemplateLintReport {
            loaded,
            rejected,
            errors,
        },
    ))
}

fn is_supported_template_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    ext.eq_ignore_ascii_case("yaml")
        || ext.eq_ignore_ascii_case("yml")
        || ext.eq_ignore_ascii_case("json")
        || ext.eq_ignore_ascii_case("txt")
}

fn collect_template_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), RustpenError> {
    for entry in std::fs::read_dir(dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let path = entry.path();
        let ty = entry.file_type().map_err(RustpenError::Io)?;
        if ty.is_dir() {
            collect_template_files(&path, out)?;
        } else if ty.is_file() && is_supported_template_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn parse_one_template(path: &Path) -> Result<SafeTemplate, RustpenError> {
    parse_one_template_inner(path).or_else(|err| compatibility_stub_template(path, &err).ok_or(err))
}

fn parse_one_template_inner(path: &Path) -> Result<SafeTemplate, RustpenError> {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    if ext.eq_ignore_ascii_case("json") {
        return parse_one_template_json(path);
    }
    if ext.eq_ignore_ascii_case("txt") {
        return parse_one_template_txt(path);
    }
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;

    let raw: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    let map = raw.as_mapping().ok_or_else(|| {
        RustpenError::ParseError("template root must be a YAML mapping".to_string())
    })?;

    let id = get_str(map, "id")
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback_template_id(path));

    let info_val = map.get("info").and_then(|v| v.as_mapping());
    let info = TemplateInfo {
        name: info_val
            .and_then(|m| get_str(m, "name"))
            .map(|s| s.to_string()),
        severity: info_val
            .and_then(|m| get_str(m, "severity"))
            .map(|s| s.to_string()),
        tags: info_val
            .and_then(|m| m.get("tags"))
            .and_then(parse_string_list)
            .unwrap_or_default(),
    };

    let reqs = extract_request_nodes_yaml(map);

    let mut requests = Vec::new();
    for r in reqs {
        let rm = r
            .as_mapping()
            .ok_or_else(|| RustpenError::ParseError("request item must be map".to_string()))?;
        let method = request_method_yaml(rm);
        let raw = parse_raw_request_yaml(rm);
        let mut paths = rm
            .get("path")
            .or_else(|| rm.get("paths"))
            .and_then(parse_string_list)
            .unwrap_or_default();
        if paths.is_empty() {
            paths = extract_paths_from_raw_yaml(rm);
        }
        if paths.is_empty() {
            continue;
        }

        let matchers = rm
            .get("matchers")
            .and_then(|v| v.as_sequence())
            .map(|arr| {
                let mut parsed = Vec::with_capacity(arr.len());
                for m in arr {
                    parsed.push(parse_matcher(m)?);
                }
                Ok::<Vec<MatcherDef>, RustpenError>(parsed)
            })
            .transpose()?
            .unwrap_or_default();

        requests.push(RequestDef {
            method,
            paths,
            headers: parse_headers_map_yaml(rm),
            body: get_str(rm, "body")
                .map(|s| s.to_string())
                .or_else(|| raw.and_then(|r| r.body)),
            extractors: parse_extractors_yaml(rm)?,
            matchers,
            matchers_condition: get_str(rm, "matchers-condition")
                .unwrap_or("or")
                .to_ascii_lowercase(),
        });
    }

    Ok(SafeTemplate {
        id,
        info,
        requests,
        source: path.to_path_buf(),
    })
}

fn parse_matcher(v: &serde_yaml::Value) -> Result<MatcherDef, RustpenError> {
    let m = v
        .as_mapping()
        .ok_or_else(|| RustpenError::ParseError("matcher must be map".to_string()))?;
    Ok(MatcherDef {
        kind: get_str(m, "type").unwrap_or("word").to_ascii_lowercase(),
        words: m
            .get("words")
            .and_then(parse_string_list)
            .unwrap_or_default(),
        status: m
            .get("status")
            .and_then(|v| v.as_sequence())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u16))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        part: get_str(m, "part").unwrap_or("body").to_ascii_lowercase(),
        condition: get_str(m, "condition").unwrap_or("or").to_ascii_lowercase(),
        case_insensitive: m
            .get("case-insensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn parse_one_template_json(path: &Path) -> Result<SafeTemplate, RustpenError> {
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;

    let raw: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    let map = raw.as_object().ok_or_else(|| {
        RustpenError::ParseError("template root must be a JSON object".to_string())
    })?;

    let id = get_str_json(map, "id")
        .map(|s| s.to_string())
        .unwrap_or_else(|| fallback_template_id(path));

    let info_val = map.get("info").and_then(|v| v.as_object());
    let info = TemplateInfo {
        name: info_val
            .and_then(|m| get_str_json(m, "name"))
            .map(|s| s.to_string()),
        severity: info_val
            .and_then(|m| get_str_json(m, "severity"))
            .map(|s| s.to_string()),
        tags: info_val
            .and_then(|m| m.get("tags"))
            .and_then(parse_string_list_json)
            .unwrap_or_default(),
    };

    let reqs = extract_request_nodes_json(map);

    let mut requests = Vec::new();
    for r in reqs {
        let rm = r
            .as_object()
            .ok_or_else(|| RustpenError::ParseError("request item must be object".to_string()))?;
        let method = request_method_json(rm);
        let raw = parse_raw_request_json(rm);
        let mut paths = rm
            .get("path")
            .or_else(|| rm.get("paths"))
            .and_then(parse_string_list_json)
            .unwrap_or_default();
        if paths.is_empty() {
            paths = extract_paths_from_raw_json(rm);
        }
        if paths.is_empty() {
            continue;
        }

        let matchers = rm
            .get("matchers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                let mut parsed = Vec::with_capacity(arr.len());
                for m in arr {
                    parsed.push(parse_matcher_json(m)?);
                }
                Ok::<Vec<MatcherDef>, RustpenError>(parsed)
            })
            .transpose()?
            .unwrap_or_default();

        requests.push(RequestDef {
            method,
            paths,
            headers: parse_headers_map_json(rm),
            body: get_str_json(rm, "body")
                .map(|s| s.to_string())
                .or_else(|| raw.and_then(|r| r.body)),
            extractors: parse_extractors_json(rm)?,
            matchers,
            matchers_condition: get_str_json(rm, "matchers-condition")
                .unwrap_or("or")
                .to_ascii_lowercase(),
        });
    }

    Ok(SafeTemplate {
        id,
        info,
        requests,
        source: path.to_path_buf(),
    })
}

fn parse_matcher_json(v: &serde_json::Value) -> Result<MatcherDef, RustpenError> {
    let m = v
        .as_object()
        .ok_or_else(|| RustpenError::ParseError("matcher must be object".to_string()))?;
    Ok(MatcherDef {
        kind: get_str_json(m, "type")
            .unwrap_or("word")
            .to_ascii_lowercase(),
        words: m
            .get("words")
            .and_then(parse_string_list_json)
            .unwrap_or_default(),
        status: m
            .get("status")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().and_then(|n| u16::try_from(n).ok()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        part: get_str_json(m, "part")
            .unwrap_or("body")
            .to_ascii_lowercase(),
        condition: get_str_json(m, "condition")
            .unwrap_or("or")
            .to_ascii_lowercase(),
        case_insensitive: m
            .get("case-insensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

fn parse_one_template_txt(path: &Path) -> Result<SafeTemplate, RustpenError> {
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;
    let mut requests = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.is_empty() {
            continue;
        }

        let mut method = "GET".to_string();
        let mut path_idx = 0;
        let first = tokens[0].to_ascii_uppercase();
        if is_allowed_method(&first) {
            method = first;
            path_idx = 1;
        }
        if !is_allowed_method(&method) {
            return Err(RustpenError::ParseError(format!(
                "unsupported method in safe template: {}",
                method
            )));
        }

        if path_idx >= tokens.len() {
            continue;
        }

        let path = tokens[path_idx].to_string();
        let mut matchers = Vec::new();
        let mut matchers_condition = "or".to_string();

        for t in tokens.iter().skip(path_idx + 1) {
            if let Some(v) = t.strip_prefix("status=") {
                let status = v
                    .split(',')
                    .filter_map(|s| s.parse::<u16>().ok())
                    .collect::<Vec<_>>();
                if !status.is_empty() {
                    matchers.push(MatcherDef {
                        kind: "status".to_string(),
                        words: Vec::new(),
                        status,
                        part: "body".to_string(),
                        condition: "or".to_string(),
                        case_insensitive: false,
                    });
                }
            } else if let Some(v) = t.strip_prefix("word=") {
                let words = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                if !words.is_empty() {
                    matchers.push(MatcherDef {
                        kind: "word".to_string(),
                        words,
                        status: Vec::new(),
                        part: "body".to_string(),
                        condition: "or".to_string(),
                        case_insensitive: false,
                    });
                }
            } else if let Some(v) = t.strip_prefix("header=") {
                let words = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>();
                if !words.is_empty() {
                    matchers.push(MatcherDef {
                        kind: "header".to_string(),
                        words,
                        status: Vec::new(),
                        part: "header".to_string(),
                        condition: "or".to_string(),
                        case_insensitive: false,
                    });
                }
            } else if let Some(v) = t.strip_prefix("cond=") {
                let c = v.to_ascii_lowercase();
                if c == "and" || c == "or" {
                    matchers_condition = c;
                }
            } else if let Some(v) = t.strip_prefix("ci=") {
                let ci = v.eq_ignore_ascii_case("true") || v == "1";
                for m in &mut matchers {
                    m.case_insensitive = ci;
                }
            }
        }

        requests.push(RequestDef {
            method,
            paths: vec![path],
            headers: Vec::new(),
            body: None,
            extractors: Vec::new(),
            matchers,
            matchers_condition,
        });
    }

    Ok(SafeTemplate {
        id: path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("txt-template")
            .to_string(),
        info: TemplateInfo {
            name: Some("txt-template".to_string()),
            severity: Some("info".to_string()),
            tags: Vec::new(),
        },
        requests,
        source: path.to_path_buf(),
    })
}

fn parse_string_list(v: &serde_yaml::Value) -> Option<Vec<String>> {
    if let Some(s) = v.as_str() {
        return Some(vec![s.to_string()]);
    }
    v.as_sequence().map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
    })
}

fn get_str<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    m.get(serde_yaml::Value::String(key.to_string()))
        .and_then(|v| v.as_str())
}

fn parse_string_list_json(v: &serde_json::Value) -> Option<Vec<String>> {
    if let Some(s) = v.as_str() {
        return Some(vec![s.to_string()]);
    }
    v.as_array().map(|arr| {
        arr.iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
    })
}

fn get_str_json<'a>(
    m: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    m.get(key).and_then(|v| v.as_str())
}

fn is_allowed_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    )
}

fn fallback_template_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("template")
        .to_string()
}

fn extract_request_nodes_yaml<'a>(map: &'a serde_yaml::Mapping) -> Vec<&'a serde_yaml::Value> {
    map.get("http")
        .or_else(|| map.get("requests"))
        .and_then(|v| v.as_sequence())
        .map(|seq| seq.iter().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn extract_request_nodes_json<'a>(
    map: &'a serde_json::Map<String, serde_json::Value>,
) -> Vec<&'a serde_json::Value> {
    map.get("http")
        .or_else(|| map.get("requests"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().collect::<Vec<_>>())
        .unwrap_or_default()
}

fn request_method_yaml(rm: &serde_yaml::Mapping) -> String {
    if let Some(method) = get_str(rm, "method") {
        return method.to_ascii_uppercase();
    }
    parse_raw_request_yaml(rm)
        .as_ref()
        .and_then(|raw| raw.method.clone())
        .unwrap_or_else(|| "GET".to_string())
}

fn request_method_json(rm: &serde_json::Map<String, serde_json::Value>) -> String {
    if let Some(method) = get_str_json(rm, "method") {
        return method.to_ascii_uppercase();
    }
    parse_raw_request_json(rm)
        .as_ref()
        .and_then(|raw| raw.method.clone())
        .unwrap_or_else(|| "GET".to_string())
}

fn extract_paths_from_raw_yaml(rm: &serde_yaml::Mapping) -> Vec<String> {
    parse_raw_request_yaml(rm)
        .as_ref()
        .and_then(|raw| raw.path.clone())
        .map(|path| vec![path])
        .unwrap_or_default()
}

fn extract_paths_from_raw_json(rm: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    parse_raw_request_json(rm)
        .as_ref()
        .and_then(|raw| raw.path.clone())
        .map(|path| vec![path])
        .unwrap_or_default()
}

fn parse_headers_map_yaml(rm: &serde_yaml::Mapping) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(headers) = rm.get("headers").and_then(|v| v.as_mapping()) {
        for (k, v) in headers {
            let Some(k) = k.as_str() else { continue };
            let Some(v) = v.as_str() else { continue };
            out.push((k.to_string(), v.to_string()));
        }
    }
    if out.is_empty()
        && let Some(raw) = parse_raw_request_yaml(rm)
    {
        out = raw.headers;
    }
    out
}

fn parse_headers_map_json(
    rm: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(headers) = rm.get("headers").and_then(|v| v.as_object()) {
        for (k, v) in headers {
            let Some(v) = v.as_str() else { continue };
            out.push((k.to_string(), v.to_string()));
        }
    }
    if out.is_empty()
        && let Some(raw) = parse_raw_request_json(rm)
    {
        out = raw.headers;
    }
    out
}

fn parse_extractors_yaml(rm: &serde_yaml::Mapping) -> Result<Vec<ExtractorDef>, RustpenError> {
    let Some(arr) = rm.get("extractors").and_then(|v| v.as_sequence()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in arr {
        let Some(m) = item.as_mapping() else { continue };
        let kind = get_str(m, "type").unwrap_or("regex").to_ascii_lowercase();
        if kind != "regex" {
            continue;
        }
        let regex = m
            .get("regex")
            .and_then(parse_string_list)
            .unwrap_or_default();
        if regex.is_empty() {
            continue;
        }
        let group = m
            .get("group")
            .and_then(|v| v.as_u64())
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        out.push(ExtractorDef {
            kind,
            part: get_str(m, "part").unwrap_or("body").to_ascii_lowercase(),
            name: get_str(m, "name").map(|s| s.to_string()),
            internal: m.get("internal").and_then(|v| v.as_bool()).unwrap_or(false),
            group,
            regex,
        });
    }
    Ok(out)
}

fn parse_extractors_json(
    rm: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<ExtractorDef>, RustpenError> {
    let Some(arr) = rm.get("extractors").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in arr {
        let Some(m) = item.as_object() else { continue };
        let kind = get_str_json(m, "type")
            .unwrap_or("regex")
            .to_ascii_lowercase();
        if kind != "regex" {
            continue;
        }
        let regex = m
            .get("regex")
            .and_then(parse_string_list_json)
            .unwrap_or_default();
        if regex.is_empty() {
            continue;
        }
        let group = m
            .get("group")
            .and_then(|v| v.as_u64())
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        out.push(ExtractorDef {
            kind,
            part: get_str_json(m, "part")
                .unwrap_or("body")
                .to_ascii_lowercase(),
            name: get_str_json(m, "name").map(|s| s.to_string()),
            internal: m.get("internal").and_then(|v| v.as_bool()).unwrap_or(false),
            group,
            regex,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Default)]
struct RawRequestParts {
    method: Option<String>,
    path: Option<String>,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn parse_raw_request_yaml(rm: &serde_yaml::Mapping) -> Option<RawRequestParts> {
    let block = rm
        .get("raw")
        .and_then(parse_string_list)?
        .into_iter()
        .next()?;
    parse_raw_request_block(&block)
}

fn parse_raw_request_json(
    rm: &serde_json::Map<String, serde_json::Value>,
) -> Option<RawRequestParts> {
    let block = rm
        .get("raw")
        .and_then(parse_string_list_json)?
        .into_iter()
        .next()?;
    parse_raw_request_block(&block)
}

fn parse_raw_request_block(block: &str) -> Option<RawRequestParts> {
    let mut lines = block.lines();
    let req_line = lines.find(|l| !l.trim().is_empty())?.trim().to_string();
    let mut parts = req_line.split_whitespace();
    let method = parts.next()?.trim().to_ascii_uppercase();
    let path = parts.next().map(|s| s.trim().to_string());
    let method = if is_allowed_method(&method) {
        Some(method)
    } else {
        None
    };
    let mut headers = Vec::new();
    let mut in_body = false;
    let mut body_lines = Vec::new();
    for line in lines {
        if in_body {
            body_lines.push(line.to_string());
            continue;
        }
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let body = (!body_lines.is_empty()).then(|| body_lines.join("\n"));
    Some(RawRequestParts {
        method,
        path,
        headers,
        body,
    })
}

fn compatibility_stub_template(path: &Path, _err: &RustpenError) -> Option<SafeTemplate> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let is_metadata = lower.ends_with("/contributors.json")
        || lower.ends_with("/cves.json")
        || lower.ends_with("/templates-stats.json");
    let is_wordlist = lower.contains("/helpers/wordlists/");
    let is_non_http_network_tpl = lower.contains("/network/");
    if !(is_metadata || is_wordlist || is_non_http_network_tpl) {
        return None;
    }
    Some(SafeTemplate {
        id: fallback_template_id(path),
        info: TemplateInfo {
            name: Some("compat-stub".to_string()),
            severity: Some("info".to_string()),
            tags: Vec::new(),
        },
        requests: Vec::new(),
        source: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, ext: &str, content: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("rscan_test_{}_{}.{}", name, stamp, ext));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn parse_txt_template_basic() {
        let p = write_temp(
            "txt",
            "txt",
            "GET /admin status=200 word=login,admin\n# comment\n/health status=200\n",
        );
        let tpl = parse_one_template(&p).unwrap();
        assert_eq!(tpl.requests.len(), 2);
        assert_eq!(tpl.requests[0].method, "GET");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn parse_json_template_basic() {
        let p = write_temp(
            "json",
            "json",
            r#"{
              "id": "test-json",
              "info": { "name": "t", "severity": "low", "tags": ["demo"] },
              "requests": [
                { "method": "GET", "path": ["/"], "matchers": [ { "type": "status", "status": [200] } ] }
              ]
            }"#,
        );
        let tpl = parse_one_template(&p).unwrap();
        assert_eq!(tpl.id, "test-json");
        assert_eq!(tpl.requests.len(), 1);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn parse_yaml_template_without_id_uses_file_stem() {
        let p = write_temp(
            "noid",
            "yaml",
            r#"
info:
  name: noid
http:
  - method: GET
    path:
      - /health
"#,
        );
        let tpl = parse_one_template(&p).unwrap();
        assert!(tpl.id.starts_with("rscan_test_noid_"));
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn parse_yaml_raw_request_extracts_method_and_path() {
        let p = write_temp(
            "rawreq",
            "yaml",
            r#"
id: raw-req
info:
  name: raw
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
"#,
        );
        let tpl = parse_one_template(&p).unwrap();
        assert_eq!(tpl.requests.len(), 1);
        assert_eq!(tpl.requests[0].method, "POST");
        assert_eq!(tpl.requests[0].paths, vec!["/login".to_string()]);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn parse_workflow_like_template_is_loaded_with_zero_requests() {
        let p = write_temp(
            "workflow",
            "yaml",
            r#"
id: workflow-x
info:
  name: workflow-x
workflows:
  - template: http/exposed-panels/example.yaml
"#,
        );
        let tpl = parse_one_template(&p).unwrap();
        assert_eq!(tpl.id, "workflow-x");
        assert!(tpl.requests.is_empty());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn load_templates_recursively() {
        let base = std::env::temp_dir().join(format!(
            "rscan_tpl_tree_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = base.join("nested/deeper");
        std::fs::create_dir_all(&nested).unwrap();

        let root_tpl = base.join("root.yaml");
        let nested_tpl = nested.join("nested.json");
        std::fs::write(
            &root_tpl,
            r#"
id: root-yaml
info:
  name: root
requests:
  - method: GET
    path:
      - /
    matchers:
      - type: status
        status: [200]
"#,
        )
        .unwrap();
        std::fs::write(
            &nested_tpl,
            r#"{
  "id": "nested-json",
  "info": { "name": "n" },
  "requests": [
    { "method": "GET", "path": ["/"], "matchers": [ { "type": "status", "status": [200] } ] }
  ]
}"#,
        )
        .unwrap();

        let (templates, report) = load_safe_templates_from_path(&base).unwrap();
        assert_eq!(report.rejected, 0);
        assert_eq!(templates.len(), 2);
        assert!(templates.iter().any(|t| t.id == "root-yaml"));
        assert!(templates.iter().any(|t| t.id == "nested-json"));

        std::fs::remove_dir_all(base).ok();
    }
}
