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
    pub matchers: Vec<MatcherDef>,
    pub matchers_condition: String,
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
        for entry in std::fs::read_dir(path).map_err(RustpenError::Io)? {
            let entry = entry.map_err(RustpenError::Io)?;
            let p = entry.path();
            if p.is_file() {
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or_default();
                if ext.eq_ignore_ascii_case("yaml")
                    || ext.eq_ignore_ascii_case("yml")
                    || ext.eq_ignore_ascii_case("json")
                    || ext.eq_ignore_ascii_case("txt")
                {
                    out.push(p);
                }
            }
        }
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

fn parse_one_template(path: &Path) -> Result<SafeTemplate, RustpenError> {
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
    if contains_forbidden_sections(&text) {
        return Err(RustpenError::ParseError(
            "template contains unsupported/unsafe sections".to_string(),
        ));
    }

    let raw: serde_yaml::Value =
        serde_yaml::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    let map = raw.as_mapping().ok_or_else(|| {
        RustpenError::ParseError("template root must be a YAML mapping".to_string())
    })?;

    let id = get_str(map, "id")
        .ok_or_else(|| RustpenError::PocRuleInvalid {
            name: path.display().to_string(),
            field: "id".to_string(),
        })?
        .to_string();

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

    let req_node = map
        .get("http")
        .or_else(|| map.get("requests"))
        .ok_or_else(|| RustpenError::PocRuleInvalid {
            name: id.clone(),
            field: "http/requests".to_string(),
        })?;
    let reqs = req_node
        .as_sequence()
        .ok_or_else(|| RustpenError::ParseError("http/requests must be an array".to_string()))?;

    let mut requests = Vec::new();
    for r in reqs {
        let rm = r
            .as_mapping()
            .ok_or_else(|| RustpenError::ParseError("request item must be map".to_string()))?;
        let method = get_str(rm, "method").unwrap_or("GET").to_ascii_uppercase();
        if !is_allowed_method(&method) {
            return Err(RustpenError::ParseError(format!(
                "unsupported method in safe template: {}",
                method
            )));
        }
        let paths = rm
            .get("path")
            .or_else(|| rm.get("paths"))
            .and_then(parse_string_list)
            .unwrap_or_default();
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
            matchers,
            matchers_condition: get_str(rm, "matchers-condition")
                .unwrap_or("or")
                .to_ascii_lowercase(),
        });
    }

    if requests.is_empty() {
        return Err(RustpenError::PocRuleInvalid {
            name: id.clone(),
            field: "requests".to_string(),
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
    if contains_forbidden_sections(&text) {
        return Err(RustpenError::ParseError(
            "template contains unsupported/unsafe sections".to_string(),
        ));
    }

    let raw: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))?;
    let map = raw.as_object().ok_or_else(|| {
        RustpenError::ParseError("template root must be a JSON object".to_string())
    })?;

    let id = get_str_json(map, "id")
        .ok_or_else(|| RustpenError::PocRuleInvalid {
            name: path.display().to_string(),
            field: "id".to_string(),
        })?
        .to_string();

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

    let req_node = map
        .get("http")
        .or_else(|| map.get("requests"))
        .ok_or_else(|| RustpenError::PocRuleInvalid {
            name: id.clone(),
            field: "http/requests".to_string(),
        })?;
    let reqs = req_node
        .as_array()
        .ok_or_else(|| RustpenError::ParseError("http/requests must be an array".to_string()))?;

    let mut requests = Vec::new();
    for r in reqs {
        let rm = r
            .as_object()
            .ok_or_else(|| RustpenError::ParseError("request item must be object".to_string()))?;
        let method = get_str_json(rm, "method")
            .unwrap_or("GET")
            .to_ascii_uppercase();
        if !is_allowed_method(&method) {
            return Err(RustpenError::ParseError(format!(
                "unsupported method in safe template: {}",
                method
            )));
        }
        let paths = rm
            .get("path")
            .or_else(|| rm.get("paths"))
            .and_then(parse_string_list_json)
            .unwrap_or_default();
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
            matchers,
            matchers_condition: get_str_json(rm, "matchers-condition")
                .unwrap_or("or")
                .to_ascii_lowercase(),
        });
    }

    if requests.is_empty() {
        return Err(RustpenError::PocRuleInvalid {
            name: id.clone(),
            field: "requests".to_string(),
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
    for (idx, raw) in text.lines().enumerate() {
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
            return Err(RustpenError::ParseError(format!(
                "txt template missing path at line {}",
                idx + 1
            )));
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
            matchers,
            matchers_condition,
        });
    }

    if requests.is_empty() {
        return Err(RustpenError::ParseError(
            "txt template contains no valid rules".to_string(),
        ));
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
    matches!(method, "GET" | "HEAD")
}

fn contains_forbidden_sections(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["payloads:", "attack:", "raw:", "javascript:", "code:"]
        .iter()
        .any(|k| lower.contains(k))
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
}
