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
                if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
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
                arr.iter()
                    .filter_map(|m| parse_matcher(m).ok())
                    .collect::<Vec<_>>()
            })
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

fn contains_forbidden_sections(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["payloads:", "attack:", "raw:", "javascript:", "code:"]
        .iter()
        .any(|k| lower.contains(k))
}
