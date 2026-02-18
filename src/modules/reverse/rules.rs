use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::errors::RustpenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleThresholds {
    pub high_entropy: f64,
    pub apk_high_entropy: f64,
    pub tiny_import_table_max: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleLibrary {
    pub anti_debug_keywords: Vec<String>,
    pub suspicious_import_keywords: Vec<String>,
    pub suspicious_string_keywords: Vec<String>,
    pub packer_section_names: Vec<String>,
    pub packer_string_keywords: Vec<String>,
    pub thresholds: RuleThresholds,
}

impl Default for RuleLibrary {
    fn default() -> Self {
        Self {
            anti_debug_keywords: vec![
                "ptrace".to_string(),
                "isdebuggerpresent".to_string(),
                "checkremotedebuggerpresent".to_string(),
                "ntqueryinformationprocess".to_string(),
                "tracerpid".to_string(),
                "frida".to_string(),
                "xposed".to_string(),
                "gdb".to_string(),
                "windbg".to_string(),
                "ollydbg".to_string(),
            ],
            suspicious_import_keywords: vec![
                "virtualprotect".to_string(),
                "writeprocessmemory".to_string(),
                "createremotethread".to_string(),
                "loadlibrary".to_string(),
                "getprocaddress".to_string(),
                "dlopen".to_string(),
                "dlsym".to_string(),
                "execve".to_string(),
                "system".to_string(),
                "socket".to_string(),
                "connect".to_string(),
            ],
            suspicious_string_keywords: vec![
                "/proc/self/status".to_string(),
                "sandbox".to_string(),
                "vmware".to_string(),
                "vbox".to_string(),
                "upx".to_string(),
            ],
            packer_section_names: vec![
                "UPX0".to_string(),
                "UPX1".to_string(),
                "UPX2".to_string(),
                ".aspack".to_string(),
                ".petite".to_string(),
                ".packed".to_string(),
                ".vmp0".to_string(),
                ".vmp1".to_string(),
            ],
            packer_string_keywords: vec![
                "upx".to_string(),
                "aspack".to_string(),
                "vmprotect".to_string(),
            ],
            thresholds: RuleThresholds {
                high_entropy: 7.2,
                apk_high_entropy: 7.5,
                tiny_import_table_max: 2,
            },
        }
    }
}

impl RuleLibrary {
    pub fn load(path: &Path) -> Result<Self, RustpenError> {
        let raw = std::fs::read_to_string(path)?;
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        match ext.as_str() {
            "yaml" | "yml" => serde_yaml::from_str(&raw)
                .map_err(|e| RustpenError::ParseError(format!("invalid YAML rules file: {}", e))),
            "json" => serde_json::from_str(&raw)
                .map_err(|e| RustpenError::ParseError(format!("invalid JSON rules file: {}", e))),
            _ => {
                if raw.trim_start().starts_with('{') {
                    serde_json::from_str(&raw).map_err(|e| {
                        RustpenError::ParseError(format!(
                            "unable to parse rules as JSON (extension not set): {}",
                            e
                        ))
                    })
                } else {
                    serde_yaml::from_str(&raw).map_err(|e| {
                        RustpenError::ParseError(format!(
                            "unable to parse rules as YAML (extension not set): {}",
                            e
                        ))
                    })
                }
            }
        }
    }

    pub fn write_template(path: &Path) -> Result<(), RustpenError> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("yaml")
            .to_ascii_lowercase();
        let rules = Self::default();
        let content = if ext == "json" {
            serde_json::to_string_pretty(&rules).map_err(|e| {
                RustpenError::ParseError(format!("serialize rules to JSON failed: {}", e))
            })?
        } else {
            serde_yaml::to_string(&rules).map_err(|e| {
                RustpenError::ParseError(format!("serialize rules to YAML failed: {}", e))
            })?
        };
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RuleHotReloader {
    path: std::path::PathBuf,
    mtime: Option<std::time::SystemTime>,
    cached: RuleLibrary,
}

impl RuleHotReloader {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<Self, RustpenError> {
        let path = path.into();
        let md = std::fs::metadata(&path)?;
        let mtime = md.modified().ok();
        let cached = RuleLibrary::load(&path)?;
        Ok(Self {
            path,
            mtime,
            cached,
        })
    }

    pub fn rules(&mut self) -> Result<&RuleLibrary, RustpenError> {
        let md = std::fs::metadata(&self.path)?;
        let new_mtime = md.modified().ok();
        let changed = match (self.mtime, new_mtime) {
            (Some(old), Some(new)) => new > old,
            (None, Some(_)) => true,
            _ => false,
        };

        if changed {
            self.cached = RuleLibrary::load(&self.path)?;
            self.mtime = new_mtime;
        }

        Ok(&self.cached)
    }
}

#[cfg(test)]
mod tests {
    use super::RuleLibrary;

    #[test]
    fn rules_template_roundtrip_yaml() {
        let path = std::env::temp_dir().join("rscan_rules_template.yaml");
        RuleLibrary::write_template(&path).unwrap();
        let loaded = RuleLibrary::load(&path).unwrap();
        assert!(!loaded.anti_debug_keywords.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
