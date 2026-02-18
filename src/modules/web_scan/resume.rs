use crate::errors::RustpenError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    pub mode: String,
    pub target: String,
    pub completed_requests: HashSet<String>,
    pub discovered_urls: HashSet<String>,
}

impl ResumeState {
    pub fn new(mode: &str, target: &str) -> Self {
        Self {
            mode: mode.to_string(),
            target: target.to_string(),
            completed_requests: HashSet::new(),
            discovered_urls: HashSet::new(),
        }
    }

    pub fn is_done(&self, request_key: &str) -> bool {
        self.completed_requests.contains(request_key)
    }

    pub fn mark_done(&mut self, request_key: &str) {
        self.completed_requests.insert(request_key.to_string());
    }

    pub fn mark_discovered(&mut self, url: &str) {
        self.discovered_urls.insert(url.to_string());
    }
}

pub fn load_or_new(file: &Path, mode: &str, target: &str) -> Result<ResumeState, RustpenError> {
    if !file.exists() {
        return Ok(ResumeState::new(mode, target));
    }
    let raw = std::fs::read_to_string(file)?;
    let mut st: ResumeState = serde_json::from_str(&raw)
        .map_err(|e| RustpenError::ParseError(format!("invalid resume file: {}", e)))?;
    if st.mode != mode || st.target != target {
        st = ResumeState::new(mode, target);
    }
    Ok(st)
}

pub fn save(file: &Path, st: &ResumeState) -> Result<(), RustpenError> {
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let raw = serde_json::to_string_pretty(st)
        .map_err(|e| RustpenError::ParseError(format!("resume serialize failed: {}", e)))?;
    std::fs::write(file, raw)?;
    Ok(())
}

pub fn maybe_resume_path(path: &Option<PathBuf>) -> Option<&Path> {
    path.as_deref()
}
