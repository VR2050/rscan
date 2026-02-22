use std::path::Path;
use std::path::PathBuf;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DecompileMode, ToolInvocation};
use crate::modules::reverse::tooling::ReverseTooling;
use sha2::Digest;

use super::{BackendBinary, BackendCapabilities, BackendKind, ReverseBackend};

pub struct GhidraBackend {
    binary: BackendBinary,
}

impl GhidraBackend {
    pub fn new(binary: BackendBinary) -> Self {
        Self { binary }
    }
}

impl ReverseBackend for GhidraBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Ghidra
    }

    fn name(&self) -> &'static str {
        "ghidra"
    }

    fn binary(&self) -> &BackendBinary {
        &self.binary
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            pseudocode: true,
            debugging: false,
            symbols: true,
            apk_decompile: false,
        }
    }

    fn build_pseudocode_plan(
        &self,
        input: &Path,
        out_dir: &Path,
        mode: DecompileMode,
        function: Option<&str>,
    ) -> Result<ToolInvocation, RustpenError> {
        std::fs::create_dir_all(out_dir)?;
        let out_abs = std::fs::canonicalize(out_dir).unwrap_or_else(|_| out_dir.to_path_buf());
        let (script_name, output_name) = match mode {
            DecompileMode::Full => ("ghidra_export_pseudocode.java", "pseudocode.jsonl"),
            DecompileMode::Index => ("ghidra_export_index.java", "index.jsonl"),
            DecompileMode::Function => ("ghidra_export_function.java", "function.jsonl"),
        };
        let script = out_abs.join(script_name);
        match mode {
            DecompileMode::Full => ReverseTooling::write_ghidra_export_script(&script)?,
            DecompileMode::Index => ReverseTooling::write_ghidra_index_script(&script)?,
            DecompileMode::Function => ReverseTooling::write_ghidra_function_script(&script)?,
        }
        let pseudo_file = out_abs.join(output_name);

        let (project_dir, project_name, reuse_project, no_analysis) =
            resolve_ghidra_project(input, &out_abs);
        let mut plan = ReverseTooling::build_ghidra_invocation(
            &project_dir,
            &project_name,
            input,
            &out_abs,
            reuse_project,
            no_analysis,
        );
        if let Some(pos) = plan.args.iter().position(|a| a == "-postScript") {
            if let Some(slot) = plan.args.get_mut(pos + 1) {
                *slot = script.display().to_string();
            }
        }
        if let Some(last) = plan.args.last_mut() {
            *last = pseudo_file.display().to_string();
        }
        if mode == DecompileMode::Function {
            let target = function.ok_or_else(|| {
                RustpenError::ParseError("missing --function for ghidra function mode".to_string())
            })?;
            plan.args.push(target.to_string());
        }
        if let Some(path) = &self.binary.path {
            plan.program = path.display().to_string();
        }
        Ok(plan)
    }
}

fn resolve_ghidra_project(
    input: &Path,
    out_dir: &Path,
) -> (PathBuf, String, bool, bool) {
    let use_cache = env_flag("RSCAN_GHIDRA_PROJECT_CACHE", true);
    let reuse_project = env_flag("RSCAN_GHIDRA_REUSE_PROJECT", true);
    let no_analysis = env_flag("RSCAN_GHIDRA_NO_ANALYSIS", false);

    let project_root = if use_cache {
        std::env::var("RSCAN_GHIDRA_PROJECT_ROOT")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                out_dir
                    .parent()
                    .map(|p| p.join("ghidra_cache"))
                    .unwrap_or_else(|| out_dir.join("ghidra_cache"))
            })
    } else {
        out_dir.to_path_buf()
    };

    if use_cache {
        let _ = std::fs::create_dir_all(&project_root);
    }

    let project_name = if use_cache {
        let mut hasher = sha2::Sha256::new();
        hasher.update(input.as_os_str().to_string_lossy().as_bytes());
        if let Ok(meta) = std::fs::metadata(input) {
            hasher.update(meta.len().to_string().as_bytes());
            if let Ok(mtime) = meta.modified() {
                if let Ok(dur) = mtime.duration_since(std::time::UNIX_EPOCH) {
                    hasher.update(dur.as_secs().to_string().as_bytes());
                }
            }
        }
        format!("rscan_{}", hex::encode(hasher.finalize()))
    } else {
        std::env::var("RSCAN_GHIDRA_PROJECT_NAME").unwrap_or_else(|_| "rscan_project".to_string())
    };

    (project_root, project_name, reuse_project, no_analysis)
}

fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}
