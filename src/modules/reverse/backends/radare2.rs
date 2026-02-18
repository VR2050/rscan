use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DecompileMode, ToolInvocation};

use super::{BackendBinary, BackendCapabilities, BackendKind, ReverseBackend};

pub struct Radare2Backend {
    binary: BackendBinary,
}

impl Radare2Backend {
    pub fn new(binary: BackendBinary) -> Self {
        Self { binary }
    }
}

impl ReverseBackend for Radare2Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::Radare2
    }

    fn name(&self) -> &'static str {
        "radare2"
    }

    fn binary(&self) -> &BackendBinary {
        &self.binary
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            pseudocode: false,
            debugging: true,
            symbols: true,
            apk_decompile: false,
        }
    }

    fn build_pseudocode_plan(
        &self,
        input: &Path,
        _out_dir: &Path,
        mode: DecompileMode,
        _function: Option<&str>,
    ) -> Result<ToolInvocation, RustpenError> {
        if mode != DecompileMode::Full {
            return Err(RustpenError::ScanError(
                "radare2 backend only supports full analysis".to_string(),
            ));
        }
        Ok(ToolInvocation {
            program: self
                .binary
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "r2".to_string()),
            args: vec!["-A".to_string(), input.display().to_string()],
            note: "Radare2 analysis mode (fallback, non-pseudocode)".to_string(),
        })
    }
}
