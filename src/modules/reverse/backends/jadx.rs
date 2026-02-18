use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DecompileMode, ToolInvocation};

use super::{BackendBinary, BackendCapabilities, BackendKind, ReverseBackend};

pub struct JadxBackend {
    binary: BackendBinary,
}

impl JadxBackend {
    pub fn new(binary: BackendBinary) -> Self {
        Self { binary }
    }
}

impl ReverseBackend for JadxBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Jadx
    }

    fn name(&self) -> &'static str {
        "jadx"
    }

    fn binary(&self) -> &BackendBinary {
        &self.binary
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            pseudocode: false,
            debugging: false,
            symbols: false,
            apk_decompile: true,
        }
    }

    fn build_pseudocode_plan(
        &self,
        input: &Path,
        out_dir: &Path,
        mode: DecompileMode,
        _function: Option<&str>,
    ) -> Result<ToolInvocation, RustpenError> {
        if mode != DecompileMode::Full {
            return Err(RustpenError::ScanError(
                "jadx backend only supports full decompile export".to_string(),
            ));
        }
        Ok(ToolInvocation {
            program: self
                .binary
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "jadx".to_string()),
            args: vec![
                "-d".to_string(),
                out_dir.display().to_string(),
                input.display().to_string(),
            ],
            note: "JADX source export for APK".to_string(),
        })
    }
}
