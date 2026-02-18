use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DecompileMode, ToolInvocation};
use crate::modules::reverse::tooling::ReverseTooling;

use super::{BackendBinary, BackendCapabilities, BackendKind, ReverseBackend};

pub struct IdaBackend {
    binary: BackendBinary,
}

impl IdaBackend {
    pub fn new(binary: BackendBinary) -> Self {
        Self { binary }
    }
}

impl ReverseBackend for IdaBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Ida
    }

    fn name(&self) -> &'static str {
        "ida"
    }

    fn binary(&self) -> &BackendBinary {
        &self.binary
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            pseudocode: true,
            debugging: true,
            symbols: true,
            apk_decompile: false,
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
                "ida backend only supports full pseudocode export".to_string(),
            ));
        }
        std::fs::create_dir_all(out_dir)?;
        let script = out_dir.join("ida_export_pseudocode.py");
        ReverseTooling::write_ida_export_script(&script)?;

        let mut plan = ReverseTooling::build_decompile_invocation(
            crate::modules::reverse::DecompilerEngine::Ida,
            input,
            Some(out_dir),
        );
        if let Some(path) = &self.binary.path {
            plan.program = path.display().to_string();
        }
        Ok(plan)
    }
}
