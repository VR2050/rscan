use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DebugProfile, ToolInvocation};
use crate::modules::reverse::tooling::ReverseTooling;

use super::{BackendBinary, BackendCapabilities, BackendKind, ReverseBackend};

pub struct GdbBackend {
    binary: BackendBinary,
    pwndbg_init: BackendBinary,
}

impl GdbBackend {
    pub fn new(binary: BackendBinary, pwndbg_init: BackendBinary) -> Self {
        Self {
            binary,
            pwndbg_init,
        }
    }
}

impl ReverseBackend for GdbBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Gdb
    }

    fn name(&self) -> &'static str {
        "gdb"
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

    fn build_debug_plan(
        &self,
        input: &Path,
        profile: DebugProfile,
        script_path: &Path,
        pwndbg_init: Option<&Path>,
    ) -> Result<ToolInvocation, RustpenError> {
        let init = pwndbg_init.or(self.pwndbg_init.path.as_deref());
        ReverseTooling::write_debug_script_with_pwndbg(profile, input, script_path, init)?;

        Ok(ToolInvocation {
            program: self
                .binary
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "gdb".to_string()),
            args: vec![
                "-q".to_string(),
                "-x".to_string(),
                script_path.display().to_string(),
                input.display().to_string(),
            ],
            note: "GDB debug session bootstrap from generated script".to_string(),
        })
    }
}
