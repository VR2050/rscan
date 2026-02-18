use std::path::Path;

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DecompileMode, ToolInvocation};
use crate::modules::reverse::tooling::ReverseTooling;

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

        let mut plan = ReverseTooling::build_decompile_invocation(
            crate::modules::reverse::DecompilerEngine::Ghidra,
            input,
            Some(&out_abs),
        );
        if let Some(pos) = plan.args.iter().position(|a| a == "-postScript") {
            if let Some(slot) = plan.args.get_mut(pos + 1) {
                *slot = script_name.to_string();
            }
        }
        if let Some(last) = plan.args.last_mut() {
            *last = pseudo_file.display().to_string();
        }
        if mode == DecompileMode::Function {
            let target = function.ok_or_else(|| {
                RustpenError::ParseError(
                    "missing --function for ghidra function mode".to_string(),
                )
            })?;
            plan.args.push(target.to_string());
        }
        if let Some(path) = &self.binary.path {
            plan.program = path.display().to_string();
        }
        Ok(plan)
    }
}
