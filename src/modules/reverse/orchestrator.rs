use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::errors::RustpenError;

use super::backends::{BackendKind, BackendRegistry, ReverseBackend};
use super::model::{DebugProfile, DecompileMode, DecompilerEngine, ToolInvocation};
use super::tooling::ReverseTooling;

pub struct ReverseOrchestrator {
    registry: BackendRegistry,
}

impl ReverseOrchestrator {
    pub fn detect() -> Self {
        Self {
            registry: BackendRegistry::detect(),
        }
    }

    pub fn registry(&self) -> &BackendRegistry {
        &self.registry
    }

    pub fn select_pseudocode_backend(
        &self,
        preferred: Option<&str>,
    ) -> Result<&dyn ReverseBackend, RustpenError> {
        if let Some(p) = preferred {
            let kind = match p.to_ascii_lowercase().as_str() {
                "ghidra" => Some(BackendKind::Ghidra),
                "ida" | "idat64" => Some(BackendKind::Ida),
                _ => None,
            }
            .ok_or_else(|| {
                RustpenError::ParseError("invalid pseudocode backend. use ghidra|ida".to_string())
            })?;

            if let Some(b) = self.registry.by_kind(kind)
                && b.available()
            {
                return Ok(b);
            }
            return Err(RustpenError::ScanError(format!(
                "requested backend '{}' is not available",
                p
            )));
        }

        if let Some(best) = self.registry.best_pseudocode() {
            return Ok(best);
        }

        Err(RustpenError::ScanError(
            "no pseudocode backend found (need ghidra or ida)".to_string(),
        ))
    }

    pub fn build_pseudocode_plan(
        &self,
        input: &Path,
        out_dir: &Path,
        preferred: Option<&str>,
        mode: DecompileMode,
        function: Option<&str>,
    ) -> Result<ToolInvocation, RustpenError> {
        let backend = self.select_pseudocode_backend(preferred)?;
        backend.build_pseudocode_plan(input, out_dir, mode, function)
    }

    pub fn build_decompile_plan(
        &self,
        engine: DecompilerEngine,
        input: &Path,
        output_dir: Option<&Path>,
    ) -> Result<ToolInvocation, RustpenError> {
        match engine {
            DecompilerEngine::Objdump => Ok(ReverseTooling::build_decompile_invocation(
                engine, input, output_dir,
            )),
            DecompilerEngine::Radare2 => self.build_pseudocode_plan(
                input,
                output_dir.unwrap_or(Path::new(".")),
                Some("r2"),
                DecompileMode::Full,
                None,
            ),
            DecompilerEngine::Ghidra => self.build_pseudocode_plan(
                input,
                output_dir.unwrap_or(Path::new("./ghidra_out")),
                Some("ghidra"),
                DecompileMode::Full,
                None,
            ),
            DecompilerEngine::Ida => self.build_pseudocode_plan(
                input,
                output_dir.unwrap_or(Path::new("./ida_pseudo")),
                Some("ida"),
                DecompileMode::Full,
                None,
            ),
            DecompilerEngine::Jadx => self.build_pseudocode_plan(
                input,
                output_dir.unwrap_or(Path::new("./jadx_out")),
                Some("jadx"),
                DecompileMode::Full,
                None,
            ),
        }
    }

    pub fn build_debug_plan(
        &self,
        input: &Path,
        profile: DebugProfile,
        script_path: &Path,
        pwndbg_init: Option<&Path>,
    ) -> Result<ToolInvocation, RustpenError> {
        let backend = self.registry.best_debugger().ok_or_else(|| {
            RustpenError::ScanError("no debugger backend found (need gdb)".to_string())
        })?;
        backend.build_debug_plan(input, profile, script_path, pwndbg_init)
    }

    pub fn execute_plan(plan: &ToolInvocation) -> Result<(), RustpenError> {
        let status = Command::new(&plan.program)
            .args(&plan.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| {
                RustpenError::ScanError(format!("failed to launch {}: {}", plan.program, e))
            })?;
        if !status.success() {
            return Err(RustpenError::ScanError(format!(
                "tool '{}' exited with status {}",
                plan.program, status
            )));
        }
        Ok(())
    }

    pub fn write_gdb_plugin(output: &Path) -> Result<(), RustpenError> {
        ReverseTooling::write_gdb_python_plugin(output)
    }

    pub fn write_ida_script(output: &Path) -> Result<(), RustpenError> {
        ReverseTooling::write_ida_export_script(output)
    }

    pub fn write_ghidra_script(output: &Path) -> Result<(), RustpenError> {
        ReverseTooling::write_ghidra_export_script(output)
    }

    pub fn write_ghidra_index_script(output: &Path) -> Result<(), RustpenError> {
        ReverseTooling::write_ghidra_index_script(output)
    }

    pub fn write_ghidra_function_script(output: &Path) -> Result<(), RustpenError> {
        ReverseTooling::write_ghidra_function_script(output)
    }

    pub fn default_workspace() -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
}
