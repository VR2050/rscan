use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};

use crate::errors::RustpenError;
use crate::modules::reverse::model::{DebugProfile, DecompileMode, ToolInvocation};

pub mod gdb;
pub mod ghidra;
pub mod ida;
pub mod jadx;
pub mod radare2;

pub use gdb::GdbBackend;
pub use ghidra::GhidraBackend;
pub use ida::IdaBackend;
pub use jadx::JadxBackend;
pub use radare2::Radare2Backend;

#[derive(Debug, Clone, Serialize)]
pub struct BackendBinary {
    pub name: String,
    pub available: bool,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendCatalog {
    pub gdb: BackendBinary,
    pub pwndbg_init: BackendBinary,
    pub ghidra_headless: BackendBinary,
    pub idat64: BackendBinary,
    pub jadx: BackendBinary,
    pub radare2: BackendBinary,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum BackendKind {
    Ghidra,
    Ida,
    Gdb,
    Jadx,
    Radare2,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendCapabilities {
    pub pseudocode: bool,
    pub debugging: bool,
    pub symbols: bool,
    pub apk_decompile: bool,
}

pub trait ReverseBackend: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn name(&self) -> &'static str;
    fn binary(&self) -> &BackendBinary;
    fn capabilities(&self) -> BackendCapabilities;

    fn available(&self) -> bool {
        self.binary().available
    }

    fn build_pseudocode_plan(
        &self,
        _input: &Path,
        _out_dir: &Path,
        _mode: DecompileMode,
        _function: Option<&str>,
    ) -> Result<ToolInvocation, RustpenError> {
        Err(RustpenError::ScanError(format!(
            "backend '{}' does not support pseudocode export",
            self.name()
        )))
    }

    fn build_debug_plan(
        &self,
        _input: &Path,
        _profile: DebugProfile,
        _script_path: &Path,
        _pwndbg_init: Option<&Path>,
    ) -> Result<ToolInvocation, RustpenError> {
        Err(RustpenError::ScanError(format!(
            "backend '{}' does not support debugging",
            self.name()
        )))
    }
}

pub struct BackendRegistry {
    catalog: BackendCatalog,
    backends: Vec<Box<dyn ReverseBackend>>,
}

impl BackendRegistry {
    pub fn detect() -> Self {
        let catalog = BackendCatalog::detect();
        let backends: Vec<Box<dyn ReverseBackend>> = vec![
            Box::new(GhidraBackend::new(catalog.ghidra_headless.clone())),
            Box::new(IdaBackend::new(catalog.idat64.clone())),
            Box::new(GdbBackend::new(
                catalog.gdb.clone(),
                catalog.pwndbg_init.clone(),
            )),
            Box::new(JadxBackend::new(catalog.jadx.clone())),
            Box::new(Radare2Backend::new(catalog.radare2.clone())),
        ];
        Self { catalog, backends }
    }

    pub fn catalog(&self) -> &BackendCatalog {
        &self.catalog
    }

    pub fn all(&self) -> &[Box<dyn ReverseBackend>] {
        &self.backends
    }

    pub fn by_kind(&self, kind: BackendKind) -> Option<&dyn ReverseBackend> {
        self.backends
            .iter()
            .find(|b| b.kind() == kind)
            .map(|b| b.as_ref())
    }

    pub fn best_pseudocode(&self) -> Option<&dyn ReverseBackend> {
        self.backends
            .iter()
            .find(|b| b.available() && b.capabilities().pseudocode)
            .map(|b| b.as_ref())
    }

    pub fn best_debugger(&self) -> Option<&dyn ReverseBackend> {
        self.backends
            .iter()
            .find(|b| b.available() && b.capabilities().debugging)
            .map(|b| b.as_ref())
    }
}

impl BackendCatalog {
    pub fn detect() -> Self {
        Self {
            gdb: probe_binary("gdb", &["gdb"]),
            pwndbg_init: probe_file(
                "pwndbg_init",
                &[
                    "~/pwndbg/gdbinit.py",
                    "~/.local/share/pwndbg/gdbinit.py",
                    "~/.pwndbg/gdbinit.py",
                ],
            ),
            ghidra_headless: probe_ghidra_headless(),
            idat64: probe_binary("idat64", &["idat64", "idat", "ida64"]),
            jadx: probe_binary("jadx", &["jadx"]),
            radare2: probe_binary("r2", &["r2", "radare2"]),
        }
    }

    pub fn best_pseudocode_backend(&self) -> Option<&'static str> {
        if self.ghidra_headless.available {
            Some("ghidra")
        } else if self.idat64.available {
            Some("ida")
        } else {
            None
        }
    }
}

fn probe_ghidra_headless() -> BackendBinary {
    if let Ok(path) = env::var("RSCAN_GHIDRA_HEADLESS") {
        let p = expand_tilde(&path);
        if p.exists() && ghidra_runtime_ok(p.parent()) {
            return BackendBinary {
                name: "analyzeHeadless".to_string(),
                available: true,
                path: Some(p),
            };
        }
    }
    if let Ok(home) = env::var("RSCAN_GHIDRA_HOME") {
        let base = expand_tilde(&home);
        let run = base.join("run-headless.sh");
        if run.exists() && ghidra_runtime_ok(Some(&base)) {
            return BackendBinary {
                name: "analyzeHeadless".to_string(),
                available: true,
                path: Some(run),
            };
        }
        let bin = base.join("support").join("analyzeHeadless");
        if bin.exists() && ghidra_runtime_ok(Some(&base)) {
            return BackendBinary {
                name: "analyzeHeadless".to_string(),
                available: true,
                path: Some(bin),
            };
        }
    }
    if let Some(p) = probe_bundled_ghidra_headless() {
        return BackendBinary {
            name: "analyzeHeadless".to_string(),
            available: true,
            path: Some(p),
        };
    }
    probe_binary("analyzeHeadless", &["analyzeHeadless", "ghidraRun", "ghidraRun.bat"])
}

fn probe_bundled_ghidra_headless() -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();

    if let Ok(cwd) = std::env::current_dir() {
        push_root(&mut roots, &mut seen, cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_root(&mut roots, &mut seen, dir.to_path_buf());
        }
    }

    let mut bases: Vec<PathBuf> = Vec::new();
    for root in roots {
        for p in walk_up(root, 6) {
            push_root(&mut bases, &mut seen, p.join("third_party/ghidra_core_headless_x86_min"));
            push_root(&mut bases, &mut seen, p.join("ghidra_core_headless_x86_min"));
        }
    }

    for base in bases {
        let run = base.join("run-headless.sh");
        if run.exists() && ghidra_runtime_ok(Some(&base)) {
            return Some(run);
        }
        let bin = base.join("support").join("analyzeHeadless");
        if bin.exists() && ghidra_runtime_ok(Some(&base)) {
            return Some(bin);
        }
    }
    None
}

fn walk_up(start: PathBuf, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut cur = Some(start);
    for _ in 0..=depth {
        if let Some(p) = cur {
            out.push(p.clone());
            cur = p.parent().map(|v| v.to_path_buf());
        } else {
            break;
        }
    }
    out
}

fn push_root(out: &mut Vec<PathBuf>, seen: &mut std::collections::BTreeSet<PathBuf>, p: PathBuf) {
    if seen.insert(p.clone()) {
        out.push(p);
    }
}

fn ghidra_runtime_ok(base: Option<&Path>) -> bool {
    let Some(base) = base else {
        return true;
    };
    let ghidra = base.join("Ghidra");
    let decompiler = ghidra.join("Features").join("Decompiler");
    let base_feat = ghidra.join("Features").join("Base");
    let x86 = ghidra.join("Processors").join("x86");
    decompiler.exists() && base_feat.exists() && x86.exists()
}

fn probe_binary(label: &str, candidates: &[&str]) -> BackendBinary {
    for c in candidates {
        if let Some(path) = find_in_path(c) {
            return BackendBinary {
                name: label.to_string(),
                available: true,
                path: Some(path),
            };
        }
    }
    BackendBinary {
        name: label.to_string(),
        available: false,
        path: None,
    }
}

fn probe_file(label: &str, candidates: &[&str]) -> BackendBinary {
    for c in candidates {
        let p = expand_tilde(c);
        if p.exists() {
            return BackendBinary {
                name: label.to_string(),
                available: true,
                path: Some(p),
            };
        }
    }
    BackendBinary {
        name: label.to_string(),
        available: false,
        path: None,
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(bin);
        if is_executable(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{}.exe", bin));
            if is_executable(&exe) {
                return Some(exe);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path) {
            return md.permissions().mode() & 0o111 != 0;
        }
    }
    #[cfg(not(unix))]
    {
        return true;
    }
    false
}
