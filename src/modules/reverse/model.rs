use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    Apk,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardeningReport {
    pub nx: Option<bool>,
    pub pie_or_aslr: Option<bool>,
    pub relro: Option<bool>,
    pub stack_canary: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileHashes {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecuritySignals {
    pub anti_debug_indicators: Vec<String>,
    pub packer_indicators: Vec<String>,
    pub suspicious_imports: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub entropy: f64,
    pub malware_score: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryReport {
    pub path: PathBuf,
    pub format: BinaryFormat,
    pub architecture: Option<String>,
    pub entry_point: Option<u64>,
    pub file_size: u64,
    pub hashes: FileHashes,
    pub sections: Vec<String>,
    pub imports: Vec<String>,
    pub hardening: HardeningReport,
    pub security: SecuritySignals,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApkReport {
    pub path: PathBuf,
    pub file_size: u64,
    pub hashes: FileHashes,
    pub entries: Vec<String>,
    pub has_manifest: bool,
    pub has_classes_dex: bool,
    pub has_native_libs: bool,
    pub native_libs: Vec<String>,
    pub security: SecuritySignals,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Copy)]
pub enum DecompilerEngine {
    Objdump,
    Radare2,
    Ghidra,
    Ida,
    Jadx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompileMode {
    Full,
    Index,
    Function,
}

impl DecompileMode {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "index" => Some(Self::Index),
            "function" | "func" | "fn" => Some(Self::Function),
            _ => None,
        }
    }
}

impl DecompilerEngine {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "objdump" => Some(Self::Objdump),
            "radare2" | "r2" => Some(Self::Radare2),
            "ghidra" => Some(Self::Ghidra),
            "ida" | "idat64" => Some(Self::Ida),
            "jadx" => Some(Self::Jadx),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DebugProfile {
    PwnGdbLike,
    PwndbgCompat,
}

impl DebugProfile {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "pwngdb" | "pwn" => Some(Self::PwnGdbLike),
            "pwndbg" => Some(Self::PwndbgCompat),
            _ => None,
        }
    }
}
