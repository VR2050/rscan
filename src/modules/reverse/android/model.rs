use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct AndroidReverseReport {
    pub path: PathBuf,
    pub file_size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub apk: ApkIndexReport,
    pub profile: AndroidProfileReport,
    pub dex: DexIndexReport,
    pub native: NativeIndexReport,
    pub forensics: AndroidForensicsReport,
    pub score: AndroidRiskScore,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApkIndexReport {
    pub entries_total: usize,
    pub classes_dex_files: Vec<String>,
    pub native_libs: Vec<String>,
    pub has_manifest: bool,
    pub has_resources_arsc: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidProfileReport {
    pub package_name: Option<String>,
    pub uses_cleartext_traffic: bool,
    pub permissions: Vec<String>,
    pub dangerous_permissions: Vec<String>,
    pub exported_components: Vec<String>,
    pub endpoint_urls: Vec<String>,
    pub endpoint_domains: Vec<String>,
    pub ioc_keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexSensitiveHit {
    pub api: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexIndexReport {
    pub dex_files: usize,
    pub dex_string_pool_total: usize,
    pub class_hints: Vec<String>,
    pub sensitive_api_hits: Vec<DexSensitiveHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeLibReport {
    pub name: String,
    pub size: u64,
    pub arch: String,
    pub imports_count: usize,
    pub suspicious_import_hits: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeIndexReport {
    pub libs: Vec<NativeLibReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidRiskScore {
    pub total: u8,
    pub breakdown: BTreeMap<String, u8>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidForensicsReport {
    pub manifest_parser: String,
    pub main_activity: Option<String>,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: u32,
    pub compile_sdk: Option<String>,
    pub application_debuggable: Option<bool>,
    pub application_allow_backup: Option<bool>,
    pub signature_count: usize,
    pub native_abis: Vec<String>,
    pub component_stats: AndroidComponentStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct AndroidComponentStats {
    pub activities: usize,
    pub activity_aliases: usize,
    pub services: usize,
    pub receivers: usize,
    pub providers: usize,
    pub exported_activities: usize,
    pub exported_activity_aliases: usize,
    pub exported_services: usize,
    pub exported_receivers: usize,
    pub exported_providers: usize,
}
