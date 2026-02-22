// src/errors.rs
use std::path::PathBuf;
use thiserror::Error;

/// RustPen 全局统一错误类型
#[derive(Error, Debug)]
pub enum RustpenError {
    // === 网络与基础 I/O ===
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    // #[error("DNS resolution failed for '{domain}': {source}")]
    // DnsResolution {
    //     domain: String,
    //     #[source]
    //     source: trust_dns_resolver::error::ResolveError,
    // },

    // #[error("Invalid URL: {0}")]
    // InvalidUrl(#[from] url::ParseError),
    #[error("无效的主机: {0}")]
    InvalidHost(String),

    #[error("扫描错误: {0}")]
    ScanError(String),

    #[error("网络错误: {0}")]
    NetworkError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("HTTP request failed to '{url}': {source}")]
    HttpRequest {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    // === 参数与配置错误 ===
    #[error("Invalid port or port range: '{input}'")]
    InvalidPort { input: String },

    #[error("Invalid concurrency limit: {value} (must be >= 1)")]
    InvalidConcurrency { value: usize },

    #[error("Missing required argument: {arg}")]
    MissingArgument { arg: String },

    #[error("Invalid wordlist path: '{path}'")]
    InvalidWordlistPath { path: String },

    // === 字典/爆破相关 ===
    #[error("Failed to load wordlist from '{path}': {source}")]
    WordlistLoad {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Wordlist is empty or contains no valid entries")]
    EmptyWordlist,

    // === Web 扫描特有 ===
    #[error("HTTP status code {status} not expected during probing")]
    UnexpectedHttpStatus { status: u16 },

    #[error("Target '{url}' appears to be down (no response within timeout)")]
    TargetUnreachable { url: String },

    #[error("Authentication brute-force failed: too many retries or lockout suspected")]
    AuthBruteFailed { target: String },

    // === 漏洞扫描 / PoC 相关 ===
    // #[error("Failed to parse PoC rule from '{path}': {source}")]
    // PocRuleParse {
    //     path: PathBuf,
    //     #[source]
    //     source: serde_yaml::Error, // 或 toml/json，按你用的格式
    // },
    #[error("PoC validation failed for '{name}': missing required field '{field}'")]
    PocRuleInvalid { name: String, field: String },

    #[error("Vulnerability not confirmed: response did not match expected pattern")]
    VulnerabilityNotConfirmed,

    // === Shell / WebShell 相关 ===
    #[error("Failed to generate reverse shell payload: unsupported platform '{platform}'")]
    UnsupportedShellPlatform { platform: String },

    #[error("Invalid shell payload type: '{payload_type}'")]
    InvalidShellPayloadType { payload_type: String },

    #[error("Failed to bind listener on {host}:{port}: {source}")]
    ListenerBindFailed {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("Shell interaction error: {0}")]
    ShellInteraction(String),

    #[error("Result receiver already taken")]
    ResultsReceiverTaken,

    // === 通用兜底 ===
    #[error("Operation failed: {0}")]
    Generic(String),
}
