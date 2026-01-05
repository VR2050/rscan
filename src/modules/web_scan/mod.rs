pub mod dir_scan;
pub mod fuzz_scan;
pub mod dns_scan;
pub mod live_scan;
pub mod web_scan;

// expose WebScanner and config types to modules root
pub use web_scan::WebScanner;
pub use web_scan::WebScanConfig;

use serde::{Serialize, Deserialize};

/// 输出格式选项
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Raw,
    Json,
    Csv,
}

/// 模块层统一的扫描结果类型（便于序列化/格式化）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleScanResult {
    pub url: String,
    pub status: u16,
    pub content_len: Option<u64>,
}

impl ModuleScanResult {
    pub fn from_tuple(t: (String, u16, Option<u64>)) -> Self {
        Self { url: t.0, status: t.1, content_len: t.2 }
    }
}

/// 格式化结果为字符串（便于 CLI 输出）
pub fn format_scan_result(r: &ModuleScanResult, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Raw => format!("{} {} {:?}", r.url, r.status, r.content_len),
        OutputFormat::Json => serde_json::to_string(r).unwrap_or_else(|_| format!("{}", r.url)),
        OutputFormat::Csv => format!("{},{},{}", r.url, r.status, r.content_len.map(|v| v.to_string()).unwrap_or_default()),
    }
}

// 高级配置：统一模块扫描参数
#[derive(Debug, Clone)]
pub struct ModuleScanConfig {
    /// 底层 Fetcher 配置
    pub fetcher: crate::cores::web_en::FetcherConfig,
    /// 并发度（传给 fetch_many）
    pub concurrency: usize,
    /// 单次请求超时时间（毫秒），覆盖 FetchRequest.timeout_ms
    pub timeout_ms: Option<u64>,
    /// 覆盖每请求的重试次数
    pub max_retries: Option<u32>,
    /// per-host 并发覆盖（优先于 fetcher 的 per_host_concurrency）
    pub per_host_concurrency_override: Option<usize>,
    /// 是否对结果进行 URL 去重（模块层）
    pub dedupe_results: bool,
    /// 是否在模块层输出 JSON（便于 CLI/流水线），与 OutputFormat 配合
    pub output_format: Option<OutputFormat>,
    /// 返回结果状态码过滤（inclusive）： (min, max)
    pub status_min: Option<u16>,
    pub status_max: Option<u16>,
}

impl Default for ModuleScanConfig {
    fn default() -> Self {
        Self {
            fetcher: crate::cores::web_en::FetcherConfig::default(),
            concurrency: 10,
            timeout_ms: Some(5000),
            max_retries: Some(0),
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            status_min: None,
            status_max: None,
        }
    }
}

// 导出常用函数
pub use dir_scan::{run_dir_scan, run_dir_scan_stream, run_dir_scan_with_callback};
pub use fuzz_scan::{run_fuzz_scan, run_fuzz_scan_stream};
pub use dns_scan::run_subdomain_burst;
