mod common;
pub mod dir_scan;
pub mod dns_scan;
pub mod fuzz_scan;
pub mod live_scan;
mod resume;
pub mod web_scan;

// expose WebScanner and config types to modules root
pub use web_scan::WebScanConfig;
pub use web_scan::WebScanner;

use serde::{Deserialize, Serialize};

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
        Self {
            url: t.0,
            status: t.1,
            content_len: t.2,
        }
    }
}

/// 格式化结果为字符串（便于 CLI 输出）
pub fn format_scan_result(r: &ModuleScanResult, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Raw => format!("{} {} {:?}", r.url, r.status, r.content_len),
        OutputFormat::Json => serde_json::to_string(r).unwrap_or_else(|_| format!("{}", r.url)),
        OutputFormat::Csv => format!(
            "{},{},{}",
            r.url,
            r.status,
            r.content_len.map(|v| v.to_string()).unwrap_or_default()
        ),
    }
}

/// Pretty formatter for CLI/terminal output (aligned columns + optional ANSI colors).
pub fn format_scan_result_pretty(r: &ModuleScanResult, color: bool) -> String {
    let (label, label_color) = status_label(r.status);
    let label = format!("{:>6}", label);
    let label = if color {
        format!("\x1b[{label_color}m{label}\x1b[0m")
    } else {
        label
    };
    let status = format!("{:>3}", r.status);
    let size = match r.content_len {
        Some(v) => human_size(v),
        None => "-".to_string(),
    };
    let size = format!("{:>7}", size);
    let status_colored = if color {
        colorize_status(&status, r.status)
    } else {
        status
    };
    format!("{label} {status_colored} {size} {}", r.url)
}

fn human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.1}G", b / GB)
    } else if b >= MB {
        format!("{:.1}M", b / MB)
    } else if b >= KB {
        format!("{:.1}K", b / KB)
    } else {
        format!("{bytes}B")
    }
}

fn colorize_status(s: &str, status: u16) -> String {
    let code = match status {
        100..=199 => "35", // magenta
        200..=299 => "32", // green
        300..=399 => "36", // cyan
        400..=499 => "33", // yellow
        500..=599 => "31", // red
        _ => "90",         // dim
    };
    format!("\x1b[{code}m{s}\x1b[0m")
}

fn status_label(status: u16) -> (&'static str, &'static str) {
    match status {
        100..=199 => ("INFO", "35"),
        200..=299 => ("OK", "32"),
        300..=399 => ("REDIR", "36"),
        400..=499 => ("CLIENT", "33"),
        500..=599 => ("SERVER", "31"),
        _ => ("OTHER", "90"),
    }
}

// 高级配置：统一模块扫描参数
#[derive(Debug, Clone)]
pub struct ModuleScanConfig {
    /// 底层 Fetcher 配置
    pub fetcher: crate::cores::web::FetcherConfig,
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
    /// 自动探测并过滤 wildcard 响应（减少目录/参数扫描误报）
    pub wildcard_filter: bool,
    /// wildcard 探测样本数量
    pub wildcard_sample_count: usize,
    /// wildcard 过滤时允许的响应体长度误差
    pub wildcard_len_tolerance: u64,
    /// 基于响应指纹（title + simhash）进行近似去重
    pub fingerprint_filter: bool,
    /// simhash 汉明距离阈值（越小越严格）
    pub fingerprint_distance_threshold: u32,
    /// 可选断点续扫文件（json）
    pub resume_file: Option<std::path::PathBuf>,
    /// 根据 429/5xx 比例自适应批次间延迟
    pub adaptive_rate: bool,
    pub adaptive_initial_delay_ms: u64,
    pub adaptive_max_delay_ms: u64,
    /// HTTP method for requests (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH...)
    pub request_method: reqwest::Method,
    /// enable recursive directory scanning (dir scan only)
    pub recursive: bool,
    /// max recursion depth for directory scanning
    pub recursive_max_depth: usize,
}

impl Default for ModuleScanConfig {
    fn default() -> Self {
        Self {
            fetcher: crate::cores::web::FetcherConfig::default(),
            concurrency: 10,
            timeout_ms: Some(5000),
            max_retries: Some(0),
            per_host_concurrency_override: None,
            dedupe_results: true,
            output_format: None,
            status_min: None,
            status_max: None,
            wildcard_filter: false,
            wildcard_sample_count: 2,
            wildcard_len_tolerance: 16,
            fingerprint_filter: false,
            fingerprint_distance_threshold: 6,
            resume_file: None,
            adaptive_rate: false,
            adaptive_initial_delay_ms: 0,
            adaptive_max_delay_ms: 2000,
            request_method: reqwest::Method::GET,
            recursive: false,
            recursive_max_depth: 2,
        }
    }
}

// 导出常用函数
pub use dir_scan::{run_dir_scan, run_dir_scan_stream, run_dir_scan_with_callback};
pub use dns_scan::{run_subdomain_burst, run_subdomain_burst_stream};
pub use fuzz_scan::{run_fuzz_scan, run_fuzz_scan_stream};
