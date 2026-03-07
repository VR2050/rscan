use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum VulnActions {
    /// Validate safe nuclei-like templates (no exploit sections)
    #[command(visible_alias = "l")]
    Lint {
        /// template file or directory
        #[arg(short = 't', long)]
        templates: PathBuf,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Async multi-target safe vulnerability scan
    #[command(visible_alias = "s")]
    Scan {
        /// one or more base targets (e.g. https://example.com)
        #[arg(short = 'u', long, required = true)]
        targets: Vec<String>,
        /// template file or directory
        #[arg(short = 't', long)]
        templates: PathBuf,
        /// filter templates by severity (repeat or comma-separated), e.g. high,critical
        #[arg(long = "severity", value_delimiter = ',')]
        severities: Vec<String>,
        /// filter templates by tags (repeat or comma-separated), e.g. cve,rce
        #[arg(long = "tag", value_delimiter = ',')]
        tags: Vec<String>,
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
        #[arg(short = 'T', long, default_value_t = 5000)]
        timeout_ms: u64,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Audit Kubernetes/container manifests for risky security settings
    #[command(visible_alias = "ca")]
    ContainerAudit {
        /// manifest file or directory (yaml/yml/json, recursive for directory)
        #[arg(short = 'm', long)]
        manifests: PathBuf,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Local security control audit (AV/EDR/firewall/audit baseline)
    #[command(visible_alias = "sg")]
    SystemGuard {
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// HTTP anti-scan capability check (low-noise vs burst behavior)
    #[command(visible_alias = "sc")]
    StealthCheck {
        /// base target URL, e.g. https://example.com
        #[arg(short = 'u', long)]
        target: String,
        /// number of low-noise requests
        #[arg(long, default_value_t = 8)]
        low_noise_requests: usize,
        /// low-noise inter-request delay in ms
        #[arg(long, default_value_t = 250)]
        low_noise_interval_ms: u64,
        /// number of burst requests
        #[arg(long, default_value_t = 24)]
        burst_requests: usize,
        /// burst concurrency
        #[arg(short = 'c', long, default_value_t = 12)]
        burst_concurrency: usize,
        /// timeout per request in ms
        #[arg(short = 'T', long, default_value_t = 3000)]
        timeout_ms: u64,
        /// enable advanced variant probes (encoding/header/method variants)
        #[arg(long, default_value_t = true)]
        advanced_checks: bool,
        /// explicitly disable advanced variant probes
        #[arg(long, default_value_t = false)]
        no_advanced_checks: bool,
        /// per-variant request count when advanced checks are enabled
        #[arg(long, default_value_t = 8)]
        variant_requests: usize,
        /// per-variant concurrency when advanced checks are enabled
        #[arg(long, default_value_t = 4)]
        variant_concurrency: usize,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Fragment/reassembly resilience audit (defensive, non-bypass)
    #[command(visible_alias = "fa")]
    FragmentAudit {
        /// base target URL, e.g. https://example.com
        #[arg(short = 'u', long)]
        target: String,
        /// number of probe requests per payload tier
        #[arg(long, default_value_t = 6)]
        requests_per_tier: usize,
        /// concurrency for each tier
        #[arg(short = 'c', long, default_value_t = 4)]
        concurrency: usize,
        /// timeout per request in ms
        #[arg(short = 'T', long, default_value_t = 4000)]
        timeout_ms: u64,
        /// minimum payload bytes in tier sweep
        #[arg(long, default_value_t = 1024)]
        payload_min_bytes: usize,
        /// maximum payload bytes in tier sweep
        #[arg(long, default_value_t = 24576)]
        payload_max_bytes: usize,
        /// payload step bytes in tier sweep
        #[arg(long, default_value_t = 4096)]
        payload_step_bytes: usize,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
}
