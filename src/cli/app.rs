use crate::cores::engine::async_engine::AsyncConnectEngine;
use crate::cores::engine::engine_trait::ScanEngine;
use crate::cores::engine::raw_engine::RawPacketEngine;
use crate::cores::engine::scan_job::{ScanJob, ScanType};
use crate::cores::engine::scan_result::ScanResult as EngineScanResult;
use crate::cores::engine::task::{
    EventKind, TaskEvent, TaskEventWriter, TaskMeta, TaskStatus, ensure_task_dir, new_task_id,
    now_epoch_secs, write_task_meta,
};
use crate::cores::host::ScanResult as HostScanResult;
use crate::errors::RustpenError;
use crate::modules::port_scan::ports::HostScanner;
use crate::modules::reverse::{
    DebugProfile, DecompileMode, DecompilerEngine, MalwareAnalyzer, ReverseAnalyzer,
    ReverseConsoleConfig, ReverseOrchestrator, RuleHotReloader, RuleLibrary, clear_jobs,
    inspect_job_health, list_jobs, load_job_by_id, load_job_logs, load_job_pseudocode_rows,
    prune_jobs, run_decompile_batch, run_decompile_job, run_reverse_interactive, run_reverse_tui,
};
use crate::modules::vuln_check::{
    AntiScanConfig, AntiScanReport, ContainerAuditReport, FragmentAuditConfig, FragmentAuditReport,
    SafeTemplate, SystemGuardReport, VulnScanConfig, VulnScanReport,
    audit_container_manifests_from_path, audit_http_anti_scan, audit_http_fragment_resilience,
    audit_local_system_guard, load_safe_templates_from_path, vuln_scan_targets,
};
use crate::modules::web_scan::live_scan::ping as live_ping;
use crate::modules::web_scan::{
    ModuleScanConfig, ModuleScanResult, OutputFormat, WebScanner, format_scan_result,
    format_scan_result_pretty,
};
use crate::services::service_probe::ServiceProbeEngine;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

// logging
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(name = "rscan", about = "rscan CLI", version)]
pub struct Cli {
    /// global log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, global = true, default_value = "info")]
    pub log_level: String,
    /// Optional workspace for task/TUI integration (writes tasks/<id>/)
    #[arg(long, global = true)]
    pub task_workspace: Option<PathBuf>,
    /// Optional task id (default auto)
    #[arg(long, global = true)]
    pub task_id: Option<String>,
    /// Optional note saved into task meta
    #[arg(long, global = true)]
    pub task_note: Option<String>,

    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanProfile {
    LowNoise,
    Balanced,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzKeywordTransform {
    Raw,
    UrlEncode,
    DoubleUrlEncode,
    Lower,
    Upper,
    PathWrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FuzzPreset {
    Api,
    Path,
    Param,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RequestBodyModeArg {
    Raw,
    Form,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DnsDiscoveryMode {
    /// rough discovery: DNS-resolvable subdomains only
    Rough,
    /// precise discovery: DNS + HTTP/HTTPS reachable subdomains
    Precise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SynMode {
    /// raw SYN only (faster, may miss some open ports as filtered)
    Strict,
    /// raw SYN + TCP connect verification on filtered results (slower, more complete)
    VerifyFiltered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TcpMode {
    /// single pass TCP connect scan
    Standard,
    /// faster first-pass only, may leave more filtered ports
    Turbo,
    /// turbo first-pass + targeted second-pass verification on filtered ports
    TurboVerify,
    /// turbo with adaptive verification strategy (speed/accuracy balance)
    TurboAdaptive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TcpScanOrderArg {
    Serial,
    Random,
    Interleave,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Web-related scans
    #[command(visible_alias = "w")]
    Web {
        #[command(subcommand)]
        action: WebActions,
    },
    /// Host/port scanning
    #[command(visible_alias = "h")]
    Host {
        #[command(subcommand)]
        action: HostActions,
    },
    /// Reverse engineering helpers
    #[command(visible_alias = "r")]
    Reverse {
        /// default console target input (works when no subcommand is provided)
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// default console workspace (works when no subcommand is provided)
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        /// optional pwndbg init path for default console mode
        #[arg(short = 'P', long)]
        pwndbg_init: Option<PathBuf>,
        /// enable TUI when using default console mode
        #[arg(long, default_value_t = false)]
        tui: bool,
        /// Override Ghidra headless runtime in default console mode
        #[arg(long)]
        ghidra_home: Option<PathBuf>,
        #[command(subcommand)]
        action: Option<ReverseActions>,
    },
    /// Vulnerability checks (safe template subset)
    #[command(visible_alias = "v")]
    Vuln {
        #[command(subcommand)]
        action: VulnActions,
    },
    /// Generate shell completions (bash/zsh)
    Completions {
        /// shell type: bash|zsh
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Unified TUI dashboard (preview)
    Tui {
        /// workspace path containing tasks/
        #[arg(long)]
        workspace: Option<PathBuf>,
        /// auto refresh interval in ms
        #[arg(long, default_value = "500")]
        refresh_ms: u64,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum HostActions {
    /// TCP port scan
    Tcp {
        /// target host (ip or hostname)
        #[arg(short = 'H', long)]
        host: String,
        /// ports to scan (comma separated or repeated)
        #[arg(short = 'p', long, required = true)]
        ports: Vec<String>,
        /// output format: raw/json
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        /// write output to file
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
        /// Enable service fingerprint enrichment on responses
        #[arg(short = 's', long, default_value_t = false)]
        service_detect: bool,
        /// nmap-service-probes file path used when --service-detect is set
        #[arg(short = 'P', long)]
        probes_file: Option<PathBuf>,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
        /// override TCP connect timeout in milliseconds (non-service mode)
        #[arg(long)]
        tcp_timeout_ms: Option<u64>,
        /// override TCP scanner concurrency (non-service mode)
        #[arg(long)]
        tcp_concurrency: Option<usize>,
        /// override retry count for timeout/filtered ports (non-service mode)
        #[arg(long)]
        tcp_retries: Option<u32>,
        /// optional global scan rate limit (ports per second, non-service mode)
        #[arg(long)]
        tcp_max_rate: Option<u32>,
        /// optional pacing jitter in milliseconds (non-service mode)
        #[arg(long)]
        tcp_jitter_ms: Option<u64>,
        /// port scheduling strategy: serial|random|interleave (non-service mode)
        #[arg(long, value_enum)]
        tcp_scan_order: Option<TcpScanOrderArg>,
        /// enable adaptive backpressure when filtered/timeout rises (non-service mode)
        #[arg(long, default_value_t = false)]
        tcp_adaptive_backpressure: bool,
        /// auto-tune TCP pacing/concurrency on a sample set before full scan (non-service mode)
        #[arg(long, default_value_t = false)]
        tcp_auto_tune: bool,
        /// TCP strategy mode: standard|turbo|turbo-verify (non-service mode)
        #[arg(long, value_enum, default_value_t = TcpMode::Standard)]
        tcp_mode: TcpMode,
    },
    /// UDP scan
    Udp {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'p', long, required = true)]
        ports: Vec<String>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
        #[arg(short = 's', long, default_value_t = false)]
        service_detect: bool,
        #[arg(short = 'P', long)]
        probes_file: Option<PathBuf>,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
    },
    /// SYN scan
    Syn {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'p', long, required = true)]
        ports: Vec<String>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
        #[arg(short = 's', long, default_value_t = false)]
        service_detect: bool,
        #[arg(short = 'P', long)]
        probes_file: Option<PathBuf>,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
        /// SYN result handling mode: strict|verify-filtered
        #[arg(long, value_enum, default_value_t = SynMode::VerifyFiltered)]
        syn_mode: SynMode,
    },
    /// Quick TCP scan of common ports
    Quick {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
    },
    /// ARP scan a CIDR for hosts
    Arp {
        /// CIDR notation, e.g. 192.168.1.0/24
        #[arg(short = 'c', long)]
        cidr: String,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
}
#[derive(Subcommand, Debug, Clone)]
pub enum WebActions {
    /// Directory scan: provide a base URL and one or more paths
    #[command(visible_alias = "d")]
    Dir {
        /// base URL (e.g. http://127.0.0.1:8080)
        #[arg(short = 'b', long)]
        base: String,
        /// paths to request (can be provided multiple times)
        #[arg(short = 'p', long, required = true)]
        paths: Vec<String>,
        /// optional output file to stream results to (will write one entry per line)
        #[arg(short = 'f', long)]
        stream_to: Option<PathBuf>,
        /// output format: raw,json,csv
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        /// concurrency for module scan
        #[arg(short = 'c', long)]
        concurrency: Option<usize>,
        /// timeout per request in milliseconds
        #[arg(short = 't', long)]
        timeout_ms: Option<u64>,
        /// max retries per request (module-level override)
        #[arg(short = 'r', long)]
        max_retries: Option<u32>,
        /// request header (repeatable), e.g. -H 'Authorization: Bearer xxx'
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// optional request body template
        #[arg(long)]
        body: Option<String>,
        /// body encoding hint (auto sets Content-Type if absent)
        #[arg(long, value_enum, default_value_t = RequestBodyModeArg::Raw)]
        body_mode: RequestBodyModeArg,
        /// override per-host concurrency
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        /// disable deduplication
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        /// explicitly disable deduplication
        #[arg(long, default_value_t = false)]
        no_dedupe: bool,
        /// minimum status code to include
        #[arg(long)]
        status_min: Option<u16>,
        /// maximum status code to include
        #[arg(long)]
        status_max: Option<u16>,
        /// enable wildcard response filtering (reduce false positives)
        #[arg(long, default_value_t = false)]
        wildcard_filter: bool,
        /// wildcard probe sample count
        #[arg(long)]
        wildcard_samples: Option<usize>,
        /// wildcard body length tolerance
        #[arg(long)]
        wildcard_len_tolerance: Option<u64>,
        /// enable near-duplicate fingerprint filtering (title+simhash)
        #[arg(long, default_value_t = false)]
        fingerprint_filter: bool,
        /// simhash hamming distance threshold
        #[arg(long)]
        fingerprint_distance: Option<u32>,
        /// resume state file for dir scan
        #[arg(long)]
        resume_file: Option<PathBuf>,
        /// adaptive rate based on 429/5xx ratio
        #[arg(long, default_value_t = false)]
        adaptive_rate: bool,
        #[arg(long)]
        adaptive_initial_delay_ms: Option<u64>,
        #[arg(long)]
        adaptive_max_delay_ms: Option<u64>,
        /// HTTP method, e.g. GET/POST/HEAD/OPTIONS
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// do not follow HTTP redirects
        #[arg(long, default_value_t = false)]
        no_follow_redirect: bool,
        /// high-speed mode for large wordlists: enable wildcard/fingerprint filters and disable redirect following
        #[arg(long, default_value_t = false)]
        smart_fast: bool,
        /// stricter high-speed mode: stronger filtering and default 200-399 status range
        #[arg(long, default_value_t = false, conflicts_with = "smart_fast")]
        smart_fast_strict: bool,
        /// enable recursive wordlist directory scan
        #[arg(short = 'R', long, default_value_t = false)]
        recursive: bool,
        /// max recursive depth when --recursive is enabled
        #[arg(short = 'D', long, default_value_t = 2)]
        recursive_depth: usize,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
    },
    /// Fuzz scan: URL template should contain FUZZ
    #[command(visible_alias = "f")]
    Fuzz {
        #[arg(short = 'u', long)]
        url: String,
        #[arg(short = 'k', long)]
        keywords: Vec<String>,
        /// optional keyword file path (one keyword per line)
        #[arg(long)]
        keywords_file: Option<PathBuf>,
        /// keyword transforms (repeat or comma-separated)
        #[arg(long = "kw-transform", value_enum, value_delimiter = ',')]
        kw_transforms: Vec<FuzzKeywordTransform>,
        /// built-in fuzz keyword preset: api|path|param
        #[arg(long, value_enum)]
        preset: Option<FuzzPreset>,
        /// optional prefix added to each generated keyword
        #[arg(long)]
        keyword_prefix: Option<String>,
        /// optional suffix added to each generated keyword
        #[arg(long)]
        keyword_suffix: Option<String>,
        /// max keyword length after transforms (drop longer entries)
        #[arg(long)]
        keyword_max_len: Option<usize>,
        /// show clustering summary (status + content length) after fuzz scan
        #[arg(long, default_value_t = false)]
        summary: bool,
        /// number of top clusters in summary output
        #[arg(long, default_value_t = 8)]
        summary_top: usize,
        /// minimum content length filter (inclusive)
        #[arg(long)]
        content_len_min: Option<u64>,
        /// maximum content length filter (inclusive)
        #[arg(long)]
        content_len_max: Option<u64>,
        #[arg(short = 'f', long)]
        stream_to: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'c', long)]
        concurrency: Option<usize>,
        #[arg(short = 't', long)]
        timeout_ms: Option<u64>,
        #[arg(short = 'r', long)]
        max_retries: Option<u32>,
        /// request header (repeatable), e.g. -H 'Authorization: Bearer xxx'
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// optional request body template; FUZZ will be replaced per keyword
        #[arg(long)]
        body: Option<String>,
        /// body encoding hint (auto sets Content-Type if absent)
        #[arg(long, value_enum, default_value_t = RequestBodyModeArg::Raw)]
        body_mode: RequestBodyModeArg,
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        /// explicitly disable deduplication
        #[arg(long, default_value_t = false)]
        no_dedupe: bool,
        #[arg(long)]
        status_min: Option<u16>,
        #[arg(long)]
        status_max: Option<u16>,
        #[arg(long, default_value_t = false)]
        wildcard_filter: bool,
        #[arg(long)]
        wildcard_samples: Option<usize>,
        #[arg(long)]
        wildcard_len_tolerance: Option<u64>,
        #[arg(long, default_value_t = false)]
        fingerprint_filter: bool,
        #[arg(long)]
        fingerprint_distance: Option<u32>,
        #[arg(long)]
        resume_file: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        adaptive_rate: bool,
        #[arg(long)]
        adaptive_initial_delay_ms: Option<u64>,
        #[arg(long)]
        adaptive_max_delay_ms: Option<u64>,
        /// HTTP method, e.g. GET/POST/HEAD/OPTIONS
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// do not follow HTTP redirects
        #[arg(long, default_value_t = false)]
        no_follow_redirect: bool,
        /// high-speed mode for large wordlists: enable wildcard/fingerprint filters and disable redirect following
        #[arg(long, default_value_t = false)]
        smart_fast: bool,
        /// stricter high-speed mode: stronger filtering and default 200-399 status range
        #[arg(long, default_value_t = false, conflicts_with = "smart_fast")]
        smart_fast_strict: bool,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
    },

    /// Subdomain burst (dns)
    #[command(visible_alias = "n")]
    Dns {
        #[arg(short = 'd', long)]
        domain: String,
        #[arg(short = 'w', long)]
        words: Vec<String>,
        /// optional wordlist file path (one word per line)
        #[arg(long)]
        words_file: Option<PathBuf>,
        /// subdomain discovery mode: rough|precise
        #[arg(long, value_enum, default_value_t = DnsDiscoveryMode::Precise)]
        discovery_mode: DnsDiscoveryMode,
        #[arg(short = 'f', long)]
        stream_to: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'c', long)]
        concurrency: Option<usize>,
        #[arg(short = 't', long)]
        timeout_ms: Option<u64>,
        #[arg(short = 'r', long)]
        max_retries: Option<u32>,
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        /// explicitly disable deduplication
        #[arg(long, default_value_t = false)]
        no_dedupe: bool,
        #[arg(long)]
        status_min: Option<u16>,
        #[arg(long)]
        status_max: Option<u16>,
        /// HTTP method, e.g. GET/POST/HEAD/OPTIONS
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// scan profile tuning: low-noise|balanced|aggressive
        #[arg(long, value_enum, default_value_t = ScanProfile::Balanced)]
        profile: ScanProfile,
    },
    /// Recursive crawler from seed URL(s)
    #[command(visible_alias = "c")]
    Crawl {
        #[arg(short = 's', long, required = true)]
        seeds: Vec<String>,
        #[arg(short = 'd', long, default_value_t = 2)]
        max_depth: usize,
        #[arg(short = 'c', long, default_value_t = 4)]
        concurrency: usize,
        #[arg(short = 'm', long)]
        max_pages: Option<usize>,
        #[arg(short = 'R', long, default_value_t = true)]
        obey_robots: bool,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Liveness check for one or more URLs
    #[command(visible_alias = "l")]
    Live {
        #[arg(short = 'u', long, required = true)]
        urls: Vec<String>,
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        #[arg(short = 'c', long, default_value_t = 16)]
        concurrency: usize,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ReverseActions {
    /// Static analysis for ELF/PE/APK + malware/packer heuristics
    Analyze {
        /// input file path
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input file path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        /// optional YAML/JSON rule file for anti-debug/packer detection
        #[arg(short = 'r', long)]
        rules_file: Option<PathBuf>,
        /// enable lightweight dynamic checks (Linux only)
        #[arg(long, default_value_t = false)]
        dynamic: bool,
        /// dynamic timeout in ms (implies --dynamic)
        #[arg(long)]
        dynamic_timeout_ms: Option<u64>,
        /// dynamic syscall list for strace (implies --dynamic)
        #[arg(long)]
        dynamic_syscalls: Option<String>,
        /// dynamic blocklist keywords (comma-separated, implies --dynamic)
        #[arg(long)]
        dynamic_blocklist: Option<String>,
        /// output format: raw/json
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        /// write output to file
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Build decompiler command plan for external engines
    DecompilePlan {
        /// input file path
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input file path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        /// engine: objdump|radare2|ghidra|jadx
        #[arg(short = 'e', long)]
        engine: String,
        /// optional output dir for engines that need it
        #[arg(short = 'd', long)]
        output_dir: Option<PathBuf>,
        /// output format: raw/json
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        /// write output to file
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Run decompile as managed job (store logs/artifacts under workspace/jobs)
    DecompileRun {
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input file path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        #[arg(short = 'e', long, default_value = "auto")]
        engine: String,
        /// decompile mode: full|index|function (ghidra only for index/function)
        #[arg(long, default_value = "full")]
        mode: String,
        /// function name or address (required when --mode function)
        #[arg(long)]
        function: Option<String>,
        /// enable deep decompile path (prefer Ghidra/JADX backend)
        #[arg(long, default_value_t = false)]
        deep: bool,
        /// prefer Rust-first pipeline when engine=auto (default true)
        #[arg(long, default_value_t = true, conflicts_with = "no_rust_first")]
        rust_first: bool,
        /// disable Rust-first pipeline and prefer backend decompile path
        #[arg(long, default_value_t = false)]
        no_rust_first: bool,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 't', long)]
        timeout_secs: Option<u64>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Run managed decompile for multiple inputs with bounded parallelism
    DecompileBatch {
        #[arg(short = 'i', long, alias = "input")]
        inputs: Vec<PathBuf>,
        /// input file paths (positional)
        #[arg(value_name = "INPUTS", index = 1, num_args = 1..)]
        inputs_pos: Vec<PathBuf>,
        #[arg(short = 'e', long, default_value = "auto")]
        engine: String,
        /// decompile mode: full|index|function (ghidra only for index/function)
        #[arg(long, default_value = "full")]
        mode: String,
        /// function name or address (used when --mode function)
        #[arg(long)]
        function: Option<String>,
        /// enable deep decompile path (prefer Ghidra/JADX backend)
        #[arg(long, default_value_t = false)]
        deep: bool,
        /// prefer Rust-first pipeline when engine=auto (default true)
        #[arg(long, default_value_t = true, conflicts_with = "no_rust_first")]
        rust_first: bool,
        /// disable Rust-first pipeline and prefer backend decompile path
        #[arg(long, default_value_t = false)]
        no_rust_first: bool,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 't', long)]
        timeout_secs: Option<u64>,
        #[arg(short = 'c', long, default_value_t = 2)]
        parallel_jobs: usize,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// List reverse decompile jobs
    Jobs {
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Query one job status
    JobStatus {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Print job logs
    JobLogs {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        /// stdout|stderr|both
        #[arg(short = 's', long, default_value = "both")]
        stream: String,
    },
    /// Show job artifacts
    JobArtifacts {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// List function symbols from job pseudocode
    JobFunctions {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Show one function pseudocode by name/ea from job
    JobShow {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'n', long, alias = "function")]
        name: Option<String>,
        /// function name or address (positional)
        #[arg(value_name = "NAME", index = 2)]
        name_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Search keyword in function name/pseudocode from job
    JobSearch {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'k', long, alias = "query")]
        keyword: Option<String>,
        /// keyword (positional)
        #[arg(value_name = "KEYWORD", index = 2)]
        keyword_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'm', long, default_value_t = 30)]
        max: usize,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Clear reverse jobs
    JobClear {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Prune old reverse jobs and keep only latest N
    JobPrune {
        #[arg(short = 'k', long, default_value_t = 20)]
        keep: usize,
        #[arg(long)]
        older_than_days: Option<u64>,
        #[arg(long, default_value_t = false)]
        include_running: bool,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Validate one job's artifacts/logs/jsonl integrity
    JobDoctor {
        #[arg(short = 'j', long, alias = "id")]
        job: Option<String>,
        /// job id (positional)
        #[arg(value_name = "JOB", index = 1)]
        job_pos: Option<String>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Generate a pwngdb-like gdb script for dynamic debugging bootstrap
    DebugScript {
        /// target executable path
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// target executable path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        /// profile name: pwngdb|pwndbg
        #[arg(short = 'p', long, default_value = "pwndbg")]
        profile: String,
        /// optional pwndbg init script path, e.g. ~/pwndbg/gdbinit.py
        #[arg(short = 'P', long)]
        pwndbg_init: Option<PathBuf>,
        /// script file output path
        #[arg(short = 's', long)]
        script_out: PathBuf,
    },
    /// Generate GDB Python plugin (register/stack/heap/symbol helpers)
    GdbPlugin {
        /// output plugin path, e.g. ./rscan_gdb_plugin.py
        #[arg(short = 'f', long)]
        out: PathBuf,
    },
    /// Generate Ghidra Headless export script (function-level pseudocode JSONL)
    GhidraScript {
        /// output script path, e.g. ./ghidra_export_pseudocode.java
        #[arg(short = 'f', long)]
        out: PathBuf,
    },
    /// Generate Ghidra index export script (functions + externals)
    GhidraIndexScript {
        /// output script path, e.g. ./ghidra_export_index.java
        #[arg(short = 'f', long)]
        out: PathBuf,
    },
    /// Generate Ghidra function export script (single function pseudocode)
    GhidraFunctionScript {
        /// output script path, e.g. ./ghidra_export_function.java
        #[arg(short = 'f', long)]
        out: PathBuf,
    },
    /// Emit default reverse detection rules template (YAML/JSON by extension)
    RulesTemplate {
        /// output rules file path, e.g. ./reverse_rules.yaml
        #[arg(short = 'f', long)]
        out: PathBuf,
    },
    /// Malware triage: IOC extraction + shell/payload behavior hints
    MalwareTriage {
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input file path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Audit shell script/text for suspicious payload patterns
    ShellAudit {
        /// direct script string; if omitted use --input
        #[arg(short = 't', long)]
        text: Option<String>,
        /// script file path (used when --text omitted)
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// script file path (positional, used when --text omitted)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Interactive reverse console (analysis + pseudocode + debug in one session)
    Console {
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input file path (positional)
        #[arg(value_name = "INPUT", index = 1)]
        input_pos: Option<PathBuf>,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'P', long)]
        pwndbg_init: Option<PathBuf>,
        /// Enable TUI mode (split panes)
        #[arg(long, default_value_t = false)]
        tui: bool,
        /// Override Ghidra headless runtime (run-headless.sh or analyzeHeadless)
        #[arg(long)]
        ghidra_home: Option<PathBuf>,
    },
    /// Check availability of external reverse backends (ghidra/jadx/pwndbg/etc.)
    BackendStatus {
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
}

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

fn parse_output(fmt: &str) -> OutputFormat {
    match fmt.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "csv" => OutputFormat::Csv,
        _ => OutputFormat::Raw,
    }
}

fn normalize_filter_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn load_keywords_file(path: &PathBuf) -> Result<Vec<String>, RustpenError> {
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;
    let mut out = Vec::new();
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        out.push(s.to_string());
    }
    Ok(out)
}

fn percent_encode_non_unreserved(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn apply_kw_transform(s: &str, t: FuzzKeywordTransform) -> String {
    match t {
        FuzzKeywordTransform::Raw => s.to_string(),
        FuzzKeywordTransform::UrlEncode => percent_encode_non_unreserved(s),
        FuzzKeywordTransform::DoubleUrlEncode => {
            percent_encode_non_unreserved(&percent_encode_non_unreserved(s))
        }
        FuzzKeywordTransform::Lower => s.to_ascii_lowercase(),
        FuzzKeywordTransform::Upper => s.to_ascii_uppercase(),
        FuzzKeywordTransform::PathWrap => format!("/{}/", s.trim_matches('/')),
    }
}

fn preset_default_transforms(preset: FuzzPreset) -> Vec<FuzzKeywordTransform> {
    match preset {
        FuzzPreset::Api => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::Lower,
            FuzzKeywordTransform::UrlEncode,
        ],
        FuzzPreset::Path => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::PathWrap,
            FuzzKeywordTransform::UrlEncode,
        ],
        FuzzPreset::Param => vec![
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::UrlEncode,
            FuzzKeywordTransform::DoubleUrlEncode,
        ],
    }
}

fn expand_keywords_with_preset(words: Vec<String>, preset: Option<FuzzPreset>) -> Vec<String> {
    let Some(preset) = preset else { return words };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for kw in words {
        if kw.trim().is_empty() {
            continue;
        }
        let variants: Vec<String> = match preset {
            FuzzPreset::Api => vec![
                kw.clone(),
                format!("api/{kw}"),
                format!("v1/{kw}"),
                format!("{kw}.json"),
                format!("{kw}.xml"),
            ],
            FuzzPreset::Path => vec![
                kw.clone(),
                format!("{kw}/"),
                format!(".{kw}"),
                format!("{kw}.bak"),
                format!("{kw}.old"),
            ],
            FuzzPreset::Param => vec![
                kw.clone(),
                format!("{kw}=1"),
                format!("{kw}=test"),
                format!("{kw}[]="),
                format!("{kw}=%7B%7D"),
            ],
        };
        for v in variants {
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

fn build_fuzz_keywords(
    base_keywords: Vec<String>,
    transforms: &[FuzzKeywordTransform],
    prefix: Option<String>,
    suffix: Option<String>,
    max_len: Option<usize>,
) -> Vec<String> {
    let transform_set = if transforms.is_empty() {
        vec![FuzzKeywordTransform::Raw]
    } else {
        transforms.to_vec()
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for kw in base_keywords {
        let trimmed = kw.trim();
        if trimmed.is_empty() {
            continue;
        }
        for t in &transform_set {
            let mut v = apply_kw_transform(trimmed, *t);
            if let Some(p) = prefix.as_ref() {
                v = format!("{p}{v}");
            }
            if let Some(s) = suffix.as_ref() {
                v.push_str(s);
            }
            if let Some(mx) = max_len
                && v.len() > mx
            {
                continue;
            }
            if seen.insert(v.clone()) {
                out.push(v);
            }
        }
    }
    out
}

fn filter_vuln_templates(
    templates: Vec<SafeTemplate>,
    severities: &[String],
    tags: &[String],
) -> Vec<SafeTemplate> {
    let sev_set = normalize_filter_set(severities);
    let tag_set = normalize_filter_set(tags);
    if sev_set.is_empty() && tag_set.is_empty() {
        return templates;
    }

    templates
        .into_iter()
        .filter(|tpl| {
            let sev_ok = if sev_set.is_empty() {
                true
            } else {
                tpl.info
                    .severity
                    .as_ref()
                    .map(|s| sev_set.contains(&s.to_ascii_lowercase()))
                    .unwrap_or(false)
            };
            let tag_ok = if tag_set.is_empty() {
                true
            } else {
                tpl.info
                    .tags
                    .iter()
                    .any(|t| tag_set.contains(&t.to_ascii_lowercase()))
            };
            sev_ok && tag_ok
        })
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct EngineTuning {
    workers: usize,
    max_in_flight: usize,
    timeout_ms: u64,
    retries: u32,
    retry_delay_ms: Option<u64>,
}

fn async_engine_tuning(profile: ScanProfile) -> EngineTuning {
    match profile {
        ScanProfile::LowNoise => EngineTuning {
            workers: 8,
            max_in_flight: 16,
            timeout_ms: 2500,
            retries: 1,
            retry_delay_ms: Some(120),
        },
        ScanProfile::Balanced => EngineTuning {
            workers: 64,
            max_in_flight: 64,
            timeout_ms: 1200,
            retries: 1,
            retry_delay_ms: None,
        },
        ScanProfile::Aggressive => EngineTuning {
            workers: 128,
            max_in_flight: 128,
            timeout_ms: 900,
            retries: 0,
            retry_delay_ms: None,
        },
    }
}

fn raw_engine_tuning(profile: ScanProfile) -> EngineTuning {
    match profile {
        ScanProfile::LowNoise => EngineTuning {
            workers: 4,
            max_in_flight: 8,
            timeout_ms: 2800,
            retries: 1,
            retry_delay_ms: Some(140),
        },
        ScanProfile::Balanced => EngineTuning {
            workers: 16,
            max_in_flight: 256,
            timeout_ms: 1200,
            retries: 1,
            retry_delay_ms: None,
        },
        ScanProfile::Aggressive => EngineTuning {
            workers: 32,
            max_in_flight: 512,
            timeout_ms: 900,
            retries: 0,
            retry_delay_ms: None,
        },
    }
}

fn tcp_config_for_profile(profile: ScanProfile) -> crate::cores::host::TcpConfig {
    match profile {
        ScanProfile::LowNoise => crate::cores::host::TcpConfig {
            timeout_seconds: 4,
            timeout_ms: Some(2500),
            concurrent: true,
            concurrency: 16,
            retries: 1,
            max_rate: Some(220),
            jitter_ms: Some(12),
            scan_order: crate::cores::host::TcpScanOrder::Interleave,
            adaptive_backpressure: true,
        },
        ScanProfile::Balanced => crate::cores::host::TcpConfig {
            timeout_seconds: 2,
            timeout_ms: Some(1300),
            concurrent: true,
            concurrency: 512,
            retries: 0,
            max_rate: Some(3200),
            jitter_ms: Some(3),
            scan_order: crate::cores::host::TcpScanOrder::Interleave,
            adaptive_backpressure: true,
        },
        ScanProfile::Aggressive => crate::cores::host::TcpConfig {
            timeout_seconds: 1,
            timeout_ms: Some(800),
            concurrent: true,
            concurrency: 1024,
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: crate::cores::host::TcpScanOrder::Random,
            adaptive_backpressure: false,
        },
    }
}

fn tcp_config_with_overrides(
    profile: ScanProfile,
    tcp_timeout_ms: Option<u64>,
    tcp_concurrency: Option<usize>,
    tcp_retries: Option<u32>,
    tcp_max_rate: Option<u32>,
    tcp_jitter_ms: Option<u64>,
    tcp_scan_order: Option<TcpScanOrderArg>,
    tcp_adaptive_backpressure: bool,
) -> crate::cores::host::TcpConfig {
    let mut cfg = tcp_config_for_profile(profile);
    if let Some(ms) = tcp_timeout_ms {
        cfg.timeout_ms = Some(ms.max(1));
        cfg.timeout_seconds = std::cmp::max(1, ms / 1000);
    }
    if let Some(c) = tcp_concurrency {
        cfg.concurrency = c.max(1);
        cfg.concurrent = true;
    }
    if let Some(r) = tcp_retries {
        cfg.retries = r;
    }
    if let Some(rate) = tcp_max_rate {
        cfg.max_rate = Some(rate.max(1));
    }
    if let Some(j) = tcp_jitter_ms {
        cfg.jitter_ms = Some(j.min(200));
    }
    if let Some(order) = tcp_scan_order {
        cfg.scan_order = match order {
            TcpScanOrderArg::Serial => crate::cores::host::TcpScanOrder::Serial,
            TcpScanOrderArg::Random => crate::cores::host::TcpScanOrder::Random,
            TcpScanOrderArg::Interleave => crate::cores::host::TcpScanOrder::Interleave,
        };
    }
    if tcp_adaptive_backpressure {
        cfg.adaptive_backpressure = true;
    }
    cfg
}

fn turbo_phase1_config(mut cfg: crate::cores::host::TcpConfig) -> crate::cores::host::TcpConfig {
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(800).min(500));
    cfg.timeout_seconds = 1;
    cfg.concurrent = true;
    cfg.concurrency = cfg.concurrency.max(3072);
    cfg.retries = 0;
    cfg
}

fn turbo_phase2_verify_config(
    baseline: crate::cores::host::TcpConfig,
) -> crate::cores::host::TcpConfig {
    let mut cfg = baseline;
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(1000).max(1200));
    cfg.timeout_seconds = cfg.timeout_ms.unwrap_or(1200) / 1000;
    cfg.concurrent = true;
    cfg.concurrency = cfg.concurrency.clamp(128, 1024);
    cfg.retries = cfg.retries.max(1);
    cfg
}

fn turbo_phase2_verify_config_adaptive(
    baseline: crate::cores::host::TcpConfig,
    filtered_ratio: f64,
) -> crate::cores::host::TcpConfig {
    let mut cfg = baseline;
    let timeout_floor = if filtered_ratio >= 0.7 {
        1600
    } else if filtered_ratio >= 0.45 {
        1300
    } else {
        1100
    };
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(1000).max(timeout_floor));
    cfg.timeout_seconds = std::cmp::max(1, cfg.timeout_ms.unwrap_or(timeout_floor) / 1000);
    cfg.concurrent = true;
    cfg.concurrency = if filtered_ratio >= 0.7 {
        cfg.concurrency.clamp(512, 1536)
    } else {
        cfg.concurrency.clamp(768, 2048)
    };
    cfg.retries = cfg.retries.max(1);
    cfg
}

fn merge_verified_tcp_subset(
    first: &mut HostScanResult,
    second: &HostScanResult,
    verified_ports: &[u16],
) {
    for &port in verified_ports {
        let status = if second.is_port_open(port) {
            crate::cores::host::PortStatus::Open
        } else if second.is_port_filtered(port) {
            crate::cores::host::PortStatus::Filtered
        } else {
            crate::cores::host::PortStatus::Closed
        };
        first.overwrite_port_status(port, status);
    }
    for detail in second.open_port_details() {
        first.merge_open_port_detail(detail.clone());
    }
}

fn prioritized_filtered_ports(filtered: &[u16]) -> Vec<u16> {
    // Common service ports worth a deterministic second look in adaptive mode.
    const PRIORITY: &[u16] = &[
        20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445,
        465, 587, 636, 873, 902, 912, 993, 995, 1433, 1521, 2049, 2179, 2375, 2376, 3306, 3389,
        4712, 5040, 5357, 5432, 5601, 5672, 5900, 6379, 6443, 7001, 7680, 7897, 8080, 8083, 8443,
        8888, 9000, 9012, 9013, 9200, 11211, 27017,
    ];
    let set: BTreeSet<u16> = filtered.iter().copied().collect();
    PRIORITY
        .iter()
        .filter(|p| set.contains(p))
        .copied()
        .collect()
}

fn sample_ports_for_autotune(ports: &[u16], limit: usize) -> Vec<u16> {
    if ports.is_empty() {
        return Vec::new();
    }
    if ports.len() <= limit {
        return ports.to_vec();
    }
    let stride = (ports.len() / limit.max(1)).max(1);
    let mut sampled = Vec::with_capacity(limit.min(ports.len()));
    for offset in 0..stride.min(16) {
        let mut idx = offset;
        while idx < ports.len() && sampled.len() < limit {
            sampled.push(ports[idx]);
            idx += stride;
        }
        if sampled.len() >= limit {
            break;
        }
    }
    sampled.sort_unstable();
    sampled.dedup();
    sampled
}

fn udp_config_for_profile(profile: ScanProfile) -> crate::cores::host::UdpConfig {
    match profile {
        ScanProfile::LowNoise => crate::cores::host::UdpConfig {
            send_timeout_seconds: 3,
            receive_timeout_seconds: 4,
            concurrent: true,
            concurrency: 6,
            probe_data: vec![0x00, 0x01],
            max_retries: 2,
            delay_ms: Some(80),
        },
        ScanProfile::Balanced => crate::cores::host::UdpConfig {
            send_timeout_seconds: 2,
            receive_timeout_seconds: 3,
            concurrent: true,
            concurrency: 32,
            probe_data: vec![0x00, 0x01, 0x02, 0x03],
            max_retries: 1,
            delay_ms: None,
        },
        ScanProfile::Aggressive => crate::cores::host::UdpConfig {
            send_timeout_seconds: 1,
            receive_timeout_seconds: 2,
            concurrent: true,
            concurrency: 128,
            probe_data: vec![0x00, 0x01, 0x02, 0x03],
            max_retries: 0,
            delay_ms: None,
        },
    }
}

fn apply_web_profile(mcfg: &mut ModuleScanConfig, profile: ScanProfile) {
    match profile {
        ScanProfile::LowNoise => {
            mcfg.concurrency = 4;
            mcfg.timeout_ms = Some(8000);
            mcfg.max_retries = Some(2);
            mcfg.per_host_concurrency_override = Some(1);
            mcfg.adaptive_rate = true;
            mcfg.adaptive_initial_delay_ms = 120;
            mcfg.adaptive_max_delay_ms = 2200;
        }
        ScanProfile::Balanced => {
            mcfg.concurrency = 24;
            mcfg.timeout_ms = Some(5000);
            mcfg.max_retries = Some(0);
            mcfg.per_host_concurrency_override = Some(16);
        }
        ScanProfile::Aggressive => {
            mcfg.concurrency = 64;
            mcfg.timeout_ms = Some(2500);
            mcfg.max_retries = Some(0);
            mcfg.per_host_concurrency_override = Some(32);
            mcfg.adaptive_rate = false;
            mcfg.adaptive_initial_delay_ms = 0;
            mcfg.adaptive_max_delay_ms = 800;
        }
    }
}

fn apply_web_smart_fast(
    mcfg: &mut ModuleScanConfig,
    status_min: Option<u16>,
    status_max: Option<u16>,
) {
    mcfg.follow_redirects = false;
    mcfg.wildcard_filter = true;
    mcfg.fingerprint_filter = true;
    // Keep user-provided status filter first. If not provided, use a practical default
    // that preserves common "interesting" ranges while reducing noisy 4xx/5xx tails.
    if status_min.is_none() && status_max.is_none() {
        mcfg.status_min = Some(200);
        mcfg.status_max = Some(403);
    }
}

fn apply_web_smart_fast_strict(
    mcfg: &mut ModuleScanConfig,
    status_min: Option<u16>,
    status_max: Option<u16>,
) {
    mcfg.follow_redirects = false;
    mcfg.wildcard_filter = true;
    mcfg.wildcard_sample_count = 1;
    mcfg.wildcard_len_tolerance = 8;
    mcfg.fingerprint_filter = true;
    mcfg.fingerprint_distance_threshold = 3;
    mcfg.max_retries = Some(0);
    if status_min.is_none() && status_max.is_none() {
        mcfg.status_min = Some(200);
        mcfg.status_max = Some(399);
    }
}

fn parse_http_method(method: &str) -> Result<reqwest::Method, RustpenError> {
    reqwest::Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
        .map_err(|e| RustpenError::ParseError(format!("invalid --method '{}': {}", method, e)))
}

fn parse_request_headers(
    values: &[String],
) -> Result<reqwest::header::HeaderMap, RustpenError> {
    let mut map = reqwest::header::HeaderMap::new();
    for raw in values {
        let Some((name, value)) = raw.split_once(':') else {
            return Err(RustpenError::ParseError(format!(
                "invalid --header '{}', expected 'Name: Value'",
                raw
            )));
        };
        let name = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|e| RustpenError::ParseError(format!("invalid header name: {}", e)))?;
        let value = reqwest::header::HeaderValue::from_str(value.trim())
            .map_err(|e| RustpenError::ParseError(format!("invalid header value: {}", e)))?;
        map.insert(name, value);
    }
    Ok(map)
}

fn apply_body_mode_default_content_type(
    headers: &mut reqwest::header::HeaderMap,
    mode: RequestBodyModeArg,
    has_body: bool,
) {
    if !has_body || headers.contains_key(reqwest::header::CONTENT_TYPE) {
        return;
    }
    let value = match mode {
        RequestBodyModeArg::Raw => return,
        RequestBodyModeArg::Form => "application/x-www-form-urlencoded",
        RequestBodyModeArg::Json => "application/json",
    };
    if let Ok(v) = reqwest::header::HeaderValue::from_str(value) {
        headers.insert(reqwest::header::CONTENT_TYPE, v);
    }
}

fn parse_decompile_mode(mode: &str) -> Result<DecompileMode, RustpenError> {
    DecompileMode::parse(mode).ok_or_else(|| {
        RustpenError::ParseError("invalid --mode. use: full|index|function".to_string())
    })
}

fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("RSCAN_NO_COLOR").is_some() {
        return false;
    }
    if let Ok(v) = std::env::var("RSCAN_COLOR") {
        return v != "0";
    }
    std::io::stdout().is_terminal()
}

fn format_scan_for_stdout(r: &ModuleScanResult, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Raw => format_scan_result_pretty(r, color_enabled()),
        _ => format_scan_result(r, fmt),
    }
}

fn format_scan_error_line(err: &RustpenError, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Json => serde_json::json!({ "error": err.to_string() }).to_string(),
        OutputFormat::Csv => format!("error,{}", err.to_string().replace(',', " ")),
        OutputFormat::Raw => format!("ERROR {}", err),
    }
}

fn colorize(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn severity_badge(sev: Option<&str>) -> (&'static str, &'static str) {
    match sev.unwrap_or("").to_ascii_lowercase().as_str() {
        "critical" => ("CRIT", "31"),
        "high" => ("HIGH", "31"),
        "medium" => ("MED", "33"),
        "low" => ("LOW", "32"),
        "info" => ("INFO", "36"),
        _ => ("UNKWN", "90"),
    }
}

fn format_host_scan_pretty(r: &HostScanResult, color: bool) -> String {
    let proto = format!("{:?}", r.protocol).to_lowercase();
    let proto_col = match proto.as_str() {
        "tcp" => colorize("tcp", "36", color),
        "udp" => colorize("udp", "35", color),
        "syn" => colorize("syn", "33", color),
        "arp" => colorize("arp", "32", color),
        "icmp" => colorize("icmp", "34", color),
        _ => proto,
    };
    let header = format!(
        "host={} ip={} proto={} open={} filtered={} scanned={} errors={} duration_ms={}",
        r.host,
        r.ip,
        proto_col,
        colorize(&r.open_ports_count().to_string(), "32", color),
        colorize(&r.filtered_ports_count().to_string(), "33", color),
        r.total_scanned,
        r.errors,
        r.scan_duration.as_millis()
    );
    let mut lines = vec![header];
    if r.open_ports_count() == 0 {
        lines.push(colorize("no open ports", "90", color));
        return lines.join("\n");
    }
    lines.push(format!(
        "{:>6} {:>5} {:>8} {}",
        "PORT", "PROTO", "LAT(ms)", "BANNER"
    ));
    for p in r.open_port_details() {
        let port = colorize(&format!("{:>6}", p.port), "32", color);
        let proto = colorize(&format!("{:?}", p.protocol).to_lowercase(), "36", color);
        let lat = p
            .latency_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let banner = p
            .banner
            .as_ref()
            .map(|s| s.as_ref().replace('\n', " "))
            .unwrap_or_else(|| "".to_string());
        lines.push(format!("{port} {:>5} {:>8} {banner}", proto, lat));
    }
    lines.join("\n")
}

fn format_engine_scan_pretty(results: &[EngineScanResult], color: bool) -> String {
    if results.is_empty() {
        return colorize("no results", "90", color);
    }
    let mut out = Vec::new();
    out.push(format!(
        "{:>15} {:>6} {:>5} {:>9} {:>10} {}",
        "IP", "PORT", "PROTO", "STATUS", "LAT(ms)", "META"
    ));
    for r in results {
        let status = format!("{:?}", r.status);
        let status_col = if status.eq_ignore_ascii_case("open") {
            colorize(&format!("{:>9}", status.to_lowercase()), "32", color)
        } else if status.eq_ignore_ascii_case("closed") {
            colorize(&format!("{:>9}", status.to_lowercase()), "90", color)
        } else {
            colorize(&format!("{:>9}", status.to_lowercase()), "33", color)
        };
        let proto = colorize(&format!("{:?}", r.protocol).to_lowercase(), "36", color);
        let lat = r
            .latency_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let port = r
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push(format!(
            "{:>15} {:>6} {:>5} {} {:>10} {:?}",
            r.target_ip, port, proto, status_col, lat, r.metadata
        ));
    }
    out.join("\n")
}

fn format_vuln_report_pretty(r: &VulnScanReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "scan=ok requests={} findings={} errors={}",
        r.scanned_requests,
        r.findings.len(),
        r.errors.len()
    ));
    if r.findings.is_empty() {
        lines.push(colorize("no findings", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<16} {:<6} {}",
            "SEV", "TEMPLATE", "METHOD", "URL"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(f.severity.as_deref());
            let sev = colorize(&format!("{:>6}", badge), code, color);
            let tpl = f.template_id.clone();
            let method = f.method.to_ascii_uppercase();
            lines.push(format!("{sev} {:<16} {:<6} {}", tpl, method, f.url));
            if !f.matched.is_empty() {
                lines.push(format!("      matched={}", f.matched.join(",")));
            }
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

fn format_container_audit_pretty(r: &ContainerAuditReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "audit=ok files={} objects={} findings={} errors={}",
        r.files_scanned,
        r.objects_scanned,
        r.findings.len(),
        r.errors.len()
    ));

    if r.findings.is_empty() {
        lines.push(colorize("no risky manifest settings found", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<28} {:<24} {}",
            "SEV", "RULE", "OBJECT", "PATH"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(Some(&f.severity));
            let sev = colorize(&format!("{:>6}", badge), code, color);
            lines.push(format!("{sev} {:<28} {:<24} {}", f.rule, f.object, f.path));
        }
    }

    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

fn format_system_guard_pretty(r: &SystemGuardReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "system-guard os={} processes={} controls={}/{} score={}",
        r.host_os, r.processes_scanned, r.controls_present, r.controls_total, r.score
    ));

    if r.findings.is_empty() {
        lines.push(colorize("no findings", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<22} {:<28} {}",
            "SEV", "CATEGORY", "RULE", "EVIDENCE"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(Some(&f.severity));
            let sev = colorize(&format!("{:>6}", badge), code, color);
            lines.push(format!(
                "{sev} {:<22} {:<28} {}",
                f.category, f.rule, f.evidence
            ));
            lines.push(format!("      {}", f.message));
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

fn format_stealth_check_pretty(r: &AntiScanReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!("stealth-check target={}", r.target));
    lines.push(format!(
        "protection_score={} confidence={}",
        r.protection_score, r.confidence
    ));
    lines.push(format!(
        "phase=low-noise sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.low_noise.sent,
        r.low_noise.success,
        r.low_noise.blocked,
        r.low_noise.timeouts,
        r.low_noise.network_errors,
        r.low_noise.avg_latency_ms,
        r.low_noise.p95_latency_ms,
        r.low_noise.block_ratio
    ));
    lines.push(format!(
        "phase=burst sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.burst.sent,
        r.burst.success,
        r.burst.blocked,
        r.burst.timeouts,
        r.burst.network_errors,
        r.burst.avg_latency_ms,
        r.burst.p95_latency_ms,
        r.burst.block_ratio
    ));

    if !r.variant_probes.is_empty() {
        lines.push("variants:".to_string());
        for v in &r.variant_probes {
            lines.push(format!(
                "variant={} sent={} success={} blocked={} timeout={} avg_ms={} block_ratio={:.2}",
                v.name,
                v.stats.sent,
                v.stats.success,
                v.stats.blocked,
                v.stats.timeouts,
                v.stats.avg_latency_ms,
                v.stats.block_ratio
            ));
        }
    }

    if !r.header_signals.is_empty() {
        lines.push(format!("header_signals={}", r.header_signals.join(",")));
    }

    lines.push("findings:".to_string());
    for f in &r.findings {
        let (badge, code) = severity_badge(Some(&f.severity));
        let sev = colorize(&format!("{:>6}", badge), code, color);
        lines.push(format!(
            "{sev} {:<18} {:<28} {}",
            f.category, f.rule, f.message
        ));
        lines.push(format!("      evidence={}", f.evidence));
    }
    if !r.recommendations.is_empty() {
        lines.push("recommendations:".to_string());
        for x in &r.recommendations {
            lines.push(format!("- {}", x));
        }
    }

    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }

    lines.join("\n")
}

fn format_fragment_audit_pretty(r: &FragmentAuditReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!("fragment-audit target={}", r.target));
    lines.push(format!(
        "reassembly_score={} confidence={}",
        r.reassembly_score, r.confidence
    ));
    lines.push(format!(
        "baseline sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.baseline.sent,
        r.baseline.success,
        r.baseline.blocked,
        r.baseline.timeouts,
        r.baseline.network_errors,
        r.baseline.avg_latency_ms,
        r.baseline.p95_latency_ms,
        r.baseline.block_ratio
    ));
    if !r.tiers.is_empty() {
        lines.push("tiers:".to_string());
        for t in &r.tiers {
            lines.push(format!(
                "tier={} payload_bytes={} header(block={:.2},timeout={},avg_ms={}) body(block={:.2},timeout={},avg_ms={})",
                t.name,
                t.payload_bytes,
                t.header_probe.block_ratio,
                t.header_probe.timeouts,
                t.header_probe.avg_latency_ms,
                t.body_probe.block_ratio,
                t.body_probe.timeouts,
                t.body_probe.avg_latency_ms
            ));
        }
    }
    if !r.header_signals.is_empty() {
        lines.push(format!("header_signals={}", r.header_signals.join(",")));
    }
    lines.push("findings:".to_string());
    for f in &r.findings {
        let (badge, code) = severity_badge(Some(&f.severity));
        let sev = colorize(&format!("{:>6}", badge), code, color);
        lines.push(format!(
            "{sev} {:<18} {:<28} {}",
            f.category, f.rule, f.message
        ));
        lines.push(format!("      evidence={}", f.evidence));
    }
    if !r.recommendations.is_empty() {
        lines.push("recommendations:".to_string());
        for x in &r.recommendations {
            lines.push(format!("- {}", x));
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

fn stream_progress_pct(processed: usize, total_hint: Option<usize>) -> f32 {
    match total_hint {
        Some(total) if total > 0 => {
            let ratio = (processed.min(total) as f32) / (total as f32);
            (10.0 + ratio * 85.0).min(95.0)
        }
        _ => (10.0 + (processed as f32).ln_1p() * 18.0).min(95.0),
    }
}

fn report_progress(events: &Option<TaskEventWriter>, pct: f32, message: impl Into<String>) {
    if let Some(w) = events.as_ref() {
        let _ = w.progress(pct, Some(message.into()));
    }
}

fn report_log(events: &Option<TaskEventWriter>, message: impl Into<String>) {
    if let Some(w) = events.as_ref() {
        let _ = w.log("info", message.into());
    }
}

async fn consume_module_stream(
    mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>,
    out_path: Option<PathBuf>,
    fmt: OutputFormat,
    events: Option<TaskEventWriter>,
    total_hint: Option<usize>,
    stage: &str,
) -> Result<(), RustpenError> {
    report_progress(&events, 12.0, format!("{stage}: start"));

    let mut file = if let Some(path) = out_path {
        Some(File::create(path).await.map_err(RustpenError::Io)?)
    } else {
        None
    };

    let mut processed = 0usize;
    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                if let Some(file) = file.as_mut() {
                    let line = format!("{}\n", format_scan_result(&m, &fmt));
                    file.write_all(line.as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else {
                    println!("{}", format_scan_for_stdout(&m, &fmt));
                }
            }
            Err(e) => {
                let err_line = format_scan_error_line(&e, &fmt);
                if let Some(file) = file.as_mut() {
                    file.write_all(format!("{err_line}\n").as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else {
                    println!("{err_line}");
                }
            }
        }

        let pct = stream_progress_pct(processed, total_hint);
        let msg = match total_hint {
            Some(total) if total > 0 => format!("{stage}: processed {processed}/{total}"),
            _ => format!("{stage}: processed {processed}"),
        };
        report_progress(&events, pct, msg);
    }

    if processed == 0 {
        report_progress(&events, 95.0, format!("{stage}: no result"));
    }
    Ok(())
}

async fn consume_module_stream_with_summary(
    mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>,
    out_path: Option<PathBuf>,
    fmt: OutputFormat,
    events: Option<TaskEventWriter>,
    total_hint: Option<usize>,
    stage: &str,
    top_n: usize,
) -> Result<(), RustpenError> {
    report_progress(&events, 12.0, format!("{stage}: start"));

    let mut file = if let Some(path) = out_path {
        Some(File::create(path).await.map_err(RustpenError::Io)?)
    } else {
        None
    };

    let mut processed = 0usize;
    let mut clusters: std::collections::BTreeMap<(u16, Option<u64>), usize> =
        std::collections::BTreeMap::new();
    let mut err_count = 0usize;

    while let Some(r) = rx.recv().await {
        processed += 1;
        match r {
            Ok(m) => {
                let key = (m.status, m.content_len);
                *clusters.entry(key).or_insert(0) += 1;
                if let Some(file) = file.as_mut() {
                    let line = format!("{}\n", format_scan_result(&m, &fmt));
                    file.write_all(line.as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else {
                    println!("{}", format_scan_for_stdout(&m, &fmt));
                }
            }
            Err(e) => {
                err_count += 1;
                let err_line = format_scan_error_line(&e, &fmt);
                if let Some(file) = file.as_mut() {
                    file.write_all(format!("{err_line}\n").as_bytes())
                        .await
                        .map_err(RustpenError::Io)?;
                } else {
                    println!("{err_line}");
                }
            }
        }

        let pct = stream_progress_pct(processed, total_hint);
        let msg = match total_hint {
            Some(total) if total > 0 => format!("{stage}: processed {processed}/{total}"),
            _ => format!("{stage}: processed {processed}"),
        };
        report_progress(&events, pct, msg);
    }

    let mut ranked: Vec<_> = clusters.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));
    let n = top_n.max(1);
    let summary_lines = ranked
        .iter()
        .take(n)
        .map(|((status, len), count)| {
            format!(
                "cluster status={} content_len={} count={}",
                status,
                len.map(|v| v.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                count
            )
        })
        .collect::<Vec<_>>();
    let summary_header = format!(
        "summary clusters={} shown={} errors={}",
        ranked.len(),
        summary_lines.len(),
        err_count
    );

    if let Some(file) = file.as_mut() {
        file.write_all(format!("{summary_header}\n").as_bytes())
            .await
            .map_err(RustpenError::Io)?;
        for ln in &summary_lines {
            file.write_all(format!("{ln}\n").as_bytes())
                .await
                .map_err(RustpenError::Io)?;
        }
    } else {
        println!("{summary_header}");
        for ln in &summary_lines {
            println!("{ln}");
        }
    }

    if processed == 0 {
        report_progress(&events, 95.0, format!("{stage}: no result"));
    }
    Ok(())
}

fn format_host_scan_result(r: &HostScanResult, fmt: &str) -> String {
    match fmt.to_lowercase().as_str() {
        "json" => serde_json::to_string(&r.to_json())
            .unwrap_or_else(|_| format!("host: {} open: {:?}", r.host, r.open_ports())),
        _ => format_host_scan_pretty(r, color_enabled()),
    }
}

fn format_engine_scan_results(results: &[EngineScanResult], fmt: &str) -> String {
    match fmt.to_lowercase().as_str() {
        "json" => {
            let rows: Vec<_> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "target_ip": r.target_ip.to_string(),
                        "port": r.port,
                        "protocol": format!("{:?}", r.protocol),
                        "status": format!("{:?}", r.status),
                        "latency_ms": r.latency_ms,
                        "response_len": r.response.as_ref().map(|v| v.len()),
                        "metadata": r.metadata,
                    })
                })
                .collect();
            serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
        }
        _ => format_engine_scan_pretty(results, color_enabled()),
    }
}

fn engine_status_to_host_status(
    status: crate::cores::engine::scan_result::ScanStatus,
) -> crate::cores::host::PortStatus {
    match status {
        crate::cores::engine::scan_result::ScanStatus::Open => crate::cores::host::PortStatus::Open,
        crate::cores::engine::scan_result::ScanStatus::Closed => {
            crate::cores::host::PortStatus::Closed
        }
        crate::cores::engine::scan_result::ScanStatus::Filtered => {
            crate::cores::host::PortStatus::Filtered
        }
        crate::cores::engine::scan_result::ScanStatus::Unknown
        | crate::cores::engine::scan_result::ScanStatus::Error => {
            crate::cores::host::PortStatus::Error
        }
    }
}

fn engine_rows_to_host_result(
    host: &str,
    ip: std::net::IpAddr,
    protocol: crate::cores::host::Protocol,
    rows: &[EngineScanResult],
) -> HostScanResult {
    let mut out = HostScanResult::new(host.to_string(), ip, protocol);
    for row in rows {
        let Some(port) = row.port else { continue };
        let status = engine_status_to_host_status(row.status);
        out.record_port(port, status);
        if status == crate::cores::host::PortStatus::Open {
            let mut pr = crate::cores::host::PortResult::new(port, status, protocol);
            if let Some(ms) = row.latency_ms {
                pr = pr.with_latency(ms.min(u16::MAX as u64) as u16);
            }
            out.add_open_port_detail(pr);
        }
    }
    out
}

fn to_json_or_raw<T: serde::Serialize + std::fmt::Debug>(
    value: &T,
    fmt: &str,
) -> Result<String, RustpenError> {
    if fmt.eq_ignore_ascii_case("json") {
        serde_json::to_string_pretty(value).map_err(|e| RustpenError::ParseError(e.to_string()))
    } else {
        Ok(format!("{value:#?}"))
    }
}

fn parse_ports_flags(ports: &[String]) -> Result<Vec<u16>, RustpenError> {
    let merged = ports.join(",");
    crate::cores::host::parse_ports(&merged)
}

fn require_root_for_raw_scan(action: &str) -> Result<(), RustpenError> {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(RustpenError::ScanError(format!(
                "{action} requires root or CAP_NET_RAW"
            )));
        }
    }
    Ok(())
}

fn resolve_target_ip(host: &str) -> Result<std::net::IpAddr, RustpenError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    let addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| RustpenError::InvalidHost(e.to_string()))?;
    addrs
        .map(|a| a.ip())
        .next()
        .ok_or_else(|| RustpenError::InvalidHost("no resolved ip".to_string()))
}

fn load_probe_engine_if_requested(
    service_detect: bool,
    probes_file: Option<PathBuf>,
) -> Result<Option<std::sync::Arc<ServiceProbeEngine>>, RustpenError> {
    if !service_detect {
        return Ok(None);
    }
    let path = probes_file.ok_or_else(|| {
        RustpenError::ParseError("--service-detect requires --probes-file".to_string())
    })?;
    let engine = ServiceProbeEngine::from_nmap_file(path)?;
    Ok(Some(std::sync::Arc::new(engine)))
}

fn probe_engine_stats_line(engine: &std::sync::Arc<ServiceProbeEngine>) -> String {
    let stats = engine.load_stats();
    format!(
        "probe-engine loaded: probes={} rules={} skipped_rules={}",
        stats.probes, stats.loaded_rules, stats.skipped_rules
    )
}

async fn run_engine_host_scan(
    host: &str,
    ports: &[u16],
    scan_type: ScanType,
    probe_engine: Option<std::sync::Arc<ServiceProbeEngine>>,
    profile: ScanProfile,
    syn_mode: Option<SynMode>,
) -> Result<Vec<EngineScanResult>, RustpenError> {
    let target_ip = resolve_target_ip(host)?;
    let mut out = Vec::new();
    match scan_type {
        ScanType::Connect | ScanType::UdpProbe | ScanType::Dns => {
            let tuning = async_engine_tuning(profile);
            let mut engine = AsyncConnectEngine::new_with_probe(1024, tuning.workers, probe_engine);
            let mut rx = engine.take_results()?;
            for &p in ports {
                let protocol = match scan_type {
                    ScanType::Connect => crate::cores::host::Protocol::Tcp,
                    ScanType::Dns => crate::cores::host::Protocol::Dns,
                    _ => crate::cores::host::Protocol::Udp,
                };
                let mut job = ScanJob::new(target_ip, protocol, scan_type.clone())
                    .with_port(p)
                    .with_timeout_ms(tuning.timeout_ms)
                    .with_retries(tuning.retries);
                if let Some(d) = tuning.retry_delay_ms {
                    job = job.with_retry_delay_ms(d);
                }
                engine.submit(job)?;
            }
            let expected = ports.len();
            drop(engine);
            while out.len() < expected {
                match rx.recv().await {
                    Some(r) => out.push(r),
                    None => break,
                }
            }
        }
        ScanType::Syn | ScanType::IcmpEcho | ScanType::Arp => {
            require_root_for_raw_scan("raw packet scan")?;
            let tuning = raw_engine_tuning(profile);
            let mut engine = RawPacketEngine::new_with_probe(
                1024,
                tuning.workers,
                tuning.max_in_flight,
                probe_engine,
            );
            let mut rx = engine.take_results()?;
            for &p in ports {
                let mut job = ScanJob::new(
                    target_ip,
                    crate::cores::host::Protocol::Tcp,
                    scan_type.clone(),
                )
                .with_port(p)
                .with_timeout_ms(tuning.timeout_ms)
                .with_retries(tuning.retries);
                if matches!(scan_type, ScanType::Syn) {
                    job = match syn_mode.unwrap_or(SynMode::VerifyFiltered) {
                        SynMode::Strict => job.with_tag("syn_mode:strict"),
                        SynMode::VerifyFiltered => job.with_tag("syn_mode:verify-filtered"),
                    };
                }
                if let Some(d) = tuning.retry_delay_ms {
                    job = job.with_retry_delay_ms(d);
                }
                engine.submit(job)?;
            }
            let expected = ports.len();
            drop(engine);
            while out.len() < expected {
                match rx.recv().await {
                    Some(r) => out.push(r),
                    None => break,
                }
            }
        }
    }
    out.sort_by_key(|r| r.port.unwrap_or(0));
    Ok(out)
}

async fn write_host_output_to_file(mut file: File, s: &str) -> Result<(), RustpenError> {
    file.write_all(format!("{}\n", s).as_bytes())
        .await
        .map_err(RustpenError::Io)?;
    Ok(())
}

/// 轻量任务上下文，用于写 meta / 事件流，供 TUI 读取。
struct TaskCtx {
    dir: PathBuf,
    meta: TaskMeta,
    writer: TaskEventWriter,
}

fn init_task_ctx(
    cli: &Cli,
    kind: &str,
    tags: Vec<String>,
) -> Result<Option<TaskCtx>, RustpenError> {
    let workspace = match &cli.task_workspace {
        Some(w) => w.clone(),
        None => return Ok(None),
    };
    let id = cli.task_id.clone().unwrap_or_else(|| new_task_id());
    let dir = ensure_task_dir(&workspace, &id)?;
    let now = now_epoch_secs();
    let meta = TaskMeta {
        id: id.clone(),
        kind: kind.to_string(),
        tags,
        status: TaskStatus::Running,
        created_at: now,
        started_at: Some(now),
        ended_at: None,
        progress: Some(0.0),
        note: cli.task_note.clone(),
        artifacts: Vec::new(),
        logs: vec![dir.join("stdout.log"), dir.join("stderr.log")],
        extra: None,
    };
    write_task_meta(&dir, &meta)?;
    let writer = TaskEventWriter::new(dir.clone());
    let _ = writer.log("info", "task started");
    let ev = TaskEvent {
        ts: now,
        level: "info".to_string(),
        kind: EventKind::Progress,
        message: Some("start".to_string()),
        data: Some(0.0.into()),
    };
    let _ = crate::cores::engine::task::append_task_event(&dir, &ev);
    Ok(Some(TaskCtx { dir, meta, writer }))
}

fn finalize_task_ctx(
    ctx: &mut Option<TaskCtx>,
    status: TaskStatus,
    note: Option<String>,
) -> Result<(), RustpenError> {
    if let Some(c) = ctx.as_mut() {
        c.meta.status = status;
        c.meta.ended_at = Some(now_epoch_secs());
        c.meta.progress = Some(100.0);
        if let Some(n) = note {
            match c.meta.note.as_mut() {
                Some(existing) => {
                    existing.push_str("; ");
                    existing.push_str(&n);
                }
                None => c.meta.note = Some(n),
            }
        }
        write_task_meta(&c.dir, &c.meta)?;
        let _ = c
            .writer
            .log("info", format!("task finished: {:?}", c.meta.status));
    }
    Ok(())
}

async fn with_task<F, Fut, T>(
    cli: &Cli,
    kind: &str,
    tags: Vec<String>,
    f: F,
) -> Result<T, RustpenError>
where
    F: FnOnce(Option<TaskEventWriter>) -> Fut,
    Fut: std::future::Future<Output = Result<T, RustpenError>>,
{
    if cli.task_workspace.is_none() {
        return f(None).await;
    }
    let mut ctx = init_task_ctx(cli, kind, tags)?;
    let writer = ctx.as_ref().map(|c| c.writer.clone());
    let result = f(writer).await;
    match result {
        Ok(v) => {
            finalize_task_ctx(&mut ctx, TaskStatus::Succeeded, None)?;
            Ok(v)
        }
        Err(e) => {
            let _ = finalize_task_ctx(&mut ctx, TaskStatus::Failed, Some(e.to_string()));
            Err(e)
        }
    }
}

pub async fn run_from_args<I, T>(args: I) -> Result<(), RustpenError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    // initialize tracing according to log_level (ok if already initialized in tests)
    let env_filter = EnvFilter::new(cli.log_level.clone());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
    info!("Starting rscan, log_level={}", cli.log_level);

    let cmd = cli.cmd.clone();
    match cmd {
        Commands::Tui {
            workspace,
            refresh_ms,
        } => {
            return crate::tui::app::run_tui(
                workspace.or(cli.task_workspace.clone()),
                Some(refresh_ms),
            );
        }
        Commands::Web { action } => match action {
            WebActions::Dir {
                base,
                paths,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                headers,
                body,
                body_mode,
                per_host_concurrency,
                dedupe,
                no_dedupe,
                status_min,
                status_max,
                wildcard_filter,
                wildcard_samples,
                wildcard_len_tolerance,
                fingerprint_filter,
                fingerprint_distance,
                resume_file,
                adaptive_rate,
                adaptive_initial_delay_ms,
                adaptive_max_delay_ms,
                method,
                no_follow_redirect,
                smart_fast,
                smart_fast_strict,
                recursive,
                recursive_depth,
                profile,
            } => {
                with_task(&cli, "web", vec![base.clone()], |events| async move {
                    report_log(
                        &events,
                        format!("web dir base={} paths={}", base, paths.len()),
                    );
                    report_progress(&events, 8.0, "web.dir: config building");
                    let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                    let fmt = parse_output(&output);
                    let mut mcfg = ModuleScanConfig {
                        request_method: parse_http_method(&method)?,
                        recursive,
                        recursive_max_depth: recursive_depth.max(1),
                        ..Default::default()
                    };
                    apply_web_profile(&mut mcfg, profile);
                    if let Some(c) = concurrency {
                        mcfg.concurrency = c;
                    }
                    if let Some(t) = timeout_ms {
                        mcfg.timeout_ms = Some(t);
                    }
                    if let Some(r) = max_retries {
                        mcfg.max_retries = Some(r);
                    }
                    let mut header_map = parse_request_headers(&headers)?;
                    apply_body_mode_default_content_type(&mut header_map, body_mode, body.is_some());
                    mcfg.request_headers = if header_map.is_empty() {
                        None
                    } else {
                        Some(header_map)
                    };
                    mcfg.request_body_template = body.clone();
                    mcfg.follow_redirects = !no_follow_redirect;
                    if let Some(p) = per_host_concurrency {
                        mcfg.per_host_concurrency_override = Some(p);
                    }
                    mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                    mcfg.status_min = status_min;
                    mcfg.status_max = status_max;
                    mcfg.wildcard_filter = wildcard_filter;
                    if let Some(v) = wildcard_samples {
                        mcfg.wildcard_sample_count = v;
                    }
                    if let Some(v) = wildcard_len_tolerance {
                        mcfg.wildcard_len_tolerance = v;
                    }
                    mcfg.fingerprint_filter = fingerprint_filter;
                    if let Some(v) = fingerprint_distance {
                        mcfg.fingerprint_distance_threshold = v;
                    }
                    mcfg.resume_file = resume_file;
                    mcfg.adaptive_rate = adaptive_rate;
                    if let Some(v) = adaptive_initial_delay_ms {
                        mcfg.adaptive_initial_delay_ms = v;
                    }
                    if let Some(v) = adaptive_max_delay_ms {
                        mcfg.adaptive_max_delay_ms = v;
                    }
                    if smart_fast {
                        apply_web_smart_fast(&mut mcfg, status_min, status_max);
                    }
                    if smart_fast_strict {
                        apply_web_smart_fast_strict(&mut mcfg, status_min, status_max);
                    }
                    let total_hint = if recursive { None } else { Some(paths.len()) };
                    let rx = ws.dir_scan_stream(&base, paths, Some(mcfg));
                    consume_module_stream(
                        rx,
                        stream_to,
                        fmt,
                        events.clone(),
                        total_hint,
                        "web.dir",
                    )
                    .await?;
                    report_progress(&events, 98.0, "web.dir: output done");
                    Ok(())
                })
                .await?;
            }
            WebActions::Fuzz {
                url,
                keywords,
                keywords_file,
                kw_transforms,
                preset,
                keyword_prefix,
                keyword_suffix,
                keyword_max_len,
                summary,
                summary_top,
                content_len_min,
                content_len_max,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                headers,
                body,
                body_mode,
                per_host_concurrency,
                dedupe,
                no_dedupe,
                status_min,
                status_max,
                wildcard_filter,
                wildcard_samples,
                wildcard_len_tolerance,
                fingerprint_filter,
                fingerprint_distance,
                resume_file,
                adaptive_rate,
                adaptive_initial_delay_ms,
                adaptive_max_delay_ms,
                method,
                no_follow_redirect,
                smart_fast,
                smart_fast_strict,
                profile,
            } => {
                with_task(&cli, "web", vec![url.clone()], |events| async move {
                    let mut base_keywords = keywords.clone();
                    if let Some(path) = keywords_file.as_ref() {
                        let mut from_file = load_keywords_file(path)?;
                        base_keywords.append(&mut from_file);
                    }
                    let base_keywords = expand_keywords_with_preset(base_keywords, preset);
                    let eff_transforms = if kw_transforms.is_empty() {
                        if let Some(p) = preset {
                            preset_default_transforms(p)
                        } else {
                            vec![FuzzKeywordTransform::Raw]
                        }
                    } else {
                        kw_transforms.clone()
                    };
                    let expanded_keywords = build_fuzz_keywords(
                        base_keywords,
                        &eff_transforms,
                        keyword_prefix.clone(),
                        keyword_suffix.clone(),
                        keyword_max_len,
                    );
                    if expanded_keywords.is_empty() {
                        return Err(RustpenError::ParseError(
                            "no fuzz keywords produced after transforms/filters".to_string(),
                        ));
                    }
                    report_log(
                        &events,
                        format!(
                            "web fuzz url={} base_words={} expanded_words={} transforms={}",
                            url,
                            keywords.len(),
                            expanded_keywords.len(),
                            eff_transforms
                                .iter()
                                .map(|x| format!("{x:?}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    );
                    report_progress(&events, 8.0, "web.fuzz: config building");
                    let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                    let fmt = parse_output(&output);
                    let mut mcfg = ModuleScanConfig {
                        request_method: parse_http_method(&method)?,
                        ..Default::default()
                    };
                    apply_web_profile(&mut mcfg, profile);
                    if let Some(c) = concurrency {
                        mcfg.concurrency = c;
                    }
                    if let Some(t) = timeout_ms {
                        mcfg.timeout_ms = Some(t);
                    }
                    if let Some(r) = max_retries {
                        mcfg.max_retries = Some(r);
                    }
                    let mut header_map = parse_request_headers(&headers)?;
                    apply_body_mode_default_content_type(&mut header_map, body_mode, body.is_some());
                    mcfg.request_headers = if header_map.is_empty() {
                        None
                    } else {
                        Some(header_map)
                    };
                    mcfg.request_body_template = body.clone();
                    mcfg.follow_redirects = !no_follow_redirect;
                    if let Some(p) = per_host_concurrency {
                        mcfg.per_host_concurrency_override = Some(p);
                    }
                    mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                    mcfg.status_min = status_min;
                    mcfg.status_max = status_max;
                    mcfg.content_len_min = content_len_min;
                    mcfg.content_len_max = content_len_max;
                    mcfg.wildcard_filter = wildcard_filter;
                    if let Some(v) = wildcard_samples {
                        mcfg.wildcard_sample_count = v;
                    }
                    if let Some(v) = wildcard_len_tolerance {
                        mcfg.wildcard_len_tolerance = v;
                    }
                    mcfg.fingerprint_filter = fingerprint_filter;
                    if let Some(v) = fingerprint_distance {
                        mcfg.fingerprint_distance_threshold = v;
                    }
                    mcfg.resume_file = resume_file;
                    mcfg.adaptive_rate = adaptive_rate;
                    if let Some(v) = adaptive_initial_delay_ms {
                        mcfg.adaptive_initial_delay_ms = v;
                    }
                    if let Some(v) = adaptive_max_delay_ms {
                        mcfg.adaptive_max_delay_ms = v;
                    }
                    if smart_fast {
                        apply_web_smart_fast(&mut mcfg, status_min, status_max);
                    }
                    if smart_fast_strict {
                        apply_web_smart_fast_strict(&mut mcfg, status_min, status_max);
                    }
                    let total_hint = Some(expanded_keywords.len());
                    let rx = ws.fuzz_scan_stream(&url, expanded_keywords, Some(mcfg));
                    if summary {
                        consume_module_stream_with_summary(
                            rx,
                            stream_to,
                            fmt,
                            events.clone(),
                            total_hint,
                            "web.fuzz",
                            summary_top,
                        )
                        .await?;
                    } else {
                        consume_module_stream(
                            rx,
                            stream_to,
                            fmt,
                            events.clone(),
                            total_hint,
                            "web.fuzz",
                        )
                        .await?;
                    }
                    report_progress(&events, 98.0, "web.fuzz: output done");
                    Ok(())
                })
                .await?;
            }
            WebActions::Dns {
                domain,
                words,
                words_file,
                discovery_mode,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                per_host_concurrency,
                dedupe,
                no_dedupe,
                status_min,
                status_max,
                method,
                profile,
            } => {
                with_task(&cli, "web", vec![domain.clone()], |events| async move {
                    let mut eff_words = words.clone();
                    if let Some(path) = words_file.as_ref() {
                        let mut from_file = load_keywords_file(path)?;
                        eff_words.append(&mut from_file);
                    }
                    eff_words = eff_words
                        .into_iter()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    if eff_words.is_empty() {
                        return Err(RustpenError::ParseError(
                            "web dns requires at least one word via --words or --words-file"
                                .to_string(),
                        ));
                    }
                    eff_words.sort();
                    eff_words.dedup();
                    report_log(
                        &events,
                        format!("web dns domain={} words={}", domain, eff_words.len()),
                    );
                    report_progress(&events, 8.0, "web.dns: config building");
                    let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                    let fmt = parse_output(&output);
                    let mut mcfg = ModuleScanConfig {
                        request_method: parse_http_method(&method)?,
                        ..Default::default()
                    };
                    apply_web_profile(&mut mcfg, profile);
                    if let Some(c) = concurrency {
                        mcfg.concurrency = c;
                    }
                    if let Some(t) = timeout_ms {
                        mcfg.timeout_ms = Some(t);
                    }
                    if let Some(r) = max_retries {
                        mcfg.max_retries = Some(r);
                    }
                    if let Some(p) = per_host_concurrency {
                        mcfg.per_host_concurrency_override = Some(p);
                    }
                    mcfg.dedupe_results = if no_dedupe { false } else { dedupe };
                    mcfg.status_min = status_min;
                    mcfg.status_max = status_max;
                    mcfg.dns_http_verify = matches!(discovery_mode, DnsDiscoveryMode::Precise);
                    let total_hint = Some(eff_words.len());
                    let rx = ws.subdomain_burst_stream(&domain, eff_words, Some(mcfg));
                    consume_module_stream(
                        rx,
                        stream_to,
                        fmt,
                        events.clone(),
                        total_hint,
                        "web.dns",
                    )
                    .await?;
                    report_progress(&events, 98.0, "web.dns: output done");
                    Ok(())
                })
                .await?;
            }
            WebActions::Crawl {
                seeds,
                max_depth,
                concurrency,
                max_pages,
                obey_robots,
                output,
                out,
            } => {
                with_task(&cli, "web", seeds.clone(), |events| async move {
                    report_log(
                        &events,
                        format!("crawl seeds={} max_depth={}", seeds.len(), max_depth),
                    );
                    report_progress(&events, 10.0, "web.crawl: start");
                    let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig {
                        max_depth,
                        concurrency,
                        max_pages,
                        obey_robots,
                        ..Default::default()
                    })?;
                    report_progress(&events, 20.0, "web.crawl: crawling");
                    let crawled = ws.scan(seeds).await?;
                    report_progress(&events, 90.0, format!("web.crawl: pages={}", crawled.len()));
                    let s = if output.eq_ignore_ascii_case("json") {
                        serde_json::to_string_pretty(&crawled)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    } else {
                        crawled.join("\n")
                    };
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(RustpenError::Io)?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{s}");
                    }
                    report_progress(&events, 98.0, "web.crawl: output done");
                    Ok(())
                })
                .await?;
            }
            WebActions::Live {
                urls,
                method,
                concurrency,
                output,
                out,
            } => {
                with_task(&cli, "web", urls.clone(), |events| async move {
                    report_log(
                        &events,
                        format!("live check urls={} method={}", urls.len(), method),
                    );
                    report_progress(&events, 8.0, "web.live: start");
                    let method = parse_http_method(&method)?;
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(false)
                        .build()
                        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;
                    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
                    let mut tasks = Vec::with_capacity(urls.len());
                    for url in urls {
                        let sem = std::sync::Arc::clone(&sem);
                        let client = client.clone();
                        let method = method.clone();
                        tasks.push(tokio::spawn(async move {
                            let _permit = sem.acquire_owned().await.ok();
                            let r = live_ping(&client, &url, method).await;
                            (url, r)
                        }));
                    }
                    let mut rows: Vec<(String, Result<String, String>)> = Vec::new();
                    let total = tasks.len().max(1);
                    let mut done = 0usize;
                    for t in tasks {
                        if let Ok((url, res)) = t.await {
                            match res {
                                Ok(msg) => rows.push((url, Ok(msg))),
                                Err(e) => rows.push((url, Err(e.to_string()))),
                            }
                            done += 1;
                            let pct = 15.0 + ((done as f32) / (total as f32)) * 75.0;
                            report_progress(
                                &events,
                                pct,
                                format!("web.live: processed {done}/{total}"),
                            );
                        }
                    }
                    let s = if output.eq_ignore_ascii_case("json") {
                        let json_rows: Vec<_> = rows
                            .iter()
                            .map(|(url, res)| match res {
                                Ok(msg) => serde_json::json!({"url": url, "result": msg}),
                                Err(e) => serde_json::json!({"url": url, "error": e}),
                            })
                            .collect();
                        serde_json::to_string_pretty(&json_rows)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?
                    } else {
                        let color = color_enabled();
                        let mut out = Vec::new();
                        out.push(format!("{:>4} {:<7} {}", "LIVE", "METHOD", "URL"));
                        for (url, res) in rows {
                            match res {
                                Ok(msg) => {
                                    let tag = colorize("OK", "32", color);
                                    out.push(format!("{:>4} {:<7} {} {}", tag, method, url, msg));
                                }
                                Err(e) => {
                                    let tag = colorize("ERR", "31", color);
                                    out.push(format!("{:>4} {:<7} {} {}", tag, method, url, e));
                                }
                            }
                        }
                        out.join("\n")
                    };
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(RustpenError::Io)?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{s}");
                    }
                    report_progress(&events, 98.0, "web.live: output done");
                    Ok(())
                })
                .await?;
            }
        },
        Commands::Host { action } => match action {
            HostActions::Tcp {
                host,
                ports,
                output,
                out,
                service_detect,
                probes_file,
                profile,
                tcp_timeout_ms,
                tcp_concurrency,
                tcp_retries,
                tcp_max_rate,
                tcp_jitter_ms,
                tcp_scan_order,
                tcp_adaptive_backpressure,
                tcp_auto_tune,
                tcp_mode,
            } => {
                with_task(&cli, "host", vec![host.clone()], |events| async move {
                    report_log(&events, format!("tcp scan host={} ports={:?}", host, ports));
                    report_progress(&events, 8.0, "host.tcp: start");
                    if service_detect {
                        report_progress(&events, 18.0, "host.tcp: parse ports");
                        let parsed = parse_ports_flags(&ports)?;
                        let probe_engine =
                            load_probe_engine_if_requested(service_detect, probes_file)?;
                        if let Some(engine) = probe_engine.as_ref() {
                            report_log(&events, probe_engine_stats_line(engine));
                        }
                        report_progress(&events, 35.0, "host.tcp: scanning (service-detect)");
                        let rows = run_engine_host_scan(
                            &host,
                            &parsed,
                            ScanType::Connect,
                            probe_engine,
                            profile,
                            None,
                        )
                        .await?;
                        report_progress(&events, 88.0, format!("host.tcp: rows={}", rows.len()));
                        let s = format_engine_scan_results(&rows, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    } else {
                        report_progress(&events, 18.0, "host.tcp: parse ports");
                        let mut base_cfg = tcp_config_with_overrides(
                            profile,
                            tcp_timeout_ms,
                            tcp_concurrency,
                            tcp_retries,
                            tcp_max_rate,
                            tcp_jitter_ms,
                            tcp_scan_order,
                            tcp_adaptive_backpressure,
                        );
                        let parsed = parse_ports_flags(&ports)?;
                        if tcp_auto_tune && parsed.len() >= 256 {
                            report_progress(&events, 24.0, "host.tcp: auto-tune sampling");
                            let sample_ports = sample_ports_for_autotune(&parsed, 2048);
                            if !sample_ports.is_empty() {
                                let mut candidates = Vec::new();
                                let rate_candidates: &[Option<u32>] = &[Some(8000), Some(9500)];
                                let jitter_candidates: &[Option<u64>] = &[Some(0), Some(2)];
                                for rate in rate_candidates {
                                    for jitter in jitter_candidates {
                                        let mut c = base_cfg.clone();
                                        c.max_rate = *rate;
                                        c.jitter_ms = *jitter;
                                        c.scan_order = crate::cores::host::TcpScanOrder::Interleave;
                                        c.adaptive_backpressure = true;
                                        c.concurrency = c.concurrency.clamp(1024, 3072);
                                        candidates.push(c);
                                    }
                                }
                                let mut best_cfg = base_cfg.clone();
                                let mut best_score = f64::MIN;
                                for (idx, cand) in candidates.into_iter().enumerate() {
                                    let test_cfg = match tcp_mode {
                                        TcpMode::Turbo => turbo_phase1_config(cand.clone()),
                                        TcpMode::TurboAdaptive => turbo_phase1_config(cand.clone()),
                                        _ => cand.clone(),
                                    };
                                    let scanner = HostScanner::with_manager(
                                        crate::cores::host::ScanManager::new(test_cfg),
                                    );
                                    let started = std::time::Instant::now();
                                    let res = scanner.scan_tcp(&host, &sample_ports).await?;
                                    let elapsed_ms = started.elapsed().as_millis().max(1) as f64;
                                    let throughput = (sample_ports.len() as f64) / (elapsed_ms / 1000.0);
                                    let filtered_ratio = (res.filtered_ports_count() as f64)
                                        / (res.total_scanned.max(1) as f64);
                                    let score = throughput
                                        + (res.open_ports_count() as f64 * 120.0)
                                        - (filtered_ratio * 450.0);
                                    report_log(
                                        &events,
                                        format!(
                                            "auto-tune[{idx}] rate={:?} jitter={:?} open={} filtered_ratio={:.3} throughput={:.1} score={:.1}",
                                            cand.max_rate,
                                            cand.jitter_ms,
                                            res.open_ports_count(),
                                            filtered_ratio,
                                            throughput,
                                            score
                                        ),
                                    );
                                    if score > best_score {
                                        best_score = score;
                                        best_cfg = cand;
                                    }
                                }
                                base_cfg = best_cfg;
                                report_log(
                                    &events,
                                    format!(
                                        "auto-tune selected rate={:?} jitter={:?} concurrency={} scan_order=interleave adaptive_backpressure=true",
                                        base_cfg.max_rate,
                                        base_cfg.jitter_ms,
                                        base_cfg.concurrency
                                    ),
                                );
                            }
                        }
                        let scan_started = std::time::Instant::now();
                        let mut res = match tcp_mode {
                            TcpMode::Standard => {
                                let scanner = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(base_cfg.clone()),
                                );
                                report_progress(&events, 35.0, "host.tcp: scanning (standard)");
                                scanner.scan_tcp(&host, &parsed).await?
                            }
                            TcpMode::Turbo => {
                                let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                                let scanner = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(phase1_cfg),
                                );
                                report_progress(&events, 35.0, "host.tcp: scanning (turbo-pass1)");
                                scanner.scan_tcp(&host, &parsed).await?
                            }
                            TcpMode::TurboVerify => {
                                let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                                let scanner1 = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(phase1_cfg),
                                );
                                report_progress(&events, 32.0, "host.tcp: scanning (turbo-pass1)");
                                let mut first = scanner1.scan_tcp(&host, &parsed).await?;
                                let filtered = first.filtered_ports();
                                if !filtered.is_empty() {
                                    report_progress(
                                        &events,
                                        62.0,
                                        format!(
                                            "host.tcp: verify filtered ports={}",
                                            filtered.len()
                                        ),
                                    );
                                    let phase2_cfg = turbo_phase2_verify_config(base_cfg.clone());
                                    let scanner2 = HostScanner::with_manager(
                                        crate::cores::host::ScanManager::new(phase2_cfg),
                                    );
                                    let second = scanner2.scan_tcp(&host, &filtered).await?;
                                    merge_verified_tcp_subset(&mut first, &second, &filtered);
                                }
                                first
                            }
                            TcpMode::TurboAdaptive => {
                                let phase1_cfg = turbo_phase1_config(base_cfg.clone());
                                let scanner1 = HostScanner::with_manager(
                                    crate::cores::host::ScanManager::new(phase1_cfg),
                                );
                                report_progress(
                                    &events,
                                    32.0,
                                    "host.tcp: scanning (turbo-adaptive-pass1)",
                                );
                                let mut first = scanner1.scan_tcp(&host, &parsed).await?;
                                let filtered = first.filtered_ports();
                                if !filtered.is_empty() {
                                    let priority_verify = prioritized_filtered_ports(&filtered);
                                    if !priority_verify.is_empty() {
                                        report_progress(
                                            &events,
                                            46.0,
                                            format!(
                                                "host.tcp: adaptive-priority-verify ports={}",
                                                priority_verify.len()
                                            ),
                                        );
                                        let pri_cfg = turbo_phase2_verify_config_adaptive(
                                            base_cfg.clone(),
                                            (filtered.len() as f64) / (parsed.len().max(1) as f64),
                                        );
                                        let pri_scanner = HostScanner::with_manager(
                                            crate::cores::host::ScanManager::new(pri_cfg),
                                        );
                                        let pri_second =
                                            pri_scanner.scan_tcp(&host, &priority_verify).await?;
                                        merge_verified_tcp_subset(
                                            &mut first,
                                            &pri_second,
                                            &priority_verify,
                                        );
                                    }
                                    let filtered_ratio =
                                        (filtered.len() as f64) / (parsed.len().max(1) as f64);
                                    let sample_cap = if filtered_ratio >= 0.7 {
                                        4096
                                    } else if filtered_ratio >= 0.45 {
                                        2048
                                    } else {
                                        1024
                                    };
                                    let sample_len = filtered.len().min(sample_cap);
                                    let step = (filtered.len() / sample_len.max(1)).max(1);
                                    let sample_ports: Vec<u16> = filtered
                                        .iter()
                                        .step_by(step)
                                        .take(sample_len)
                                        .copied()
                                        .collect();
                                    report_progress(
                                        &events,
                                        58.0,
                                        format!(
                                            "host.tcp: adaptive-sample filtered={} sample={}",
                                            filtered.len(),
                                            sample_ports.len()
                                        ),
                                    );
                                    let phase2_cfg = turbo_phase2_verify_config_adaptive(
                                        base_cfg.clone(),
                                        filtered_ratio,
                                    );
                                    let scanner2 = HostScanner::with_manager(
                                        crate::cores::host::ScanManager::new(phase2_cfg.clone()),
                                    );
                                    let sample_second = scanner2.scan_tcp(&host, &sample_ports).await?;
                                    let sample_open = sample_ports
                                        .iter()
                                        .filter(|&&p| sample_second.is_port_open(p))
                                        .count();
                                    let sample_open_rate =
                                        (sample_open as f64) / (sample_ports.len().max(1) as f64);
                                    merge_verified_tcp_subset(
                                        &mut first,
                                        &sample_second,
                                        &sample_ports,
                                    );
                                    let verify_all = filtered.len() <= 4096 || sample_open_rate >= 0.01;
                                    let verify_limit = 6000usize;
                                    let should_verify_more = verify_all
                                        || (sample_open_rate >= 0.004
                                            && filtered.len() > sample_ports.len());
                                    if should_verify_more {
                                        let sampled_set: BTreeSet<u16> =
                                            sample_ports.iter().copied().collect();
                                        let remaining: Vec<u16> = filtered
                                            .iter()
                                            .filter(|p| !sampled_set.contains(p))
                                            .copied()
                                            .collect();
                                        if !remaining.is_empty() {
                                            let to_verify: Vec<u16> = if verify_all {
                                                remaining
                                            } else {
                                                remaining.into_iter().take(verify_limit).collect()
                                            };
                                            report_progress(
                                                &events,
                                                70.0,
                                                format!(
                                                    "host.tcp: adaptive-verify more={} open_rate={:.4}",
                                                    to_verify.len(),
                                                    sample_open_rate
                                                ),
                                            );
                                            let chunk_size = 1200usize;
                                            let mut since_last_open = 0usize;
                                            let mut offset = 0usize;
                                            while offset < to_verify.len() {
                                                let end = (offset + chunk_size).min(to_verify.len());
                                                let chunk = &to_verify[offset..end];
                                                let scanner3 = HostScanner::with_manager(
                                                    crate::cores::host::ScanManager::new(
                                                        phase2_cfg.clone(),
                                                    ),
                                                );
                                                let more_second = scanner3.scan_tcp(&host, chunk).await?;
                                                let new_open = chunk
                                                    .iter()
                                                    .filter(|&&p| more_second.is_port_open(p))
                                                    .count();
                                                merge_verified_tcp_subset(&mut first, &more_second, chunk);
                                                if new_open == 0 {
                                                    since_last_open += chunk.len();
                                                } else {
                                                    since_last_open = 0;
                                                }
                                                if since_last_open >= 2400 && sample_open_rate < 0.01 {
                                                    report_log(
                                                        &events,
                                                        format!(
                                                            "host.tcp: adaptive-verify early-stop at {}/{} (no new open in recent chunks)",
                                                            end,
                                                            to_verify.len()
                                                        ),
                                                    );
                                                    break;
                                                }
                                                offset = end;
                                            }
                                        }
                                    }
                                }
                                first
                            }
                        };
                        res.scan_duration = scan_started.elapsed();
                        report_progress(
                            &events,
                            88.0,
                            format!(
                                "host.tcp: open_ports={} filtered={}",
                                res.open_ports_count(),
                                res.filtered_ports_count()
                            ),
                        );
                        let s = format_host_scan_result(&res, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    }
                    report_progress(&events, 98.0, "host.tcp: output done");
                    Ok(())
                })
                .await?;
            }
            HostActions::Udp {
                host,
                ports,
                output,
                out,
                service_detect,
                probes_file,
                profile,
            } => {
                with_task(&cli, "host", vec![host.clone()], |events| async move {
                    report_log(&events, format!("udp scan host={} ports={:?}", host, ports));
                    report_progress(&events, 8.0, "host.udp: start");
                    if service_detect {
                        report_progress(&events, 18.0, "host.udp: parse ports");
                        let parsed = parse_ports_flags(&ports)?;
                        let probe_engine =
                            load_probe_engine_if_requested(service_detect, probes_file)?;
                        if let Some(engine) = probe_engine.as_ref() {
                            report_log(&events, probe_engine_stats_line(engine));
                        }
                        report_progress(&events, 35.0, "host.udp: scanning (service-detect)");
                        let rows = run_engine_host_scan(
                            &host,
                            &parsed,
                            ScanType::UdpProbe,
                            probe_engine,
                            profile,
                            None,
                        )
                        .await?;
                        report_progress(&events, 88.0, format!("host.udp: rows={}", rows.len()));
                        let s = format_engine_scan_results(&rows, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    } else {
                        report_progress(&events, 18.0, "host.udp: parse ports");
                        use crate::cores::host::ScanManager;
                        let manager = ScanManager::new_with_udp(
                            tcp_config_for_profile(profile),
                            Some(udp_config_for_profile(profile)),
                        );
                        let scanner = HostScanner::with_manager(manager);
                        let parsed = parse_ports_flags(&ports)?;
                        report_progress(&events, 35.0, "host.udp: scanning");
                        let res = scanner.scan_udp(&host, &parsed).await?;
                        report_progress(
                            &events,
                            88.0,
                            format!("host.udp: open_ports={}", res.open_ports_count()),
                        );
                        let s = format_host_scan_result(&res, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    }
                    report_progress(&events, 98.0, "host.udp: output done");
                    Ok(())
                })
                .await?;
            }
            HostActions::Syn {
                host,
                ports,
                output,
                out,
                service_detect,
                probes_file,
                profile,
                syn_mode,
            } => {
                require_root_for_raw_scan("SYN scan")?;
                with_task(&cli, "host", vec![host.clone()], |events| async move {
                    report_log(&events, format!("syn scan host={} ports={:?}", host, ports));
                    report_progress(&events, 8.0, "host.syn: start");
                    if service_detect {
                        report_progress(&events, 18.0, "host.syn: parse ports");
                        let parsed = parse_ports_flags(&ports)?;
                        let probe_engine =
                            load_probe_engine_if_requested(service_detect, probes_file)?;
                        if let Some(engine) = probe_engine.as_ref() {
                            report_log(&events, probe_engine_stats_line(engine));
                        }
                        report_progress(&events, 35.0, "host.syn: scanning (service-detect)");
                        let rows = run_engine_host_scan(
                            &host,
                            &parsed,
                            ScanType::Syn,
                            probe_engine,
                            profile,
                            Some(syn_mode),
                        )
                        .await?;
                        report_progress(&events, 88.0, format!("host.syn: rows={}", rows.len()));
                        let s = format_engine_scan_results(&rows, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    } else {
                        report_progress(&events, 18.0, "host.syn: parse ports");
                        let parsed = parse_ports_flags(&ports)?;
                        report_progress(&events, 35.0, "host.syn: scanning (raw-engine)");
                        let rows = run_engine_host_scan(
                            &host,
                            &parsed,
                            ScanType::Syn,
                            None,
                            profile,
                            Some(syn_mode),
                        )
                        .await?;
                        let ip = resolve_target_ip(&host)?;
                        let res = engine_rows_to_host_result(
                            &host,
                            ip,
                            crate::cores::host::Protocol::Tcp,
                            &rows,
                        );
                        report_progress(
                            &events,
                            88.0,
                            format!("host.syn: open_ports={}", res.open_ports_count()),
                        );
                        let s = format_host_scan_result(&res, &output);
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{}", s);
                        }
                    }
                    report_progress(&events, 98.0, "host.syn: output done");
                    Ok(())
                })
                .await?;
            }
            HostActions::Quick {
                host,
                output,
                out,
                profile,
            } => {
                with_task(&cli, "host", vec![host.clone()], |events| async move {
                    report_log(&events, format!("quick scan host={}", host));
                    report_progress(&events, 10.0, "host.quick: start");
                    let scanner = HostScanner::with_manager(crate::cores::host::ScanManager::new(
                        tcp_config_for_profile(profile),
                    ));
                    report_progress(&events, 35.0, "host.quick: scanning");
                    let res = scanner.quick_tcp(&host).await?;
                    report_progress(
                        &events,
                        88.0,
                        format!("host.quick: open_ports={}", res.open_ports_count()),
                    );
                    let s = format_host_scan_result(&res, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(RustpenError::Io)?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                    report_progress(&events, 98.0, "host.quick: output done");
                    Ok(())
                })
                .await?;
            }
            HostActions::Arp { cidr, output, out } => {
                require_root_for_raw_scan("ARP scan")?;
                with_task(&cli, "host", vec![cidr.clone()], |events| async move {
                    report_log(&events, format!("arp scan cidr={}", cidr));
                    report_progress(&events, 10.0, "host.arp: start");
                    let scanner = HostScanner::default();
                    report_progress(&events, 35.0, "host.arp: scanning");
                    let res = scanner.arp_scan_cidr(&cidr).await?;
                    report_progress(&events, 88.0, format!("host.arp: alive={}", res.len()));
                    if output.to_lowercase() == "json" {
                        let json_vec: Vec<_> = res.iter().map(|h| serde_json::json!({"ip": h.ip, "mac": h.mac.to_string(), "interface": h.interface})).collect();
                        let s = serde_json::to_string(&json_vec)
                            .map_err(|e| RustpenError::ParseError(e.to_string()))?;
                        if let Some(path) = &out {
                            let mut file = File::create(path).await.map_err(RustpenError::Io)?;
                            file.write_all(format!("{}\n", s).as_bytes())
                                .await
                                .map_err(RustpenError::Io)?;
                        } else {
                            println!("{}", s);
                        }
                    } else {
                        if let Some(path) = &out {
                            let mut file = File::create(path).await.map_err(RustpenError::Io)?;
                            for h in res {
                                let line = format!("{} {} {}\n", h.ip, h.mac, h.interface);
                                file.write_all(line.as_bytes())
                                    .await
                                    .map_err(RustpenError::Io)?;
                            }
                        } else {
                            for h in res {
                                let line = format!("{} {} {}\n", h.ip, h.mac, h.interface);
                                print!("{}", line);
                            }
                        }
                    }
                    report_progress(&events, 98.0, "host.arp: output done");
                    Ok(())
                })
                .await?;
            }
        },
        Commands::Reverse {
            input,
            workspace,
            pwndbg_init,
            tui,
            ghidra_home,
            action,
        } => {
            let action = action.unwrap_or(ReverseActions::Console {
                input,
                input_pos: None,
                workspace,
                pwndbg_init,
                tui,
                ghidra_home,
            });
            match action {
            ReverseActions::Analyze {
                input,
                input_pos,
                rules_file,
                dynamic,
                dynamic_timeout_ms,
                dynamic_syscalls,
                dynamic_blocklist,
                output,
                out,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                if dynamic
                    || dynamic_timeout_ms.is_some()
                    || dynamic_syscalls.is_some()
                    || dynamic_blocklist.is_some()
                {
                    unsafe {
                        std::env::set_var("RSCAN_REVERSE_DYNAMIC", "1");
                    }
                }
                if let Some(v) = dynamic_timeout_ms {
                    unsafe {
                        std::env::set_var("RSCAN_REVERSE_DYNAMIC_TIMEOUT_MS", v.to_string());
                    }
                }
                if let Some(v) = dynamic_syscalls {
                    unsafe {
                        std::env::set_var("RSCAN_REVERSE_DYNAMIC_SYSCALLS", v);
                    }
                }
                if let Some(v) = dynamic_blocklist {
                    unsafe {
                        std::env::set_var("RSCAN_REVERSE_DYNAMIC_BLOCKLIST", v);
                    }
                }

                with_task(
                    &cli,
                    "reverse",
                    vec![input.display().to_string()],
                    |events| async move {
                        if let Some(w) = events {
                            let _ = w.log("info", format!("reverse analyze {}", input.display()));
                        }
                        let bytes = std::fs::read(&input)?;
                        let is_apk = bytes.len() >= 4
                            && &bytes[0..4] == b"PK\x03\x04"
                            && (bytes
                                .windows("AndroidManifest.xml".len())
                                .any(|w| w == b"AndroidManifest.xml")
                                || bytes
                                    .windows("classes.dex".len())
                                    .any(|w| w == b"classes.dex"));

                        let mut hot_rules = match rules_file {
                            Some(path) => Some(RuleHotReloader::new(path)?),
                            None => None,
                        };
                        let default_rules = RuleLibrary::default();
                        let rules_ref = match hot_rules.as_mut() {
                            Some(loader) => loader.rules()?,
                            None => &default_rules,
                        };

                        let s = if is_apk {
                            let report =
                                ReverseAnalyzer::analyze_apk_with_rules(&input, rules_ref)?;
                            to_json_or_raw(&report, &output)?
                        } else {
                            let report =
                                ReverseAnalyzer::analyze_binary_with_rules(&input, rules_ref)?;
                            to_json_or_raw(&report, &output)?
                        };

                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            ReverseActions::DecompilePlan {
                input,
                input_pos,
                engine,
                output_dir,
                output,
                out,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                let engine = DecompilerEngine::parse(&engine).ok_or_else(|| {
                    RustpenError::ParseError(
                        "invalid --engine. use: objdump|radare2|ghidra|jadx".to_string(),
                    )
                })?;
                let orchestrator = ReverseOrchestrator::detect();
                let plan =
                    orchestrator.build_decompile_plan(engine, &input, output_dir.as_deref())?;
                let s = to_json_or_raw(&plan, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::DecompileRun {
                input,
                input_pos,
                engine,
                mode,
                function,
                deep,
                rust_first,
                no_rust_first,
                workspace,
                timeout_secs,
                output,
                out,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let mode = parse_decompile_mode(&mode)?;
                let func = function.as_deref();
                if mode == DecompileMode::Function && func.is_none() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--function".to_string(),
                    });
                }
                let rust_first_enabled = rust_first && !no_rust_first;
                unsafe {
                    std::env::set_var(
                        "RSCAN_REVERSE_RUST_FIRST",
                        if rust_first_enabled { "1" } else { "0" },
                    );
                    std::env::set_var("RSCAN_REVERSE_DEEP", if deep { "1" } else { "0" });
                }
                with_task(
                    &cli,
                    "reverse",
                    vec![input.display().to_string()],
                    |events| async move {
                        if let Some(w) = events {
                            let _ = w.log(
                                "info",
                                format!(
                                    "decompile-run engine={} mode={:?} file={}",
                                    engine,
                                    mode,
                                    input.display()
                                ),
                            );
                        }
                        let report = run_decompile_job(
                            &input,
                            &workspace,
                            &engine,
                            mode,
                            func,
                            timeout_secs,
                        )?;
                        let s = to_json_or_raw(&report, &output)?;
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            ReverseActions::DecompileBatch {
                inputs,
                inputs_pos,
                engine,
                mode,
                function,
                deep,
                rust_first,
                no_rust_first,
                workspace,
                timeout_secs,
                parallel_jobs,
                output,
                out,
            } => {
                let mut inputs = inputs;
                inputs.extend(inputs_pos);
                if inputs.is_empty() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--inputs <paths> or <INPUTS...>".to_string(),
                    });
                }
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let mode = parse_decompile_mode(&mode)?;
                let func = function.as_deref();
                if mode == DecompileMode::Function && func.is_none() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--function".to_string(),
                    });
                }
                let rust_first_enabled = rust_first && !no_rust_first;
                unsafe {
                    std::env::set_var(
                        "RSCAN_REVERSE_RUST_FIRST",
                        if rust_first_enabled { "1" } else { "0" },
                    );
                    std::env::set_var("RSCAN_REVERSE_DEEP", if deep { "1" } else { "0" });
                }
                with_task(
                    &cli,
                    "reverse",
                    vec![format!("batch:{} files", inputs.len())],
                    |events| async move {
                        if let Some(w) = events {
                            let _ = w.log(
                                "info",
                                format!(
                                    "decompile-batch engine={} mode={:?} inputs={}",
                                    engine,
                                    mode,
                                    inputs.len()
                                ),
                            );
                        }
                        let report = run_decompile_batch(
                            &inputs,
                            &workspace,
                            &engine,
                            mode,
                            func,
                            timeout_secs,
                            parallel_jobs,
                        )?;
                        let s = to_json_or_raw(&report, &output)?;
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        Ok(())
                    },
                )
                .await?;
            }
            ReverseActions::Jobs {
                workspace,
                output,
                out,
            } => {
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let jobs = list_jobs(&workspace)?;
                let s = to_json_or_raw(&jobs, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobStatus {
                job,
                job_pos,
                workspace,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let info = load_job_by_id(&workspace, &job)?;
                let s = to_json_or_raw(&info, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobLogs {
                job,
                job_pos,
                workspace,
                stream,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let (stdout, stderr) = load_job_logs(&workspace, &job)?;
                match stream.to_ascii_lowercase().as_str() {
                    "stdout" => print!("{}", stdout),
                    "stderr" => print!("{}", stderr),
                    "both" => {
                        println!("--- stdout ---");
                        print!("{}", stdout);
                        println!("--- stderr ---");
                        print!("{}", stderr);
                    }
                    _ => {
                        return Err(RustpenError::ParseError(
                            "invalid --stream. use stdout|stderr|both".to_string(),
                        ));
                    }
                }
            }
            ReverseActions::JobArtifacts {
                job,
                job_pos,
                workspace,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let info = load_job_by_id(&workspace, &job)?;
                let s = to_json_or_raw(&info.artifacts, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobFunctions {
                job,
                job_pos,
                workspace,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let rows = load_job_pseudocode_rows(&workspace, &job)?;
                let funcs: Vec<_> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "ea": r.get("ea").and_then(|v| v.as_str()).unwrap_or(""),
                            "name": r.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        })
                    })
                    .collect();
                let s = if output.eq_ignore_ascii_case("raw") {
                    funcs
                        .iter()
                        .map(|f| format!("{} {}", f["ea"], f["name"]))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    to_json_or_raw(&funcs, &output)?
                };
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobShow {
                job,
                job_pos,
                name,
                name_pos,
                workspace,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let name = name
                    .or(name_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--name <fn> or <NAME>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let rows = load_job_pseudocode_rows(&workspace, &job)?;
                let one = rows.into_iter().find(|r| {
                    r.get("name").and_then(|v| v.as_str()) == Some(name.as_str())
                        || r.get("ea").and_then(|v| v.as_str()) == Some(name.as_str())
                });
                let v = one.ok_or_else(|| {
                    RustpenError::ScanError(format!("function '{}' not found in job {}", name, job))
                })?;
                let s = to_json_or_raw(&v, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobSearch {
                job,
                job_pos,
                keyword,
                keyword_pos,
                workspace,
                max,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let keyword =
                    keyword
                        .or(keyword_pos)
                        .ok_or_else(|| RustpenError::MissingArgument {
                            arg: "--keyword <kw> or <KEYWORD>".to_string(),
                        })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let kw = keyword.to_ascii_lowercase();
                let rows = load_job_pseudocode_rows(&workspace, &job)?;
                let mut hits = Vec::new();
                for r in rows {
                    let name = r
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let ea = r
                        .get("ea")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let code = r
                        .get("pseudocode")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let matched = name.to_ascii_lowercase().contains(&kw)
                        || code.to_ascii_lowercase().contains(&kw)
                        || ea.to_ascii_lowercase().contains(&kw);
                    if matched {
                        hits.push(serde_json::json!({"ea": ea, "name": name}));
                        if hits.len() >= max.max(1) {
                            break;
                        }
                    }
                }
                let s = if output.eq_ignore_ascii_case("raw") {
                    hits.iter()
                        .map(|h| format!("{} {}", h["ea"], h["name"]))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    to_json_or_raw(&hits, &output)?
                };
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobClear {
                job,
                job_pos,
                workspace,
                all,
                output,
                out,
            } => {
                let job = job.or(job_pos);
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let removed = if all {
                    clear_jobs(&workspace, None)?
                } else {
                    clear_jobs(&workspace, job.as_deref())?
                };
                let v = serde_json::json!({ "removed": removed, "all": all, "job": job });
                let s = to_json_or_raw(&v, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobPrune {
                keep,
                older_than_days,
                include_running,
                workspace,
                output,
                out,
            } => {
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let removed = prune_jobs(
                    &workspace,
                    crate::modules::reverse::JobPrunePolicy {
                        keep_latest: Some(keep.max(1)),
                        older_than_days,
                        include_running,
                    },
                )?;
                let v = serde_json::json!({
                    "removed": removed,
                    "keep": keep.max(1),
                    "older_than_days": older_than_days,
                    "include_running": include_running
                });
                let s = to_json_or_raw(&v, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::JobDoctor {
                job,
                job_pos,
                workspace,
                output,
                out,
            } => {
                let job = job
                    .or(job_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--job <id> or <JOB>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let health = inspect_job_health(&workspace, &job)?;
                let s = to_json_or_raw(&health, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::DebugScript {
                input,
                input_pos,
                profile,
                pwndbg_init,
                script_out,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                let profile = DebugProfile::parse(&profile).ok_or_else(|| {
                    RustpenError::ParseError(
                        "invalid --profile, supported: pwngdb|pwndbg".to_string(),
                    )
                })?;
                let orchestrator = ReverseOrchestrator::detect();
                orchestrator.build_debug_plan(
                    &input,
                    profile,
                    &script_out,
                    pwndbg_init.as_deref(),
                )?;
                println!("written debug script to {}", script_out.display());
            }
            ReverseActions::GdbPlugin { out } => {
                ReverseOrchestrator::write_gdb_plugin(&out)?;
                println!("written gdb plugin to {}", out.display());
            }
            ReverseActions::GhidraScript { out } => {
                ReverseOrchestrator::write_ghidra_script(&out)?;
                println!("written ghidra export script to {}", out.display());
            }
            ReverseActions::GhidraIndexScript { out } => {
                ReverseOrchestrator::write_ghidra_index_script(&out)?;
                println!("written ghidra index script to {}", out.display());
            }
            ReverseActions::GhidraFunctionScript { out } => {
                ReverseOrchestrator::write_ghidra_function_script(&out)?;
                println!("written ghidra function script to {}", out.display());
            }
            ReverseActions::RulesTemplate { out } => {
                RuleLibrary::write_template(&out)?;
                println!("written reverse rules template to {}", out.display());
            }
            ReverseActions::MalwareTriage {
                input,
                input_pos,
                output,
                out,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                let report = MalwareAnalyzer::triage_file(&input)?;
                let s = to_json_or_raw(&report, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::ShellAudit {
                text,
                input,
                input_pos,
                output,
                out,
            } => {
                let report = match (text, input) {
                    (Some(t), _) => MalwareAnalyzer::audit_shell_text(&t),
                    (None, Some(p)) => {
                        let bytes = std::fs::read(p)?;
                        match std::str::from_utf8(&bytes) {
                            Ok(text) => MalwareAnalyzer::audit_shell_text(text),
                            Err(_) => MalwareAnalyzer::audit_shell_bytes(&bytes),
                        }
                    }
                    (None, None) => {
                        if let Some(p) = input_pos {
                            let bytes = std::fs::read(p)?;
                            match std::str::from_utf8(&bytes) {
                                Ok(text) => MalwareAnalyzer::audit_shell_text(text),
                                Err(_) => MalwareAnalyzer::audit_shell_bytes(&bytes),
                            }
                        } else {
                            return Err(RustpenError::MissingArgument {
                                arg: "--text or --input or <INPUT>".to_string(),
                            });
                        }
                    }
                };
                let s = to_json_or_raw(&report, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::Console {
                input,
                input_pos,
                workspace,
                pwndbg_init,
                tui,
                ghidra_home,
            } => {
                let input = input
                    .or(input_pos)
                    .ok_or_else(|| RustpenError::MissingArgument {
                        arg: "--input <path> or <INPUT>".to_string(),
                    })?;
                let workspace = workspace.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                if let Some(p) = ghidra_home {
                    unsafe {
                        std::env::set_var("RSCAN_GHIDRA_HOME", p);
                    }
                }
                let cfg = ReverseConsoleConfig {
                    input,
                    workspace,
                    pwndbg_init,
                };
                if tui {
                    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
                        eprintln!(
                            "[rscan] TUI requires a TTY; falling back to interactive console"
                        );
                        run_reverse_interactive(cfg)?;
                    } else {
                        run_reverse_tui(cfg)?;
                    }
                } else {
                    run_reverse_interactive(cfg)?;
                }
            }
            ReverseActions::BackendStatus { output, out } => {
                let status = ReverseOrchestrator::detect().registry().catalog().clone();
                let s = to_json_or_raw(&status, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
        }},
        Commands::Vuln { action } => match action {
            VulnActions::Lint {
                templates,
                output,
                out,
            } => {
                let (_templates, report) = load_safe_templates_from_path(&templates)?;
                let s = to_json_or_raw(&report, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            VulnActions::Scan {
                targets,
                templates,
                severities,
                tags,
                concurrency,
                timeout_ms,
                output,
                out,
            } => {
                with_task(&cli, "vuln", targets.clone(), |events| async move {
                    report_log(
                        &events,
                        format!(
                            "vuln scan targets={} templates={} severity_filters={} tag_filters={}",
                            targets.len(),
                            templates.display(),
                            severities.len(),
                            tags.len(),
                        ),
                    );
                    report_progress(&events, 10.0, "vuln.scan: loading templates");
                    let (templates, lint) = load_safe_templates_from_path(&templates)?;
                    let templates = filter_vuln_templates(templates, &severities, &tags);
                    if templates.is_empty() {
                        return Err(RustpenError::ParseError(format!(
                            "no usable templates loaded after filters (severity={:?}, tags={:?}): {:?}",
                            severities,
                            tags,
                            lint.errors
                        )));
                    }
                    let cfg = VulnScanConfig {
                        concurrency,
                        timeout_ms,
                    };
                    report_progress(
                        &events,
                        35.0,
                        format!(
                            "vuln.scan: scanning targets={} templates={}",
                            targets.len(),
                            templates.len()
                        ),
                    );
                    let report = vuln_scan_targets(&targets, &templates, cfg).await?;
                    report_progress(
                        &events,
                        90.0,
                        format!(
                            "vuln.scan: findings={} errors={}",
                            report.findings.len(),
                            report.errors.len()
                        ),
                    );
                    let s = if output.eq_ignore_ascii_case("json") {
                        to_json_or_raw(&report, &output)?
                    } else {
                        format_vuln_report_pretty(&report, color_enabled())
                    };
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(RustpenError::Io)?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{s}");
                    }
                    report_progress(&events, 98.0, "vuln.scan: output done");
                    Ok(())
                })
                .await?;
            }
            VulnActions::ContainerAudit {
                manifests,
                output,
                out,
            } => {
                with_task(
                    &cli,
                    "vuln-container-audit",
                    vec![manifests.display().to_string()],
                    |events| async move {
                        report_progress(&events, 10.0, "vuln.container-audit: loading manifests");
                        let report = audit_container_manifests_from_path(&manifests)?;
                        report_progress(
                            &events,
                            85.0,
                            format!(
                                "vuln.container-audit: findings={} errors={}",
                                report.findings.len(),
                                report.errors.len()
                            ),
                        );
                        let s = if output.eq_ignore_ascii_case("json") {
                            to_json_or_raw(&report, &output)?
                        } else {
                            format_container_audit_pretty(&report, color_enabled())
                        };
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        report_progress(&events, 98.0, "vuln.container-audit: output done");
                        Ok(())
                    },
                )
                .await?;
            }
            VulnActions::SystemGuard { output, out } => {
                with_task(
                    &cli,
                    "vuln-system-guard",
                    vec!["local-system".to_string()],
                    |events| async move {
                        report_progress(&events, 10.0, "vuln.system-guard: collecting controls");
                        let report = audit_local_system_guard()?;
                        report_progress(
                            &events,
                            85.0,
                            format!(
                                "vuln.system-guard: controls={}/{} score={}",
                                report.controls_present, report.controls_total, report.score
                            ),
                        );
                        let s = if output.eq_ignore_ascii_case("json") {
                            to_json_or_raw(&report, &output)?
                        } else {
                            format_system_guard_pretty(&report, color_enabled())
                        };
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        report_progress(&events, 98.0, "vuln.system-guard: output done");
                        Ok(())
                    },
                )
                .await?;
            }
            VulnActions::StealthCheck {
                target,
                low_noise_requests,
                low_noise_interval_ms,
                burst_requests,
                burst_concurrency,
                timeout_ms,
                advanced_checks,
                no_advanced_checks,
                variant_requests,
                variant_concurrency,
                output,
                out,
            } => {
                with_task(
                    &cli,
                    "vuln-stealth-check",
                    vec![target.clone()],
                    |events| async move {
                        report_progress(&events, 10.0, "vuln.stealth-check: probe planning");
                        let cfg = AntiScanConfig {
                            low_noise_requests,
                            low_noise_interval_ms,
                            burst_requests,
                            burst_concurrency,
                            timeout_ms,
                            advanced_checks: if no_advanced_checks {
                                false
                            } else {
                                advanced_checks
                            },
                            variant_requests,
                            variant_concurrency,
                        };
                        report_progress(
                            &events,
                            35.0,
                            format!(
                                "vuln.stealth-check: target={} low={} burst={}",
                                target, cfg.low_noise_requests, cfg.burst_requests
                            ),
                        );
                        let report = audit_http_anti_scan(&target, cfg).await?;
                        report_progress(
                            &events,
                            90.0,
                            format!(
                                "vuln.stealth-check: findings={} errors={}",
                                report.findings.len(),
                                report.errors.len()
                            ),
                        );
                        let s = if output.eq_ignore_ascii_case("json") {
                            to_json_or_raw(&report, &output)?
                        } else {
                            format_stealth_check_pretty(&report, color_enabled())
                        };
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        report_progress(&events, 98.0, "vuln.stealth-check: output done");
                        Ok(())
                    },
                )
                .await?;
            }
            VulnActions::FragmentAudit {
                target,
                requests_per_tier,
                concurrency,
                timeout_ms,
                payload_min_bytes,
                payload_max_bytes,
                payload_step_bytes,
                output,
                out,
            } => {
                with_task(
                    &cli,
                    "vuln-fragment-audit",
                    vec![target.clone()],
                    |events| async move {
                        report_progress(&events, 10.0, "vuln.fragment-audit: probe planning");
                        let cfg = FragmentAuditConfig {
                            requests_per_tier,
                            concurrency,
                            timeout_ms,
                            payload_min_bytes,
                            payload_max_bytes,
                            payload_step_bytes,
                        };
                        report_progress(
                            &events,
                            35.0,
                            format!(
                                "vuln.fragment-audit: target={} tiers={}..{} step={}",
                                target,
                                cfg.payload_min_bytes,
                                cfg.payload_max_bytes,
                                cfg.payload_step_bytes
                            ),
                        );
                        let report = audit_http_fragment_resilience(&target, cfg).await?;
                        report_progress(
                            &events,
                            90.0,
                            format!(
                                "vuln.fragment-audit: findings={} errors={}",
                                report.findings.len(),
                                report.errors.len()
                            ),
                        );
                        let s = if output.eq_ignore_ascii_case("json") {
                            to_json_or_raw(&report, &output)?
                        } else {
                            format_fragment_audit_pretty(&report, color_enabled())
                        };
                        if let Some(path) = out {
                            let file = File::create(path).await.map_err(RustpenError::Io)?;
                            write_host_output_to_file(file, &s).await?;
                        } else {
                            println!("{s}");
                        }
                        report_progress(&events, 98.0, "vuln.fragment-audit: output done");
                        Ok(())
                    },
                )
                .await?;
            }
        },
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin, &mut std::io::stdout());
        }
    }

    Ok(())
}

/// Run using environment args
pub async fn run() -> Result<(), RustpenError> {
    run_from_args(std::env::args()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tokio::net::{TcpListener, UdpSocket};

    fn is_root() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    #[tokio::test]
    async fn cli_host_tcp_writes_output_file() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let tmp = env::temp_dir().join(format!("rscan_cli_tcp_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "host",
            "tcp",
            "--host",
            "127.0.0.1",
            "--ports",
            &port_str,
            "--output",
            "json",
            "--out",
            &tmp_str,
        ];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_udp_writes_output_file() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
                let _ = socket.send_to(&buf[..len], &addr).await;
            }
        });

        let tmp = env::temp_dir().join(format!("rscan_cli_udp_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "host",
            "udp",
            "--host",
            "127.0.0.1",
            "--ports",
            &port_str,
            "--output",
            "json",
            "--out",
            &tmp_str,
        ];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_syn_writes_output_file() {
        if !is_root() {
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let tmp = env::temp_dir().join(format!("rscan_cli_syn_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "host",
            "syn",
            "--host",
            "127.0.0.1",
            "--ports",
            &port_str,
            "--output",
            "json",
            "--out",
            &tmp_str,
        ];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_quick_returns_ok() {
        let tmp = env::temp_dir().join("rscan_cli_quick.out");
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "host",
            "quick",
            "--host",
            "127.0.0.1",
            "--output",
            "json",
            "--out",
            &tmp_str,
        ];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports_count\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_concurrent_run_from_args_initialization_is_safe() {
        use std::ffi::OsString;
        // Spawn two concurrent invocations which both initialize tracing via try_init()
        let tmp1 = env::temp_dir().join("rscan_cli_concur1.out");
        let tmp2 = env::temp_dir().join("rscan_cli_concur2.out");
        let tmp1_os = tmp1.as_os_str().to_os_string();
        let tmp2_os = tmp2.as_os_str().to_os_string();
        let args1: Vec<OsString> = vec![
            "rscan".into(),
            "--log-level".into(),
            "info".into(),
            "host".into(),
            "quick".into(),
            "--host".into(),
            "127.0.0.1".into(),
            "--output".into(),
            "json".into(),
            "--out".into(),
            tmp1_os,
        ];
        let args2: Vec<OsString> = vec![
            "rscan".into(),
            "--log-level".into(),
            "info".into(),
            "host".into(),
            "quick".into(),
            "--host".into(),
            "127.0.0.1".into(),
            "--output".into(),
            "json".into(),
            "--out".into(),
            tmp2_os,
        ];
        let j1 = tokio::spawn(async move { run_from_args(args1).await });
        let j2 = tokio::spawn(async move { run_from_args(args2).await });
        let r1 = j1.await.unwrap();
        let r2 = j2.await.unwrap();
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        let _ = fs::remove_file(tmp1);
        let _ = fs::remove_file(tmp2);
    }

    #[tokio::test]
    async fn cli_service_detect_requires_probes_file() {
        let args = vec![
            "rscan",
            "host",
            "udp",
            "--host",
            "127.0.0.1",
            "--ports",
            "53",
            "--service-detect",
        ];
        let err = run_from_args(args).await.unwrap_err();
        assert!(format!("{err}").contains("--service-detect requires --probes-file"));
    }

    #[tokio::test]
    async fn cli_host_ports_range_is_supported() {
        let tmp = env::temp_dir().join("rscan_cli_range.out");
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "host",
            "tcp",
            "--host",
            "127.0.0.1",
            "--ports",
            "1-2",
            "--output",
            "json",
            "--out",
            &tmp_str,
        ];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"total_scanned\":2"));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_fuzz_summary_writes_cluster_lines() {
        let tmp = env::temp_dir().join("rscan_cli_fuzz_summary.out");
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tx.send(Ok(ModuleScanResult {
            url: "http://x/a".to_string(),
            status: 404,
            content_len: Some(100),
        }))
        .await
        .unwrap();
        tx.send(Ok(ModuleScanResult {
            url: "http://x/b".to_string(),
            status: 404,
            content_len: Some(100),
        }))
        .await
        .unwrap();
        tx.send(Ok(ModuleScanResult {
            url: "http://x/c".to_string(),
            status: 200,
            content_len: Some(20),
        }))
        .await
        .unwrap();
        drop(tx);

        consume_module_stream_with_summary(
            rx,
            Some(tmp.clone()),
            OutputFormat::Raw,
            None,
            Some(3),
            "web.fuzz",
            2,
        )
        .await
        .unwrap();

        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("summary clusters=2 shown=2 errors=0"));
        assert!(s.contains("cluster status=404 content_len=100 count=2"));
        assert!(s.contains("cluster status=200 content_len=20 count=1"));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_web_fuzz_preset_and_keywords_file_work() {
        use warp::Filter;

        let route = warp::path!(String).map(|s: String| {
            warp::reply::with_status(format!("ok:{s}"), warp::http::StatusCode::OK)
        });
        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let kw_file = env::temp_dir().join(format!("rscan_kw_{}.txt", addr.port()));
        let out_file = env::temp_dir().join(format!("rscan_cli_fuzz_{}.out", addr.port()));
        fs::write(&kw_file, "A B\n").unwrap();

        let base_url = format!("{}/FUZZ", base);
        let kw_path = kw_file.to_str().unwrap().to_string();
        let out_path = out_file.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "web",
            "fuzz",
            "--url",
            &base_url,
            "--keywords",
            "root",
            "--keywords-file",
            &kw_path,
            "--preset",
            "api",
            "--summary",
            "--summary-top",
            "3",
            "--stream-to",
            &out_path,
            "--output",
            "raw",
        ];
        run_from_args(args).await.unwrap();

        let s = tokio::fs::read_to_string(&out_file).await.unwrap();
        assert!(s.contains("/api/root"));
        assert!(s.contains("A%20B"));
        assert!(s.contains("summary clusters="));
        let _ = fs::remove_file(&kw_file);
        let _ = fs::remove_file(&out_file);
    }

    #[tokio::test]
    async fn cli_web_dns_words_file_works() {
        use warp::Filter;

        let route = warp::any().map(|| warp::reply::with_status("ok", warp::http::StatusCode::OK));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let domain = format!("127.0.0.1:{}", addr.port());
        let words_file = env::temp_dir().join(format!("rscan_dns_words_{}.txt", addr.port()));
        let out_file = env::temp_dir().join(format!("rscan_dns_out_{}.out", addr.port()));
        fs::write(&words_file, "a\nb\n").unwrap();

        let words_path = words_file.to_str().unwrap().to_string();
        let out_path = out_file.to_str().unwrap().to_string();
        let args = vec![
            "rscan",
            "web",
            "dns",
            "--domain",
            &domain,
            "--words",
            "a",
            "--words-file",
            &words_path,
            "--stream-to",
            &out_path,
            "--output",
            "raw",
        ];
        run_from_args(args).await.unwrap();

        let s = tokio::fs::read_to_string(&out_file).await.unwrap();
        assert!(s.contains("a.127.0.0.1"));
        assert!(s.contains("b.127.0.0.1"));
        let _ = fs::remove_file(&words_file);
        let _ = fs::remove_file(&out_file);
    }

    #[test]
    fn fuzz_keyword_transforms_expand_and_dedupe() {
        let words = vec!["Admin".to_string(), "a b".to_string(), "Admin".to_string()];
        let out = build_fuzz_keywords(
            words,
            &[
                FuzzKeywordTransform::Raw,
                FuzzKeywordTransform::Lower,
                FuzzKeywordTransform::UrlEncode,
            ],
            Some("p-".to_string()),
            Some("-s".to_string()),
            Some(64),
        );
        assert!(out.iter().any(|x| x == "p-Admin-s"));
        assert!(out.iter().any(|x| x == "p-admin-s"));
        assert!(out.iter().any(|x| x == "p-a%20b-s"));
        assert!(out.len() >= 3);
    }

    #[test]
    fn fuzz_keyword_max_len_filters_long_entries() {
        let out = build_fuzz_keywords(
            vec!["abc".to_string()],
            &[FuzzKeywordTransform::Raw],
            Some("prefix-".to_string()),
            Some("-suffix".to_string()),
            Some(8),
        );
        assert!(out.is_empty());
    }

    #[test]
    fn fuzz_preset_expands_keywords() {
        let out = expand_keywords_with_preset(vec!["admin".to_string()], Some(FuzzPreset::Api));
        assert!(out.iter().any(|x| x == "admin"));
        assert!(out.iter().any(|x| x == "api/admin"));
        assert!(out.iter().any(|x| x == "admin.json"));
    }

    #[test]
    fn fuzz_preset_defaults_are_not_empty() {
        let t = preset_default_transforms(FuzzPreset::Param);
        assert!(!t.is_empty());
    }
}
