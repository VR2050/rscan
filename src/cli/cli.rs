use crate::cores::engine::async_engine::AsyncConnectEngine;
use crate::cores::engine::engine_trait::ScanEngine;
use crate::cores::engine::raw_engine::RawPacketEngine;
use crate::cores::engine::scan_job::{ScanJob, ScanType};
use crate::cores::engine::scan_result::ScanResult as EngineScanResult;
use crate::cores::host::ScanResult as HostScanResult;
use crate::errors::RustpenError;
use crate::modules::port_scan::ports::HostScanner;
use crate::modules::reverse::{
    DebugProfile, DecompilerEngine, DecompileMode, MalwareAnalyzer, ReverseAnalyzer, ReverseConsoleConfig,
    ReverseOrchestrator, RuleHotReloader, RuleLibrary, clear_jobs, inspect_job_health, list_jobs,
    load_job_by_id, load_job_logs, load_job_pseudocode_rows, prune_jobs, run_decompile_batch,
    run_decompile_job, run_reverse_interactive,
};
use crate::modules::vuln_check::{
    VulnScanConfig, VulnScanReport, load_safe_templates_from_path, vuln_scan_targets,
};
use crate::modules::web_scan::live_scan::ping as live_ping;
use crate::modules::web_scan::{
    ModuleScanConfig, ModuleScanResult, OutputFormat, WebScanner, format_scan_result,
    format_scan_result_pretty,
};
use crate::services::service_probe::ServiceProbeEngine;
use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{Shell, generate};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::io::IsTerminal;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

// logging
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rscan", about = "rscan CLI", version)]
pub struct Cli {
    /// global log level (trace, debug, info, warn, error)
    #[arg(short = 'l', long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand, Debug)]
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
        #[command(subcommand)]
        action: ReverseActions,
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
}

#[derive(Subcommand, Debug)]
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
    },
    /// Quick TCP scan of common ports
    Quick {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
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
#[derive(Subcommand, Debug)]
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
        /// override per-host concurrency
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        /// disable deduplication
        #[arg(long, default_value_t = true)]
        dedupe: bool,
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
        /// enable recursive wordlist directory scan
        #[arg(short = 'R', long, default_value_t = false)]
        recursive: bool,
        /// max recursive depth when --recursive is enabled
        #[arg(short = 'D', long, default_value_t = 2)]
        recursive_depth: usize,
    },
    /// Fuzz scan: URL template should contain FUZZ
    #[command(visible_alias = "f")]
    Fuzz {
        #[arg(short = 'u', long)]
        url: String,
        #[arg(short = 'k', long, required = true)]
        keywords: Vec<String>,
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
    },

    /// Subdomain burst (dns)
    #[command(visible_alias = "n")]
    Dns {
        #[arg(short = 'd', long)]
        domain: String,
        #[arg(short = 'w', long, required = true)]
        words: Vec<String>,
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
        #[arg(long)]
        status_min: Option<u16>,
        #[arg(long)]
        status_max: Option<u16>,
        /// HTTP method, e.g. GET/POST/HEAD/OPTIONS
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
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

#[derive(Subcommand, Debug)]
pub enum ReverseActions {
    /// Static analysis for ELF/PE/APK + malware/packer heuristics
    Analyze {
        /// input file path
        #[arg(short = 'i', long)]
        input: PathBuf,
        /// optional YAML/JSON rule file for anti-debug/packer detection
        #[arg(short = 'r', long)]
        rules_file: Option<PathBuf>,
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
        #[arg(short = 'i', long)]
        input: PathBuf,
        /// engine: objdump|radare2|ghidra|ida|jadx
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
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(short = 'e', long, default_value = "auto")]
        engine: String,
        /// decompile mode: full|index|function (ghidra only for index/function)
        #[arg(long, default_value = "full")]
        mode: String,
        /// function name or address (required when --mode function)
        #[arg(long)]
        function: Option<String>,
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
        #[arg(short = 'i', long, required = true)]
        inputs: Vec<PathBuf>,
        #[arg(short = 'e', long, default_value = "auto")]
        engine: String,
        /// decompile mode: full|index|function (ghidra only for index/function)
        #[arg(long, default_value = "full")]
        mode: String,
        /// function name or address (used when --mode function)
        #[arg(long)]
        function: Option<String>,
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
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Print job logs
    JobLogs {
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        /// stdout|stderr|both
        #[arg(short = 's', long, default_value = "both")]
        stream: String,
    },
    /// Show job artifacts
    JobArtifacts {
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// List function symbols from job pseudocode
    JobFunctions {
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Show one function pseudocode by name/ea from job
    JobShow {
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'n', long)]
        name: String,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "raw")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Search keyword in function name/pseudocode from job
    JobSearch {
        #[arg(short = 'j', long)]
        job: String,
        #[arg(short = 'k', long)]
        keyword: String,
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
        #[arg(short = 'j', long)]
        job: Option<String>,
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
        #[arg(short = 'j', long)]
        job: String,
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
        #[arg(short = 'i', long)]
        input: PathBuf,
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
    /// Generate IDAPython batch export script (function-level pseudocode JSONL)
    IdaScript {
        /// output script path, e.g. ./ida_export_pseudocode.py
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
        #[arg(short = 'i', long)]
        input: PathBuf,
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
        #[arg(short = 'i', long)]
        input: Option<PathBuf>,
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
    /// Interactive reverse console (analysis + pseudocode + debug in one session)
    Console {
        #[arg(short = 'i', long)]
        input: PathBuf,
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'P', long)]
        pwndbg_init: Option<PathBuf>,
    },
    /// Check availability of external reverse backends (ghidra/pwndbg/ida/etc.)
    BackendStatus {
        #[arg(short = 'o', long, default_value = "json")]
        output: String,
        #[arg(short = 'f', long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
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
        #[arg(short = 'c', long, default_value_t = 32)]
        concurrency: usize,
        #[arg(short = 'T', long, default_value_t = 5000)]
        timeout_ms: u64,
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

fn parse_http_method(method: &str) -> Result<reqwest::Method, RustpenError> {
    reqwest::Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes())
        .map_err(|e| RustpenError::ParseError(format!("invalid --method '{}': {}", method, e)))
}

fn parse_decompile_mode(mode: &str) -> Result<DecompileMode, RustpenError> {
    DecompileMode::parse(mode).ok_or_else(|| {
        RustpenError::ParseError(
            "invalid --mode. use: full|index|function".to_string(),
        )
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
        OutputFormat::Json => {
            serde_json::json!({ "error": err.to_string() }).to_string()
        }
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
        "host={} ip={} proto={} open={} scanned={} errors={} duration_ms={}",
        r.host,
        r.ip,
        proto_col,
        colorize(&r.open_ports_count().to_string(), "32", color),
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

async fn write_lines_to_file(
    mut file: File,
    mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>,
    fmt: OutputFormat,
) -> Result<(), RustpenError> {
    while let Some(r) = rx.recv().await {
        match r {
            Ok(m) => {
                let line = format!("{}\n", format_scan_result(&m, &fmt));
                file.write_all(line.as_bytes())
                    .await
                    .map_err(|e| RustpenError::Io(e))?;
            }
            Err(e) => {
                let line = format!("{}\n", format_scan_error_line(&e, &fmt));
                file.write_all(line.as_bytes())
                    .await
                    .map_err(|e| RustpenError::Io(e))?;
            }
        }
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
    let mut parsed = Vec::new();
    for p in ports {
        for part in p.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            parsed.push(
                part.parse::<u16>()
                    .map_err(|e| RustpenError::ParseError(e.to_string()))?,
            );
        }
    }
    Ok(parsed)
}

fn resolve_target_ip(host: &str) -> Result<std::net::IpAddr, RustpenError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    let mut addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| RustpenError::InvalidHost(e.to_string()))?;
    addrs
        .find_map(|a| Some(a.ip()))
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

async fn run_engine_host_scan(
    host: &str,
    ports: &[u16],
    scan_type: ScanType,
    probe_engine: Option<std::sync::Arc<ServiceProbeEngine>>,
) -> Result<Vec<EngineScanResult>, RustpenError> {
    let target_ip = resolve_target_ip(host)?;
    let mut out = Vec::new();
    match scan_type {
        ScanType::Connect | ScanType::UdpProbe | ScanType::Dns => {
            let mut engine = AsyncConnectEngine::new_with_probe(1024, 64, probe_engine);
            let mut rx = engine.take_results();
            for &p in ports {
                let protocol = match scan_type {
                    ScanType::Connect => crate::cores::host::Protocol::Tcp,
                    ScanType::Dns => crate::cores::host::Protocol::Dns,
                    _ => crate::cores::host::Protocol::Udp,
                };
                engine.submit(
                    ScanJob::new(target_ip, protocol, scan_type.clone())
                        .with_port(p)
                        .with_timeout_ms(1200)
                        .with_retries(1),
                )?;
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
            let mut engine = RawPacketEngine::new_with_probe(1024, 16, 256, probe_engine);
            let mut rx = engine.take_results();
            for &p in ports {
                engine.submit(
                    ScanJob::new(
                        target_ip,
                        crate::cores::host::Protocol::Tcp,
                        scan_type.clone(),
                    )
                    .with_port(p)
                    .with_timeout_ms(1200)
                    .with_retries(1),
                )?;
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
        .map_err(|e| RustpenError::Io(e))?;
    Ok(())
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

    match cli.cmd {
        Commands::Web { action } => match action {
            WebActions::Dir {
                base,
                paths,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                per_host_concurrency,
                dedupe,
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
                recursive,
                recursive_depth,
            } => {
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                mcfg.request_method = parse_http_method(&method)?;
                mcfg.recursive = recursive;
                mcfg.recursive_max_depth = recursive_depth.max(1);
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
                mcfg.dedupe_results = dedupe;
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

                if let Some(path) = stream_to {
                    let rx = ws.dir_scan_stream(&base, paths, Some(mcfg));
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_lines_to_file(file, rx, fmt).await?;
                } else {
                    let paths_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                    let res = ws.dir_scan(&base, &paths_refs, Some(mcfg)).await?;
                    for r in res {
                        println!("{}", format_scan_for_stdout(&r, &fmt));
                    }
                }
            }
            WebActions::Fuzz {
                url,
                keywords,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                per_host_concurrency,
                dedupe,
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
            } => {
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                mcfg.request_method = parse_http_method(&method)?;
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
                mcfg.dedupe_results = dedupe;
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

                if let Some(path) = stream_to {
                    let rx = ws.fuzz_scan_stream(&url, keywords, Some(mcfg));
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_lines_to_file(file, rx, fmt).await?;
                } else {
                    let kws: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
                    let res = ws.fuzz_scan(&url, &kws, Some(mcfg)).await?;
                    for r in res {
                        println!("{}", format_scan_for_stdout(&r, &fmt));
                    }
                }
            }
            WebActions::Dns {
                domain,
                words,
                stream_to,
                output,
                concurrency,
                timeout_ms,
                max_retries,
                per_host_concurrency,
                dedupe,
                status_min,
                status_max,
                method,
            } => {
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig::default())?;
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                mcfg.request_method = parse_http_method(&method)?;
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
                mcfg.dedupe_results = dedupe;
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;

                if let Some(path) = stream_to {
                    let rx = ws.subdomain_burst_stream(&domain, words, Some(mcfg));
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_lines_to_file(file, rx, fmt).await?;
                } else {
                    let words_ref: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
                    let res = ws.subdomain_burst(&domain, &words_ref, Some(mcfg)).await?;
                    for r in res {
                        println!("{}", format_scan_for_stdout(&r, &fmt));
                    }
                }
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
                let ws = WebScanner::new(crate::modules::web_scan::WebScanConfig {
                    max_depth,
                    concurrency,
                    max_pages,
                    obey_robots,
                    ..Default::default()
                })?;
                let crawled = ws.scan(seeds).await?;
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
            }
            WebActions::Live {
                urls,
                method,
                concurrency,
                output,
                out,
            } => {
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
                for t in tasks {
                    if let Ok((url, res)) = t.await {
                        match res {
                            Ok(msg) => rows.push((url, Ok(msg))),
                            Err(e) => {
                                rows.push((url, Err(e.to_string())))
                            }
                        }
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
                    out.push(format!(
                        "{:>4} {:<7} {}",
                        "LIVE", "METHOD", "URL"
                    ));
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
            } => {
                if service_detect {
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine = load_probe_engine_if_requested(service_detect, probes_file)?;
                    let rows =
                        run_engine_host_scan(&host, &parsed, ScanType::Connect, probe_engine)
                            .await?;
                    let s = format_engine_scan_results(&rows, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    let scanner = HostScanner::default();
                    let parsed = parse_ports_flags(&ports)?;
                    let res = scanner.scan_tcp(&host, &parsed).await?;
                    let s = format_host_scan_result(&res, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                }
            }
            HostActions::Udp {
                host,
                ports,
                output,
                out,
                service_detect,
                probes_file,
            } => {
                if service_detect {
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine = load_probe_engine_if_requested(service_detect, probes_file)?;
                    let rows =
                        run_engine_host_scan(&host, &parsed, ScanType::UdpProbe, probe_engine)
                            .await?;
                    let s = format_engine_scan_results(&rows, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    // Create a manager with UDP enabled for UDP scans
                    use crate::cores::host::{ScanManager, TcpConfig, UdpConfig};
                    let manager =
                        ScanManager::new_with_udp(TcpConfig::default(), Some(UdpConfig::default()));
                    let scanner = HostScanner::with_manager(manager);
                    let parsed = parse_ports_flags(&ports)?;
                    let res = scanner.scan_udp(&host, &parsed).await?;
                    let s = format_host_scan_result(&res, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                }
            }
            HostActions::Syn {
                host,
                ports,
                output,
                out,
                service_detect,
                probes_file,
            } => {
                if service_detect {
                    let parsed = parse_ports_flags(&ports)?;
                    let probe_engine = load_probe_engine_if_requested(service_detect, probes_file)?;
                    let rows =
                        run_engine_host_scan(&host, &parsed, ScanType::Syn, probe_engine).await?;
                    let s = format_engine_scan_results(&rows, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    // Create a manager with SYN enabled for SYN scans
                    use crate::cores::host::{ScanManager, SynConfig, TcpConfig};
                    let manager =
                        ScanManager::new_with_syn(TcpConfig::default(), Some(SynConfig::default()));
                    let scanner = HostScanner::with_manager(manager);
                    let parsed = parse_ports_flags(&ports)?;
                    let res = scanner.scan_syn(&host, &parsed).await?;
                    let s = format_host_scan_result(&res, &output);
                    if let Some(path) = out {
                        let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        write_host_output_to_file(file, &s).await?;
                    } else {
                        println!("{}", s);
                    }
                }
            }
            HostActions::Quick { host, output, out } => {
                let scanner = HostScanner::default();
                let res = scanner.quick_tcp(&host).await?;
                let s = format_host_scan_result(&res, &output);
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{}", s);
                }
            }
            HostActions::Arp { cidr, output, out } => {
                let scanner = HostScanner::default();
                let res = scanner.arp_scan_cidr(&cidr).await?;
                if output.to_lowercase() == "json" {
                    let json_vec: Vec<_> = res.iter().map(|h| serde_json::json!({"ip": h.ip, "mac": h.mac.to_string(), "interface": h.interface})).collect();
                    let s = serde_json::to_string(&json_vec)
                        .map_err(|e| RustpenError::ParseError(e.to_string()))?;
                    if let Some(path) = out {
                        let mut file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                        file.write_all(format!("{}\n", s).as_bytes())
                            .await
                            .map_err(|e| RustpenError::Io(e))?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    for h in res {
                        let line = format!("{} {} {}\n", h.ip, h.mac, h.interface);
                        if let Some(path) = &out {
                            let mut file =
                                File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                            file.write_all(line.as_bytes())
                                .await
                                .map_err(|e| RustpenError::Io(e))?;
                        } else {
                            print!("{}", line);
                        }
                    }
                }
            }
        },
        Commands::Reverse { action } => match action {
            ReverseActions::Analyze {
                input,
                rules_file,
                output,
                out,
            } => {
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
                    let report = ReverseAnalyzer::analyze_apk_with_rules(&input, rules_ref)?;
                    to_json_or_raw(&report, &output)?
                } else {
                    let report = ReverseAnalyzer::analyze_binary_with_rules(&input, rules_ref)?;
                    to_json_or_raw(&report, &output)?
                };

                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::DecompilePlan {
                input,
                engine,
                output_dir,
                output,
                out,
            } => {
                let engine = DecompilerEngine::parse(&engine).ok_or_else(|| {
                    RustpenError::ParseError(
                        "invalid --engine. use: objdump|radare2|ghidra|ida|jadx".to_string(),
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
                engine,
                mode,
                function,
                workspace,
                timeout_secs,
                output,
                out,
            } => {
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let mode = parse_decompile_mode(&mode)?;
                let func = function.as_deref();
                if mode == DecompileMode::Function && func.is_none() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--function".to_string(),
                    });
                }
                let report = run_decompile_job(&input, &workspace, &engine, mode, func, timeout_secs)?;
                let s = to_json_or_raw(&report, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
            }
            ReverseActions::DecompileBatch {
                inputs,
                engine,
                mode,
                function,
                workspace,
                timeout_secs,
                parallel_jobs,
                output,
                out,
            } => {
                let workspace = workspace.unwrap_or_else(ReverseOrchestrator::default_workspace);
                let mode = parse_decompile_mode(&mode)?;
                let func = function.as_deref();
                if mode == DecompileMode::Function && func.is_none() {
                    return Err(RustpenError::MissingArgument {
                        arg: "--function".to_string(),
                    });
                }
                let report =
                    run_decompile_batch(&inputs, &workspace, &engine, mode, func, timeout_secs, parallel_jobs)?;
                let s = to_json_or_raw(&report, &output)?;
                if let Some(path) = out {
                    let file = File::create(path).await.map_err(RustpenError::Io)?;
                    write_host_output_to_file(file, &s).await?;
                } else {
                    println!("{s}");
                }
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
                workspace,
                output,
                out,
            } => {
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
                workspace,
                stream,
            } => {
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
                workspace,
                output,
                out,
            } => {
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
                workspace,
                output,
                out,
            } => {
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
                name,
                workspace,
                output,
                out,
            } => {
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
                keyword,
                workspace,
                max,
                output,
                out,
            } => {
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
                workspace,
                all,
                output,
                out,
            } => {
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
                workspace,
                output,
                out,
            } => {
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
                profile,
                pwndbg_init,
                script_out,
            } => {
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
            ReverseActions::IdaScript { out } => {
                ReverseOrchestrator::write_ida_script(&out)?;
                println!("written ida export script to {}", out.display());
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
            ReverseActions::MalwareTriage { input, output, out } => {
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
                output,
                out,
            } => {
                let content = match (text, input) {
                    (Some(t), _) => t,
                    (None, Some(p)) => std::fs::read_to_string(p)?,
                    (None, None) => {
                        return Err(RustpenError::MissingArgument {
                            arg: "--text or --input".to_string(),
                        });
                    }
                };
                let report = MalwareAnalyzer::audit_shell_text(&content);
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
                workspace,
                pwndbg_init,
            } => {
                let workspace = workspace.unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                });
                let cfg = ReverseConsoleConfig {
                    input,
                    workspace,
                    pwndbg_init,
                };
                run_reverse_interactive(cfg)?;
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
        },
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
                concurrency,
                timeout_ms,
                output,
                out,
            } => {
                let (templates, lint) = load_safe_templates_from_path(&templates)?;
                if templates.is_empty() {
                    return Err(RustpenError::ParseError(format!(
                        "no usable templates loaded: {:?}",
                        lint.errors
                    )));
                }
                let cfg = VulnScanConfig {
                    concurrency,
                    timeout_ms,
                };
                let report = vuln_scan_targets(&targets, &templates, cfg).await?;
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
}
