use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

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
pub enum NativePaneKind {
    Work,
    Inspect,
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
    #[command(hide = true)]
    Pane {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(value_enum, long)]
        kind: NativePaneKind,
    },
}

#[path = "defs_host.rs"]
mod defs_host;
#[path = "defs_reverse.rs"]
mod defs_reverse;
#[path = "defs_vuln.rs"]
mod defs_vuln;
#[path = "defs_web.rs"]
mod defs_web;

pub use defs_host::HostActions;
pub use defs_reverse::ReverseActions;
pub use defs_vuln::VulnActions;
pub use defs_web::WebActions;
