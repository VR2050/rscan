use super::*;

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
        /// optional nmap-service-probes path for --service-detect (auto-discovered by default)
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
