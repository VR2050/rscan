use super::*;

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
