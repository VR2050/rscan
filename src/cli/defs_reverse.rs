use super::*;

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
    /// Native reverse picker for Reverse tab (zellij 内默认直接拉起 filepicker)
    Picker {
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'p', long)]
        project: Option<PathBuf>,
    },
    /// Full reverse viewer surface for zellij Reverse tab
    Surface {
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'p', long)]
        project: Option<PathBuf>,
    },
    /// Reverse auxiliary deck for zellij Reverse tab
    Deck {
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'p', long)]
        project: Option<PathBuf>,
    },
    /// Legacy reverse workbench launcher for zellij Reverse tab
    Workbench {
        #[arg(short = 'w', long)]
        workspace: Option<PathBuf>,
        #[arg(short = 'p', long)]
        project: Option<PathBuf>,
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
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
    /// Android APK technical triage (APK index + profile + DEX/native lightweight analysis)
    AndroidAnalyze {
        #[arg(short = 'i', long, alias = "file")]
        input: Option<PathBuf>,
        /// input APK path (positional)
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
