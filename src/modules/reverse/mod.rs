pub mod analyzer;
pub mod backends;
pub mod console;
pub mod jobs;
pub mod malware;
pub mod model;
pub mod orchestrator;
pub mod rules;
pub mod tooling;

pub use analyzer::ReverseAnalyzer;
pub use backends::{BackendCatalog, BackendRegistry, ReverseBackend};
pub use console::{ReverseConsoleConfig, run_interactive as run_reverse_interactive};
pub use jobs::{
    DecompileBatchReport, DecompileRunReport, JobPrunePolicy, ReverseJobHealth, ReverseJobMeta,
    ReverseJobStatus, clear_jobs, inspect_job_health, inspect_jobs_health, list_jobs,
    load_job_by_id, load_job_logs, load_job_pseudocode_rows, prune_jobs, prune_jobs_keep_recent,
    run_decompile_batch, run_decompile_job,
};
pub use malware::{MalwareAnalyzer, MalwareTriageReport, ShellIndicator};
pub use model::{
    ApkReport, BinaryFormat, BinaryReport, DebugProfile, DecompileMode, DecompilerEngine, ToolInvocation,
};
pub use orchestrator::ReverseOrchestrator;
pub use rules::{RuleHotReloader, RuleLibrary};
pub use tooling::ReverseTooling;
