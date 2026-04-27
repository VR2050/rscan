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
    AndroidAnalyzer, DebugProfile, DecompileMode, DecompilerEngine, MalwareAnalyzer,
    ReverseAnalyzer, ReverseConsoleConfig, ReverseOrchestrator, RuleHotReloader, RuleLibrary,
    clear_jobs, inspect_job_health, list_jobs, load_job_by_id, load_job_logs,
    load_job_pseudocode_rows, prune_jobs, run_decompile_batch, run_decompile_job,
    run_reverse_interactive, run_reverse_tui,
};
use crate::modules::vuln_check::{
    AntiScanConfig, AntiScanReport, ContainerAuditReport, FragmentAuditConfig, FragmentAuditReport,
    FuzzAttackConfig, FuzzAttackHit, PocHttpConfig, PocHttpReport, SafeTemplate, SystemGuardReport,
    VulnScanConfig, VulnScanReport, audit_container_manifests_from_path, audit_http_anti_scan,
    audit_http_fragment_resilience, audit_local_system_guard, load_safe_templates_from_path,
    run_poc_http_probe, run_simple_fuzz_attack, vuln_scan_targets,
};
use crate::modules::web_scan::live_scan::ping as live_ping;
use crate::modules::web_scan::{
    ModuleScanConfig, ModuleScanResult, OutputFormat, WebScanner, format_scan_result,
    format_scan_result_pretty,
};
use crate::services::service_probe::ServiceProbeEngine;
use clap::{CommandFactory, Parser};
use clap_complete::generate;
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

// logging
use tracing::info;
use tracing_subscriber::EnvFilter;

#[path = "common.rs"]
mod common;
#[path = "defs.rs"]
mod defs;
#[path = "formatters.rs"]
mod formatters;
#[path = "host_router.rs"]
mod host_router;
#[path = "reverse_exec.rs"]
mod reverse_exec;
#[path = "reverse_jobs.rs"]
mod reverse_jobs;
#[path = "reverse_misc.rs"]
mod reverse_misc;
#[path = "reverse_router.rs"]
mod reverse_router;
#[path = "stream_output.rs"]
mod stream_output;
#[path = "vuln_router.rs"]
mod vuln_router;
#[path = "web_router.rs"]
mod web_router;

use common::*;
use defs::*;
use formatters::*;
use stream_output::*;

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
        Commands::Pane { workspace, kind } => {
            let workspace = workspace.or(cli.task_workspace.clone());
            return match kind {
                NativePaneKind::Work => crate::tui::native_hubs::run_work_hub_entry(workspace),
                NativePaneKind::Inspect => {
                    crate::tui::native_hubs::run_inspect_hub_entry(workspace)
                }
            };
        }
        Commands::Web { action } => {
            web_router::handle_web_command(&cli, action).await?;
        }
        Commands::Host { action } => {
            host_router::handle_host_command(&cli, action).await?;
        }
        Commands::Reverse {
            input,
            workspace,
            pwndbg_init,
            tui,
            ghidra_home,
            action,
        } => {
            reverse_router::handle_reverse_command(
                &cli,
                input,
                workspace,
                pwndbg_init,
                tui,
                ghidra_home,
                action,
            )
            .await?;
        }
        Commands::Vuln { action } => {
            vuln_router::handle_vuln_command(&cli, action).await?;
        }
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
#[path = "app_tests.rs"]
mod tests;
