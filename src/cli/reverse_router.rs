use super::*;

pub(super) async fn handle_reverse_command(
    cli: &Cli,
    input: Option<PathBuf>,
    workspace: Option<PathBuf>,
    pwndbg_init: Option<PathBuf>,
    tui: bool,
    ghidra_home: Option<PathBuf>,
    action: Option<ReverseActions>,
) -> Result<(), RustpenError> {
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
            reverse_exec::handle_analyze(
                cli,
                input,
                input_pos,
                rules_file,
                dynamic,
                dynamic_timeout_ms,
                dynamic_syscalls,
                dynamic_blocklist,
                output,
                out,
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
            reverse_exec::handle_decompile_plan(input, input_pos, engine, output_dir, output, out)
                .await?;
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
            reverse_exec::handle_decompile_run(
                cli,
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
            reverse_exec::handle_decompile_batch(
                cli,
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
            )
            .await?;
        }
        ReverseActions::Picker { workspace, project } => {
            reverse_misc::handle_picker(workspace, project)?;
        }
        ReverseActions::Surface { workspace, project } => {
            reverse_misc::handle_surface(workspace, project)?;
        }
        ReverseActions::Deck { workspace, project } => {
            reverse_misc::handle_deck(workspace, project)?;
        }
        ReverseActions::Workbench {
            workspace,
            project,
            input,
        } => {
            reverse_misc::handle_workbench(workspace, project, input)?;
        }
        ReverseActions::Jobs {
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_jobs(workspace, output, out).await?;
        }
        ReverseActions::JobStatus {
            job,
            job_pos,
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_job_status(job, job_pos, workspace, output, out).await?;
        }
        ReverseActions::JobLogs {
            job,
            job_pos,
            workspace,
            stream,
        } => {
            reverse_jobs::handle_job_logs(job, job_pos, workspace, stream).await?;
        }
        ReverseActions::JobArtifacts {
            job,
            job_pos,
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_job_artifacts(job, job_pos, workspace, output, out).await?;
        }
        ReverseActions::JobFunctions {
            job,
            job_pos,
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_job_functions(job, job_pos, workspace, output, out).await?;
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
            reverse_jobs::handle_job_show(job, job_pos, name, name_pos, workspace, output, out)
                .await?;
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
            reverse_jobs::handle_job_search(
                job,
                job_pos,
                keyword,
                keyword_pos,
                workspace,
                max,
                output,
                out,
            )
            .await?;
        }
        ReverseActions::JobClear {
            job,
            job_pos,
            workspace,
            all,
            output,
            out,
        } => {
            reverse_jobs::handle_job_clear(job, job_pos, workspace, all, output, out).await?;
        }
        ReverseActions::JobPrune {
            keep,
            older_than_days,
            include_running,
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_job_prune(
                keep,
                older_than_days,
                include_running,
                workspace,
                output,
                out,
            )
            .await?;
        }
        ReverseActions::JobDoctor {
            job,
            job_pos,
            workspace,
            output,
            out,
        } => {
            reverse_jobs::handle_job_doctor(job, job_pos, workspace, output, out).await?;
        }
        ReverseActions::DebugScript {
            input,
            input_pos,
            profile,
            pwndbg_init,
            script_out,
        } => {
            reverse_misc::handle_debug_script(input, input_pos, profile, pwndbg_init, script_out)?;
        }
        ReverseActions::GdbPlugin { out } => {
            reverse_misc::handle_gdb_plugin(out)?;
        }
        ReverseActions::GhidraScript { out } => {
            reverse_misc::handle_ghidra_script(out)?;
        }
        ReverseActions::GhidraIndexScript { out } => {
            reverse_misc::handle_ghidra_index_script(out)?;
        }
        ReverseActions::GhidraFunctionScript { out } => {
            reverse_misc::handle_ghidra_function_script(out)?;
        }
        ReverseActions::RulesTemplate { out } => {
            reverse_misc::handle_rules_template(out)?;
        }
        ReverseActions::MalwareTriage {
            input,
            input_pos,
            output,
            out,
        } => {
            reverse_misc::handle_malware_triage(input, input_pos, output, out).await?;
        }
        ReverseActions::AndroidAnalyze {
            input,
            input_pos,
            output,
            out,
        } => {
            reverse_misc::handle_android_analyze(input, input_pos, output, out).await?;
        }
        ReverseActions::ShellAudit {
            text,
            input,
            input_pos,
            output,
            out,
        } => {
            reverse_misc::handle_shell_audit(text, input, input_pos, output, out).await?;
        }
        ReverseActions::Console {
            input,
            input_pos,
            workspace,
            pwndbg_init,
            tui,
            ghidra_home,
        } => {
            reverse_misc::handle_console(
                input,
                input_pos,
                workspace,
                pwndbg_init,
                tui,
                ghidra_home,
            )?;
        }
        ReverseActions::BackendStatus { output, out } => {
            reverse_misc::handle_backend_status(output, out).await?;
        }
    }
    Ok(())
}
