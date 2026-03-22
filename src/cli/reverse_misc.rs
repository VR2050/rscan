use super::*;

pub(super) fn handle_debug_script(
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    profile: String,
    pwndbg_init: Option<PathBuf>,
    script_out: PathBuf,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    let profile = DebugProfile::parse(&profile).ok_or_else(|| {
        RustpenError::ParseError("invalid --profile, supported: pwngdb|pwndbg".to_string())
    })?;
    let orchestrator = ReverseOrchestrator::detect();
    orchestrator.build_debug_plan(&input, profile, &script_out, pwndbg_init.as_deref())?;
    println!("written debug script to {}", script_out.display());
    Ok(())
}

pub(super) fn handle_gdb_plugin(out: PathBuf) -> Result<(), RustpenError> {
    ReverseOrchestrator::write_gdb_plugin(&out)?;
    println!("written gdb plugin to {}", out.display());
    Ok(())
}

pub(super) fn handle_ghidra_script(out: PathBuf) -> Result<(), RustpenError> {
    ReverseOrchestrator::write_ghidra_script(&out)?;
    println!("written ghidra export script to {}", out.display());
    Ok(())
}

pub(super) fn handle_ghidra_index_script(out: PathBuf) -> Result<(), RustpenError> {
    ReverseOrchestrator::write_ghidra_index_script(&out)?;
    println!("written ghidra index script to {}", out.display());
    Ok(())
}

pub(super) fn handle_ghidra_function_script(out: PathBuf) -> Result<(), RustpenError> {
    ReverseOrchestrator::write_ghidra_function_script(&out)?;
    println!("written ghidra function script to {}", out.display());
    Ok(())
}

pub(super) fn handle_rules_template(out: PathBuf) -> Result<(), RustpenError> {
    RuleLibrary::write_template(&out)?;
    println!("written reverse rules template to {}", out.display());
    Ok(())
}

pub(super) async fn handle_malware_triage(
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
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
    Ok(())
}

pub(super) async fn handle_android_analyze(
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    let report = AndroidAnalyzer::analyze_apk(&input)?;
    let s = to_json_or_raw(&report, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}

pub(super) async fn handle_shell_audit(
    text: Option<String>,
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
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
    Ok(())
}

pub(super) fn handle_console(
    input: Option<PathBuf>,
    input_pos: Option<PathBuf>,
    workspace: Option<PathBuf>,
    pwndbg_init: Option<PathBuf>,
    tui: bool,
    ghidra_home: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let input = input
        .or(input_pos)
        .ok_or_else(|| RustpenError::MissingArgument {
            arg: "--input <path> or <INPUT>".to_string(),
        })?;
    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
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
            eprintln!("[rscan] TUI requires a TTY; falling back to interactive console");
            run_reverse_interactive(cfg)?;
        } else {
            run_reverse_tui(cfg)?;
        }
    } else {
        run_reverse_interactive(cfg)?;
    }
    Ok(())
}

pub(super) fn handle_workbench(
    workspace: Option<PathBuf>,
    project: Option<PathBuf>,
    input: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    crate::tui::reverse_workbench::run_reverse_workbench(workspace, project, input)
}

pub(super) fn handle_surface(
    workspace: Option<PathBuf>,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    crate::tui::reverse_surface::run_reverse_surface(workspace, project)
}

pub(super) fn handle_deck(
    workspace: Option<PathBuf>,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    crate::tui::reverse_deck::run_reverse_deck(workspace, project)
}

pub(super) fn handle_picker(
    workspace: Option<PathBuf>,
    project: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let workspace =
        workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    crate::tui::reverse_picker::run_reverse_picker(workspace, project)
}

pub(super) async fn handle_backend_status(
    output: String,
    out: Option<PathBuf>,
) -> Result<(), RustpenError> {
    let status = ReverseOrchestrator::detect().registry().catalog().clone();
    let s = to_json_or_raw(&status, &output)?;
    if let Some(path) = out {
        let file = File::create(path).await.map_err(RustpenError::Io)?;
        write_host_output_to_file(file, &s).await?;
    } else {
        println!("{s}");
    }
    Ok(())
}
