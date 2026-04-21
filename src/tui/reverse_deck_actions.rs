use std::fs;
use std::path::{Path, PathBuf};

use crate::cores::engine::task::TaskRuntimeBinding;
use crate::modules::reverse::ReverseJobMeta;
use crate::tui::task_store::REVERSE_JOB_RUNTIME_FILE;
use crate::tui::zellij;
use crate::tui::zellij_registry;

use super::DeckLogMode;

pub(super) fn open_reverse_job_logs_pane(job: &ReverseJobMeta, mode: DeckLogMode) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }

    let job_dir = reverse_job_dir(job);
    let pane_name = short_reverse_pane_name(log_pane_prefix(mode), &job.id);
    let cmd = build_logs_follow_command(job, mode);
    match zellij::open_command_pane_in_tab(
        zellij::INSPECT_TAB,
        &job.workspace,
        &cmd,
        &job_dir,
        Some(pane_name.clone()),
    ) {
        Ok(msg) => {
            remember_runtime(
                job,
                zellij::INSPECT_TAB,
                &pane_name,
                "inspect-logs",
                job_dir.clone(),
                Some(cmd),
            );
            format!(
                "{msg} | 已在 Inspect 跟随 {} ({})",
                job.id,
                log_mode_label(mode)
            )
        }
        Err(e) => format!("打开 reverse job 日志失败: {e}"),
    }
}

pub(super) fn open_reverse_job_artifacts_pane(job: &ReverseJobMeta) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }

    let cwd = reverse_artifact_dir(job);
    let pane_name = short_reverse_pane_name("rart", &job.id);
    let cmd = build_artifact_shell_command(job);
    match zellij::open_command_pane_in_tab(
        zellij::INSPECT_TAB,
        &job.workspace,
        &cmd,
        &cwd,
        Some(pane_name.clone()),
    ) {
        Ok(msg) => {
            remember_runtime(
                job,
                zellij::INSPECT_TAB,
                &pane_name,
                "inspect-artifacts",
                cwd.clone(),
                Some(cmd),
            );
            format!("{msg} | 已在 Inspect 打开 reverse artifacts {}", job.id)
        }
        Err(e) => format!("打开 reverse artifacts 失败: {e}"),
    }
}

pub(super) fn open_reverse_job_shell_pane(job: &ReverseJobMeta) -> String {
    if !zellij::is_managed_runtime() {
        return "该动作需要 zellij managed mode".to_string();
    }

    let cwd = reverse_artifact_dir(job);
    let pane_name = short_reverse_pane_name("rjob", &job.id);
    match zellij::open_shell_pane_in_tab(
        zellij::REVERSE_TAB,
        &job.workspace,
        &cwd,
        Some(pane_name.clone()),
    ) {
        Ok(msg) => {
            remember_runtime(
                job,
                zellij::REVERSE_TAB,
                &pane_name,
                "reverse-job-shell",
                cwd.clone(),
                None,
            );
            format!("{msg} | 已在 Reverse 打开 job shell {}", job.id)
        }
        Err(e) => format!("打开 reverse job shell 失败: {e}"),
    }
}

fn remember_runtime(
    job: &ReverseJobMeta,
    tab: &str,
    pane_name: &str,
    role: &str,
    cwd: PathBuf,
    command: Option<String>,
) {
    let registry_cwd = cwd.clone();
    let registry_command = command.clone();
    let binding = TaskRuntimeBinding {
        backend: "zellij".to_string(),
        session: Some(zellij::config().session),
        tab: Some(tab.to_string()),
        pane_name: Some(pane_name.to_string()),
        role: Some(role.to_string()),
        cwd: Some(cwd),
        command,
    };
    if let Ok(text) = serde_json::to_string_pretty(&binding) {
        let _ = fs::write(reverse_job_dir(job).join(REVERSE_JOB_RUNTIME_FILE), text);
    }
    let _ = zellij_registry::record_pane(
        &job.workspace,
        pane_name.to_string(),
        tab.to_string(),
        registry_cwd,
        Some(role.to_string()),
        registry_command,
    );
}

fn build_logs_follow_command(job: &ReverseJobMeta, mode: DeckLogMode) -> String {
    let shell = shell_quote(&user_shell());
    let id = shell_quote(&job.id);
    let kind = shell_quote(&job.kind);
    let status = shell_quote(&job_status(job));
    let target = shell_quote(&job.target.display().to_string());
    let mode_label = shell_quote(log_mode_label(mode));

    let mut script = format!(
        "printf 'reverse-job=%s kind=%s status=%s mode=%s\\n' {id} {kind} {status} {mode_label}; \
printf 'target=%s\\n\\n' {target}; \
set --;"
    );
    if matches!(mode, DeckLogMode::Both | DeckLogMode::Stdout) {
        script.push_str("if [ -e stdout.log ]; then set -- \"$@\" stdout.log; fi;");
    }
    if matches!(mode, DeckLogMode::Both | DeckLogMode::Stderr) {
        script.push_str("if [ -e stderr.log ]; then set -- \"$@\" stderr.log; fi;");
    }
    script.push_str(&format!(
        "if [ \"$#\" -eq 0 ]; then \
echo 'no stdout/stderr log yet; dropping to shell'; \
exec {shell} -i; \
else \
exec tail -n 80 -F \"$@\"; \
fi"
    ));
    script
}

fn build_artifact_shell_command(job: &ReverseJobMeta) -> String {
    let shell = shell_quote(&user_shell());
    let id = shell_quote(&job.id);
    let kind = shell_quote(&job.kind);
    let status = shell_quote(&job_status(job));
    let target = shell_quote(&job.target.display().to_string());
    let backend = shell_quote(&job.backend);
    let mode = shell_quote(job.mode.as_deref().unwrap_or("-"));

    let mut script = format!(
        "printf 'reverse-job=%s kind=%s status=%s\\n' {id} {kind} {status}; \
printf 'backend=%s mode=%s\\n' {backend} {mode}; \
printf 'target=%s\\n\\n' {target}; \
printf 'recorded artifacts:\\n';"
    );
    if job.artifacts.is_empty() {
        script.push_str("printf ' - <none recorded>\\n';");
    } else {
        for artifact in &job.artifacts {
            let path = normalize_reverse_path(&job.workspace, artifact);
            let quoted = shell_quote(&path.display().to_string());
            script.push_str(&format!("printf ' - %s\\n' {quoted};"));
        }
    }
    script.push_str("printf '\\nlisting:\\n'; ls -lah; printf '\\n';");
    script.push_str(&format!("exec {shell} -i"));
    script
}

fn reverse_job_dir(job: &ReverseJobMeta) -> PathBuf {
    job.workspace.join("jobs").join(&job.id)
}

fn reverse_artifact_dir(job: &ReverseJobMeta) -> PathBuf {
    let out_dir = job.workspace.join("reverse_out").join(&job.id);
    if out_dir.exists() {
        out_dir
    } else {
        reverse_job_dir(job)
    }
}

fn normalize_reverse_path(workspace: &Path, raw: &str) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        workspace.join(path)
    }
}

fn short_reverse_pane_name(prefix: &str, job_id: &str) -> String {
    let short = job_id.trim_start_matches("job-");
    let short = &short[..short.len().min(10)];
    format!("{prefix}-{short}")
}

fn log_pane_prefix(mode: DeckLogMode) -> &'static str {
    match mode {
        DeckLogMode::Both => "rlog",
        DeckLogMode::Stdout => "rout",
        DeckLogMode::Stderr => "rerr",
    }
}

fn log_mode_label(mode: DeckLogMode) -> &'static str {
    match mode {
        DeckLogMode::Both => "both",
        DeckLogMode::Stdout => "stdout",
        DeckLogMode::Stderr => "stderr",
    }
}

fn job_status(job: &ReverseJobMeta) -> String {
    format!("{:?}", job.status).to_ascii_lowercase()
}

fn user_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "zsh".to_string())
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::reverse::ReverseJobStatus;

    fn fake_job() -> ReverseJobMeta {
        ReverseJobMeta {
            id: "job-1".to_string(),
            kind: "reverse".to_string(),
            backend: "ghidra".to_string(),
            mode: Some("index".to_string()),
            function: None,
            target: PathBuf::from("/tmp/bin"),
            workspace: PathBuf::from("/tmp/ws"),
            status: ReverseJobStatus::Running,
            created_at: 0,
            started_at: None,
            ended_at: None,
            exit_code: None,
            program: "rscan".to_string(),
            args: Vec::new(),
            note: String::new(),
            artifacts: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn reverse_logs_follow_command_uses_positional_args_for_files() {
        let script = build_logs_follow_command(&fake_job(), DeckLogMode::Both);
        assert!(script.contains("set --;"));
        assert!(script.contains("set -- \"$@\" stdout.log;"));
        assert!(script.contains("set -- \"$@\" stderr.log;"));
        assert!(script.contains("tail -n 80 -F \"$@\""));
        assert!(!script.contains("tail -n 80 -F $files"));
    }
}
