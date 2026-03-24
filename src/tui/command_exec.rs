use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::cores::engine::task::new_task_id;
use crate::tui::command_build::build_task_spawn_args;
use crate::tui::task_actions::{
    open_reverse_workspace_shell, open_task_artifacts_by_id, open_task_logs_by_id,
    open_task_shell_by_id,
};
use crate::tui::zellij;

pub(crate) struct CommandExecResult {
    pub(crate) status_line: String,
    pub(crate) task_id: Option<String>,
}

pub(crate) fn execute_short_command(workspace: &PathBuf, cmd: &str) -> CommandExecResult {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return CommandExecResult {
            status_line: "空命令".to_string(),
            task_id: None,
        };
    }
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let head = parts.first().copied().unwrap_or("");

    match head {
        "zrun" => execute_zrun(workspace, cmd),
        "zlogs" => {
            if parts.len() < 2 {
                CommandExecResult {
                    status_line: "用法: zlogs <task_id>".to_string(),
                    task_id: None,
                }
            } else {
                CommandExecResult {
                    status_line: open_task_logs_by_id(workspace, parts[1]),
                    task_id: None,
                }
            }
        }
        "zshell" => {
            if parts.len() < 2 {
                CommandExecResult {
                    status_line: "用法: zshell <task_id>".to_string(),
                    task_id: None,
                }
            } else {
                CommandExecResult {
                    status_line: open_task_shell_by_id(workspace, parts[1]),
                    task_id: None,
                }
            }
        }
        "zart" => {
            if parts.len() < 2 {
                CommandExecResult {
                    status_line: "用法: zart <task_id>".to_string(),
                    task_id: None,
                }
            } else {
                CommandExecResult {
                    status_line: open_task_artifacts_by_id(workspace, parts[1]),
                    task_id: None,
                }
            }
        }
        "zrev" => CommandExecResult {
            status_line: open_reverse_workspace_shell(workspace),
            task_id: None,
        },
        "zfocus" => {
            if parts.len() < 2 {
                CommandExecResult {
                    status_line: "用法: zfocus <control|work|inspect|reverse>".to_string(),
                    task_id: None,
                }
            } else {
                CommandExecResult {
                    status_line: match zellij::focus_managed_tab(workspace, parts[1]) {
                        Ok(msg) => format!("{msg} | tab 已聚焦"),
                        Err(e) => format!("zellij tab 聚焦失败: {e}"),
                    },
                    task_id: None,
                }
            }
        }
        _ => spawn_task_process(workspace, head, &parts),
    }
}

fn execute_zrun(workspace: &PathBuf, raw_cmd: &str) -> CommandExecResult {
    let cmd = raw_cmd.trim_start_matches("zrun").trim();
    if cmd.is_empty() {
        return CommandExecResult {
            status_line: "用法: zrun <shell_command...>".to_string(),
            task_id: None,
        };
    }
    CommandExecResult {
        status_line: match zellij::open_pane(cmd, workspace, None) {
            Ok(msg) => msg,
            Err(e) => format!("zellij 启动失败: {e}"),
        },
        task_id: None,
    }
}

fn spawn_task_process(workspace: &PathBuf, head: &str, parts: &[&str]) -> CommandExecResult {
    let mut args = match build_task_spawn_args(workspace, head, parts) {
        Ok(args) => args,
        Err(e) => {
            return CommandExecResult {
                status_line: e,
                task_id: None,
            };
        }
    };

    let task_id = new_task_id();
    args.push("--task-workspace".into());
    args.push(workspace.display().to_string());
    args.push("--task-id".into());
    args.push(task_id.clone());

    let task_dir = workspace.join("tasks").join(&task_id);
    if let Err(e) = fs::create_dir_all(&task_dir) {
        return CommandExecResult {
            status_line: format!("启动失败: 创建任务目录失败: {}", e),
            task_id: None,
        };
    }
    let stdout_path = task_dir.join("stdout.log");
    let stderr_path = task_dir.join("stderr.log");
    let stdout_file = match fs::File::create(&stdout_path) {
        Ok(f) => f,
        Err(e) => {
            return CommandExecResult {
                status_line: format!("启动失败: 创建 stdout.log 失败: {}", e),
                task_id: None,
            };
        }
    };
    let stderr_file = match fs::File::create(&stderr_path) {
        Ok(f) => f,
        Err(e) => {
            return CommandExecResult {
                status_line: format!("启动失败: 创建 stderr.log 失败: {}", e),
                task_id: None,
            };
        }
    };

    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rscan"));
    let spawn_res = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn();

    match spawn_res {
        Ok(_) => CommandExecResult {
            status_line: if zellij::is_managed_runtime() {
                format!(
                    "task started: {head} task_id={task_id} | 在 Tasks/Results 中查看，真实终端仅保留给 g / zrun"
                )
            } else {
                format!(
                    "launching {head} task_id={task_id} (logs: {}/stdout.log)",
                    task_dir.display()
                )
            },
            task_id: Some(task_id),
        },
        Err(e) => CommandExecResult {
            status_line: format!("启动失败: {e}"),
            task_id: None,
        },
    }
}
