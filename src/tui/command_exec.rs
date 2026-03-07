use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::cores::engine::task::new_task_id;
use crate::errors::RustpenError;

pub(crate) fn launcher_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Host Quick (127.0.0.1)", "h.quick 127.0.0.1"),
        ("Host TCP 22,80,443", "h.tcp 127.0.0.1 22,80,443"),
        (
            "Web Dir example.com",
            "w.dir https://example.com /,/robots.txt",
        ),
        (
            "Web Fuzz example.com/FUZZ",
            "w.fuzz https://example.com/FUZZ admin,login",
        ),
        ("Web DNS example.com", "w.dns example.com www,api,dev"),
        ("Vuln Scan example.com", "v.scan https://example.com"),
        ("Reverse Analyze /bin/ls", "r.analyze /bin/ls"),
        ("Reverse Plan /bin/ls", "r.plan /bin/ls objdump"),
    ]
}

pub(crate) fn execute_short_command(workspace: &PathBuf, cmd: &str) -> String {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return "空命令".to_string();
    }
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let head = parts.first().copied().unwrap_or("");
    let mut args: Vec<String> = Vec::new();
    let task_id = new_task_id();

    match head {
        "h.quick" => {
            if parts.len() < 2 {
                return "用法: h.quick <host>".to_string();
            }
            args.extend([
                "host".to_string(),
                "quick".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
            ]);
        }
        "h.tcp" => {
            if parts.len() < 3 {
                return "用法: h.tcp <host> <ports>".to_string();
            }
            args.extend([
                "host".to_string(),
                "tcp".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
                "--ports".to_string(),
                parts[2].to_string(),
            ]);
        }
        "w.dir" => {
            if parts.len() < 3 {
                return "用法: w.dir <base> <paths_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "dir".to_string(),
                "--base".to_string(),
                parts[1].to_string(),
            ]);
            for p in parts[2].split(',') {
                args.push("--paths".into());
                args.push(p.to_string());
            }
        }
        "w.fuzz" => {
            if parts.len() < 3 {
                return "用法: w.fuzz <url_with_FUZZ> <keywords_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "fuzz".to_string(),
                "--url".to_string(),
                parts[1].to_string(),
            ]);
            for kw in parts[2].split(',') {
                args.push("--keywords".into());
                args.push(kw.to_string());
            }
        }
        "w.dns" => {
            if parts.len() < 3 {
                return "用法: w.dns <domain> <words_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "dns".to_string(),
                "--domain".to_string(),
                parts[1].to_string(),
            ]);
            for w in parts[2].split(',') {
                args.push("--words".into());
                args.push(w.to_string());
            }
        }
        "v.scan" => {
            if parts.len() < 2 {
                return "用法: v.scan <target_url> [templates_dir]".to_string();
            }
            let templates = if parts.len() >= 3 {
                PathBuf::from(parts[2])
            } else {
                match ensure_builtin_vuln_templates(workspace) {
                    Ok(p) => p,
                    Err(e) => return format!("准备漏洞模板失败: {}", e),
                }
            };
            if !templates.exists() {
                return format!("模板目录不存在: {}", templates.display());
            }
            args.extend([
                "vuln".to_string(),
                "scan".to_string(),
                "--targets".to_string(),
                parts[1].to_string(),
                "--templates".to_string(),
                templates.display().to_string(),
            ]);
        }
        "r.analyze" => {
            if parts.len() < 2 {
                return "用法: r.analyze <input_file>".to_string();
            }
            args.extend([
                "reverse".to_string(),
                "analyze".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.plan" => {
            if parts.len() < 2 {
                return "用法: r.plan <input_file> [engine]".to_string();
            }
            let engine = parts.get(2).copied().unwrap_or("objdump");
            let engine_ok = matches!(
                engine.to_ascii_lowercase().as_str(),
                "objdump" | "radare2" | "r2" | "ghidra" | "ida" | "idat64" | "jadx"
            );
            if !engine_ok {
                return format!(
                    "engine 不支持: {}，可选 objdump|radare2|ghidra|ida|jadx",
                    engine
                );
            }
            args.extend([
                "reverse".to_string(),
                "decompile-plan".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
                "--engine".to_string(),
                engine.to_string(),
            ]);
        }
        _ => return format!("未知命令: {head}"),
    }

    args.push("--task-workspace".into());
    args.push(workspace.display().to_string());
    args.push("--task-id".into());
    args.push(task_id.clone());

    let task_dir = workspace.join("tasks").join(&task_id);
    if let Err(e) = fs::create_dir_all(&task_dir) {
        return format!("启动失败: 创建任务目录失败: {}", e);
    }
    let stdout_path = task_dir.join("stdout.log");
    let stderr_path = task_dir.join("stderr.log");
    let stdout_file = match fs::File::create(&stdout_path) {
        Ok(f) => f,
        Err(e) => return format!("启动失败: 创建 stdout.log 失败: {}", e),
    };
    let stderr_file = match fs::File::create(&stderr_path) {
        Ok(f) => f,
        Err(e) => return format!("启动失败: 创建 stderr.log 失败: {}", e),
    };

    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rscan"));
    let spawn_res = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn();
    match spawn_res {
        Ok(_) => format!(
            "launching {head} task_id={task_id} (logs: {}/stdout.log)",
            task_dir.display()
        ),
        Err(e) => format!("启动失败: {e}"),
    }
}

fn ensure_builtin_vuln_templates(workspace: &PathBuf) -> Result<PathBuf, RustpenError> {
    let dir = workspace.join("vuln_templates");
    fs::create_dir_all(&dir).map_err(RustpenError::Io)?;
    let tpl_path = dir.join("basic_http.yaml");
    if !tpl_path.exists() {
        let content = r#"id: rscan-basic-http
info:
  name: Basic HTTP Status Probe
  severity: info
  tags: [default, health]
http:
  - method: GET
    path:
      - /
      - /robots.txt
    matchers:
      - type: status
        status: [200, 204, 301, 302, 401, 403]
"#;
        fs::write(&tpl_path, content).map_err(RustpenError::Io)?;
    }
    Ok(dir)
}
