use std::fs;
use std::path::PathBuf;

use crate::errors::RustpenError;

pub(crate) fn build_task_spawn_args(
    workspace: &PathBuf,
    head: &str,
    parts: &[&str],
) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    match head {
        "host" => {
            if parts.len() < 2 {
                return Err("用法: host <quick|tcp> ...".to_string());
            }
            let sub = parts[1];
            match sub {
                "quick" => {
                    if parts.len() < 3 {
                        return Err("用法: host quick <host>".to_string());
                    }
                    args.extend([
                        "host".to_string(),
                        "quick".to_string(),
                        "--host".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "tcp" => {
                    if parts.len() < 4 {
                        return Err("用法: host tcp <host> <ports>".to_string());
                    }
                    args.extend([
                        "host".to_string(),
                        "tcp".to_string(),
                        "--host".to_string(),
                        parts[2].to_string(),
                        "--ports".to_string(),
                        parts[3].to_string(),
                    ]);
                }
                _ => return Err(format!("未知 host 子命令: {sub}")),
            }
        }
        "web" => {
            if parts.len() < 2 {
                return Err("用法: web <dir|fuzz|dns> ...".to_string());
            }
            let sub = parts[1];
            match sub {
                "dir" => {
                    if parts.len() < 4 {
                        return Err("用法: web dir <base> <paths_csv>".to_string());
                    }
                    args.extend([
                        "web".to_string(),
                        "dir".to_string(),
                        "--base".to_string(),
                        parts[2].to_string(),
                    ]);
                    for p in parts[3].split(',') {
                        args.push("--paths".into());
                        args.push(p.to_string());
                    }
                }
                "fuzz" => {
                    if parts.len() < 4 {
                        return Err("用法: web fuzz <url_with_FUZZ> <keywords_csv>".to_string());
                    }
                    args.extend([
                        "web".to_string(),
                        "fuzz".to_string(),
                        "--url".to_string(),
                        parts[2].to_string(),
                    ]);
                    for kw in parts[3].split(',') {
                        args.push("--keywords".into());
                        args.push(kw.to_string());
                    }
                }
                "dns" => {
                    if parts.len() < 4 {
                        return Err("用法: web dns <domain> <words_csv>".to_string());
                    }
                    args.extend([
                        "web".to_string(),
                        "dns".to_string(),
                        "--domain".to_string(),
                        parts[2].to_string(),
                    ]);
                    for w in parts[3].split(',') {
                        args.push("--words".into());
                        args.push(w.to_string());
                    }
                }
                _ => return Err(format!("未知 web 子命令: {sub}")),
            }
        }
        "vuln" => {
            if parts.len() < 2 {
                return Err("用法: vuln scan <target_url> [templates_dir]".to_string());
            }
            let sub = parts[1];
            if sub != "scan" {
                return Err(format!("未知 vuln 子命令: {sub}"));
            }
            if parts.len() < 3 {
                return Err("用法: vuln scan <target_url> [templates_dir]".to_string());
            }
            let templates = if parts.len() >= 4 {
                PathBuf::from(parts[3])
            } else {
                ensure_builtin_vuln_templates(workspace)
                    .map_err(|e| format!("准备漏洞模板失败: {}", e))?
            };
            if !templates.exists() {
                return Err(format!("模板目录不存在: {}", templates.display()));
            }
            args.extend([
                "vuln".to_string(),
                "scan".to_string(),
                "--targets".to_string(),
                parts[2].to_string(),
                "--templates".to_string(),
                templates.display().to_string(),
            ]);
        }
        "reverse" => {
            if parts.len() < 2 {
                return Err("用法: reverse <analyze|plan|run> ...".to_string());
            }
            let sub = parts[1];
            match sub {
                "analyze" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse analyze <input_file>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "analyze".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "plan" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse plan <input_file> [engine]".to_string());
                    }
                    let engine = parts.get(3).copied().unwrap_or("objdump");
                    let engine_ok = matches!(
                        engine.to_ascii_lowercase().as_str(),
                        "objdump" | "radare2" | "r2" | "ghidra" | "ida" | "idat64" | "jadx"
                    );
                    if !engine_ok {
                        return Err(format!(
                            "engine 不支持: {}，可选 objdump|radare2|ghidra|ida|jadx",
                            engine
                        ));
                    }
                    args.extend([
                        "reverse".to_string(),
                        "decompile-plan".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                        "--engine".to_string(),
                        engine.to_string(),
                    ]);
                }
                "run" => {
                    append_reverse_run_args(&mut args, workspace, parts, 2, 3, 4, 5)?;
                }
                _ => return Err(format!("未知 reverse 子命令: {sub}")),
            }
        }
        "h.quick" => {
            if parts.len() < 2 {
                return Err("用法: h.quick <host>".to_string());
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
                return Err("用法: h.tcp <host> <ports>".to_string());
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
                return Err("用法: w.dir <base> <paths_csv>".to_string());
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
                return Err("用法: w.fuzz <url_with_FUZZ> <keywords_csv>".to_string());
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
                return Err("用法: w.dns <domain> <words_csv>".to_string());
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
                return Err("用法: v.scan <target_url> [templates_dir]".to_string());
            }
            let templates = if parts.len() >= 3 {
                PathBuf::from(parts[2])
            } else {
                ensure_builtin_vuln_templates(workspace)
                    .map_err(|e| format!("准备漏洞模板失败: {}", e))?
            };
            if !templates.exists() {
                return Err(format!("模板目录不存在: {}", templates.display()));
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
                return Err("用法: r.analyze <input_file>".to_string());
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
                return Err("用法: r.plan <input_file> [engine]".to_string());
            }
            let engine = parts.get(2).copied().unwrap_or("objdump");
            let engine_ok = matches!(
                engine.to_ascii_lowercase().as_str(),
                "objdump" | "radare2" | "r2" | "ghidra" | "ida" | "idat64" | "jadx"
            );
            if !engine_ok {
                return Err(format!(
                    "engine 不支持: {}，可选 objdump|radare2|ghidra|ida|jadx",
                    engine
                ));
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
        "r.run" => {
            append_reverse_run_args(&mut args, workspace, parts, 1, 2, 3, 4)?;
        }
        _ => return Err(format!("未知命令: {head}")),
    }
    Ok(args)
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

fn append_reverse_run_args(
    args: &mut Vec<String>,
    workspace: &PathBuf,
    parts: &[&str],
    input_idx: usize,
    engine_idx: usize,
    mode_idx: usize,
    function_idx: usize,
) -> Result<(), String> {
    let Some(input) = parts.get(input_idx) else {
        return Err("用法: reverse run <input_file> [engine] [mode] [function]".to_string());
    };
    let engine = parts.get(engine_idx).copied().unwrap_or("auto");
    if !reverse_run_engine_supported(engine) {
        return Err(format!(
            "engine 不支持: {}，可选 auto|objdump|radare2|ghidra|ida|jadx|rust|rust-asm|rust-index",
            engine
        ));
    }
    let mode = parts.get(mode_idx).copied().unwrap_or("full");
    if !matches!(mode, "full" | "index" | "function") {
        return Err(format!("mode 不支持: {}，可选 full|index|function", mode));
    }

    args.extend([
        "reverse".to_string(),
        "decompile-run".to_string(),
        "--input".to_string(),
        (*input).to_string(),
        "--engine".to_string(),
        engine.to_string(),
        "--mode".to_string(),
        mode.to_string(),
        "--workspace".to_string(),
        workspace.display().to_string(),
    ]);
    if mode == "function" {
        let Some(function) = parts.get(function_idx) else {
            return Err(
                "function 模式需要额外参数: reverse run <input_file> [engine] function <function>"
                    .to_string(),
            );
        };
        args.extend(["--function".to_string(), (*function).to_string()]);
    }
    Ok(())
}

fn reverse_run_engine_supported(engine: &str) -> bool {
    matches!(
        engine.to_ascii_lowercase().as_str(),
        "auto"
            | "objdump"
            | "radare2"
            | "r2"
            | "ghidra"
            | "ida"
            | "idat64"
            | "jadx"
            | "rust"
            | "rust-asm"
            | "rust-index"
    )
}

#[cfg(test)]
mod tests {
    use super::build_task_spawn_args;

    #[test]
    fn build_reverse_run_adds_workspace_and_mode() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = ["r.run", "/bin/ls", "auto", "full"];
        let args = build_task_spawn_args(&ws, "r.run", &parts).unwrap();
        assert!(args.windows(2).any(|w| w == ["--engine", "auto"]));
        assert!(args.windows(2).any(|w| w == ["--mode", "full"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--workspace", ws.display().to_string().as_str()])
        );
    }
}
