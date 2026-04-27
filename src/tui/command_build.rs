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
                return Err("用法: host <quick|tcp|udp|syn|arp> ...".to_string());
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
                    append_host_extra_args(&mut args, &parts[3..], HostExtraKind::Quick)?;
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
                    append_host_extra_args(&mut args, &parts[4..], HostExtraKind::Tcp)?;
                }
                "udp" => {
                    if parts.len() < 4 {
                        return Err("用法: host udp <host> <ports>".to_string());
                    }
                    args.extend([
                        "host".to_string(),
                        "udp".to_string(),
                        "--host".to_string(),
                        parts[2].to_string(),
                        "--ports".to_string(),
                        parts[3].to_string(),
                    ]);
                    append_host_extra_args(&mut args, &parts[4..], HostExtraKind::Udp)?;
                }
                "syn" => {
                    if parts.len() < 4 {
                        return Err("用法: host syn <host> <ports>".to_string());
                    }
                    args.extend([
                        "host".to_string(),
                        "syn".to_string(),
                        "--host".to_string(),
                        parts[2].to_string(),
                        "--ports".to_string(),
                        parts[3].to_string(),
                    ]);
                    append_host_extra_args(&mut args, &parts[4..], HostExtraKind::Syn)?;
                }
                "arp" => {
                    if parts.len() < 3 {
                        return Err("用法: host arp <cidr>".to_string());
                    }
                    args.extend([
                        "host".to_string(),
                        "arp".to_string(),
                        "--cidr".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_host_extra_args(&mut args, &parts[3..], HostExtraKind::Arp)?;
                }
                _ => return Err(format!("未知 host 子命令: {sub}")),
            }
        }
        "web" => {
            if parts.len() < 2 {
                return Err("用法: web <dir|fuzz|dns|crawl|live> ...".to_string());
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
                    append_web_extra_args(&mut args, &parts[4..], WebExtraKind::Dir)?;
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
                    append_web_extra_args(&mut args, &parts[4..], WebExtraKind::Fuzz)?;
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
                    append_web_extra_args(&mut args, &parts[4..], WebExtraKind::Dns)?;
                }
                "crawl" => {
                    if parts.len() < 3 {
                        return Err("用法: web crawl <seed_url>".to_string());
                    }
                    args.extend([
                        "web".to_string(),
                        "crawl".to_string(),
                        "--seeds".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_web_extra_args(&mut args, &parts[3..], WebExtraKind::Crawl)?;
                }
                "live" => {
                    if parts.len() < 3 {
                        return Err("用法: web live <url_csv>".to_string());
                    }
                    args.extend(["web".to_string(), "live".to_string()]);
                    for url in parts[2].split(',') {
                        args.push("--urls".into());
                        args.push(url.to_string());
                    }
                    append_web_extra_args(&mut args, &parts[3..], WebExtraKind::Live)?;
                }
                _ => return Err(format!("未知 web 子命令: {sub}")),
            }
        }
        "vuln" => {
            if parts.len() < 2 {
                return Err(
                    "用法: vuln <lint|scan|container-audit|system-guard|stealth-check|fragment-audit|fuzz|poc> ..."
                        .to_string(),
                );
            }
            let sub = parts[1];
            match sub {
                "lint" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln lint <templates_path>".to_string());
                    }
                    args.extend([
                        "vuln".to_string(),
                        "lint".to_string(),
                        "--templates".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_vuln_common_output_args(&mut args, &parts[3..])?;
                }
                "scan" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln scan <target_url> [templates_dir]".to_string());
                    }
                    let templates = if parts.len() >= 4 && !parts[3].starts_with("--") {
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
                    let extra_start = if parts.len() >= 4 && !parts[3].starts_with("--") {
                        4
                    } else {
                        3
                    };
                    append_vuln_scan_extra_args(&mut args, &parts[extra_start..])?;
                }
                "container-audit" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln container-audit <manifests_path>".to_string());
                    }
                    args.extend([
                        "vuln".to_string(),
                        "container-audit".to_string(),
                        "--manifests".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_vuln_common_output_args(&mut args, &parts[3..])?;
                }
                "system-guard" => {
                    args.extend(["vuln".to_string(), "system-guard".to_string()]);
                    append_vuln_common_output_args(&mut args, &parts[2..])?;
                }
                "stealth-check" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln stealth-check <target_url>".to_string());
                    }
                    args.extend([
                        "vuln".to_string(),
                        "stealth-check".to_string(),
                        "--target".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_vuln_targeted_extra_args(
                        &mut args,
                        &parts[3..],
                        VulnTargetedKind::Stealth,
                    )?;
                }
                "fragment-audit" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln fragment-audit <target_url>".to_string());
                    }
                    args.extend([
                        "vuln".to_string(),
                        "fragment-audit".to_string(),
                        "--target".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_vuln_targeted_extra_args(
                        &mut args,
                        &parts[3..],
                        VulnTargetedKind::Fragment,
                    )?;
                }
                "fuzz" => {
                    if parts.len() < 3 {
                        return Err(
                            "用法: vuln fuzz <url_with_FUZZ> [keywords_csv] [--keyword ...]"
                                .to_string(),
                        );
                    }
                    args.extend([
                        "vuln".to_string(),
                        "fuzz".to_string(),
                        "--url".to_string(),
                        parts[2].to_string(),
                    ]);
                    let extra_start = if parts.len() >= 4 && !parts[3].starts_with("--") {
                        for kw in parts[3].split(',').filter(|kw| !kw.is_empty()) {
                            args.push("--keyword".into());
                            args.push(kw.to_string());
                        }
                        4
                    } else {
                        3
                    };
                    append_vuln_fuzz_extra_args(&mut args, &parts[extra_start..])?;
                }
                "poc" => {
                    if parts.len() < 3 {
                        return Err("用法: vuln poc <target_url> [path]".to_string());
                    }
                    args.extend([
                        "vuln".to_string(),
                        "poc".to_string(),
                        "--target".to_string(),
                        parts[2].to_string(),
                    ]);
                    let extra_start = if parts.len() >= 4 && !parts[3].starts_with("--") {
                        args.extend(["--path".to_string(), parts[3].to_string()]);
                        4
                    } else {
                        3
                    };
                    append_vuln_poc_extra_args(&mut args, &parts[extra_start..])?;
                }
                _ => return Err(format!("未知 vuln 子命令: {sub}")),
            }
        }
        "reverse" => {
            if parts.len() < 2 {
                return Err(
                    "用法: reverse <analyze|plan|run|jobs|job-status|job-logs|job-artifacts|job-functions|job-show|job-search|job-clear|job-prune|job-doctor|debug-script|backend-status|android-analyze|malware-triage|shell-audit|console> ..."
                        .to_string(),
                );
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
                    append_reverse_analyze_extra_args(&mut args, &parts[3..])?;
                }
                "plan" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse plan <input_file> [engine]".to_string());
                    }
                    let engine = if let Some(value) = parts.get(3) {
                        if value.starts_with("--") {
                            "objdump"
                        } else {
                            value
                        }
                    } else {
                        "objdump"
                    };
                    let engine_ok = matches!(
                        engine.to_ascii_lowercase().as_str(),
                        "objdump" | "radare2" | "r2" | "ghidra" | "jadx"
                    );
                    if !engine_ok {
                        return Err(format!(
                            "engine 不支持: {}，可选 objdump|radare2|ghidra|jadx",
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
                    let extra_start = if parts.len() >= 4 && !parts[3].starts_with("--") {
                        4
                    } else {
                        3
                    };
                    append_reverse_plan_extra_args(&mut args, &parts[extra_start..])?;
                }
                "run" => {
                    append_reverse_run_args(&mut args, workspace, parts, 2, 3, 4, 5)?;
                }
                "jobs" => {
                    args.extend(["reverse".to_string(), "jobs".to_string()]);
                }
                "job-status" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-status <job_id>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-status".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "job-logs" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-logs <job_id>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-logs".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_reverse_job_logs_extra_args(&mut args, &parts[3..])?;
                }
                "job-artifacts" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-artifacts <job_id>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-artifacts".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "job-functions" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-functions <job_id>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-functions".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "job-show" => {
                    if parts.len() < 4 {
                        return Err("用法: reverse job-show <job_id> <function>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-show".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                        "--name".to_string(),
                        parts[3].to_string(),
                    ]);
                }
                "job-search" => {
                    if parts.len() < 4 {
                        return Err("用法: reverse job-search <job_id> <keyword>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-search".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                        "--keyword".to_string(),
                        parts[3].to_string(),
                    ]);
                    append_reverse_job_search_extra_args(&mut args, &parts[4..])?;
                }
                "job-clear" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-clear <job_id>|--all".to_string());
                    }
                    args.extend(["reverse".to_string(), "job-clear".to_string()]);
                    if parts[2] == "--all" {
                        args.push("--all".to_string());
                        append_reverse_job_clear_extra_args(&mut args, &parts[3..])?;
                    } else {
                        args.extend(["--job".to_string(), parts[2].to_string()]);
                        append_reverse_job_clear_extra_args(&mut args, &parts[3..])?;
                    }
                }
                "job-prune" => {
                    args.extend(["reverse".to_string(), "job-prune".to_string()]);
                    append_reverse_job_prune_extra_args(&mut args, &parts[2..])?;
                }
                "job-doctor" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse job-doctor <job_id>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "job-doctor".to_string(),
                        "--job".to_string(),
                        parts[2].to_string(),
                    ]);
                }
                "debug-script" => {
                    if parts.len() < 4 {
                        return Err(
                            "用法: reverse debug-script <input_file> <script_out> [profile]"
                                .to_string(),
                        );
                    }
                    args.extend([
                        "reverse".to_string(),
                        "debug-script".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                        "--script-out".to_string(),
                        parts[3].to_string(),
                    ]);
                    let extra_start = if parts.len() >= 5 && !parts[4].starts_with("--") {
                        args.extend(["--profile".to_string(), parts[4].to_string()]);
                        5
                    } else {
                        4
                    };
                    append_reverse_debug_script_extra_args(&mut args, &parts[extra_start..])?;
                }
                "backend-status" => {
                    args.extend(["reverse".to_string(), "backend-status".to_string()]);
                    append_reverse_output_extra_args(&mut args, &parts[2..])?;
                }
                "android-analyze" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse android-analyze <input_file>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "android-analyze".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_reverse_output_extra_args(&mut args, &parts[3..])?;
                }
                "malware-triage" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse malware-triage <input_file>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "malware-triage".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_reverse_output_extra_args(&mut args, &parts[3..])?;
                }
                "shell-audit" => {
                    if parts.len() < 3 {
                        return Err(
                            "用法: reverse shell-audit <input_file> [--text <script_text>]"
                                .to_string(),
                        );
                    }
                    args.extend(["reverse".to_string(), "shell-audit".to_string()]);
                    if parts[2] == "--text" {
                        let text = parts.get(3).ok_or_else(|| "--text 需要取值".to_string())?;
                        args.extend(["--text".to_string(), (*text).to_string()]);
                        append_reverse_output_extra_args(&mut args, &parts[4..])?;
                    } else {
                        args.extend(["--input".to_string(), parts[2].to_string()]);
                        append_reverse_output_extra_args(&mut args, &parts[3..])?;
                    }
                }
                "console" => {
                    if parts.len() < 3 {
                        return Err("用法: reverse console <input_file>".to_string());
                    }
                    args.extend([
                        "reverse".to_string(),
                        "console".to_string(),
                        "--input".to_string(),
                        parts[2].to_string(),
                    ]);
                    append_reverse_console_extra_args(&mut args, &parts[3..])?;
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
            append_host_extra_args(&mut args, &parts[2..], HostExtraKind::Quick)?;
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
            append_host_extra_args(&mut args, &parts[3..], HostExtraKind::Tcp)?;
        }
        "h.udp" => {
            if parts.len() < 3 {
                return Err("用法: h.udp <host> <ports>".to_string());
            }
            args.extend([
                "host".to_string(),
                "udp".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
                "--ports".to_string(),
                parts[2].to_string(),
            ]);
            append_host_extra_args(&mut args, &parts[3..], HostExtraKind::Udp)?;
        }
        "h.syn" => {
            if parts.len() < 3 {
                return Err("用法: h.syn <host> <ports>".to_string());
            }
            args.extend([
                "host".to_string(),
                "syn".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
                "--ports".to_string(),
                parts[2].to_string(),
            ]);
            append_host_extra_args(&mut args, &parts[3..], HostExtraKind::Syn)?;
        }
        "h.arp" => {
            if parts.len() < 2 {
                return Err("用法: h.arp <cidr>".to_string());
            }
            args.extend([
                "host".to_string(),
                "arp".to_string(),
                "--cidr".to_string(),
                parts[1].to_string(),
            ]);
            append_host_extra_args(&mut args, &parts[2..], HostExtraKind::Arp)?;
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
            append_web_extra_args(&mut args, &parts[3..], WebExtraKind::Dir)?;
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
            append_web_extra_args(&mut args, &parts[3..], WebExtraKind::Fuzz)?;
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
            append_web_extra_args(&mut args, &parts[3..], WebExtraKind::Dns)?;
        }
        "w.crawl" => {
            if parts.len() < 2 {
                return Err("用法: w.crawl <seed_url>".to_string());
            }
            args.extend([
                "web".to_string(),
                "crawl".to_string(),
                "--seeds".to_string(),
                parts[1].to_string(),
            ]);
            append_web_extra_args(&mut args, &parts[2..], WebExtraKind::Crawl)?;
        }
        "w.live" => {
            if parts.len() < 2 {
                return Err("用法: w.live <url_csv>".to_string());
            }
            args.extend(["web".to_string(), "live".to_string()]);
            for url in parts[1].split(',') {
                args.push("--urls".into());
                args.push(url.to_string());
            }
            append_web_extra_args(&mut args, &parts[2..], WebExtraKind::Live)?;
        }
        "v.lint" => {
            if parts.len() < 2 {
                return Err("用法: v.lint <templates_path>".to_string());
            }
            args.extend([
                "vuln".to_string(),
                "lint".to_string(),
                "--templates".to_string(),
                parts[1].to_string(),
            ]);
            append_vuln_common_output_args(&mut args, &parts[2..])?;
        }
        "v.scan" => {
            if parts.len() < 2 {
                return Err("用法: v.scan <target_url> [templates_dir]".to_string());
            }
            let templates = if parts.len() >= 3 && !parts[2].starts_with("--") {
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
            let extra_start = if parts.len() >= 3 && !parts[2].starts_with("--") {
                3
            } else {
                2
            };
            append_vuln_scan_extra_args(&mut args, &parts[extra_start..])?;
        }
        "v.ca" => {
            if parts.len() < 2 {
                return Err("用法: v.ca <manifests_path>".to_string());
            }
            args.extend([
                "vuln".to_string(),
                "container-audit".to_string(),
                "--manifests".to_string(),
                parts[1].to_string(),
            ]);
            append_vuln_common_output_args(&mut args, &parts[2..])?;
        }
        "v.sg" => {
            args.extend(["vuln".to_string(), "system-guard".to_string()]);
            append_vuln_common_output_args(&mut args, &parts[1..])?;
        }
        "v.sc" => {
            if parts.len() < 2 {
                return Err("用法: v.sc <target_url>".to_string());
            }
            args.extend([
                "vuln".to_string(),
                "stealth-check".to_string(),
                "--target".to_string(),
                parts[1].to_string(),
            ]);
            append_vuln_targeted_extra_args(&mut args, &parts[2..], VulnTargetedKind::Stealth)?;
        }
        "v.fa" => {
            if parts.len() < 2 {
                return Err("用法: v.fa <target_url>".to_string());
            }
            args.extend([
                "vuln".to_string(),
                "fragment-audit".to_string(),
                "--target".to_string(),
                parts[1].to_string(),
            ]);
            append_vuln_targeted_extra_args(&mut args, &parts[2..], VulnTargetedKind::Fragment)?;
        }
        "v.fuzz" => {
            if parts.len() < 2 {
                return Err(
                    "用法: v.fuzz <url_with_FUZZ> [keywords_csv] [--keyword ...]".to_string(),
                );
            }
            args.extend([
                "vuln".to_string(),
                "fuzz".to_string(),
                "--url".to_string(),
                parts[1].to_string(),
            ]);
            let extra_start = if parts.len() >= 3 && !parts[2].starts_with("--") {
                for kw in parts[2].split(',').filter(|kw| !kw.is_empty()) {
                    args.push("--keyword".into());
                    args.push(kw.to_string());
                }
                3
            } else {
                2
            };
            append_vuln_fuzz_extra_args(&mut args, &parts[extra_start..])?;
        }
        "v.poc" => {
            if parts.len() < 2 {
                return Err("用法: v.poc <target_url> [path]".to_string());
            }
            args.extend([
                "vuln".to_string(),
                "poc".to_string(),
                "--target".to_string(),
                parts[1].to_string(),
            ]);
            let extra_start = if parts.len() >= 3 && !parts[2].starts_with("--") {
                args.extend(["--path".to_string(), parts[2].to_string()]);
                3
            } else {
                2
            };
            append_vuln_poc_extra_args(&mut args, &parts[extra_start..])?;
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
            append_reverse_analyze_extra_args(&mut args, &parts[2..])?;
        }
        "r.plan" => {
            if parts.len() < 2 {
                return Err("用法: r.plan <input_file> [engine]".to_string());
            }
            let engine = if let Some(value) = parts.get(2) {
                if value.starts_with("--") {
                    "objdump"
                } else {
                    value
                }
            } else {
                "objdump"
            };
            let engine_ok = matches!(
                engine.to_ascii_lowercase().as_str(),
                "objdump" | "radare2" | "r2" | "ghidra" | "jadx"
            );
            if !engine_ok {
                return Err(format!(
                    "engine 不支持: {}，可选 objdump|radare2|ghidra|jadx",
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
            let extra_start = if parts.len() >= 3 && !parts[2].starts_with("--") {
                3
            } else {
                2
            };
            append_reverse_plan_extra_args(&mut args, &parts[extra_start..])?;
        }
        "r.run" => {
            append_reverse_run_args(&mut args, workspace, parts, 1, 2, 3, 4)?;
        }
        "r.jobs" => {
            args.extend(["reverse".to_string(), "jobs".to_string()]);
        }
        "r.status" => {
            if parts.len() < 2 {
                return Err("用法: r.status <job_id>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-status".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.logs" => {
            if parts.len() < 2 {
                return Err("用法: r.logs <job_id>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-logs".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
            ]);
            append_reverse_job_logs_extra_args(&mut args, &parts[2..])?;
        }
        "r.artifacts" => {
            if parts.len() < 2 {
                return Err("用法: r.artifacts <job_id>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-artifacts".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.funcs" => {
            if parts.len() < 2 {
                return Err("用法: r.funcs <job_id>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-functions".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.show" => {
            if parts.len() < 3 {
                return Err("用法: r.show <job_id> <function>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-show".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
                "--name".to_string(),
                parts[2].to_string(),
            ]);
        }
        "r.search" => {
            if parts.len() < 3 {
                return Err("用法: r.search <job_id> <keyword>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-search".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
                "--keyword".to_string(),
                parts[2].to_string(),
            ]);
            append_reverse_job_search_extra_args(&mut args, &parts[3..])?;
        }
        "r.clear" => {
            if parts.len() < 2 {
                return Err("用法: r.clear <job_id>|--all".to_string());
            }
            args.extend(["reverse".to_string(), "job-clear".to_string()]);
            if parts[1] == "--all" {
                args.push("--all".to_string());
                append_reverse_job_clear_extra_args(&mut args, &parts[2..])?;
            } else {
                args.extend(["--job".to_string(), parts[1].to_string()]);
                append_reverse_job_clear_extra_args(&mut args, &parts[2..])?;
            }
        }
        "r.prune" => {
            args.extend(["reverse".to_string(), "job-prune".to_string()]);
            append_reverse_job_prune_extra_args(&mut args, &parts[1..])?;
        }
        "r.doctor" => {
            if parts.len() < 2 {
                return Err("用法: r.doctor <job_id>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "job-doctor".to_string(),
                "--job".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.debug" => {
            if parts.len() < 3 {
                return Err("用法: r.debug <input_file> <script_out> [profile]".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "debug-script".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
                "--script-out".to_string(),
                parts[2].to_string(),
            ]);
            let extra_start = if parts.len() >= 4 && !parts[3].starts_with("--") {
                args.extend(["--profile".to_string(), parts[3].to_string()]);
                4
            } else {
                3
            };
            append_reverse_debug_script_extra_args(&mut args, &parts[extra_start..])?;
        }
        "r.backend" => {
            args.extend(["reverse".to_string(), "backend-status".to_string()]);
            append_reverse_output_extra_args(&mut args, &parts[1..])?;
        }
        "r.android" => {
            if parts.len() < 2 {
                return Err("用法: r.android <input_file>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "android-analyze".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
            ]);
            append_reverse_output_extra_args(&mut args, &parts[2..])?;
        }
        "r.mal" => {
            if parts.len() < 2 {
                return Err("用法: r.mal <input_file>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "malware-triage".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
            ]);
            append_reverse_output_extra_args(&mut args, &parts[2..])?;
        }
        "r.shell" => {
            if parts.len() < 2 {
                return Err("用法: r.shell <input_file> [--text <script_text>]".to_string());
            }
            args.extend(["reverse".to_string(), "shell-audit".to_string()]);
            if parts[1] == "--text" {
                let text = parts.get(2).ok_or_else(|| "--text 需要取值".to_string())?;
                args.extend(["--text".to_string(), (*text).to_string()]);
                append_reverse_output_extra_args(&mut args, &parts[3..])?;
            } else {
                args.extend(["--input".to_string(), parts[1].to_string()]);
                append_reverse_output_extra_args(&mut args, &parts[2..])?;
            }
        }
        "r.console" => {
            if parts.len() < 2 {
                return Err("用法: r.console <input_file>".to_string());
            }
            args.extend([
                "reverse".to_string(),
                "console".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
            ]);
            append_reverse_console_extra_args(&mut args, &parts[2..])?;
        }
        _ => return Err(format!("未知命令: {head}")),
    }
    Ok(args)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostExtraKind {
    Quick,
    Tcp,
    Udp,
    Syn,
    Arp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebExtraKind {
    Dir,
    Fuzz,
    Dns,
    Crawl,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VulnTargetedKind {
    Stealth,
    Fragment,
}

fn append_host_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
    kind: HostExtraKind,
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--profile" => {
                let Some(value) = extras.get(idx + 1) else {
                    return Err("--profile 需要取值: low-noise|balanced|aggressive".to_string());
                };
                if !matches!(*value, "low-noise" | "balanced" | "aggressive") {
                    return Err(format!(
                        "profile 不支持: {}，可选 low-noise|balanced|aggressive",
                        value
                    ));
                }
                args.extend(["--profile".to_string(), (*value).to_string()]);
                idx += 2;
            }
            "--service-detect" => {
                if matches!(kind, HostExtraKind::Arp | HostExtraKind::Quick) {
                    return Err("--service-detect 仅支持 tcp/udp/syn".to_string());
                }
                args.push("--service-detect".to_string());
                idx += 1;
            }
            "--probes-file" => {
                if matches!(kind, HostExtraKind::Arp | HostExtraKind::Quick) {
                    return Err("--probes-file 仅支持 tcp/udp/syn".to_string());
                }
                let Some(value) = extras.get(idx + 1) else {
                    return Err("--probes-file 需要文件路径".to_string());
                };
                args.extend(["--probes-file".to_string(), (*value).to_string()]);
                idx += 2;
            }
            "--syn-mode" => {
                if kind != HostExtraKind::Syn {
                    return Err("--syn-mode 仅支持 host syn / h.syn".to_string());
                }
                let Some(value) = extras.get(idx + 1) else {
                    return Err("--syn-mode 需要取值: strict|verify-filtered".to_string());
                };
                if !matches!(*value, "strict" | "verify-filtered") {
                    return Err(format!(
                        "syn-mode 不支持: {}，可选 strict|verify-filtered",
                        value
                    ));
                }
                args.extend(["--syn-mode".to_string(), (*value).to_string()]);
                idx += 2;
            }
            unknown => {
                return Err(format!("未知 host 扩展参数: {unknown}"));
            }
        }
    }
    Ok(())
}

fn append_web_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
    kind: WebExtraKind,
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--profile" => {
                let value = expect_value(extras, idx, "--profile 需要取值")?;
                ensure_profile(value)?;
                args.extend(["--profile".to_string(), value.to_string()]);
                idx += 2;
            }
            "--concurrency" | "-c" => {
                let value = expect_value(extras, idx, "--concurrency 需要取值")?;
                args.extend(["--concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--timeout-ms" | "-t" => {
                let value = expect_value(extras, idx, "--timeout-ms 需要取值")?;
                args.extend(["--timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--max-retries" | "-r" => {
                let value = expect_value(extras, idx, "--max-retries 需要取值")?;
                args.extend(["--max-retries".to_string(), value.to_string()]);
                idx += 2;
            }
            "--header" | "-H" => {
                let value = expect_value(extras, idx, "--header 需要取值")?;
                args.extend(["--header".to_string(), value.to_string()]);
                idx += 2;
            }
            "--status-min" => {
                let value = expect_value(extras, idx, "--status-min 需要取值")?;
                args.extend(["--status-min".to_string(), value.to_string()]);
                idx += 2;
            }
            "--status-max" => {
                let value = expect_value(extras, idx, "--status-max 需要取值")?;
                args.extend(["--status-max".to_string(), value.to_string()]);
                idx += 2;
            }
            "--method" | "-X" => {
                let value = expect_value(extras, idx, "--method 需要取值")?;
                args.extend(["--method".to_string(), value.to_string()]);
                idx += 2;
            }
            "--recursive" | "-R" => {
                if kind != WebExtraKind::Dir {
                    return Err("--recursive 仅支持 web dir / w.dir".to_string());
                }
                args.push("--recursive".to_string());
                idx += 1;
            }
            "--recursive-depth" | "-D" => {
                if kind != WebExtraKind::Dir {
                    return Err("--recursive-depth 仅支持 web dir / w.dir".to_string());
                }
                let value = expect_value(extras, idx, "--recursive-depth 需要取值")?;
                args.extend(["--recursive-depth".to_string(), value.to_string()]);
                idx += 2;
            }
            "--words-file" => {
                if kind != WebExtraKind::Dns {
                    return Err("--words-file 仅支持 web dns / w.dns".to_string());
                }
                let value = expect_value(extras, idx, "--words-file 需要文件路径")?;
                args.extend(["--words-file".to_string(), value.to_string()]);
                idx += 2;
            }
            "--discovery-mode" => {
                if kind != WebExtraKind::Dns {
                    return Err("--discovery-mode 仅支持 web dns / w.dns".to_string());
                }
                let value = expect_value(extras, idx, "--discovery-mode 需要取值")?;
                if !matches!(value, "rough" | "precise") {
                    return Err(format!(
                        "discovery-mode 不支持: {}，可选 rough|precise",
                        value
                    ));
                }
                args.extend(["--discovery-mode".to_string(), value.to_string()]);
                idx += 2;
            }
            "--keywords-file" => {
                if kind != WebExtraKind::Fuzz {
                    return Err("--keywords-file 仅支持 web fuzz / w.fuzz".to_string());
                }
                let value = expect_value(extras, idx, "--keywords-file 需要文件路径")?;
                args.extend(["--keywords-file".to_string(), value.to_string()]);
                idx += 2;
            }
            "--max-depth" => {
                if kind != WebExtraKind::Crawl {
                    return Err("--max-depth 仅支持 web crawl / w.crawl".to_string());
                }
                let value = expect_value(extras, idx, "--max-depth 需要取值")?;
                args.extend(["--max-depth".to_string(), value.to_string()]);
                idx += 2;
            }
            "--max-pages" => {
                if kind != WebExtraKind::Crawl {
                    return Err("--max-pages 仅支持 web crawl / w.crawl".to_string());
                }
                let value = expect_value(extras, idx, "--max-pages 需要取值")?;
                args.extend(["--max-pages".to_string(), value.to_string()]);
                idx += 2;
            }
            "--obey-robots" => {
                if kind != WebExtraKind::Crawl {
                    return Err("--obey-robots 仅支持 web crawl / w.crawl".to_string());
                }
                args.push("--obey-robots".to_string());
                idx += 1;
            }
            unknown => return Err(format!("未知 web 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_vuln_scan_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--severity" => {
                let value = expect_value(extras, idx, "--severity 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--severity".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--tag" => {
                let value = expect_value(extras, idx, "--tag 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--tag".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--concurrency" | "-c" => {
                let value = expect_value(extras, idx, "--concurrency 需要取值")?;
                args.extend(["--concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--timeout-ms" | "-T" => {
                let value = expect_value(extras, idx, "--timeout-ms 需要取值")?;
                args.extend(["--timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--findings-only" | "--success-only" => {
                args.push(extras[idx].to_string());
                idx += 1;
            }
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 vuln scan 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_vuln_fuzz_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--keyword" | "-k" => {
                let value = expect_value(extras, idx, "--keyword 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--keyword".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--keywords-file" => {
                let value = expect_value(extras, idx, "--keywords-file 需要取值")?;
                args.extend(["--keywords-file".to_string(), value.to_string()]);
                idx += 2;
            }
            "--concurrency" | "-c" => {
                let value = expect_value(extras, idx, "--concurrency 需要取值")?;
                args.extend(["--concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--timeout-ms" | "-T" => {
                let value = expect_value(extras, idx, "--timeout-ms 需要取值")?;
                args.extend(["--timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--status-min" => {
                let value = expect_value(extras, idx, "--status-min 需要取值")?;
                args.extend(["--status-min".to_string(), value.to_string()]);
                idx += 2;
            }
            "--status-max" => {
                let value = expect_value(extras, idx, "--status-max 需要取值")?;
                args.extend(["--status-max".to_string(), value.to_string()]);
                idx += 2;
            }
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 vuln fuzz 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_vuln_poc_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--path" => {
                let value = expect_value(extras, idx, "--path 需要取值")?;
                args.extend(["--path".to_string(), value.to_string()]);
                idx += 2;
            }
            "--method" => {
                let value = expect_value(extras, idx, "--method 需要取值")?;
                args.extend(["--method".to_string(), value.to_string()]);
                idx += 2;
            }
            "--header" => {
                let value = expect_value(extras, idx, "--header 需要取值")?;
                args.extend(["--header".to_string(), value.to_string()]);
                idx += 2;
            }
            "--body" => {
                let value = expect_value(extras, idx, "--body 需要取值")?;
                args.extend(["--body".to_string(), value.to_string()]);
                idx += 2;
            }
            "--timeout-ms" | "-T" => {
                let value = expect_value(extras, idx, "--timeout-ms 需要取值")?;
                args.extend(["--timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--status" => {
                let value = expect_value(extras, idx, "--status 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--status".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--word" => {
                let value = expect_value(extras, idx, "--word 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--word".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--header-word" => {
                let value = expect_value(extras, idx, "--header-word 需要取值")?;
                for item in value.split(',').filter(|item| !item.is_empty()) {
                    args.extend(["--header-word".to_string(), item.to_string()]);
                }
                idx += 2;
            }
            "--match-all" | "--case-insensitive" => {
                args.push(extras[idx].to_string());
                idx += 1;
            }
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 vuln poc 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_vuln_targeted_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
    kind: VulnTargetedKind,
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--timeout-ms" | "-T" => {
                let value = expect_value(extras, idx, "--timeout-ms 需要取值")?;
                args.extend(["--timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--concurrency" | "-c" => {
                if kind != VulnTargetedKind::Fragment {
                    return Err("--concurrency 仅支持 fragment-audit".to_string());
                }
                let value = expect_value(extras, idx, "--concurrency 需要取值")?;
                args.extend(["--concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--burst-concurrency" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--burst-concurrency 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--burst-concurrency 需要取值")?;
                args.extend(["--burst-concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--low-noise-requests" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--low-noise-requests 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--low-noise-requests 需要取值")?;
                args.extend(["--low-noise-requests".to_string(), value.to_string()]);
                idx += 2;
            }
            "--burst-requests" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--burst-requests 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--burst-requests 需要取值")?;
                args.extend(["--burst-requests".to_string(), value.to_string()]);
                idx += 2;
            }
            "--low-noise-interval-ms" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--low-noise-interval-ms 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--low-noise-interval-ms 需要取值")?;
                args.extend(["--low-noise-interval-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--advanced-checks" | "--no-advanced-checks" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err(
                        "--advanced-checks/--no-advanced-checks 仅支持 stealth-check".to_string(),
                    );
                }
                args.push(extras[idx].to_string());
                idx += 1;
            }
            "--variant-requests" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--variant-requests 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--variant-requests 需要取值")?;
                args.extend(["--variant-requests".to_string(), value.to_string()]);
                idx += 2;
            }
            "--variant-concurrency" => {
                if kind != VulnTargetedKind::Stealth {
                    return Err("--variant-concurrency 仅支持 stealth-check".to_string());
                }
                let value = expect_value(extras, idx, "--variant-concurrency 需要取值")?;
                args.extend(["--variant-concurrency".to_string(), value.to_string()]);
                idx += 2;
            }
            "--requests-per-tier" => {
                if kind != VulnTargetedKind::Fragment {
                    return Err("--requests-per-tier 仅支持 fragment-audit".to_string());
                }
                let value = expect_value(extras, idx, "--requests-per-tier 需要取值")?;
                args.extend(["--requests-per-tier".to_string(), value.to_string()]);
                idx += 2;
            }
            "--payload-min-bytes" => {
                if kind != VulnTargetedKind::Fragment {
                    return Err("--payload-min-bytes 仅支持 fragment-audit".to_string());
                }
                let value = expect_value(extras, idx, "--payload-min-bytes 需要取值")?;
                args.extend(["--payload-min-bytes".to_string(), value.to_string()]);
                idx += 2;
            }
            "--payload-max-bytes" => {
                if kind != VulnTargetedKind::Fragment {
                    return Err("--payload-max-bytes 仅支持 fragment-audit".to_string());
                }
                let value = expect_value(extras, idx, "--payload-max-bytes 需要取值")?;
                args.extend(["--payload-max-bytes".to_string(), value.to_string()]);
                idx += 2;
            }
            "--payload-step-bytes" => {
                if kind != VulnTargetedKind::Fragment {
                    return Err("--payload-step-bytes 仅支持 fragment-audit".to_string());
                }
                let value = expect_value(extras, idx, "--payload-step-bytes 需要取值")?;
                args.extend(["--payload-step-bytes".to_string(), value.to_string()]);
                idx += 2;
            }
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 vuln 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_vuln_common_output_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 vuln 扩展参数: {unknown}")),
        }
    }
    Ok(())
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
    let engine = if let Some(value) = parts.get(engine_idx) {
        if value.starts_with("--") {
            "auto"
        } else {
            value
        }
    } else {
        "auto"
    };
    if !reverse_run_engine_supported(engine) {
        return Err(format!(
            "engine 不支持: {}，可选 auto|objdump|radare2|ghidra|jadx|rust|rust-asm|rust-index",
            engine
        ));
    }
    let mode = if let Some(value) = parts.get(mode_idx) {
        if value.starts_with("--") {
            "full"
        } else {
            value
        }
    } else {
        "full"
    };
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
        if function.starts_with("--") {
            return Err(
                "function 模式需要额外参数: reverse run <input_file> [engine] function <function>"
                    .to_string(),
            );
        }
        args.extend(["--function".to_string(), (*function).to_string()]);
    }
    let extra_start = if mode == "function" {
        function_idx + 1
    } else if parts
        .get(mode_idx)
        .is_some_and(|value| !value.starts_with("--"))
    {
        mode_idx + 1
    } else if parts
        .get(engine_idx)
        .is_some_and(|value| !value.starts_with("--"))
    {
        engine_idx + 1
    } else {
        input_idx + 1
    };
    append_reverse_run_extra_args(args, &parts[extra_start..])?;
    Ok(())
}

fn append_reverse_analyze_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--rules-file" => {
                let value = expect_value(extras, idx, "--rules-file 需要文件路径")?;
                args.extend(["--rules-file".to_string(), value.to_string()]);
                idx += 2;
            }
            "--dynamic" => {
                args.push("--dynamic".to_string());
                idx += 1;
            }
            "--dynamic-timeout-ms" => {
                let value = expect_value(extras, idx, "--dynamic-timeout-ms 需要取值")?;
                args.extend(["--dynamic-timeout-ms".to_string(), value.to_string()]);
                idx += 2;
            }
            "--dynamic-syscalls" => {
                let value = expect_value(extras, idx, "--dynamic-syscalls 需要取值")?;
                args.extend(["--dynamic-syscalls".to_string(), value.to_string()]);
                idx += 2;
            }
            "--dynamic-blocklist" => {
                let value = expect_value(extras, idx, "--dynamic-blocklist 需要取值")?;
                args.extend(["--dynamic-blocklist".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse analyze 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_plan_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--output-dir" | "-d" => {
                let value = expect_value(extras, idx, "--output-dir 需要目录路径")?;
                args.extend(["--output-dir".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse plan 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_run_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--deep" => {
                args.push("--deep".to_string());
                idx += 1;
            }
            "--rust-first" => {
                args.push("--rust-first".to_string());
                idx += 1;
            }
            "--no-rust-first" => {
                args.push("--no-rust-first".to_string());
                idx += 1;
            }
            "--timeout-secs" | "-t" => {
                let value = expect_value(extras, idx, "--timeout-secs 需要取值")?;
                args.extend(["--timeout-secs".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse run 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_job_logs_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--stream" | "-s" => {
                let value = expect_value(extras, idx, "--stream 需要取值")?;
                if !matches!(value, "stdout" | "stderr" | "both") {
                    return Err(format!("stream 不支持: {}，可选 stdout|stderr|both", value));
                }
                args.extend(["--stream".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse job-logs 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_job_search_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--max" | "-m" => {
                let value = expect_value(extras, idx, "--max 需要取值")?;
                args.extend(["--max".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse job-search 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_job_clear_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    for extra in extras {
        match *extra {
            "--all" => args.push("--all".to_string()),
            unknown => return Err(format!("未知 reverse job-clear 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_job_prune_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--keep" | "-k" => {
                let value = expect_value(extras, idx, "--keep 需要取值")?;
                args.extend(["--keep".to_string(), value.to_string()]);
                idx += 2;
            }
            "--older-than-days" => {
                let value = expect_value(extras, idx, "--older-than-days 需要取值")?;
                args.extend(["--older-than-days".to_string(), value.to_string()]);
                idx += 2;
            }
            "--include-running" => {
                args.push("--include-running".to_string());
                idx += 1;
            }
            unknown => return Err(format!("未知 reverse job-prune 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_debug_script_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--pwndbg-init" | "-P" => {
                let value = expect_value(extras, idx, "--pwndbg-init 需要文件路径")?;
                args.extend(["--pwndbg-init".to_string(), value.to_string()]);
                idx += 2;
            }
            "--profile" | "-p" => {
                let value = expect_value(extras, idx, "--profile 需要取值")?;
                if !matches!(value, "pwngdb" | "pwndbg") {
                    return Err(format!("profile 不支持: {}，可选 pwngdb|pwndbg", value));
                }
                args.extend(["--profile".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse debug-script 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_output_extra_args(args: &mut Vec<String>, extras: &[&str]) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--output" | "-o" => {
                let value = expect_value(extras, idx, "--output 需要取值")?;
                args.extend(["--output".to_string(), value.to_string()]);
                idx += 2;
            }
            "--out" | "-f" => {
                let value = expect_value(extras, idx, "--out 需要取值")?;
                args.extend(["--out".to_string(), value.to_string()]);
                idx += 2;
            }
            unknown => return Err(format!("未知 reverse 输出参数: {unknown}")),
        }
    }
    Ok(())
}

fn append_reverse_console_extra_args(
    args: &mut Vec<String>,
    extras: &[&str],
) -> Result<(), String> {
    let mut idx = 0usize;
    while idx < extras.len() {
        match extras[idx] {
            "--workspace" | "-w" => {
                let value = expect_value(extras, idx, "--workspace 需要目录路径")?;
                args.extend(["--workspace".to_string(), value.to_string()]);
                idx += 2;
            }
            "--pwndbg-init" | "-P" => {
                let value = expect_value(extras, idx, "--pwndbg-init 需要文件路径")?;
                args.extend(["--pwndbg-init".to_string(), value.to_string()]);
                idx += 2;
            }
            "--ghidra-home" => {
                let value = expect_value(extras, idx, "--ghidra-home 需要目录路径")?;
                args.extend(["--ghidra-home".to_string(), value.to_string()]);
                idx += 2;
            }
            "--tui" => {
                args.push("--tui".to_string());
                idx += 1;
            }
            unknown => return Err(format!("未知 reverse console 扩展参数: {unknown}")),
        }
    }
    Ok(())
}

fn expect_value<'a>(extras: &'a [&str], idx: usize, err: &str) -> Result<&'a str, String> {
    extras.get(idx + 1).copied().ok_or_else(|| err.to_string())
}

fn ensure_profile(value: &str) -> Result<(), String> {
    if matches!(value, "low-noise" | "balanced" | "aggressive") {
        Ok(())
    } else {
        Err(format!(
            "profile 不支持: {}，可选 low-noise|balanced|aggressive",
            value
        ))
    }
}

fn reverse_run_engine_supported(engine: &str) -> bool {
    matches!(
        engine.to_ascii_lowercase().as_str(),
        "auto"
            | "objdump"
            | "radare2"
            | "r2"
            | "ghidra"
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

    #[test]
    fn build_host_syn_accepts_service_detect_profile_and_syn_mode() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = [
            "host",
            "syn",
            "127.0.0.1",
            "22,80",
            "--profile",
            "low-noise",
            "--service-detect",
            "--probes-file",
            "/tmp/probes.txt",
            "--syn-mode",
            "strict",
        ];
        let args = build_task_spawn_args(&ws, "host", &parts).unwrap();
        assert!(args.windows(2).any(|w| w == ["--profile", "low-noise"]));
        assert!(args.iter().any(|arg| arg == "--service-detect"));
        assert!(
            args.windows(2)
                .any(|w| w == ["--probes-file", "/tmp/probes.txt"])
        );
        assert!(args.windows(2).any(|w| w == ["--syn-mode", "strict"]));
    }

    #[test]
    fn build_host_udp_alias_accepts_profile_and_probes() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = [
            "h.udp",
            "127.0.0.1",
            "53,161",
            "--profile",
            "aggressive",
            "--probes-file",
            "/tmp/probes.txt",
        ];
        let args = build_task_spawn_args(&ws, "h.udp", &parts).unwrap();
        assert!(args.windows(2).any(|w| w == ["--profile", "aggressive"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--probes-file", "/tmp/probes.txt"])
        );
    }

    #[test]
    fn build_web_dir_accepts_core_extra_flags() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = [
            "web",
            "dir",
            "https://example.com",
            "/,/admin",
            "--profile",
            "aggressive",
            "--concurrency",
            "24",
            "--timeout-ms",
            "3000",
            "--header",
            "Authorization: Bearer x",
            "--recursive",
            "--recursive-depth",
            "3",
        ];
        let args = build_task_spawn_args(&ws, "web", &parts).unwrap();
        assert!(args.windows(2).any(|w| w == ["--profile", "aggressive"]));
        assert!(args.windows(2).any(|w| w == ["--concurrency", "24"]));
        assert!(args.windows(2).any(|w| w == ["--timeout-ms", "3000"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--header", "Authorization: Bearer x"])
        );
        assert!(args.iter().any(|arg| arg == "--recursive"));
        assert!(args.windows(2).any(|w| w == ["--recursive-depth", "3"]));
    }

    #[test]
    fn build_vuln_scan_accepts_filters_and_tuning() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = [
            "v.scan",
            "https://example.com",
            "--severity",
            "high,critical",
            "--tag",
            "cve,rce",
            "--concurrency",
            "16",
            "--timeout-ms",
            "4500",
            "--findings-only",
            "--success-only",
        ];
        let args = build_task_spawn_args(&ws, "v.scan", &parts).unwrap();
        assert!(args.windows(2).any(|w| w == ["--severity", "high"]));
        assert!(args.windows(2).any(|w| w == ["--severity", "critical"]));
        assert!(args.windows(2).any(|w| w == ["--tag", "cve"]));
        assert!(args.windows(2).any(|w| w == ["--tag", "rce"]));
        assert!(args.windows(2).any(|w| w == ["--concurrency", "16"]));
        assert!(args.windows(2).any(|w| w == ["--timeout-ms", "4500"]));
        assert!(args.iter().any(|arg| arg == "--findings-only"));
        assert!(args.iter().any(|arg| arg == "--success-only"));
    }

    #[test]
    fn build_vuln_fuzz_and_poc_accept_extra_flags() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let fuzz_parts = [
            "v.fuzz",
            "https://example.com/FUZZ",
            "admin,debug",
            "--status-min",
            "200",
            "--status-max",
            "403",
            "--keywords-file",
            "/tmp/words.txt",
        ];
        let fuzz_args = build_task_spawn_args(&ws, "v.fuzz", &fuzz_parts).unwrap();
        assert!(fuzz_args.windows(2).any(|w| w == ["--status-min", "200"]));
        assert!(fuzz_args.windows(2).any(|w| w == ["--status-max", "403"]));
        assert!(
            fuzz_args
                .windows(2)
                .any(|w| w == ["--keywords-file", "/tmp/words.txt"])
        );

        let poc_parts = [
            "v.poc",
            "https://example.com",
            "/login",
            "--method",
            "POST",
            "--status",
            "200,302",
            "--word",
            "token,error",
            "--match-all",
        ];
        let poc_args = build_task_spawn_args(&ws, "v.poc", &poc_parts).unwrap();
        assert!(poc_args.windows(2).any(|w| w == ["--method", "POST"]));
        assert!(poc_args.windows(2).any(|w| w == ["--status", "200"]));
        assert!(poc_args.windows(2).any(|w| w == ["--status", "302"]));
        assert!(poc_args.windows(2).any(|w| w == ["--word", "token"]));
        assert!(poc_args.windows(2).any(|w| w == ["--word", "error"]));
        assert!(poc_args.iter().any(|arg| arg == "--match-all"));

        let fuzz_kw_parts = [
            "v.fuzz",
            "https://example.com/FUZZ",
            "--keyword",
            "cfg,backup",
            "--output",
            "csv",
            "--out",
            "/tmp/vuln-fuzz.csv",
        ];
        let fuzz_kw_args = build_task_spawn_args(&ws, "v.fuzz", &fuzz_kw_parts).unwrap();
        assert!(fuzz_kw_args.windows(2).any(|w| w == ["--keyword", "cfg"]));
        assert!(
            fuzz_kw_args
                .windows(2)
                .any(|w| w == ["--keyword", "backup"])
        );
        assert!(fuzz_kw_args.windows(2).any(|w| w == ["--output", "csv"]));
        assert!(
            fuzz_kw_args
                .windows(2)
                .any(|w| w == ["--out", "/tmp/vuln-fuzz.csv"])
        );
    }

    #[test]
    fn build_vuln_stealth_accepts_advanced_and_output_flags() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let parts = [
            "v.sc",
            "https://example.com",
            "--low-noise-interval-ms",
            "400",
            "--advanced-checks",
            "--variant-requests",
            "16",
            "--variant-concurrency",
            "8",
            "--output",
            "raw",
            "--out",
            "/tmp/vuln-stealth.txt",
        ];
        let args = build_task_spawn_args(&ws, "v.sc", &parts).unwrap();
        assert!(
            args.windows(2)
                .any(|w| w == ["--low-noise-interval-ms", "400"])
        );
        assert!(args.iter().any(|arg| arg == "--advanced-checks"));
        assert!(args.windows(2).any(|w| w == ["--variant-requests", "16"]));
        assert!(args.windows(2).any(|w| w == ["--variant-concurrency", "8"]));
        assert!(args.windows(2).any(|w| w == ["--output", "raw"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--out", "/tmp/vuln-stealth.txt"])
        );
    }

    #[test]
    fn build_reverse_job_commands_and_run_flags() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");
        let run_parts = [
            "r.run",
            "/bin/ls",
            "ghidra",
            "full",
            "--deep",
            "--no-rust-first",
            "--timeout-secs",
            "90",
        ];
        let run_args = build_task_spawn_args(&ws, "r.run", &run_parts).unwrap();
        assert!(run_args.iter().any(|arg| arg == "--deep"));
        assert!(run_args.iter().any(|arg| arg == "--no-rust-first"));
        assert!(run_args.windows(2).any(|w| w == ["--timeout-secs", "90"]));

        let job_parts = ["reverse", "job-search", "job-123", "main", "--max", "10"];
        let job_args = build_task_spawn_args(&ws, "reverse", &job_parts).unwrap();
        assert!(job_args.windows(2).any(|w| w == ["--job", "job-123"]));
        assert!(job_args.windows(2).any(|w| w == ["--keyword", "main"]));
        assert!(job_args.windows(2).any(|w| w == ["--max", "10"]));
    }

    #[test]
    fn build_reverse_phase1_new_commands() {
        let ws = std::env::temp_dir().join("rscan_cmd_build_ws");

        let backend_parts = ["reverse", "backend-status", "--output", "raw"];
        let backend_args = build_task_spawn_args(&ws, "reverse", &backend_parts).unwrap();
        assert!(backend_args.windows(2).any(|w| w == ["--output", "raw"]));

        let android_parts = ["r.android", "sample.apk", "--output", "json"];
        let android_args = build_task_spawn_args(&ws, "r.android", &android_parts).unwrap();
        assert!(
            android_args
                .windows(2)
                .any(|w| w == ["--input", "sample.apk"])
        );
        assert!(android_args.windows(2).any(|w| w == ["--output", "json"]));

        let mal_parts = ["r.mal", "sample.bin", "--out", "/tmp/mal.json"];
        let mal_args = build_task_spawn_args(&ws, "r.mal", &mal_parts).unwrap();
        assert!(mal_args.windows(2).any(|w| w == ["--input", "sample.bin"]));
        assert!(mal_args.windows(2).any(|w| w == ["--out", "/tmp/mal.json"]));

        let shell_parts = ["r.shell", "--text", "echo hi", "--output", "raw"];
        let shell_args = build_task_spawn_args(&ws, "r.shell", &shell_parts).unwrap();
        assert!(shell_args.windows(2).any(|w| w == ["--text", "echo hi"]));
        assert!(shell_args.windows(2).any(|w| w == ["--output", "raw"]));

        let console_parts = [
            "r.console",
            "/bin/ls",
            "--tui",
            "--ghidra-home",
            "/opt/ghidra",
        ];
        let console_args = build_task_spawn_args(&ws, "r.console", &console_parts).unwrap();
        assert!(console_args.windows(2).any(|w| w == ["--input", "/bin/ls"]));
        assert!(console_args.iter().any(|arg| arg == "--tui"));
        assert!(
            console_args
                .windows(2)
                .any(|w| w == ["--ghidra-home", "/opt/ghidra"])
        );
    }
}
