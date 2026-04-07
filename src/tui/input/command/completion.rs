use super::super::NonNormalInputCtx;
use crate::tui::command_catalog::completion_heads;

pub(super) fn clear_completion(ctx: &mut NonNormalInputCtx<'_>) {
    ctx.cmd_completion.clear();
    *ctx.cmd_completion_idx = None;
    ctx.cmd_completion_seed.clear();
}

pub(super) fn handle_completion(ctx: &mut NonNormalInputCtx<'_>, reverse: bool) {
    let cursor = clamp_cursor_pos(ctx.cmd_buffer, *ctx.cmd_cursor);
    let (token_start, token_end, token_idx, tokens) = locate_token(ctx.cmd_buffer, cursor);
    let prefix = &ctx.cmd_buffer[token_start..cursor];
    let seed = build_completion_seed(ctx.cmd_buffer, &tokens, token_idx, prefix);
    let mut matches = build_completions(ctx.cmd_buffer, &tokens, token_idx, prefix);
    if matches.is_empty() {
        clear_completion(ctx);
        *ctx.status_line = format!("no completion for: {}", seed);
        return;
    }
    matches.sort();

    let use_existing = seed == *ctx.cmd_completion_seed && !ctx.cmd_completion.is_empty();
    if !use_existing {
        *ctx.cmd_completion = matches;
        *ctx.cmd_completion_seed = seed;
    }

    let len = ctx.cmd_completion.len();
    let next_idx = if !use_existing {
        0
    } else {
        match *ctx.cmd_completion_idx {
            None => 0,
            Some(idx) if reverse && idx == 0 => len.saturating_sub(1),
            Some(idx) if reverse => idx - 1,
            Some(idx) => (idx + 1) % len,
        }
    };

    *ctx.cmd_completion_idx = Some(next_idx);
    if let Some(candidate) = ctx.cmd_completion.get(next_idx).cloned() {
        apply_completion(ctx, &candidate, token_start, token_end, cursor);
    }
    if len > 1 {
        *ctx.status_line = format!("completions({}): {}", len, ctx.cmd_completion.join(" "));
    }
}

fn apply_completion(
    ctx: &mut NonNormalInputCtx<'_>,
    text: &str,
    token_start: usize,
    token_end: usize,
    cursor: usize,
) {
    let end = if cursor < token_end {
        token_end
    } else {
        cursor
    };
    let mut out = String::new();
    out.push_str(&ctx.cmd_buffer[..token_start]);
    out.push_str(text);
    out.push_str(&ctx.cmd_buffer[end..]);
    *ctx.cmd_buffer = out;
    *ctx.cmd_cursor = token_start + text.len();
}

fn clamp_cursor_pos(s: &str, cursor: usize) -> usize {
    let mut c = cursor.min(s.len());
    while c > 0 && !s.is_char_boundary(c) {
        c -= 1;
    }
    c
}

fn locate_token(buffer: &str, cursor: usize) -> (usize, usize, usize, Vec<(usize, usize)>) {
    let mut tokens = Vec::new();
    let mut in_tok = false;
    let mut start = 0usize;
    for (i, ch) in buffer.char_indices() {
        if ch.is_whitespace() {
            if in_tok {
                tokens.push((start, i));
                in_tok = false;
            }
        } else if !in_tok {
            start = i;
            in_tok = true;
        }
    }
    if in_tok {
        tokens.push((start, buffer.len()));
    }

    if tokens.is_empty() {
        return (0, 0, 0, tokens);
    }
    for (idx, (s, e)) in tokens.iter().enumerate() {
        if cursor < *s {
            return (cursor, cursor, idx, tokens);
        }
        if cursor >= *s && cursor <= *e {
            return (*s, *e, idx, tokens);
        }
    }
    let last = tokens.len() - 1;
    if cursor > tokens[last].1 {
        return (cursor, cursor, tokens.len(), tokens);
    }
    (cursor, cursor, tokens.len(), tokens)
}

fn build_completion_seed(
    buffer: &str,
    tokens: &[(usize, usize)],
    token_idx: usize,
    prefix: &str,
) -> String {
    let head_str = tokens
        .first()
        .and_then(|(s, e)| buffer.get(*s..*e))
        .unwrap_or("");
    format!("{}|{}|{}", head_str, token_idx, prefix)
}

fn build_completions(
    buffer: &str,
    tokens: &[(usize, usize)],
    token_idx: usize,
    prefix: &str,
) -> Vec<String> {
    let head_str = tokens
        .first()
        .and_then(|(s, e)| buffer.get(*s..*e))
        .unwrap_or("");
    let sub = tokens.get(1).and_then(|(s, e)| buffer.get(*s..*e));

    if token_idx == 0 {
        return top_level_completions(prefix);
    }

    if matches!(head_str, "host" | "web" | "vuln" | "reverse") {
        return build_parent_command_completions(head_str, sub, token_idx, prefix);
    }

    if head_str == "zfocus" && token_idx >= 1 {
        return zfocus_suggestions(prefix);
    }
    if head_str == "r.plan" && token_idx >= 2 {
        return prefer_non_empty(
            plan_engine_suggestions(prefix),
            prefer_non_empty(
                reverse_plan_option_suggestions(token_idx, prefix),
                placeholder_suggestions(head_str, None, token_idx, prefix),
            ),
        );
    }
    if head_str == "r.analyze" {
        return prefer_non_empty(
            reverse_analyze_option_suggestions(token_idx, prefix),
            placeholder_suggestions(head_str, None, token_idx, prefix),
        );
    }
    if head_str == "r.run" {
        if token_idx == 2 {
            return prefer_non_empty(
                run_engine_suggestions(prefix),
                placeholder_suggestions(head_str, None, token_idx, prefix),
            );
        }
        if token_idx == 3 {
            return prefer_non_empty(
                run_mode_suggestions(prefix),
                placeholder_suggestions(head_str, None, token_idx, prefix),
            );
        }
        if token_idx >= 4 {
            return prefer_non_empty(
                reverse_run_option_suggestions(token_idx, prefix),
                placeholder_suggestions(head_str, None, token_idx, prefix),
            );
        }
    }
    if matches!(
        head_str,
        "r.jobs"
            | "r.status"
            | "r.logs"
            | "r.artifacts"
            | "r.funcs"
            | "r.show"
            | "r.search"
            | "r.clear"
            | "r.prune"
            | "r.doctor"
            | "r.debug"
    ) {
        return prefer_non_empty(
            reverse_alias_option_suggestions(head_str, token_idx, prefix),
            placeholder_suggestions(head_str, sub, token_idx, prefix),
        );
    }
    if matches!(head_str, "w.dir" | "w.fuzz" | "w.dns" | "w.crawl" | "w.live") {
        return prefer_non_empty(
            web_alias_option_suggestions(head_str, token_idx, prefix),
            placeholder_suggestions(head_str, sub, token_idx, prefix),
        );
    }
    if matches!(head_str, "v.lint" | "v.scan" | "v.ca" | "v.sg" | "v.sc" | "v.fa") {
        return prefer_non_empty(
            vuln_alias_option_suggestions(head_str, token_idx, prefix),
            placeholder_suggestions(head_str, sub, token_idx, prefix),
        );
    }
    if matches!(head_str, "h.quick" | "h.tcp" | "h.udp" | "h.syn" | "h.arp") {
        return prefer_non_empty(
            host_alias_option_suggestions(head_str, token_idx, prefix),
            placeholder_suggestions(head_str, sub, token_idx, prefix),
        );
    }

    placeholder_suggestions(head_str, sub, token_idx, prefix)
}

fn top_level_completions(prefix: &str) -> Vec<String> {
    if prefix.contains('.') {
        return completion_heads()
            .iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .map(|s| (*s).to_string())
            .collect();
    }

    let mut primary = Vec::new();
    for cmd in ["host", "web", "vuln", "reverse"] {
        if cmd.starts_with(prefix) {
            primary.push(cmd.to_string());
        }
    }

    let mut secondary = Vec::new();
    for cmd in ["zrun", "zlogs", "zshell", "zart", "zrev", "zfocus"] {
        if cmd.starts_with(prefix) {
            secondary.push(cmd.to_string());
        }
    }

    primary.extend(secondary);
    primary
}

fn build_parent_command_completions(
    head: &str,
    sub: Option<&str>,
    token_idx: usize,
    prefix: &str,
) -> Vec<String> {
    if token_idx == 1 {
        let subs = match head {
            "host" => vec!["quick", "tcp", "udp", "syn", "arp"],
            "web" => vec!["dir", "fuzz", "dns", "crawl", "live"],
            "vuln" => vec![
                "lint",
                "scan",
                "container-audit",
                "system-guard",
                "stealth-check",
                "fragment-audit",
            ],
            "reverse" => vec![
                "analyze",
                "plan",
                "run",
                "jobs",
                "job-status",
                "job-logs",
                "job-artifacts",
                "job-functions",
                "job-show",
                "job-search",
                "job-clear",
                "job-prune",
                "job-doctor",
                "debug-script",
            ],
            _ => vec![],
        };
        return subs
            .into_iter()
            .filter(|s| s.starts_with(prefix))
            .map(|s| s.to_string())
            .collect();
    }

    if head == "reverse" && sub == Some("plan") && token_idx >= 3 {
        return prefer_non_empty(
            plan_engine_suggestions(prefix),
            prefer_non_empty(
                reverse_plan_option_suggestions(token_idx, prefix),
                placeholder_suggestions(head, sub, token_idx, prefix),
            ),
        );
    }
    if head == "reverse" && sub == Some("analyze") {
        return prefer_non_empty(
            reverse_analyze_option_suggestions(token_idx, prefix),
            placeholder_suggestions(head, sub, token_idx, prefix),
        );
    }
    if head == "reverse" && sub == Some("run") {
        if token_idx == 3 {
            return prefer_non_empty(
                run_engine_suggestions(prefix),
                placeholder_suggestions(head, sub, token_idx, prefix),
            );
        }
        if token_idx == 4 {
            return prefer_non_empty(
                run_mode_suggestions(prefix),
                placeholder_suggestions(head, sub, token_idx, prefix),
            );
        }
        if token_idx >= 5 {
            return prefer_non_empty(
                reverse_run_option_suggestions(token_idx, prefix),
                placeholder_suggestions(head, sub, token_idx, prefix),
            );
        }
    }
    if head == "host" {
        return prefer_non_empty(
            host_option_suggestions(sub, token_idx, prefix),
            placeholder_suggestions(head, sub, token_idx, prefix),
        );
    }
    if head == "web" {
        return prefer_non_empty(
            web_option_suggestions(sub, token_idx, prefix),
            placeholder_suggestions(head, sub, token_idx, prefix),
        );
    }
    if head == "vuln" {
        return prefer_non_empty(
            vuln_option_suggestions(sub, token_idx, prefix),
            placeholder_suggestions(head, sub, token_idx, prefix),
        );
    }
    if head == "reverse" {
        return prefer_non_empty(
            reverse_option_suggestions(sub, token_idx, prefix),
            placeholder_suggestions(head, sub, token_idx, prefix),
        );
    }

    placeholder_suggestions(head, sub, token_idx, prefix)
}

fn prefer_non_empty(primary: Vec<String>, fallback: Vec<String>) -> Vec<String> {
    if primary.is_empty() {
        fallback
    } else {
        primary
    }
}

fn plan_engine_suggestions(prefix: &str) -> Vec<String> {
    ["objdump", "radare2", "r2", "ghidra", "jadx"]
        .iter()
        .filter(|s| s.starts_with(prefix))
        .map(|s| (*s).to_string())
        .collect()
}

fn run_engine_suggestions(prefix: &str) -> Vec<String> {
    [
        "auto",
        "objdump",
        "radare2",
        "r2",
        "ghidra",
        "jadx",
        "rust",
        "rust-asm",
        "rust-index",
    ]
    .iter()
    .filter(|s| s.starts_with(prefix))
    .map(|s| (*s).to_string())
    .collect()
}

fn run_mode_suggestions(prefix: &str) -> Vec<String> {
    ["full", "index", "function"]
        .iter()
        .filter(|s| s.starts_with(prefix))
        .map(|s| (*s).to_string())
        .collect()
}

fn zfocus_suggestions(prefix: &str) -> Vec<String> {
    ["control", "work", "inspect", "reverse"]
        .iter()
        .filter(|s| s.starts_with(prefix))
        .map(|s| (*s).to_string())
        .collect()
}

fn host_option_suggestions(sub: Option<&str>, token_idx: usize, prefix: &str) -> Vec<String> {
    match sub {
        Some("quick") if token_idx >= 3 => host_quick_options(prefix),
        Some("tcp") if token_idx >= 4 => host_tcpish_options(prefix),
        Some("udp") if token_idx >= 4 => host_tcpish_options(prefix),
        Some("syn") if token_idx >= 4 => host_syn_options(prefix),
        Some("arp") if token_idx >= 3 => host_arp_options(prefix),
        _ => Vec::new(),
    }
}

fn host_alias_option_suggestions(head: &str, token_idx: usize, prefix: &str) -> Vec<String> {
    match head {
        "h.quick" if token_idx >= 2 => host_quick_options(prefix),
        "h.tcp" if token_idx >= 3 => host_tcpish_options(prefix),
        "h.udp" if token_idx >= 3 => host_tcpish_options(prefix),
        "h.syn" if token_idx >= 3 => host_syn_options(prefix),
        "h.arp" if token_idx >= 2 => host_arp_options(prefix),
        _ => Vec::new(),
    }
}

fn host_quick_options(prefix: &str) -> Vec<String> {
    host_flag_filter(["--profile"], prefix)
}

fn host_tcpish_options(prefix: &str) -> Vec<String> {
    host_flag_filter(["--profile", "--service-detect", "--probes-file"], prefix)
}

fn host_syn_options(prefix: &str) -> Vec<String> {
    host_flag_filter(
        ["--profile", "--service-detect", "--probes-file", "--syn-mode"],
        prefix,
    )
}

fn host_arp_options(prefix: &str) -> Vec<String> {
    host_flag_filter(["--profile"], prefix)
}

fn host_flag_filter<const N: usize>(flags: [&str; N], prefix: &str) -> Vec<String> {
    flags.iter()
        .filter(|flag| flag.starts_with(prefix))
        .map(|flag| (*flag).to_string())
        .collect()
}

fn web_option_suggestions(sub: Option<&str>, token_idx: usize, prefix: &str) -> Vec<String> {
    match sub {
        Some("dir") if token_idx >= 4 => web_dir_options(prefix),
        Some("fuzz") if token_idx >= 4 => web_fuzz_options(prefix),
        Some("dns") if token_idx >= 4 => web_dns_options(prefix),
        Some("crawl") if token_idx >= 3 => web_crawl_options(prefix),
        Some("live") if token_idx >= 3 => web_live_options(prefix),
        _ => Vec::new(),
    }
}

fn web_alias_option_suggestions(head: &str, token_idx: usize, prefix: &str) -> Vec<String> {
    match head {
        "w.dir" if token_idx >= 3 => web_dir_options(prefix),
        "w.fuzz" if token_idx >= 3 => web_fuzz_options(prefix),
        "w.dns" if token_idx >= 3 => web_dns_options(prefix),
        "w.crawl" if token_idx >= 2 => web_crawl_options(prefix),
        "w.live" if token_idx >= 2 => web_live_options(prefix),
        _ => Vec::new(),
    }
}

fn web_dir_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &[
            "--profile",
            "--concurrency",
            "--timeout-ms",
            "--max-retries",
            "--header",
            "--status-min",
            "--status-max",
            "--method",
            "--recursive",
            "--recursive-depth",
        ],
        prefix,
    )
}

fn web_fuzz_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &[
            "--profile",
            "--concurrency",
            "--timeout-ms",
            "--max-retries",
            "--header",
            "--status-min",
            "--status-max",
            "--method",
            "--keywords-file",
        ],
        prefix,
    )
}

fn web_dns_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &[
            "--profile",
            "--concurrency",
            "--timeout-ms",
            "--max-retries",
            "--status-min",
            "--status-max",
            "--method",
            "--words-file",
            "--discovery-mode",
        ],
        prefix,
    )
}

fn web_crawl_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &["--max-depth", "--concurrency", "--max-pages", "--obey-robots"],
        prefix,
    )
}

fn web_live_options(prefix: &str) -> Vec<String> {
    flag_filter(&["--method", "--concurrency"], prefix)
}

fn vuln_option_suggestions(sub: Option<&str>, token_idx: usize, prefix: &str) -> Vec<String> {
    match sub {
        Some("scan") if token_idx >= 3 => vuln_scan_options(prefix),
        Some("stealth-check") if token_idx >= 3 => vuln_stealth_options(prefix),
        Some("fragment-audit") if token_idx >= 3 => vuln_fragment_options(prefix),
        _ => Vec::new(),
    }
}

fn vuln_alias_option_suggestions(head: &str, token_idx: usize, prefix: &str) -> Vec<String> {
    match head {
        "v.scan" if token_idx >= 2 => vuln_scan_options(prefix),
        "v.sc" if token_idx >= 2 => vuln_stealth_options(prefix),
        "v.fa" if token_idx >= 2 => vuln_fragment_options(prefix),
        _ => Vec::new(),
    }
}

fn vuln_scan_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &["--severity", "--tag", "--concurrency", "--timeout-ms"],
        prefix,
    )
}

fn vuln_stealth_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &[
            "--timeout-ms",
            "--low-noise-requests",
            "--burst-requests",
            "--burst-concurrency",
        ],
        prefix,
    )
}

fn vuln_fragment_options(prefix: &str) -> Vec<String> {
    flag_filter(
        &[
            "--timeout-ms",
            "--concurrency",
            "--requests-per-tier",
            "--payload-min-bytes",
            "--payload-max-bytes",
            "--payload-step-bytes",
        ],
        prefix,
    )
}

fn reverse_option_suggestions(sub: Option<&str>, token_idx: usize, prefix: &str) -> Vec<String> {
    match sub {
        Some("analyze") => reverse_analyze_option_suggestions(token_idx, prefix),
        Some("plan") => reverse_plan_option_suggestions(token_idx, prefix),
        Some("run") => reverse_run_option_suggestions(token_idx, prefix),
        Some("job-logs") if token_idx >= 3 => flag_filter(&["--stream"], prefix),
        Some("job-search") if token_idx >= 4 => flag_filter(&["--max"], prefix),
        Some("job-clear") if token_idx >= 2 => flag_filter(&["--all"], prefix),
        Some("job-prune") if token_idx >= 2 => {
            flag_filter(&["--keep", "--older-than-days", "--include-running"], prefix)
        }
        Some("debug-script") if token_idx >= 4 => {
            flag_filter(&["--profile", "--pwndbg-init"], prefix)
        }
        _ => Vec::new(),
    }
}

fn reverse_alias_option_suggestions(head: &str, token_idx: usize, prefix: &str) -> Vec<String> {
    match head {
        "r.analyze" => reverse_analyze_option_suggestions(token_idx, prefix),
        "r.plan" => reverse_plan_option_suggestions(token_idx, prefix),
        "r.run" => reverse_run_option_suggestions(token_idx, prefix),
        "r.logs" if token_idx >= 2 => flag_filter(&["--stream"], prefix),
        "r.search" if token_idx >= 3 => flag_filter(&["--max"], prefix),
        "r.clear" if token_idx >= 1 => flag_filter(&["--all"], prefix),
        "r.prune" if token_idx >= 1 => {
            flag_filter(&["--keep", "--older-than-days", "--include-running"], prefix)
        }
        "r.debug" if token_idx >= 3 => flag_filter(&["--profile", "--pwndbg-init"], prefix),
        _ => Vec::new(),
    }
}

fn reverse_analyze_option_suggestions(token_idx: usize, prefix: &str) -> Vec<String> {
    if token_idx >= 2 {
        flag_filter(
            &[
                "--rules-file",
                "--dynamic",
                "--dynamic-timeout-ms",
                "--dynamic-syscalls",
                "--dynamic-blocklist",
            ],
            prefix,
        )
    } else {
        Vec::new()
    }
}

fn reverse_plan_option_suggestions(token_idx: usize, prefix: &str) -> Vec<String> {
    if token_idx >= 2 {
        flag_filter(&["--output-dir"], prefix)
    } else {
        Vec::new()
    }
}

fn reverse_run_option_suggestions(token_idx: usize, prefix: &str) -> Vec<String> {
    if token_idx >= 3 {
        flag_filter(
            &["--deep", "--rust-first", "--no-rust-first", "--timeout-secs"],
            prefix,
        )
    } else {
        Vec::new()
    }
}

fn flag_filter(flags: &[&str], prefix: &str) -> Vec<String> {
    flags.iter()
        .filter(|flag| flag.starts_with(prefix))
        .map(|flag| (*flag).to_string())
        .collect()
}

fn placeholder_suggestions(
    head: &str,
    sub: Option<&str>,
    token_idx: usize,
    prefix: &str,
) -> Vec<String> {
    let mut out: Vec<&str> = Vec::new();
    match head {
        "h.quick" => push_if_idx(&mut out, token_idx, 1, "<host>"),
        "h.tcp" => {
            push_if_idx(&mut out, token_idx, 1, "<host>");
            push_if_idx(&mut out, token_idx, 2, "<ports>");
        }
        "h.udp" => {
            push_if_idx(&mut out, token_idx, 1, "<host>");
            push_if_idx(&mut out, token_idx, 2, "<ports>");
        }
        "h.syn" => {
            push_if_idx(&mut out, token_idx, 1, "<host>");
            push_if_idx(&mut out, token_idx, 2, "<ports>");
        }
        "h.arp" => push_if_idx(&mut out, token_idx, 1, "<cidr>"),
        "w.dir" => {
            push_if_idx(&mut out, token_idx, 1, "<base_url>");
            push_if_idx(&mut out, token_idx, 2, "<paths_csv>");
        }
        "w.fuzz" => {
            push_if_idx(&mut out, token_idx, 1, "<url_with_FUZZ>");
            push_if_idx(&mut out, token_idx, 2, "<keywords_csv>");
        }
        "w.dns" => {
            push_if_idx(&mut out, token_idx, 1, "<domain>");
            push_if_idx(&mut out, token_idx, 2, "<words_csv>");
        }
        "w.crawl" => push_if_idx(&mut out, token_idx, 1, "<seed_url>"),
        "w.live" => push_if_idx(&mut out, token_idx, 1, "<url_csv>"),
        "v.lint" => push_if_idx(&mut out, token_idx, 1, "<templates_path>"),
        "v.scan" => {
            push_if_idx(&mut out, token_idx, 1, "<target_url>");
            push_if_idx(&mut out, token_idx, 2, "<templates_dir>");
        }
        "v.ca" => push_if_idx(&mut out, token_idx, 1, "<manifests_path>"),
        "v.sc" | "v.fa" => push_if_idx(&mut out, token_idx, 1, "<target_url>"),
        "r.analyze" | "r.plan" => push_if_idx(&mut out, token_idx, 1, "<input_file>"),
        "r.run" => {
            push_if_idx(&mut out, token_idx, 1, "<input_file>");
            push_if_idx(&mut out, token_idx, 2, "<engine>");
            push_if_idx(&mut out, token_idx, 3, "<mode>");
            push_if_idx(&mut out, token_idx, 4, "<function>");
        }
        "r.jobs" => {}
        "r.status" | "r.logs" | "r.artifacts" | "r.funcs" | "r.doctor" => {
            push_if_idx(&mut out, token_idx, 1, "<job_id>");
        }
        "r.show" => {
            push_if_idx(&mut out, token_idx, 1, "<job_id>");
            push_if_idx(&mut out, token_idx, 2, "<function>");
        }
        "r.search" => {
            push_if_idx(&mut out, token_idx, 1, "<job_id>");
            push_if_idx(&mut out, token_idx, 2, "<keyword>");
        }
        "r.clear" => push_if_idx(&mut out, token_idx, 1, "<job_id|--all>"),
        "r.prune" => {}
        "r.debug" => {
            push_if_idx(&mut out, token_idx, 1, "<input_file>");
            push_if_idx(&mut out, token_idx, 2, "<script_out>");
            push_if_idx(&mut out, token_idx, 3, "<profile>");
        }
        "zfocus" => push_if_idx(&mut out, token_idx, 1, "<control|work|inspect|reverse>"),
        "host" => match sub {
            Some("quick") => push_if_idx(&mut out, token_idx, 2, "<host>"),
            Some("tcp") => {
                push_if_idx(&mut out, token_idx, 2, "<host>");
                push_if_idx(&mut out, token_idx, 3, "<ports>");
            }
            Some("udp") => {
                push_if_idx(&mut out, token_idx, 2, "<host>");
                push_if_idx(&mut out, token_idx, 3, "<ports>");
            }
            Some("syn") => {
                push_if_idx(&mut out, token_idx, 2, "<host>");
                push_if_idx(&mut out, token_idx, 3, "<ports>");
            }
            Some("arp") => push_if_idx(&mut out, token_idx, 2, "<cidr>"),
            _ => {}
        },
        "web" => match sub {
            Some("dir") => {
                push_if_idx(&mut out, token_idx, 2, "<base_url>");
                push_if_idx(&mut out, token_idx, 3, "<paths_csv>");
            }
            Some("fuzz") => {
                push_if_idx(&mut out, token_idx, 2, "<url_with_FUZZ>");
                push_if_idx(&mut out, token_idx, 3, "<keywords_csv>");
            }
            Some("dns") => {
                push_if_idx(&mut out, token_idx, 2, "<domain>");
                push_if_idx(&mut out, token_idx, 3, "<words_csv>");
            }
            Some("crawl") => push_if_idx(&mut out, token_idx, 2, "<seed_url>"),
            Some("live") => push_if_idx(&mut out, token_idx, 2, "<url_csv>"),
            _ => {}
        },
        "vuln" => match sub {
            Some("lint") => push_if_idx(&mut out, token_idx, 2, "<templates_path>"),
            Some("scan") => {
                push_if_idx(&mut out, token_idx, 2, "<target_url>");
                push_if_idx(&mut out, token_idx, 3, "<templates_dir>");
            }
            Some("container-audit") => push_if_idx(&mut out, token_idx, 2, "<manifests_path>"),
            Some("stealth-check") | Some("fragment-audit") => {
                push_if_idx(&mut out, token_idx, 2, "<target_url>");
            }
            _ => {}
        },
        "reverse" => match sub {
            Some("analyze") | Some("plan") => push_if_idx(&mut out, token_idx, 2, "<input_file>"),
            Some("run") => {
                push_if_idx(&mut out, token_idx, 2, "<input_file>");
                push_if_idx(&mut out, token_idx, 3, "<engine>");
                push_if_idx(&mut out, token_idx, 4, "<mode>");
                push_if_idx(&mut out, token_idx, 5, "<function>");
            }
            Some("job-status")
            | Some("job-logs")
            | Some("job-artifacts")
            | Some("job-functions")
            | Some("job-doctor") => push_if_idx(&mut out, token_idx, 2, "<job_id>"),
            Some("job-show") => {
                push_if_idx(&mut out, token_idx, 2, "<job_id>");
                push_if_idx(&mut out, token_idx, 3, "<function>");
            }
            Some("job-search") => {
                push_if_idx(&mut out, token_idx, 2, "<job_id>");
                push_if_idx(&mut out, token_idx, 3, "<keyword>");
            }
            Some("job-clear") => push_if_idx(&mut out, token_idx, 2, "<job_id|--all>"),
            Some("debug-script") => {
                push_if_idx(&mut out, token_idx, 2, "<input_file>");
                push_if_idx(&mut out, token_idx, 3, "<script_out>");
                push_if_idx(&mut out, token_idx, 4, "<profile>");
            }
            _ => {}
        },
        _ => {}
    }

    out.into_iter()
        .filter(|s| s.starts_with(prefix))
        .map(|s| s.to_string())
        .collect()
}

fn push_if_idx<'a>(out: &mut Vec<&'a str>, token_idx: usize, expected: usize, value: &'a str) {
    if token_idx == expected {
        out.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::{build_completions, top_level_completions};

    #[test]
    fn top_level_completion_prefers_parent_commands() {
        let got = top_level_completions("h");
        assert_eq!(got, vec!["host".to_string()]);
    }

    #[test]
    fn dotted_alias_completion_still_available() {
        let got = top_level_completions("h.");
        assert!(got.iter().any(|item| item == "h.quick"));
        assert!(got.iter().any(|item| item == "h.tcp"));
    }

    #[test]
    fn parent_command_completes_branches_before_placeholders() {
        let buf = "host q";
        let tokens = vec![(0, 4), (5, 6)];
        let got = build_completions(buf, &tokens, 1, "q");
        assert_eq!(got, vec!["quick".to_string()]);
    }

    #[test]
    fn web_parent_completion_lists_new_branches() {
        let buf = "web c";
        let tokens = vec![(0, 3), (4, 5)];
        let got = build_completions(buf, &tokens, 1, "c");
        assert_eq!(got, vec!["crawl".to_string()]);
    }

    #[test]
    fn reverse_alias_completion_suggests_job_flags() {
        let buf = "r.search job-1 main --";
        let tokens = vec![(0, 8), (9, 14), (15, 19), (20, 22)];
        let got = build_completions(buf, &tokens, 3, "--");
        assert!(got.iter().any(|item| item == "--max"));
    }
}
