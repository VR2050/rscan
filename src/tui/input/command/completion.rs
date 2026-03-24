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
        return completion_heads()
            .iter()
            .filter(|cmd| cmd.starts_with(prefix))
            .map(|s| (*s).to_string())
            .collect();
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
    }

    placeholder_suggestions(head_str, sub, token_idx, prefix)
}

fn build_parent_command_completions(
    head: &str,
    sub: Option<&str>,
    token_idx: usize,
    prefix: &str,
) -> Vec<String> {
    if token_idx == 1 {
        let subs = match head {
            "host" => vec!["quick", "tcp"],
            "web" => vec!["dir", "fuzz", "dns"],
            "vuln" => vec!["scan"],
            "reverse" => vec!["analyze", "plan", "run"],
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
        "v.scan" => {
            push_if_idx(&mut out, token_idx, 1, "<target_url>");
            push_if_idx(&mut out, token_idx, 2, "<templates_dir>");
        }
        "r.analyze" | "r.plan" => push_if_idx(&mut out, token_idx, 1, "<input_file>"),
        "r.run" => {
            push_if_idx(&mut out, token_idx, 1, "<input_file>");
            push_if_idx(&mut out, token_idx, 2, "<engine>");
            push_if_idx(&mut out, token_idx, 3, "<mode>");
            push_if_idx(&mut out, token_idx, 4, "<function>");
        }
        "zfocus" => push_if_idx(&mut out, token_idx, 1, "<control|work|inspect|reverse>"),
        "host" => match sub {
            Some("quick") => push_if_idx(&mut out, token_idx, 2, "<host>"),
            Some("tcp") => {
                push_if_idx(&mut out, token_idx, 2, "<host>");
                push_if_idx(&mut out, token_idx, 3, "<ports>");
            }
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
            _ => {}
        },
        "vuln" if sub == Some("scan") => {
            push_if_idx(&mut out, token_idx, 2, "<target_url>");
            push_if_idx(&mut out, token_idx, 3, "<templates_dir>");
        }
        "reverse" => match sub {
            Some("analyze") | Some("plan") => push_if_idx(&mut out, token_idx, 2, "<input_file>"),
            Some("run") => {
                push_if_idx(&mut out, token_idx, 2, "<input_file>");
                push_if_idx(&mut out, token_idx, 3, "<engine>");
                push_if_idx(&mut out, token_idx, 4, "<mode>");
                push_if_idx(&mut out, token_idx, 5, "<function>");
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
