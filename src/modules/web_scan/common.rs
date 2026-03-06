use super::ModuleScanConfig;
use super::render_request_body;
use crate::cores::web::{FetchRequest, Fetcher};

#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    pub status: u16,
    pub content_len: u64,
    pub title: Option<String>,
    pub simhash: u64,
}

#[derive(Debug, Clone)]
pub struct WildcardSignature {
    pub status: u16,
    pub content_len: u64,
    pub title: Option<String>,
    pub simhash: u64,
}

pub async fn detect_dir_wildcard_signatures(
    fetcher: &Fetcher,
    base: &str,
    cfg: &ModuleScanConfig,
) -> Vec<WildcardSignature> {
    if !cfg.wildcard_filter || cfg.wildcard_sample_count == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..cfg.wildcard_sample_count {
        let token = probe_token(i);
        let probe_path = format!("/.rscan_probe_{}", token);
        let url = format!("{}{}", base.trim_end_matches('/'), probe_path);
        let req = FetchRequest {
            url,
            method: cfg.request_method.clone(),
            headers: cfg.request_headers.clone(),
            body: render_request_body(&cfg.request_body_template, None),
            timeout_ms: cfg.timeout_ms,
            max_retries: cfg.max_retries,
            follow_redirects: Some(cfg.follow_redirects),
        };
        if let Ok(resp) = fetcher.fetch_with_request(req).await {
            let fp = build_fingerprint(resp.status, &resp.body);
            out.push(WildcardSignature {
                status: resp.status,
                content_len: resp.body.len() as u64,
                title: fp.title,
                simhash: fp.simhash,
            });
        }
    }
    out
}

pub async fn detect_fuzz_wildcard_signatures(
    fetcher: &Fetcher,
    template: &str,
    cfg: &ModuleScanConfig,
) -> Vec<WildcardSignature> {
    if !cfg.wildcard_filter || cfg.wildcard_sample_count == 0 || !template.contains("FUZZ") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..cfg.wildcard_sample_count {
        let token = format!("rscanprobe{}", probe_token(i));
        let url = template.replace("FUZZ", &token);
        let req = FetchRequest {
            url,
            method: cfg.request_method.clone(),
            headers: cfg.request_headers.clone(),
            body: render_request_body(&cfg.request_body_template, Some(&token)),
            timeout_ms: cfg.timeout_ms,
            max_retries: cfg.max_retries,
            follow_redirects: Some(cfg.follow_redirects),
        };
        if let Ok(resp) = fetcher.fetch_with_request(req).await {
            let fp = build_fingerprint(resp.status, &resp.body);
            out.push(WildcardSignature {
                status: resp.status,
                content_len: resp.body.len() as u64,
                title: fp.title,
                simhash: fp.simhash,
            });
        }
    }
    out
}

pub fn is_wildcard_match(
    status: u16,
    content_len: u64,
    body: &[u8],
    signatures: &[WildcardSignature],
    tolerance: u64,
    simhash_threshold: u32,
) -> bool {
    let candidate = build_fingerprint(status, body);
    signatures.iter().any(|sig| {
        if sig.status != status {
            return false;
        }
        let len_delta = content_len.abs_diff(sig.content_len);
        if len_delta > tolerance {
            return false;
        }
        if let (Some(a), Some(b)) = (sig.title.as_ref(), candidate.title.as_ref())
            && !a.is_empty()
            && !b.is_empty()
            && a == b
        {
            return true;
        }
        hamming_u64(sig.simhash, candidate.simhash) <= simhash_threshold
    })
}

pub fn build_joined_url(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{}{}", base.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", base.trim_end_matches('/'), path)
    }
}

pub fn build_fingerprint(status: u16, body: &[u8]) -> ResponseFingerprint {
    let text = String::from_utf8_lossy(body);
    let title = extract_title(&text).map(|s| normalize_text(&s));
    let simhash = simhash64(&normalize_text(&text));
    ResponseFingerprint {
        status,
        content_len: body.len() as u64,
        title,
        simhash,
    }
}

pub fn is_near_duplicate(
    fp: &ResponseFingerprint,
    seen: &[ResponseFingerprint],
    max_distance: u32,
) -> bool {
    // For auth/forbidden classes, different paths are still useful findings.
    if fp.status == 401 || fp.status == 403 {
        return false;
    }
    // Very short bodies are often high-entropy endpoints (tokens/ids) that should not be
    // deduped aggressively, otherwise recall drops sharply.
    if fp.content_len < 64 {
        return false;
    }
    seen.iter().any(|s| {
        if s.status != fp.status {
            return false;
        }
        if s.content_len < 64 {
            return false;
        }
        let len_delta = s.content_len.abs_diff(fp.content_len);
        let allowed_len_delta = 64u64.max(s.content_len.min(fp.content_len) / 5);
        if len_delta > allowed_len_delta {
            return false;
        }
        let distance = hamming_u64(s.simhash, fp.simhash);
        if let (Some(a), Some(b)) = (&s.title, &fp.title) {
            if !a.is_empty() && !b.is_empty() && a == b {
                return distance <= max_distance.saturating_add(2).min(12);
            }
        }
        distance <= max_distance
    })
}

fn probe_token(i: usize) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{}_{:x}", i, nanos)
}

fn extract_title(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start_tag = "<title>";
    let end_tag = "</title>";
    let start = lower.find(start_tag)?;
    let rest = &text[start + start_tag.len()..];
    let rest_lower = &lower[start + start_tag.len()..];
    let end = rest_lower.find(end_tag)?;
    Some(rest[..end].to_string())
}

fn normalize_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>()
}

fn simhash64(text: &str) -> u64 {
    let mut weights = [0i32; 64];
    for tok in text.split_whitespace() {
        if tok.len() < 2 {
            continue;
        }
        let h = hash64(tok.as_bytes());
        for (i, w) in weights.iter_mut().enumerate() {
            if (h >> i) & 1 == 1 {
                *w += 1;
            } else {
                *w -= 1;
            }
        }
    }
    let mut out = 0u64;
    for (i, w) in weights.iter().enumerate() {
        if *w > 0 {
            out |= 1u64 << i;
        }
    }
    out
}

fn hash64(input: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in input {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn hamming_u64(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[cfg(test)]
mod tests {
    use super::{WildcardSignature, build_fingerprint, is_near_duplicate, is_wildcard_match};

    #[test]
    fn fingerprint_near_duplicate_detects_similar_html() {
        let a = b"<html><title>Admin</title><body>hello world one two three</body></html>";
        let b = b"<html><title>Admin</title><body>hello world one two four</body></html>";
        let fp_a = build_fingerprint(200, a);
        let fp_b = build_fingerprint(200, b);
        assert!(is_near_duplicate(&fp_b, &[fp_a], 8));
    }

    #[test]
    fn wildcard_match_requires_content_similarity_for_same_length() {
        let wildcard_body = b"<html><title>Not Found</title><body>default page qqq qqq qqq</body></html>";
        let wildcard_fp = build_fingerprint(200, wildcard_body);
        let signatures = vec![WildcardSignature {
            status: 200,
            content_len: wildcard_body.len() as u64,
            title: wildcard_fp.title,
            simhash: wildcard_fp.simhash,
        }];

        let real_hit = b"<html><title>Dashboard</title><body>app index portal users auth</body></html>";
        assert!(!is_wildcard_match(
            200,
            wildcard_body.len() as u64,
            real_hit,
            &signatures,
            16,
            6
        ));
    }

    #[test]
    fn fingerprint_filter_skips_short_bodies() {
        let fp_a = build_fingerprint(200, b"OK:hit001");
        let fp_b = build_fingerprint(200, b"OK:hit002");
        assert!(!is_near_duplicate(&fp_b, &[fp_a], 6));
    }

    #[test]
    fn fingerprint_filter_keeps_distinct_403_paths() {
        let fp_a = build_fingerprint(403, b"<html><body>Forbidden</body></html>");
        let fp_b = build_fingerprint(403, b"<html><body>Forbidden</body></html>");
        assert!(!is_near_duplicate(&fp_b, &[fp_a], 6));
    }
}
