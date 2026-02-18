use super::ModuleScanConfig;
use crate::cores::web::{FetchRequest, Fetcher};

#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    pub status: u16,
    pub title: Option<String>,
    pub simhash: u64,
}

pub async fn detect_dir_wildcard_signatures(
    fetcher: &Fetcher,
    base: &str,
    cfg: &ModuleScanConfig,
) -> Vec<(u16, u64)> {
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
            headers: None,
            body: None,
            timeout_ms: cfg.timeout_ms,
            max_retries: cfg.max_retries,
        };
        if let Ok(resp) = fetcher.fetch_with_request(req).await {
            out.push((resp.status, resp.body.len() as u64));
        }
    }
    out
}

pub async fn detect_fuzz_wildcard_signatures(
    fetcher: &Fetcher,
    template: &str,
    cfg: &ModuleScanConfig,
) -> Vec<(u16, u64)> {
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
            headers: None,
            body: None,
            timeout_ms: cfg.timeout_ms,
            max_retries: cfg.max_retries,
        };
        if let Ok(resp) = fetcher.fetch_with_request(req).await {
            out.push((resp.status, resp.body.len() as u64));
        }
    }
    out
}

pub fn is_wildcard_match(
    status: u16,
    content_len: u64,
    signatures: &[(u16, u64)],
    tolerance: u64,
) -> bool {
    signatures.iter().any(|(s, l)| {
        *s == status
            && if content_len >= *l {
                content_len - *l <= tolerance
            } else {
                *l - content_len <= tolerance
            }
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
        title,
        simhash,
    }
}

pub fn is_near_duplicate(
    fp: &ResponseFingerprint,
    seen: &[ResponseFingerprint],
    max_distance: u32,
) -> bool {
    seen.iter().any(|s| {
        if s.status != fp.status {
            return false;
        }
        if let (Some(a), Some(b)) = (&s.title, &fp.title)
            && !a.is_empty()
            && !b.is_empty()
            && a == b
        {
            return true;
        }
        hamming_u64(s.simhash, fp.simhash) <= max_distance
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
    use super::{build_fingerprint, is_near_duplicate};

    #[test]
    fn fingerprint_near_duplicate_detects_similar_html() {
        let a = b"<html><title>Admin</title><body>hello world one two three</body></html>";
        let b = b"<html><title>Admin</title><body>hello world one two four</body></html>";
        let fp_a = build_fingerprint(200, a);
        let fp_b = build_fingerprint(200, b);
        assert!(is_near_duplicate(&fp_b, &[fp_a], 8));
    }
}
