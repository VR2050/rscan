use std::collections::BTreeSet;

use regex::Regex;

pub(crate) fn extract_endpoints(strings: &[String]) -> (Vec<String>, Vec<String>) {
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let url_re = Regex::new(r#"https?://[A-Za-z0-9\.\-_:/%\?\#=&\+~\[\]@!$'()*,;]+"#).ok();
    let host_re = Regex::new(r"(?i)^[a-z0-9.-]+\.[a-z]{2,24}$").ok();

    for s in strings {
        if let Some(re) = &url_re {
            for m in re.find_iter(s) {
                let u = m.as_str().trim_end_matches(['"', '\'', ')', ']', '}']);
                urls.insert(u.to_string());
                if let Ok(parsed) = url::Url::parse(u)
                    && let Some(h) = parsed.host_str()
                {
                    let host = h.to_ascii_lowercase();
                    if is_probable_domain(&host, &host_re, false) {
                        domains.insert(host);
                    }
                }
            }
        }
        for token in tokenize_domain_candidates(s) {
            if token.chars().any(|c| c.is_ascii_uppercase()) {
                continue;
            }
            if token.starts_with('-') || token.ends_with('-') {
                continue;
            }
            let host = token.to_ascii_lowercase();
            if is_probable_domain(&host, &host_re, true) {
                domains.insert(host);
            }
        }
    }
    (
        urls.into_iter().take(3000).collect(),
        domains.into_iter().take(3000).collect(),
    )
}

fn tokenize_domain_candidates(s: &str) -> Vec<&str> {
    s.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';' | '|'
            )
    })
    .filter(|t| !t.is_empty())
    .map(|t| {
        t.trim_matches(|c: char| {
            !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != ':' && c != '/'
        })
    })
    .filter(|t| !t.is_empty())
    .collect()
}

fn is_probable_domain(token: &str, host_re: &Option<Regex>, strict: bool) -> bool {
    if token.len() > 253 || token.contains("..") || token.starts_with('.') || token.ends_with('.') {
        return false;
    }
    let starts_ok = token
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    let ends_ok = token
        .as_bytes()
        .last()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    if !starts_ok || !ends_ok {
        return false;
    }
    if token.contains('/') || token.contains(':') || token.contains('_') {
        return false;
    }
    let Some(re) = host_re else { return false };
    if !re.is_match(token) {
        return false;
    }
    let labels = token.split('.').collect::<Vec<_>>();
    if labels.len() < 2 {
        return false;
    }
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return false;
    }
    if labels
        .iter()
        .any(|l| l.starts_with('-') || l.ends_with('-'))
    {
        return false;
    }
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    if !(2..=8).contains(&tld.len()) {
        return false;
    }
    if !sld.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if labels.len() >= 4 {
        let first = labels[0];
        let resource_like_prefix = [
            "style", "theme", "widget", "layout", "drawable", "string", "color", "anim",
        ];
        if resource_like_prefix.contains(&first) {
            return false;
        }
    }
    let block_suffixes = [
        "xml", "png", "jpg", "jpeg", "webp", "gif", "svg", "json", "js", "css", "dex", "so",
        "arsc", "txt", "html", "htm",
    ];
    if block_suffixes.contains(&tld) {
        return false;
    }
    if strict {
        if token.len() < 7 {
            return false;
        }
        if sld.len() < 3 {
            return false;
        }
        if labels.len() == 2 && labels[0].len() < 3 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::extract_endpoints;

    #[test]
    fn extract_endpoints_filters_noise_domains() {
        let strings = vec![
            "https://api.example.com/v1/login?from=apk".to_string(),
            "style.TextAppearance.Material3.BodyLarge".to_string(),
            "cdn.example.org".to_string(),
            "assets/icon.png".to_string(),
            "bad_domain_with_underscore.example.com".to_string(),
            "http://sub.test-site.net/path".to_string(),
        ];

        let (urls, domains) = extract_endpoints(&strings);
        assert!(urls.iter().any(|u| u.contains("api.example.com")));
        assert!(urls.iter().any(|u| u.contains("sub.test-site.net")));
        assert!(domains.contains(&"api.example.com".to_string()));
        assert!(domains.contains(&"cdn.example.org".to_string()));
        assert!(domains.contains(&"sub.test-site.net".to_string()));
        assert!(!domains.iter().any(|d| d.contains("material3")));
        assert!(!domains.iter().any(|d| d.ends_with(".png")));
    }
}
