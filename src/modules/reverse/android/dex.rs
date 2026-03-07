use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn extract_class_hints(strings: &[String]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for s in strings {
        if s.starts_with('L') && s.ends_with(';') && s.contains('/') && s.len() < 256 {
            out.insert(s.to_string());
        } else if s.ends_with(".class") && s.len() < 256 {
            out.insert(s.to_string());
        }
    }
    out.into_iter().collect()
}

pub(crate) fn extract_sensitive_api_hits(strings: &[String]) -> Vec<(String, usize)> {
    let apis = [
        "DexClassLoader",
        "PathClassLoader",
        "Runtime.getRuntime().exec",
        "ProcessBuilder",
        "WebView",
        "setJavaScriptEnabled",
        "addJavascriptInterface",
        "setMixedContentMode",
        "loadUrl",
        "SmsManager",
        "sendTextMessage",
        "TelephonyManager",
        "getDeviceId",
        "getSubscriberId",
        "getImei",
        "AccessibilityService",
        "REQUEST_INSTALL_PACKAGES",
        "BIND_ACCESSIBILITY_SERVICE",
    ];
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for s in strings {
        for api in apis {
            if s.contains(api) {
                *map.entry(api.to_string()).or_insert(0) += 1;
            }
        }
    }
    map.into_iter().collect()
}
