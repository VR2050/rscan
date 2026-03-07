use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use regex::Regex;
use zip::ZipArchive;

use crate::errors::RustpenError;

use super::dex::{extract_class_hints, extract_sensitive_api_hits};
use super::endpoints::extract_endpoints;
use super::model::{
    AndroidProfileReport, AndroidReverseReport, ApkIndexReport, DexIndexReport, DexSensitiveHit,
    NativeIndexReport,
};
use super::native::analyze_native_so;
use super::scoring::{build_risk_score, is_dangerous_permission};
use super::strings::{extract_ascii_strings, sha256_hex, shannon_entropy};

pub struct AndroidAnalyzer;

impl AndroidAnalyzer {
    pub fn analyze_apk(path: &Path) -> Result<AndroidReverseReport, RustpenError> {
        let bytes = std::fs::read(path)?;
        let md = std::fs::metadata(path)?;
        if bytes.len() < 4 || &bytes[0..4] != b"PK\x03\x04" {
            return Err(RustpenError::ParseError(format!(
                "{} is not a valid APK/ZIP header",
                path.display()
            )));
        }

        let mut file = File::open(path)?;
        let mut zip_data = Vec::new();
        file.read_to_end(&mut zip_data)?;
        let cursor = std::io::Cursor::new(zip_data);
        let mut zip = ZipArchive::new(cursor)
            .map_err(|e| RustpenError::ParseError(format!("invalid APK zip: {}", e)))?;

        let mut entries = Vec::new();
        let mut classes_dex_files = Vec::new();
        let mut native_libs = Vec::new();
        let mut manifest_raw = Vec::new();
        let mut manifest_found = false;
        let mut has_resources_arsc = false;

        let mut dex_string_pool_total = 0usize;
        let mut class_hints = BTreeSet::new();
        let mut sensitive_hits: BTreeMap<String, usize> = BTreeMap::new();
        let mut native_reports = Vec::new();

        for i in 0..zip.len() {
            let mut entry = zip
                .by_index(i)
                .map_err(|e| RustpenError::ParseError(format!("zip entry read failed: {}", e)))?;
            let name = entry.name().to_string();
            entries.push(name.clone());

            if name == "AndroidManifest.xml" {
                manifest_found = true;
                entry.read_to_end(&mut manifest_raw).map_err(|e| {
                    RustpenError::ParseError(format!("read manifest failed: {}", e))
                })?;
            }
            if name == "resources.arsc" {
                has_resources_arsc = true;
            }

            if name.starts_with("classes") && name.ends_with(".dex") {
                classes_dex_files.push(name.clone());
                let mut dex_bytes = Vec::new();
                entry.read_to_end(&mut dex_bytes).map_err(|e| {
                    RustpenError::ParseError(format!("read dex '{}' failed: {}", name, e))
                })?;
                let strings = extract_ascii_strings(&dex_bytes, 4, 200_000);
                dex_string_pool_total += strings.len();
                for c in extract_class_hints(&strings) {
                    class_hints.insert(c);
                }
                for (api, count) in extract_sensitive_api_hits(&strings) {
                    *sensitive_hits.entry(api).or_insert(0) += count;
                }
                continue;
            }

            if name.starts_with("lib/") && name.ends_with(".so") {
                native_libs.push(name.clone());
                let mut so_bytes = Vec::new();
                entry.read_to_end(&mut so_bytes).map_err(|e| {
                    RustpenError::ParseError(format!("read so '{}' failed: {}", name, e))
                })?;
                native_reports.push(analyze_native_so(&name, &so_bytes));
            }
        }

        let all_strings = extract_ascii_strings(&bytes, 4, 300_000);
        let profile = build_profile(&all_strings, &manifest_raw);
        let score = build_risk_score(
            &profile,
            sensitive_hits.values().sum::<usize>(),
            native_reports
                .iter()
                .map(|x| x.suspicious_import_hits.len())
                .sum::<usize>(),
        );

        let dex = DexIndexReport {
            dex_files: classes_dex_files.len(),
            dex_string_pool_total,
            class_hints: class_hints.into_iter().take(5000).collect(),
            sensitive_api_hits: sensitive_hits
                .into_iter()
                .map(|(api, count)| DexSensitiveHit { api, count })
                .collect(),
        };

        Ok(AndroidReverseReport {
            path: path.to_path_buf(),
            file_size: md.len(),
            sha256: sha256_hex(&bytes),
            entropy: shannon_entropy(&bytes),
            apk: ApkIndexReport {
                entries_total: entries.len(),
                classes_dex_files,
                native_libs,
                has_manifest: manifest_found,
                has_resources_arsc,
            },
            profile,
            dex,
            native: NativeIndexReport {
                libs: native_reports,
            },
            score,
        })
    }
}

fn build_profile(strings: &[String], manifest_raw: &[u8]) -> AndroidProfileReport {
    let mut package_name = None;
    let mut uses_cleartext_traffic = false;
    let mut exported_components = BTreeSet::new();
    let mut permissions = BTreeSet::new();
    let mut ioc_keywords = BTreeSet::new();

    let manifest_text = String::from_utf8(manifest_raw.to_vec()).ok();
    if let Some(xml) = &manifest_text {
        if let Ok(pkg_re) = Regex::new(r#"package="([^"]+)""#)
            && let Some(c) = pkg_re.captures(xml)
        {
            package_name = c.get(1).map(|m| m.as_str().to_string());
        }
        uses_cleartext_traffic = xml.contains("usesCleartextTraffic=\"true\"");
        if let Ok(exported_re) = Regex::new(
            r#"<(activity|service|receiver|provider)[^>]*android:name="([^"]+)"[^>]*android:exported="true""#,
        ) {
            for c in exported_re.captures_iter(xml) {
                if let (Some(kind), Some(name)) = (c.get(1), c.get(2)) {
                    exported_components.insert(format!("{}:{}", kind.as_str(), name.as_str()));
                }
            }
        }
    } else {
        let manifest_strings = extract_ascii_strings(manifest_raw, 4, 50_000);
        if manifest_strings
            .iter()
            .any(|s| s.contains("usesCleartextTraffic"))
        {
            uses_cleartext_traffic = true;
        }
        for s in manifest_strings {
            if s.contains("exported") || s.contains("activity") || s.contains("service") {
                ioc_keywords.insert(format!("manifest_hint:{}", s));
            }
        }
    }

    let perm_re = Regex::new(r"android\.permission\.[A-Z0-9_\.]+").ok();
    for s in strings {
        if let Some(re) = &perm_re {
            for m in re.find_iter(s) {
                permissions.insert(m.as_str().to_string());
            }
        }
    }

    let (endpoint_urls, endpoint_domains) = extract_endpoints(strings);
    for kw in [
        "frida",
        "xposed",
        "magisk",
        "root",
        "su",
        "accessibilityservice",
        "dexclassloader",
        "runtime.getruntime().exec",
        "addjavascriptinterface",
    ] {
        if strings.iter().any(|s| s.to_ascii_lowercase().contains(kw)) {
            ioc_keywords.insert(kw.to_string());
        }
    }

    let dangerous_permissions = permissions
        .iter()
        .filter(|p| is_dangerous_permission(p))
        .cloned()
        .collect::<Vec<_>>();

    AndroidProfileReport {
        package_name,
        uses_cleartext_traffic,
        permissions: permissions.into_iter().collect(),
        dangerous_permissions,
        exported_components: exported_components.into_iter().collect(),
        endpoint_urls,
        endpoint_domains,
        ioc_keywords: ioc_keywords.into_iter().collect(),
    }
}
