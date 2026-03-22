use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

use apk_info::Apk;
use regex::Regex;
use zip::ZipArchive;

use crate::errors::RustpenError;

use super::dex::{extract_class_hints, extract_sensitive_api_hits};
use super::endpoints::extract_endpoints;
use super::model::{
    AndroidComponentStats, AndroidForensicsReport, AndroidProfileReport, AndroidReverseReport,
    ApkIndexReport, DexIndexReport, DexSensitiveHit, NativeIndexReport,
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
        let apk_info = extract_apk_info(path);
        let profile = build_profile(&all_strings, &manifest_raw, apk_info.as_ref());
        let forensics = build_forensics_report(apk_info.as_ref(), &profile);
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
            forensics,
            score,
        })
    }
}

fn build_profile(
    strings: &[String],
    manifest_raw: &[u8],
    apk_info: Option<&ApkInfoExtract>,
) -> AndroidProfileReport {
    let mut package_name = apk_info.and_then(|x| x.package_name.clone());
    let mut uses_cleartext_traffic = apk_info
        .and_then(|x| x.uses_cleartext_traffic)
        .unwrap_or(false);
    let mut exported_components = apk_info
        .map(|x| {
            x.exported_components
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut permissions = apk_info
        .map(|x| x.permissions.iter().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    let mut ioc_keywords = BTreeSet::new();

    if apk_info.is_none() {
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

#[derive(Debug, Clone)]
struct ApkInfoExtract {
    package_name: Option<String>,
    uses_cleartext_traffic: Option<bool>,
    permissions: Vec<String>,
    exported_components: Vec<String>,
    forensics: AndroidForensicsReport,
}

fn extract_apk_info(path: &Path) -> Option<ApkInfoExtract> {
    let apk = Apk::new(path).ok()?;

    let mut permissions = BTreeSet::new();
    permissions.extend(apk.get_permissions().map(str::to_string));
    permissions.extend(apk.get_permissions_sdk23().map(str::to_string));

    let activities = apk.get_activities().collect::<Vec<_>>();
    let activity_aliases = apk.get_activity_aliases().collect::<Vec<_>>();
    let services = apk.get_services().collect::<Vec<_>>();
    let receivers = apk.get_receivers().collect::<Vec<_>>();
    let providers = apk.get_providers().collect::<Vec<_>>();

    let exported_activities = activities
        .iter()
        .filter(|x| is_true_opt(x.exported))
        .count();
    let exported_activity_aliases = activity_aliases
        .iter()
        .filter(|x| is_true_opt(x.exported))
        .count();
    let exported_services = services.iter().filter(|x| is_true_opt(x.exported)).count();
    let exported_receivers = receivers.iter().filter(|x| is_true_opt(x.exported)).count();
    let exported_providers = providers.iter().filter(|x| is_true_opt(x.exported)).count();

    let mut exported_components = BTreeSet::new();
    for item in &activities {
        if is_true_opt(item.exported)
            && let Some(name) = item.name
        {
            exported_components.insert(format!("activity:{name}"));
        }
    }
    for item in &activity_aliases {
        if is_true_opt(item.exported)
            && let Some(name) = item.name
        {
            exported_components.insert(format!("activity-alias:{name}"));
        }
    }
    for item in &services {
        if is_true_opt(item.exported)
            && let Some(name) = item.name
        {
            exported_components.insert(format!("service:{name}"));
        }
    }
    for item in &receivers {
        if is_true_opt(item.exported)
            && let Some(name) = item.name
        {
            exported_components.insert(format!("receiver:{name}"));
        }
    }
    for item in &providers {
        if is_true_opt(item.exported)
            && let Some(name) = item.name
        {
            exported_components.insert(format!("provider:{name}"));
        }
    }

    let signatures = apk.get_signatures().map(|sigs| sigs.len()).unwrap_or(0);
    let uses_cleartext_traffic = parse_opt_bool(
        apk.get_attribute_value("application", "usesCleartextTraffic")
            .as_deref(),
    );
    let app_debuggable = parse_opt_bool(apk.get_application_debuggable().as_deref().map(str::trim));
    let app_allow_backup =
        parse_opt_bool(apk.get_application_allow_backup().as_deref().map(str::trim));

    let forensics = AndroidForensicsReport {
        manifest_parser: "apk-info".to_string(),
        main_activity: apk.get_main_activity().map(str::to_string),
        version_name: apk.get_version_name(),
        version_code: apk.get_version_code(),
        min_sdk: apk.get_min_sdk_version(),
        target_sdk: apk.get_target_sdk_version(),
        compile_sdk: apk.get_compile_sdk_version(),
        application_debuggable: app_debuggable,
        application_allow_backup: app_allow_backup,
        signature_count: signatures,
        native_abis: apk.get_native_codes(),
        component_stats: AndroidComponentStats {
            activities: activities.len(),
            activity_aliases: activity_aliases.len(),
            services: services.len(),
            receivers: receivers.len(),
            providers: providers.len(),
            exported_activities,
            exported_activity_aliases,
            exported_services,
            exported_receivers,
            exported_providers,
        },
    };

    Some(ApkInfoExtract {
        package_name: apk.get_package_name(),
        uses_cleartext_traffic,
        permissions: permissions.into_iter().collect(),
        exported_components: exported_components.into_iter().collect(),
        forensics,
    })
}

fn build_forensics_report(
    apk_info: Option<&ApkInfoExtract>,
    profile: &AndroidProfileReport,
) -> AndroidForensicsReport {
    if let Some(info) = apk_info {
        return info.forensics.clone();
    }
    AndroidForensicsReport {
        manifest_parser: "fallback-regex".to_string(),
        main_activity: None,
        version_name: None,
        version_code: None,
        min_sdk: None,
        target_sdk: 0,
        compile_sdk: None,
        application_debuggable: None,
        application_allow_backup: None,
        signature_count: 0,
        native_abis: Vec::new(),
        component_stats: AndroidComponentStats {
            activities: 0,
            activity_aliases: 0,
            services: 0,
            receivers: 0,
            providers: 0,
            exported_activities: profile
                .exported_components
                .iter()
                .filter(|x| x.starts_with("activity:"))
                .count(),
            exported_activity_aliases: profile
                .exported_components
                .iter()
                .filter(|x| x.starts_with("activity-alias:"))
                .count(),
            exported_services: profile
                .exported_components
                .iter()
                .filter(|x| x.starts_with("service:"))
                .count(),
            exported_receivers: profile
                .exported_components
                .iter()
                .filter(|x| x.starts_with("receiver:"))
                .count(),
            exported_providers: profile
                .exported_components
                .iter()
                .filter(|x| x.starts_with("provider:"))
                .count(),
        },
    }
}

fn parse_opt_bool(v: Option<&str>) -> Option<bool> {
    v.and_then(|x| {
        let t = x.trim();
        if t.eq_ignore_ascii_case("true") || t == "1" {
            Some(true)
        } else if t.eq_ignore_ascii_case("false") || t == "0" {
            Some(false)
        } else {
            None
        }
    })
}

fn is_true_opt(v: Option<&str>) -> bool {
    parse_opt_bool(v).unwrap_or(false)
}
