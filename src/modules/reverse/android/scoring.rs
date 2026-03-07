use std::collections::BTreeMap;

use super::model::{AndroidProfileReport, AndroidRiskScore};

pub(crate) fn build_risk_score(
    profile: &AndroidProfileReport,
    dex_sensitive_hits_total: usize,
    native_suspicious_hits_total: usize,
) -> AndroidRiskScore {
    let mut breakdown = BTreeMap::new();
    let mut notes = Vec::new();

    let perm_score = (profile.dangerous_permissions.len().min(10) as u8) * 4;
    breakdown.insert("dangerous_permissions".to_string(), perm_score);
    if perm_score > 0 {
        notes.push(format!(
            "dangerous permissions: {}",
            profile.dangerous_permissions.len()
        ));
    }

    let exported_score = (profile.exported_components.len().min(8) as u8) * 3;
    breakdown.insert("exported_components".to_string(), exported_score);
    if exported_score > 0 {
        notes.push(format!(
            "exported components: {}",
            profile.exported_components.len()
        ));
    }

    let endpoint_score = ((profile.endpoint_domains.len().min(20) as u8) / 2) * 2;
    breakdown.insert("network_exposure".to_string(), endpoint_score);

    let cleartext_score = if profile.uses_cleartext_traffic {
        12
    } else {
        0
    };
    breakdown.insert("cleartext_traffic".to_string(), cleartext_score);
    if cleartext_score > 0 {
        notes.push("cleartext transport hint detected".to_string());
    }

    let dex_score = (dex_sensitive_hits_total.min(30) as u8) / 2;
    breakdown.insert("dex_sensitive_api".to_string(), dex_score);

    let native_score = (native_suspicious_hits_total.min(20) as u8) * 2;
    breakdown.insert("native_suspicious_import".to_string(), native_score);

    let ioc_score = (profile.ioc_keywords.len().min(20) as u8) / 2;
    breakdown.insert("ioc_keywords".to_string(), ioc_score);

    let total_u16: u16 = breakdown.values().map(|&v| v as u16).sum();
    let total = total_u16.min(100) as u8;

    AndroidRiskScore {
        total,
        breakdown,
        notes,
    }
}

pub(crate) fn is_dangerous_permission(p: &str) -> bool {
    matches!(
        p,
        "android.permission.READ_SMS"
            | "android.permission.RECEIVE_SMS"
            | "android.permission.SEND_SMS"
            | "android.permission.READ_CONTACTS"
            | "android.permission.READ_CALL_LOG"
            | "android.permission.RECORD_AUDIO"
            | "android.permission.CAMERA"
            | "android.permission.ACCESS_FINE_LOCATION"
            | "android.permission.ACCESS_COARSE_LOCATION"
            | "android.permission.READ_PHONE_STATE"
            | "android.permission.REQUEST_INSTALL_PACKAGES"
            | "android.permission.SYSTEM_ALERT_WINDOW"
            | "android.permission.BIND_ACCESSIBILITY_SERVICE"
            | "android.permission.QUERY_ALL_PACKAGES"
    )
}

#[cfg(test)]
mod tests {
    use super::build_risk_score;
    use crate::modules::reverse::android::model::AndroidProfileReport;

    #[test]
    fn risk_score_is_capped_to_100() {
        let profile = AndroidProfileReport {
            package_name: Some("com.example.risky".to_string()),
            uses_cleartext_traffic: true,
            permissions: (0..30)
                .map(|i| format!("android.permission.TEST_{}", i))
                .collect(),
            dangerous_permissions: (0..20)
                .map(|i| format!("android.permission.DANGEROUS_{}", i))
                .collect(),
            exported_components: (0..20).map(|i| format!("activity:A{}", i)).collect(),
            endpoint_urls: (0..100)
                .map(|i| format!("https://a{}.example.com/x", i))
                .collect(),
            endpoint_domains: (0..100).map(|i| format!("a{}.example.com", i)).collect(),
            ioc_keywords: (0..30).map(|i| format!("ioc{}", i)).collect(),
        };

        let score = build_risk_score(&profile, 200, 200);
        assert_eq!(score.total, 100);
    }
}
