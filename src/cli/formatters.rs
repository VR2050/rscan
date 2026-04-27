use super::*;

pub(super) fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() || std::env::var_os("RSCAN_NO_COLOR").is_some() {
        return false;
    }
    if let Ok(v) = std::env::var("RSCAN_COLOR") {
        return v != "0";
    }
    std::io::stdout().is_terminal()
}

pub(super) fn format_scan_for_stdout(r: &ModuleScanResult, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Raw => format_scan_result_pretty(r, color_enabled()),
        _ => format_scan_result(r, fmt),
    }
}

pub(super) fn format_scan_error_line(err: &RustpenError, fmt: &OutputFormat) -> String {
    match fmt {
        OutputFormat::Json => serde_json::json!({ "error": err.to_string() }).to_string(),
        OutputFormat::Csv => format!("error,{}", err.to_string().replace(',', " ")),
        OutputFormat::Raw => format!("ERROR {}", err),
    }
}

pub(super) fn colorize(text: &str, code: &str, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub(super) fn severity_badge(sev: Option<&str>) -> (&'static str, &'static str) {
    match sev.unwrap_or("").to_ascii_lowercase().as_str() {
        "critical" => ("CRIT", "31"),
        "high" => ("HIGH", "31"),
        "medium" => ("MED", "33"),
        "low" => ("LOW", "32"),
        "info" => ("INFO", "36"),
        _ => ("UNKWN", "90"),
    }
}

pub(super) fn format_host_scan_pretty(r: &HostScanResult, color: bool) -> String {
    let proto = format!("{:?}", r.protocol).to_lowercase();
    let proto_col = match proto.as_str() {
        "tcp" => colorize("tcp", "36", color),
        "udp" => colorize("udp", "35", color),
        "syn" => colorize("syn", "33", color),
        "arp" => colorize("arp", "32", color),
        "icmp" => colorize("icmp", "34", color),
        _ => proto,
    };
    let header = format!(
        "host={} ip={} proto={} open={} filtered={} scanned={} errors={} duration_ms={}",
        r.host,
        r.ip,
        proto_col,
        colorize(&r.open_ports_count().to_string(), "32", color),
        colorize(&r.filtered_ports_count().to_string(), "33", color),
        r.total_scanned,
        r.errors,
        r.scan_duration.as_millis()
    );
    let mut lines = vec![header];
    if r.open_ports_count() == 0 {
        lines.push(colorize("no open ports", "90", color));
        return lines.join("\n");
    }
    lines.push(format!(
        "{:>6} {:>5} {:>8} {}",
        "PORT", "PROTO", "LAT(ms)", "BANNER"
    ));
    for p in r.open_port_details() {
        let port = colorize(&format!("{:>6}", p.port), "32", color);
        let proto = colorize(&format!("{:?}", p.protocol).to_lowercase(), "36", color);
        let lat = p
            .latency_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let banner = p
            .banner
            .as_ref()
            .map(|s| s.as_ref().replace('\n', " "))
            .unwrap_or_else(|| "".to_string());
        lines.push(format!("{port} {:>5} {:>8} {banner}", proto, lat));
    }
    lines.join("\n")
}

pub(super) fn format_engine_scan_pretty(results: &[EngineScanResult], color: bool) -> String {
    if results.is_empty() {
        return colorize("no results", "90", color);
    }
    let open_rows: Vec<&EngineScanResult> = results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                crate::cores::engine::scan_result::ScanStatus::Open
            )
        })
        .collect();
    let suppressed = results.len().saturating_sub(open_rows.len());
    if open_rows.is_empty() {
        return if suppressed > 0 {
            format!(
                "{} (suppressed non-open rows={})",
                colorize("no open ports", "90", color),
                suppressed
            )
        } else {
            colorize("no open ports", "90", color)
        };
    }
    let mut out = Vec::new();
    out.push(format!(
        "open_rows={} suppressed_non_open={}",
        open_rows.len(),
        suppressed
    ));
    out.push(format!(
        "{:>15} {:>6} {:>5} {:>8} {:<14} {:<12} {}",
        "IP", "PORT", "PROTO", "LAT(ms)", "SERVICE", "VERSION", "BANNER"
    ));
    let meta_value = |row: &EngineScanResult, key: &str| -> Option<String> {
        row.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    };
    let normalize_banner = |s: &str| -> String {
        let compact = s.replace(['\r', '\n'], " ");
        const MAX: usize = 120;
        if compact.chars().count() > MAX {
            let truncated: String = compact.chars().take(MAX.saturating_sub(3)).collect();
            format!("{truncated}...")
        } else {
            compact
        }
    };
    for r in open_rows {
        let proto = colorize(&format!("{:?}", r.protocol).to_lowercase(), "36", color);
        let lat = r
            .latency_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let port = r
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        let service = meta_value(r, "service")
            .or_else(|| meta_value(r, "probe"))
            .unwrap_or_else(|| "-".to_string());
        let version = meta_value(r, "service_version").unwrap_or_else(|| "-".to_string());
        let banner = meta_value(r, "banner_text")
            .as_deref()
            .map(normalize_banner)
            .unwrap_or_else(|| "".to_string());
        out.push(format!(
            "{:>15} {:>6} {:>5} {:>8} {:<14} {:<12} {}",
            r.target_ip, port, proto, lat, service, version, banner
        ));
    }
    out.join("\n")
}

pub(super) fn format_vuln_report_pretty(r: &VulnScanReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "scan=ok requests={} findings={} errors={}",
        r.scanned_requests,
        r.findings.len(),
        r.errors.len()
    ));
    if r.findings.is_empty() {
        lines.push(colorize("no findings", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<16} {:<6} {}",
            "SEV", "TEMPLATE", "METHOD", "URL"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(f.severity.as_deref());
            let sev = colorize(&format!("{:>6}", badge), code, color);
            let tpl = f.template_id.clone();
            let method = f.method.to_ascii_uppercase();
            lines.push(format!("{sev} {:<16} {:<6} {}", tpl, method, f.url));
            if !f.matched.is_empty() {
                lines.push(format!("      matched={}", f.matched.join(",")));
            }
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

pub(super) fn format_vuln_findings_only(r: &VulnScanReport, fmt: &str, color: bool) -> String {
    if fmt.eq_ignore_ascii_case("json") {
        return serde_json::to_string_pretty(&r.findings).unwrap_or_else(|_| "[]".to_string());
    }
    if fmt.eq_ignore_ascii_case("csv") {
        let mut lines = vec!["severity,template_id,method,url,target,matched".to_string()];
        for f in &r.findings {
            let severity = f.severity.clone().unwrap_or_default().replace(',', " ");
            let template_id = f.template_id.replace(',', " ");
            let method = f.method.to_ascii_uppercase().replace(',', " ");
            let url = f.url.replace(',', " ");
            let target = f.target.replace(',', " ");
            let matched = f.matched.join("|").replace(',', " ");
            lines.push(format!(
                "{severity},{template_id},{method},{url},{target},{matched}"
            ));
        }
        return lines.join("\n");
    }
    if r.findings.is_empty() {
        return colorize("no findings", "90", color);
    }
    let mut lines = vec![format!(
        "{:>6} {:<16} {:<6} {}",
        "SEV", "TEMPLATE", "METHOD", "URL"
    )];
    for f in &r.findings {
        let (badge, code) = severity_badge(f.severity.as_deref());
        let sev = colorize(&format!("{:>6}", badge), code, color);
        let tpl = f.template_id.clone();
        let method = f.method.to_ascii_uppercase();
        lines.push(format!("{sev} {:<16} {:<6} {}", tpl, method, f.url));
        if !f.matched.is_empty() {
            lines.push(format!("      matched={}", f.matched.join(",")));
        }
    }
    lines.join("\n")
}

pub(super) fn format_container_audit_pretty(r: &ContainerAuditReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "audit=ok files={} objects={} findings={} errors={}",
        r.files_scanned,
        r.objects_scanned,
        r.findings.len(),
        r.errors.len()
    ));

    if r.findings.is_empty() {
        lines.push(colorize("no risky manifest settings found", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<28} {:<24} {}",
            "SEV", "RULE", "OBJECT", "PATH"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(Some(&f.severity));
            let sev = colorize(&format!("{:>6}", badge), code, color);
            lines.push(format!("{sev} {:<28} {:<24} {}", f.rule, f.object, f.path));
        }
    }

    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

pub(super) fn format_system_guard_pretty(r: &SystemGuardReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "system-guard os={} processes={} controls={}/{} score={}",
        r.host_os, r.processes_scanned, r.controls_present, r.controls_total, r.score
    ));

    if r.findings.is_empty() {
        lines.push(colorize("no findings", "90", color));
    } else {
        lines.push(format!(
            "{:>6} {:<22} {:<28} {}",
            "SEV", "CATEGORY", "RULE", "EVIDENCE"
        ));
        for f in &r.findings {
            let (badge, code) = severity_badge(Some(&f.severity));
            let sev = colorize(&format!("{:>6}", badge), code, color);
            lines.push(format!(
                "{sev} {:<22} {:<28} {}",
                f.category, f.rule, f.evidence
            ));
            lines.push(format!("      {}", f.message));
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

pub(super) fn format_stealth_check_pretty(r: &AntiScanReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!("stealth-check target={}", r.target));
    lines.push(format!(
        "protection_score={} confidence={}",
        r.protection_score, r.confidence
    ));
    lines.push(format!(
        "phase=low-noise sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.low_noise.sent,
        r.low_noise.success,
        r.low_noise.blocked,
        r.low_noise.timeouts,
        r.low_noise.network_errors,
        r.low_noise.avg_latency_ms,
        r.low_noise.p95_latency_ms,
        r.low_noise.block_ratio
    ));
    lines.push(format!(
        "phase=burst sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.burst.sent,
        r.burst.success,
        r.burst.blocked,
        r.burst.timeouts,
        r.burst.network_errors,
        r.burst.avg_latency_ms,
        r.burst.p95_latency_ms,
        r.burst.block_ratio
    ));

    if !r.variant_probes.is_empty() {
        lines.push("variants:".to_string());
        for v in &r.variant_probes {
            lines.push(format!(
                "variant={} sent={} success={} blocked={} timeout={} avg_ms={} block_ratio={:.2}",
                v.name,
                v.stats.sent,
                v.stats.success,
                v.stats.blocked,
                v.stats.timeouts,
                v.stats.avg_latency_ms,
                v.stats.block_ratio
            ));
        }
    }

    if !r.header_signals.is_empty() {
        lines.push(format!("header_signals={}", r.header_signals.join(",")));
    }

    lines.push("findings:".to_string());
    for f in &r.findings {
        let (badge, code) = severity_badge(Some(&f.severity));
        let sev = colorize(&format!("{:>6}", badge), code, color);
        lines.push(format!(
            "{sev} {:<18} {:<28} {}",
            f.category, f.rule, f.message
        ));
        lines.push(format!("      evidence={}", f.evidence));
    }
    if !r.recommendations.is_empty() {
        lines.push("recommendations:".to_string());
        for x in &r.recommendations {
            lines.push(format!("- {}", x));
        }
    }

    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }

    lines.join("\n")
}

pub(super) fn format_fragment_audit_pretty(r: &FragmentAuditReport, color: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!("fragment-audit target={}", r.target));
    lines.push(format!(
        "reassembly_score={} confidence={}",
        r.reassembly_score, r.confidence
    ));
    lines.push(format!(
        "baseline sent={} success={} blocked={} timeout={} neterr={} avg_ms={} p95_ms={} block_ratio={:.2}",
        r.baseline.sent,
        r.baseline.success,
        r.baseline.blocked,
        r.baseline.timeouts,
        r.baseline.network_errors,
        r.baseline.avg_latency_ms,
        r.baseline.p95_latency_ms,
        r.baseline.block_ratio
    ));
    if !r.tiers.is_empty() {
        lines.push("tiers:".to_string());
        for t in &r.tiers {
            lines.push(format!(
                "tier={} payload_bytes={} header(block={:.2},timeout={},avg_ms={}) body(block={:.2},timeout={},avg_ms={})",
                t.name,
                t.payload_bytes,
                t.header_probe.block_ratio,
                t.header_probe.timeouts,
                t.header_probe.avg_latency_ms,
                t.body_probe.block_ratio,
                t.body_probe.timeouts,
                t.body_probe.avg_latency_ms
            ));
        }
    }
    if !r.header_signals.is_empty() {
        lines.push(format!("header_signals={}", r.header_signals.join(",")));
    }
    lines.push("findings:".to_string());
    for f in &r.findings {
        let (badge, code) = severity_badge(Some(&f.severity));
        let sev = colorize(&format!("{:>6}", badge), code, color);
        lines.push(format!(
            "{sev} {:<18} {:<28} {}",
            f.category, f.rule, f.message
        ));
        lines.push(format!("      evidence={}", f.evidence));
    }
    if !r.recommendations.is_empty() {
        lines.push("recommendations:".to_string());
        for x in &r.recommendations {
            lines.push(format!("- {}", x));
        }
    }
    if !r.errors.is_empty() {
        lines.push(colorize("errors:", "31", color));
        for e in &r.errors {
            lines.push(format!("ERR {}", e.replace('\n', " ")));
        }
    }
    lines.join("\n")
}

pub(super) fn format_host_scan_result(r: &HostScanResult, fmt: &str) -> String {
    match fmt.to_lowercase().as_str() {
        "json" => serde_json::to_string(&r.to_json())
            .unwrap_or_else(|_| format!("host: {} open: {:?}", r.host, r.open_ports())),
        _ => format_host_scan_pretty(r, color_enabled()),
    }
}

pub(super) fn format_engine_scan_results(results: &[EngineScanResult], fmt: &str) -> String {
    match fmt.to_lowercase().as_str() {
        "json" => {
            let rows: Vec<_> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "target_ip": r.target_ip.to_string(),
                        "port": r.port,
                        "protocol": format!("{:?}", r.protocol),
                        "status": format!("{:?}", r.status),
                        "latency_ms": r.latency_ms,
                        "response_len": r.response.as_ref().map(|v| v.len()),
                        "metadata": r.metadata,
                    })
                })
                .collect();
            serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
        }
        _ => format_engine_scan_pretty(results, color_enabled()),
    }
}

pub(super) fn engine_status_to_host_status(
    status: crate::cores::engine::scan_result::ScanStatus,
) -> crate::cores::host::PortStatus {
    match status {
        crate::cores::engine::scan_result::ScanStatus::Open => crate::cores::host::PortStatus::Open,
        crate::cores::engine::scan_result::ScanStatus::Closed => {
            crate::cores::host::PortStatus::Closed
        }
        crate::cores::engine::scan_result::ScanStatus::Filtered => {
            crate::cores::host::PortStatus::Filtered
        }
        crate::cores::engine::scan_result::ScanStatus::Unknown
        | crate::cores::engine::scan_result::ScanStatus::Error => {
            crate::cores::host::PortStatus::Error
        }
    }
}

pub(super) fn engine_rows_to_host_result(
    host: &str,
    ip: std::net::IpAddr,
    protocol: crate::cores::host::Protocol,
    rows: &[EngineScanResult],
) -> HostScanResult {
    let mut out = HostScanResult::new(host.to_string(), ip, protocol);
    for row in rows {
        let Some(port) = row.port else { continue };
        let status = engine_status_to_host_status(row.status);
        out.record_port(port, status);
        if status == crate::cores::host::PortStatus::Open {
            let mut pr = crate::cores::host::PortResult::new(port, status, protocol);
            if let Some(ms) = row.latency_ms {
                pr = pr.with_latency(ms.min(u16::MAX as u64) as u16);
            }
            out.add_open_port_detail(pr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> VulnScanReport {
        VulnScanReport {
            scanned_requests: 12,
            findings: vec![crate::modules::vuln_check::VulnFinding {
                template_id: "cvescan".to_string(),
                template_name: Some("sample".to_string()),
                severity: Some("high".to_string()),
                target: "http://target".to_string(),
                url: "http://target/login".to_string(),
                method: "get".to_string(),
                matched: vec!["word:body".to_string(), "status:code".to_string()],
            }],
            errors: vec!["network timeout".to_string()],
        }
    }

    #[test]
    fn format_vuln_findings_only_raw_omits_scan_summary_and_errors() {
        let s = format_vuln_findings_only(&sample_report(), "raw", false);
        assert!(s.contains("cvescan"));
        assert!(s.contains("matched=word:body,status:code"));
        assert!(!s.contains("scan=ok"));
        assert!(!s.contains("errors:"));
    }

    #[test]
    fn format_vuln_findings_only_json_returns_findings_array() {
        let s = format_vuln_findings_only(&sample_report(), "json", false);
        assert!(s.starts_with("["));
        assert!(s.contains("\"template_id\": \"cvescan\""));
        assert!(!s.contains("\"scanned_requests\""));
    }
}
