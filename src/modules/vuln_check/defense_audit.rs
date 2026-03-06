use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::errors::RustpenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseFinding {
    pub severity: String,
    pub category: String,
    pub rule: String,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhaseStats {
    pub sent: usize,
    pub success: usize,
    pub blocked: usize,
    pub timeouts: usize,
    pub network_errors: usize,
    pub avg_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub block_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemGuardReport {
    pub host_os: String,
    pub processes_scanned: usize,
    pub controls_total: usize,
    pub controls_present: usize,
    pub score: u8,
    pub findings: Vec<DefenseFinding>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiScanConfig {
    pub low_noise_requests: usize,
    pub low_noise_interval_ms: u64,
    pub burst_requests: usize,
    pub burst_concurrency: usize,
    pub timeout_ms: u64,
    pub advanced_checks: bool,
    pub variant_requests: usize,
    pub variant_concurrency: usize,
}

impl Default for AntiScanConfig {
    fn default() -> Self {
        Self {
            low_noise_requests: 8,
            low_noise_interval_ms: 250,
            burst_requests: 24,
            burst_concurrency: 12,
            timeout_ms: 3000,
            advanced_checks: true,
            variant_requests: 8,
            variant_concurrency: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantProbeStats {
    pub name: String,
    pub stats: PhaseStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiScanReport {
    pub target: String,
    pub low_noise: PhaseStats,
    pub burst: PhaseStats,
    pub variant_probes: Vec<VariantProbeStats>,
    pub header_signals: Vec<String>,
    pub protection_score: u8,
    pub confidence: u8,
    pub recommendations: Vec<String>,
    pub findings: Vec<DefenseFinding>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentAuditConfig {
    pub requests_per_tier: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub payload_min_bytes: usize,
    pub payload_max_bytes: usize,
    pub payload_step_bytes: usize,
}

impl Default for FragmentAuditConfig {
    fn default() -> Self {
        Self {
            requests_per_tier: 6,
            concurrency: 4,
            timeout_ms: 4000,
            payload_min_bytes: 1024,
            payload_max_bytes: 24 * 1024,
            payload_step_bytes: 4 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentTierStats {
    pub name: String,
    pub payload_bytes: usize,
    pub header_probe: PhaseStats,
    pub body_probe: PhaseStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentAuditReport {
    pub target: String,
    pub baseline: PhaseStats,
    pub tiers: Vec<FragmentTierStats>,
    pub header_signals: Vec<String>,
    pub reassembly_score: u8,
    pub confidence: u8,
    pub recommendations: Vec<String>,
    pub findings: Vec<DefenseFinding>,
    pub errors: Vec<String>,
}

pub fn audit_local_system_guard() -> Result<SystemGuardReport, RustpenError> {
    let host_os = std::env::consts::OS.to_string();
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let (processes_scanned, process_markers) = match host_os.as_str() {
        "linux" => match list_linux_process_markers() {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("process inventory failed: {}", e));
                (0, Vec::new())
            }
        },
        _ => {
            findings.push(DefenseFinding {
                severity: "info".to_string(),
                category: "platform".to_string(),
                rule: "platform-support".to_string(),
                message: "system guard currently includes Linux process/control checks".to_string(),
                evidence: host_os.clone(),
            });
            (0, Vec::new())
        }
    };

    let mut controls_total = 0usize;
    let mut controls_present = 0usize;

    controls_total += 1;
    let firewall_enabled = linux_kernel_firewall_enabled();
    if firewall_enabled {
        controls_present += 1;
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "network-hardening".to_string(),
            rule: "kernel-firewall-modules".to_string(),
            message: "kernel firewall modules detected".to_string(),
            evidence: "/proc/modules has nf_tables/ip_tables".to_string(),
        });
    } else {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "network-hardening".to_string(),
            rule: "kernel-firewall-modules".to_string(),
            message: "kernel firewall modules not detected".to_string(),
            evidence: "neither nf_tables nor ip_tables found in /proc/modules".to_string(),
        });
    }

    controls_total += 1;
    let apparmor_enabled = file_contains("/sys/module/apparmor/parameters/enabled", "Y");
    let selinux_enforcing = file_contains("/sys/fs/selinux/enforce", "1");
    let mac_enabled = apparmor_enabled || selinux_enforcing;
    if mac_enabled {
        controls_present += 1;
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "kernel-hardening".to_string(),
            rule: "mandatory-access-control".to_string(),
            message: "mandatory access control detected".to_string(),
            evidence: format!(
                "apparmor={} selinux_enforcing={}",
                apparmor_enabled, selinux_enforcing
            ),
        });
    } else {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "kernel-hardening".to_string(),
            rule: "mandatory-access-control".to_string(),
            message: "AppArmor/SELinux not detected as enabled".to_string(),
            evidence: "no AppArmor or SELinux enforcing signal".to_string(),
        });
    }

    controls_total += 1;
    let auditd_running = process_markers.iter().any(|p| p.contains("auditd"));
    if auditd_running {
        controls_present += 1;
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "audit".to_string(),
            rule: "auditd-running".to_string(),
            message: "auditd process detected".to_string(),
            evidence: "process marker contains 'auditd'".to_string(),
        });
    } else {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "audit".to_string(),
            rule: "auditd-running".to_string(),
            message: "auditd process not detected".to_string(),
            evidence: "no process marker matched 'auditd'".to_string(),
        });
    }

    let known_agents = detect_known_security_agents(&process_markers);
    controls_total += 1;
    if known_agents.is_empty() {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "endpoint-protection".to_string(),
            rule: "known-edr-av-processes".to_string(),
            message: "no known AV/EDR process marker detected".to_string(),
            evidence: "checked common process markers (defender/falcon/sentinel/wazuh/osquery)"
                .to_string(),
        });
    } else {
        controls_present += 1;
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "endpoint-protection".to_string(),
            rule: "known-edr-av-processes".to_string(),
            message: format!("detected {} known security agent(s)", known_agents.len()),
            evidence: known_agents.join(", "),
        });
    }

    let score = if controls_total == 0 {
        0
    } else {
        ((controls_present as f32 / controls_total as f32) * 100.0).round() as u8
    };

    Ok(SystemGuardReport {
        host_os,
        processes_scanned,
        controls_total,
        controls_present,
        score,
        findings,
        errors,
    })
}

pub async fn audit_http_anti_scan(
    target: &str,
    cfg: AntiScanConfig,
) -> Result<AntiScanReport, RustpenError> {
    let base = normalize_http_target(target)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let mut header_signals = BTreeSet::new();
    let mut errors = Vec::new();
    let probe_token = format!(
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let mut low_samples = Vec::with_capacity(cfg.low_noise_requests);
    for i in 0..cfg.low_noise_requests.max(1) {
        let url = build_probe_url(&base, &probe_token, i);
        let started = Instant::now();
        match client.head(&url).send().await {
            Ok(resp) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                let status = resp.status().as_u16();
                header_signals.extend(detect_waf_signals(resp.headers()));
                low_samples.push(ProbeSample::success(latency_ms, status));
            }
            Err(e) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                push_limited_error(&mut errors, format!("low-noise {}: {}", url, e), 50);
                low_samples.push(ProbeSample::failure(latency_ms, e.is_timeout()));
            }
        }
        if i + 1 < cfg.low_noise_requests.max(1) && cfg.low_noise_interval_ms > 0 {
            sleep(Duration::from_millis(cfg.low_noise_interval_ms)).await;
        }
    }

    let burst_total = cfg.burst_requests.max(1);
    let burst_jobs: Vec<String> = (0..burst_total)
        .map(|i| build_probe_url(&base, &probe_token, 1000 + i))
        .collect();
    let mut burst_samples = Vec::with_capacity(burst_total);
    let mut in_flight = stream::iter(burst_jobs.into_iter().map(|url| {
        let client = client.clone();
        async move {
            let started = Instant::now();
            let resp = client.head(&url).send().await;
            (url, started.elapsed().as_millis() as u64, resp)
        }
    }))
    .buffer_unordered(cfg.burst_concurrency.max(1));

    while let Some((url, latency_ms, resp)) = in_flight.next().await {
        match resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                header_signals.extend(detect_waf_signals(resp.headers()));
                burst_samples.push(ProbeSample::success(latency_ms, status));
            }
            Err(e) => {
                push_limited_error(&mut errors, format!("burst {}: {}", url, e), 50);
                burst_samples.push(ProbeSample::failure(latency_ms, e.is_timeout()));
            }
        }
    }

    let low_noise = summarize_phase(&low_samples);
    let burst = summarize_phase(&burst_samples);

    let mut variant_probes = Vec::new();
    if cfg.advanced_checks {
        let variant_count = cfg.variant_requests.max(1);
        let variant_concurrency = cfg.variant_concurrency.max(1);
        for variant in [
            ProbeVariant::PathEncoding,
            ProbeVariant::QueryNoise,
            ProbeVariant::HeaderNoise,
            ProbeVariant::MethodOptions,
            ProbeVariant::MethodGet,
        ] {
            let (stats, signals, mut errs) = run_variant_probe(
                &client,
                &base,
                &probe_token,
                variant,
                variant_count,
                variant_concurrency,
            )
            .await;
            header_signals.extend(signals);
            errors.append(&mut errs);
            variant_probes.push(VariantProbeStats {
                name: variant.name().to_string(),
                stats,
            });
        }
    }

    let findings = derive_anti_scan_findings(&low_noise, &burst, &variant_probes, &header_signals);
    let (protection_score, confidence, recommendations) = score_anti_scan_capability(
        &low_noise,
        &burst,
        &variant_probes,
        &header_signals,
        errors.len(),
    );

    Ok(AntiScanReport {
        target: base,
        low_noise,
        burst,
        variant_probes,
        header_signals: header_signals.into_iter().collect(),
        protection_score,
        confidence,
        recommendations,
        findings,
        errors,
    })
}

pub async fn audit_http_fragment_resilience(
    target: &str,
    cfg: FragmentAuditConfig,
) -> Result<FragmentAuditReport, RustpenError> {
    let base = normalize_http_target(target)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.max(500)))
        .redirect(reqwest::redirect::Policy::limited(2))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let count = cfg.requests_per_tier.max(1);
    let concurrency = cfg.concurrency.max(1);
    let mut header_signals = BTreeSet::new();
    let mut errors = Vec::new();
    let probe_token = format!(
        "{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let baseline_url = build_probe_url(&base, &probe_token, 0);
    let (baseline, base_signals, mut base_errs) =
        run_payload_probe(&client, &baseline_url, 0, 0, count, concurrency).await;
    header_signals.extend(base_signals);
    errors.append(&mut base_errs);

    let tiers = build_payload_tiers(
        cfg.payload_min_bytes,
        cfg.payload_max_bytes,
        cfg.payload_step_bytes,
    );
    let mut tier_stats = Vec::with_capacity(tiers.len());
    for (idx, bytes) in tiers.into_iter().enumerate() {
        let tier_url = build_probe_url(&base, &probe_token, 2000 + idx);
        let (hdr_stats, hdr_signals, mut hdr_errs) =
            run_payload_probe(&client, &tier_url, bytes, 0, count, concurrency).await;
        header_signals.extend(hdr_signals);
        errors.append(&mut hdr_errs);

        let (body_stats, body_signals, mut body_errs) =
            run_payload_probe(&client, &tier_url, 0, bytes, count, concurrency).await;
        header_signals.extend(body_signals);
        errors.append(&mut body_errs);

        tier_stats.push(FragmentTierStats {
            name: format!("tier-{}", idx + 1),
            payload_bytes: bytes,
            header_probe: hdr_stats,
            body_probe: body_stats,
        });
    }

    let findings = derive_fragment_findings(&baseline, &tier_stats, &header_signals);
    let (reassembly_score, confidence, recommendations) =
        score_fragment_resilience(&baseline, &tier_stats, &header_signals, errors.len());

    Ok(FragmentAuditReport {
        target: base,
        baseline,
        tiers: tier_stats,
        header_signals: header_signals.into_iter().collect(),
        reassembly_score,
        confidence,
        recommendations,
        findings,
        errors,
    })
}

fn list_linux_process_markers() -> Result<(usize, Vec<String>), RustpenError> {
    let mut markers = Vec::new();
    let mut count = 0usize;
    for entry in std::fs::read_dir("/proc").map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let name = entry.file_name();
        let Some(pid) = name.to_str() else { continue };
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        count += 1;
        let proc_dir = entry.path();
        let comm = read_trimmed(proc_dir.join("comm")).unwrap_or_default();
        let cmdline_raw = std::fs::read(proc_dir.join("cmdline")).unwrap_or_default();
        let cmdline = String::from_utf8_lossy(&cmdline_raw)
            .replace('\0', " ")
            .trim()
            .to_string();
        let merged = format!(
            "{} {}",
            comm.to_ascii_lowercase(),
            cmdline.to_ascii_lowercase()
        );
        if !merged.trim().is_empty() {
            markers.push(merged);
        }
    }
    Ok((count, markers))
}

fn detect_known_security_agents(process_markers: &[String]) -> Vec<String> {
    let signatures: [(&str, &[&str]); 8] = [
        ("microsoft-defender", &["mdatp", "wdavdaemon", "msmpeng"]),
        ("crowdstrike-falcon", &["falcon-sensor", "csfalconservice"]),
        ("sentinelone", &["sentinelone", "s1-agent", "sentinelctl"]),
        ("carbon-black", &["cbagent", "carbonblack"]),
        ("trend-micro", &["ds_agent", "tmccsf"]),
        ("wazuh-agent", &["wazuh-agent", "wazuhd"]),
        ("osquery", &["osqueryd"]),
        ("falco", &["falco"]),
    ];

    let mut detected = Vec::new();
    for (agent, markers) in signatures {
        let matched = process_markers
            .iter()
            .any(|p| markers.iter().any(|m| p.contains(&m.to_ascii_lowercase())));
        if matched {
            detected.push(agent.to_string());
        }
    }
    detected
}

fn linux_kernel_firewall_enabled() -> bool {
    let modules = read_trimmed("/proc/modules").unwrap_or_default();
    let m = modules.to_ascii_lowercase();
    m.contains("nf_tables") || m.contains("ip_tables")
}

fn file_contains(path: impl AsRef<Path>, expected: &str) -> bool {
    read_trimmed(path)
        .map(|v| v.contains(expected))
        .unwrap_or(false)
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn normalize_http_target(target: &str) -> Result<String, RustpenError> {
    let parsed = url::Url::parse(target)
        .map_err(|e| RustpenError::ParseError(format!("invalid URL: {}", e)))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(RustpenError::ParseError(
            "target must start with http:// or https://".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| RustpenError::ParseError("target host missing".to_string()))?;
    let mut out = format!("{}://{}", scheme, host);
    if let Some(p) = parsed.port() {
        out.push_str(&format!(":{}", p));
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        out.push_str(path);
    }
    Ok(out)
}

fn build_probe_url(base: &str, token: &str, idx: usize) -> String {
    format!(
        "{}/.well-known/rscan-probe-{}-{}",
        base.trim_end_matches('/'),
        token,
        idx
    )
}

#[derive(Debug, Clone, Copy)]
enum ProbeVariant {
    PathEncoding,
    QueryNoise,
    HeaderNoise,
    MethodOptions,
    MethodGet,
}

impl ProbeVariant {
    fn name(self) -> &'static str {
        match self {
            ProbeVariant::PathEncoding => "path-encoding",
            ProbeVariant::QueryNoise => "query-noise",
            ProbeVariant::HeaderNoise => "header-noise",
            ProbeVariant::MethodOptions => "method-options",
            ProbeVariant::MethodGet => "method-get",
        }
    }
}

async fn run_variant_probe(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    variant: ProbeVariant,
    count: usize,
    concurrency: usize,
) -> (PhaseStats, BTreeSet<String>, Vec<String>) {
    let urls: Vec<String> = (0..count)
        .map(|i| build_variant_probe_url(base, token, i, variant))
        .collect();

    let mut signals = BTreeSet::new();
    let mut errors = Vec::new();
    let mut samples = Vec::with_capacity(count);
    let mut in_flight = stream::iter(urls.into_iter().map(|url| {
        let client = client.clone();
        async move {
            let started = Instant::now();
            let mut req = match variant {
                ProbeVariant::MethodOptions => client.request(reqwest::Method::OPTIONS, &url),
                ProbeVariant::MethodGet => client.request(reqwest::Method::GET, &url),
                _ => client.request(reqwest::Method::HEAD, &url),
            };

            if matches!(variant, ProbeVariant::HeaderNoise) {
                req = req
                    .header("X-Scan-Profile", "rscan-defense-audit")
                    .header("X-Request-Pad", "a1b2c3d4e5")
                    .header("Cache-Control", "no-store");
            }

            let resp = req.send().await;
            (url, started.elapsed().as_millis() as u64, resp)
        }
    }))
    .buffer_unordered(concurrency.max(1));

    while let Some((url, latency_ms, resp)) = in_flight.next().await {
        match resp {
            Ok(resp) => {
                signals.extend(detect_waf_signals(resp.headers()));
                samples.push(ProbeSample::success(latency_ms, resp.status().as_u16()));
            }
            Err(e) => {
                push_limited_error(
                    &mut errors,
                    format!("variant {} {}: {}", variant.name(), url, e),
                    50,
                );
                samples.push(ProbeSample::failure(latency_ms, e.is_timeout()));
            }
        }
    }

    (summarize_phase(&samples), signals, errors)
}

fn build_variant_probe_url(base: &str, token: &str, idx: usize, variant: ProbeVariant) -> String {
    let b = base.trim_end_matches('/');
    match variant {
        ProbeVariant::PathEncoding => {
            format!("{}/.well-known/%72scan-probe-{}-{}%2Ftest", b, token, idx)
        }
        ProbeVariant::QueryNoise => format!(
            "{}/.well-known/rscan-probe-{}-{}?cb={}&pad=%5f{}",
            b,
            token,
            idx,
            100000usize.saturating_add(idx),
            idx % 7
        ),
        ProbeVariant::HeaderNoise | ProbeVariant::MethodOptions | ProbeVariant::MethodGet => {
            format!("{}/.well-known/rscan-probe-{}-{}", b, token, idx)
        }
    }
}

#[derive(Debug, Clone)]
struct ProbeSample {
    latency_ms: u64,
    status: Option<u16>,
    timeout: bool,
    network_error: bool,
}

impl ProbeSample {
    fn success(latency_ms: u64, status: u16) -> Self {
        Self {
            latency_ms,
            status: Some(status),
            timeout: false,
            network_error: false,
        }
    }

    fn failure(latency_ms: u64, timeout: bool) -> Self {
        Self {
            latency_ms,
            status: None,
            timeout,
            network_error: !timeout,
        }
    }
}

fn summarize_phase(samples: &[ProbeSample]) -> PhaseStats {
    if samples.is_empty() {
        return PhaseStats::default();
    }

    let sent = samples.len();
    let success = samples.iter().filter(|s| s.status.is_some()).count();
    let blocked = samples
        .iter()
        .filter_map(|s| s.status)
        .filter(|s| is_block_like_status(*s))
        .count();
    let timeouts = samples.iter().filter(|s| s.timeout).count();
    let network_errors = samples.iter().filter(|s| s.network_error).count();

    let mut lats = samples.iter().map(|s| s.latency_ms).collect::<Vec<_>>();
    lats.sort_unstable();
    let avg_latency_ms = (lats.iter().sum::<u64>() as f64 / lats.len() as f64).round() as u64;
    let p95_latency_ms = percentile_u64(&lats, 0.95);

    PhaseStats {
        sent,
        success,
        blocked,
        timeouts,
        network_errors,
        avg_latency_ms,
        p95_latency_ms,
        block_ratio: blocked as f32 / sent as f32,
    }
}

fn percentile_u64(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn is_block_like_status(status: u16) -> bool {
    matches!(
        status,
        403 | 406 | 409 | 418 | 423 | 429 | 444 | 451 | 503 | 509 | 521 | 522 | 523 | 525 | 530
    )
}

fn detect_waf_signals(headers: &HeaderMap) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (k, v) in headers {
        let name = k.as_str().to_ascii_lowercase();
        let val = v.to_str().unwrap_or_default().to_ascii_lowercase();

        if name == "cf-ray" || val.contains("cloudflare") || val.contains("__cf_bm") {
            out.insert("cloudflare-signal".to_string());
        }
        if name.contains("sucuri") || val.contains("sucuri") {
            out.insert("sucuri-signal".to_string());
        }
        if name.contains("akamai") || val.contains("akamai") {
            out.insert("akamai-signal".to_string());
        }
        if name.contains("waf") || val.contains("waf") {
            out.insert("generic-waf-signal".to_string());
        }
        if name.contains("x-denied") || val.contains("access denied") {
            out.insert("access-denied-signal".to_string());
        }
    }
    out
}

fn derive_anti_scan_findings(
    low: &PhaseStats,
    burst: &PhaseStats,
    variants: &[VariantProbeStats],
    header_signals: &BTreeSet<String>,
) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();

    if !header_signals.is_empty() {
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "anti-scan".to_string(),
            rule: "waf-header-signals".to_string(),
            message: "WAF or traffic filtering header signals detected".to_string(),
            evidence: header_signals
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    if burst.block_ratio >= (low.block_ratio + 0.25) && burst.blocked >= 3 {
        findings.push(DefenseFinding {
            severity: "high".to_string(),
            category: "anti-scan".to_string(),
            rule: "behavioral-blocking".to_string(),
            message: "burst phase shows significantly higher blocking ratio".to_string(),
            evidence: format!(
                "low_block_ratio={:.2} burst_block_ratio={:.2}",
                low.block_ratio, burst.block_ratio
            ),
        });
    }

    let low_timeout_ratio = if low.sent == 0 {
        0.0
    } else {
        low.timeouts as f32 / low.sent as f32
    };
    let burst_timeout_ratio = if burst.sent == 0 {
        0.0
    } else {
        burst.timeouts as f32 / burst.sent as f32
    };
    if burst_timeout_ratio >= (low_timeout_ratio + 0.25) && burst.timeouts >= 3 {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "anti-scan".to_string(),
            rule: "possible-tarpit-or-rate-limit".to_string(),
            message: "burst phase timeout ratio increased sharply".to_string(),
            evidence: format!(
                "low_timeout_ratio={:.2} burst_timeout_ratio={:.2}",
                low_timeout_ratio, burst_timeout_ratio
            ),
        });
    }

    if low.avg_latency_ms > 0
        && burst.avg_latency_ms >= low.avg_latency_ms.saturating_mul(2)
        && burst.block_ratio > low.block_ratio
    {
        findings.push(DefenseFinding {
            severity: "medium".to_string(),
            category: "anti-scan".to_string(),
            rule: "latency-throttling-signal".to_string(),
            message: "burst phase latency increased with stronger filtering signs".to_string(),
            evidence: format!(
                "low_avg_ms={} burst_avg_ms={}",
                low.avg_latency_ms, burst.avg_latency_ms
            ),
        });
    }

    for v in variants {
        if v.stats.sent >= 3 && v.stats.block_ratio >= (burst.block_ratio + 0.20) {
            findings.push(DefenseFinding {
                severity: "high".to_string(),
                category: "anti-scan".to_string(),
                rule: "variant-sensitive-filter".to_string(),
                message: format!(
                    "target blocks '{}' probes more aggressively than baseline burst",
                    v.name
                ),
                evidence: format!(
                    "variant={} variant_block_ratio={:.2} burst_block_ratio={:.2}",
                    v.name, v.stats.block_ratio, burst.block_ratio
                ),
            });
        }
    }

    if !variants.is_empty() {
        let max_variant = variants
            .iter()
            .max_by(|a, b| a.stats.block_ratio.total_cmp(&b.stats.block_ratio));
        if let Some(v) = max_variant {
            findings.push(DefenseFinding {
                severity: "info".to_string(),
                category: "anti-scan".to_string(),
                rule: "variant-summary".to_string(),
                message: "most sensitive probe variant identified".to_string(),
                evidence: format!("variant={} block_ratio={:.2}", v.name, v.stats.block_ratio),
            });
        }
    }

    if findings.is_empty() {
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "anti-scan".to_string(),
            rule: "no-strong-signal".to_string(),
            message: "no strong anti-scan signal observed under current sample".to_string(),
            evidence: "try larger sample size for higher confidence".to_string(),
        });
    }

    findings
}

fn score_anti_scan_capability(
    low: &PhaseStats,
    burst: &PhaseStats,
    variants: &[VariantProbeStats],
    header_signals: &BTreeSet<String>,
    error_count: usize,
) -> (u8, u8, Vec<String>) {
    let mut score = 20.0f32;
    score += (burst.block_ratio * 35.0).min(35.0);
    score += ((burst.block_ratio - low.block_ratio).max(0.0) * 25.0).min(25.0);
    score += (header_signals.len() as f32 * 5.0).min(15.0);

    let max_variant_ratio = variants
        .iter()
        .map(|v| v.stats.block_ratio)
        .fold(0.0f32, f32::max);
    score += (max_variant_ratio * 20.0).min(20.0);
    score = score.min(100.0);

    let total_samples =
        low.sent + burst.sent + variants.iter().map(|v| v.stats.sent).sum::<usize>();
    let mut confidence = 35.0f32 + (total_samples as f32 * 1.5).min(60.0);
    confidence -= (error_count as f32 * 1.2).min(25.0);
    confidence = confidence.clamp(10.0, 99.0);

    let mut rec = Vec::new();
    if score < 40.0 {
        rec.push("防护信号偏弱：建议启用 WAF 行为规则与速率限制策略".to_string());
        rec.push("建议引入按路径/Method 维度的异常请求基线与告警".to_string());
    } else if score < 70.0 {
        rec.push("防护信号中等：建议增加 query/header/path 编码变体检测规则".to_string());
        rec.push("建议对 burst 高频访问启用更严格的动态挑战策略".to_string());
    } else {
        rec.push("防护信号较强：建议定期做变体回归测试防止策略退化".to_string());
    }
    if confidence < 55.0 {
        rec.push("当前样本置信度偏低：建议提高 low-noise/burst/variant 请求数量".to_string());
    }

    (score.round() as u8, confidence.round() as u8, rec)
}

async fn run_payload_probe(
    client: &reqwest::Client,
    url: &str,
    header_pad_bytes: usize,
    body_pad_bytes: usize,
    count: usize,
    concurrency: usize,
) -> (PhaseStats, BTreeSet<String>, Vec<String>) {
    let mut signals = BTreeSet::new();
    let mut errors = Vec::new();
    let mut samples = Vec::with_capacity(count);

    let header_pad = "A".repeat(header_pad_bytes.min(64 * 1024));
    let body_pad = "B".repeat(body_pad_bytes.min(256 * 1024));
    let mut in_flight = stream::iter((0..count).map(|idx| {
        let client = client.clone();
        let url = format!("{url}?fa={idx}&hb={header_pad_bytes}&bb={body_pad_bytes}");
        let header_pad = header_pad.clone();
        let body_pad = body_pad.clone();
        async move {
            let started = Instant::now();
            let mut req = if body_pad_bytes > 0 {
                client
                    .request(reqwest::Method::POST, &url)
                    .header("Content-Type", "application/octet-stream")
                    .body(body_pad)
            } else {
                client.request(reqwest::Method::HEAD, &url)
            };
            if header_pad_bytes > 0 {
                req = req
                    .header("X-Fragment-Audit", "rscan-defense")
                    .header("X-Request-Pad", header_pad);
            }
            let resp = req.send().await;
            (url, started.elapsed().as_millis() as u64, resp)
        }
    }))
    .buffer_unordered(concurrency.max(1));

    while let Some((req_url, latency_ms, resp)) = in_flight.next().await {
        match resp {
            Ok(resp) => {
                signals.extend(detect_waf_signals(resp.headers()));
                samples.push(ProbeSample::success(latency_ms, resp.status().as_u16()));
            }
            Err(e) => {
                push_limited_error(
                    &mut errors,
                    format!("fragment-probe {}: {}", req_url, e),
                    80,
                );
                samples.push(ProbeSample::failure(latency_ms, e.is_timeout()));
            }
        }
    }
    (summarize_phase(&samples), signals, errors)
}

fn build_payload_tiers(min_b: usize, max_b: usize, step_b: usize) -> Vec<usize> {
    let min_b = min_b.max(256);
    let max_b = max_b.max(min_b).min(256 * 1024);
    let step_b = step_b.max(256);
    let mut out = Vec::new();
    let mut cur = min_b;
    while cur <= max_b {
        out.push(cur);
        cur = cur.saturating_add(step_b);
        if out.len() >= 24 {
            break;
        }
    }
    if out.is_empty() {
        out.push(min_b);
    }
    out
}

fn derive_fragment_findings(
    baseline: &PhaseStats,
    tiers: &[FragmentTierStats],
    header_signals: &BTreeSet<String>,
) -> Vec<DefenseFinding> {
    let mut findings = Vec::new();

    if !header_signals.is_empty() {
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "fragment-audit".to_string(),
            rule: "waf-header-signals".to_string(),
            message: "WAF/traffic-filter header signals observed during size-tier probes"
                .to_string(),
            evidence: header_signals
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    let baseline_timeout_ratio = if baseline.sent == 0 {
        0.0
    } else {
        baseline.timeouts as f32 / baseline.sent as f32
    };
    for t in tiers {
        let h_timeout_ratio = if t.header_probe.sent == 0 {
            0.0
        } else {
            t.header_probe.timeouts as f32 / t.header_probe.sent as f32
        };
        let b_timeout_ratio = if t.body_probe.sent == 0 {
            0.0
        } else {
            t.body_probe.timeouts as f32 / t.body_probe.sent as f32
        };
        if h_timeout_ratio >= baseline_timeout_ratio + 0.35
            || b_timeout_ratio >= baseline_timeout_ratio + 0.35
        {
            findings.push(DefenseFinding {
                severity: "medium".to_string(),
                category: "fragment-audit".to_string(),
                rule: "reassembly-timeout-surge".to_string(),
                message: format!(
                    "payload tier {} shows significant timeout increase",
                    t.payload_bytes
                ),
                evidence: format!(
                    "baseline_timeout_ratio={:.2} header_timeout_ratio={:.2} body_timeout_ratio={:.2}",
                    baseline_timeout_ratio, h_timeout_ratio, b_timeout_ratio
                ),
            });
        }

        let hdr_block = t.header_probe.block_ratio;
        let body_block = t.body_probe.block_ratio;
        if hdr_block >= 0.6 || body_block >= 0.6 {
            findings.push(DefenseFinding {
                severity: "info".to_string(),
                category: "fragment-audit".to_string(),
                rule: "size-threshold-blocking".to_string(),
                message: format!(
                    "defense likely enforces payload/size threshold around {} bytes",
                    t.payload_bytes
                ),
                evidence: format!(
                    "header_block_ratio={:.2} body_block_ratio={:.2}",
                    hdr_block, body_block
                ),
            });
        }
    }

    if findings.is_empty() {
        findings.push(DefenseFinding {
            severity: "info".to_string(),
            category: "fragment-audit".to_string(),
            rule: "no-strong-fragment-signal".to_string(),
            message: "no strong resilience or fragility signal observed in current tiers"
                .to_string(),
            evidence: "increase tier range or request count for stronger confidence".to_string(),
        });
    }
    findings
}

fn score_fragment_resilience(
    baseline: &PhaseStats,
    tiers: &[FragmentTierStats],
    header_signals: &BTreeSet<String>,
    error_count: usize,
) -> (u8, u8, Vec<String>) {
    let mut timeout_ratio_sum = 0.0f32;
    let mut block_ratio_sum = 0.0f32;
    let mut network_error_sum = 0.0f32;
    let mut tier_samples = 0usize;
    for t in tiers {
        for s in [&t.header_probe, &t.body_probe] {
            if s.sent == 0 {
                continue;
            }
            timeout_ratio_sum += s.timeouts as f32 / s.sent as f32;
            block_ratio_sum += s.block_ratio;
            network_error_sum += s.network_errors as f32 / s.sent as f32;
            tier_samples += 1;
        }
    }
    let avg_timeout_ratio = if tier_samples == 0 {
        0.0
    } else {
        timeout_ratio_sum / tier_samples as f32
    };
    let avg_block_ratio = if tier_samples == 0 {
        0.0
    } else {
        block_ratio_sum / tier_samples as f32
    };
    let avg_neterr_ratio = if tier_samples == 0 {
        0.0
    } else {
        network_error_sum / tier_samples as f32
    };

    let baseline_success = if baseline.sent == 0 {
        0.0
    } else {
        baseline.success as f32 / baseline.sent as f32
    };
    let deterministic = (1.0 - (avg_timeout_ratio + avg_neterr_ratio).min(1.0)).max(0.0);
    let controlled_blocking = avg_block_ratio.min(0.75) / 0.75;

    let mut score = 30.0f32;
    score += baseline_success * 25.0;
    score += deterministic * 30.0;
    score += controlled_blocking * 10.0;
    score += (header_signals.len() as f32 * 2.0).min(10.0);
    score -= (error_count as f32 * 0.3).min(15.0);
    score = score.clamp(0.0, 100.0);

    let total_samples = baseline.sent
        + tiers
            .iter()
            .map(|t| t.header_probe.sent + t.body_probe.sent)
            .sum::<usize>();
    let mut confidence = 30.0f32 + (total_samples as f32 * 1.4).min(60.0);
    confidence -= (error_count as f32 * 0.9).min(20.0);
    confidence = confidence.clamp(10.0, 99.0);

    let mut rec = Vec::new();
    if score < 45.0 {
        rec.push("分片/重组稳健性偏弱：建议调优网关与反向代理对大请求的超时与缓存策略".to_string());
        rec.push("建议重点检查 L7 设备对大 Header/Body 的限额与错误处理一致性".to_string());
    } else if score < 70.0 {
        rec.push("分片防护中等：建议持续做分层 payload 回归，监控 timeout 与 5xx 漂移".to_string());
    } else {
        rec.push("分片防护表现较好：建议固化阈值基线并定期回归验证策略稳定性".to_string());
    }
    if confidence < 60.0 {
        rec.push("当前置信度偏低：建议增加 requests-per-tier 与 tier 范围".to_string());
    }
    (score.round() as u8, confidence.round() as u8, rec)
}

fn push_limited_error(errors: &mut Vec<String>, msg: String, limit: usize) {
    if errors.len() < limit {
        errors.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        PhaseStats, ProbeVariant, VariantProbeStats, build_probe_url, build_variant_probe_url,
        derive_anti_scan_findings, is_block_like_status, normalize_http_target,
    };

    #[test]
    fn normalize_http_target_preserves_base_path() {
        let got = normalize_http_target("https://demo.test:8443/app/").unwrap();
        assert_eq!(got, "https://demo.test:8443/app");
    }

    #[test]
    fn build_probe_url_appends_path() {
        let url = build_probe_url("https://demo.test:8443/base", "abc", 2);
        assert_eq!(
            url,
            "https://demo.test:8443/base/.well-known/rscan-probe-abc-2"
        );
    }

    #[test]
    fn build_variant_url_path_encoding_contains_encoded_bytes() {
        let url = build_variant_probe_url(
            "https://demo.test:8443/base",
            "abc",
            2,
            ProbeVariant::PathEncoding,
        );
        assert!(url.contains("%72scan"));
        assert!(url.contains("%2Ftest"));
    }

    #[test]
    fn block_like_status_has_expected_codes() {
        assert!(is_block_like_status(403));
        assert!(is_block_like_status(429));
        assert!(is_block_like_status(521));
        assert!(!is_block_like_status(200));
    }

    #[test]
    fn derive_findings_detects_behavioral_blocking() {
        let low = PhaseStats {
            sent: 10,
            success: 9,
            blocked: 1,
            timeouts: 0,
            network_errors: 1,
            avg_latency_ms: 100,
            p95_latency_ms: 180,
            block_ratio: 0.10,
        };
        let burst = PhaseStats {
            sent: 20,
            success: 8,
            blocked: 10,
            timeouts: 2,
            network_errors: 0,
            avg_latency_ms: 260,
            p95_latency_ms: 500,
            block_ratio: 0.50,
        };
        let mut signals = BTreeSet::new();
        signals.insert("cloudflare-signal".to_string());
        let variants = vec![VariantProbeStats {
            name: "query-noise".to_string(),
            stats: PhaseStats {
                sent: 8,
                success: 1,
                blocked: 7,
                timeouts: 1,
                network_errors: 0,
                avg_latency_ms: 220,
                p95_latency_ms: 350,
                block_ratio: 0.87,
            },
        }];
        let findings = derive_anti_scan_findings(&low, &burst, &variants, &signals);
        assert!(findings.iter().any(|f| f.rule == "waf-header-signals"));
        assert!(findings.iter().any(|f| f.rule == "behavioral-blocking"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "latency-throttling-signal")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "variant-sensitive-filter")
        );
    }
}
