use super::*;

#[derive(Debug, Clone, Copy)]
pub(in crate::cli::app) struct EngineTuning {
    workers: usize,
    max_in_flight: usize,
    timeout_ms: u64,
    retries: u32,
    retry_delay_ms: Option<u64>,
}

pub(in crate::cli::app) fn async_engine_tuning(profile: ScanProfile) -> EngineTuning {
    match profile {
        ScanProfile::LowNoise => EngineTuning {
            workers: 8,
            max_in_flight: 16,
            timeout_ms: 2500,
            retries: 1,
            retry_delay_ms: Some(120),
        },
        ScanProfile::Balanced => EngineTuning {
            workers: 64,
            max_in_flight: 64,
            timeout_ms: 1200,
            retries: 1,
            retry_delay_ms: None,
        },
        ScanProfile::Aggressive => EngineTuning {
            workers: 128,
            max_in_flight: 128,
            timeout_ms: 900,
            retries: 0,
            retry_delay_ms: None,
        },
    }
}

pub(in crate::cli::app) fn raw_engine_tuning(profile: ScanProfile) -> EngineTuning {
    match profile {
        ScanProfile::LowNoise => EngineTuning {
            workers: 4,
            max_in_flight: 8,
            timeout_ms: 2800,
            retries: 1,
            retry_delay_ms: Some(140),
        },
        ScanProfile::Balanced => EngineTuning {
            workers: 16,
            max_in_flight: 256,
            timeout_ms: 1200,
            retries: 1,
            retry_delay_ms: None,
        },
        ScanProfile::Aggressive => EngineTuning {
            workers: 32,
            max_in_flight: 512,
            timeout_ms: 900,
            retries: 0,
            retry_delay_ms: None,
        },
    }
}

pub(in crate::cli::app) fn tcp_config_for_profile(
    profile: ScanProfile,
) -> crate::cores::host::TcpConfig {
    match profile {
        ScanProfile::LowNoise => crate::cores::host::TcpConfig {
            timeout_seconds: 4,
            timeout_ms: Some(2500),
            concurrent: true,
            concurrency: 16,
            retries: 1,
            max_rate: Some(220),
            jitter_ms: Some(12),
            scan_order: crate::cores::host::TcpScanOrder::Interleave,
            adaptive_backpressure: true,
        },
        ScanProfile::Balanced => crate::cores::host::TcpConfig {
            timeout_seconds: 2,
            timeout_ms: Some(1300),
            concurrent: true,
            concurrency: 512,
            retries: 0,
            max_rate: Some(3200),
            jitter_ms: Some(3),
            scan_order: crate::cores::host::TcpScanOrder::Interleave,
            adaptive_backpressure: true,
        },
        ScanProfile::Aggressive => crate::cores::host::TcpConfig {
            timeout_seconds: 1,
            timeout_ms: Some(800),
            concurrent: true,
            concurrency: 1024,
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: crate::cores::host::TcpScanOrder::Random,
            adaptive_backpressure: false,
        },
    }
}

pub(in crate::cli::app) fn tcp_config_with_overrides(
    profile: ScanProfile,
    tcp_timeout_ms: Option<u64>,
    tcp_concurrency: Option<usize>,
    tcp_retries: Option<u32>,
    tcp_max_rate: Option<u32>,
    tcp_jitter_ms: Option<u64>,
    tcp_scan_order: Option<TcpScanOrderArg>,
    tcp_adaptive_backpressure: bool,
) -> crate::cores::host::TcpConfig {
    let mut cfg = tcp_config_for_profile(profile);
    if let Some(ms) = tcp_timeout_ms {
        cfg.timeout_ms = Some(ms.max(1));
        cfg.timeout_seconds = std::cmp::max(1, ms / 1000);
    }
    if let Some(c) = tcp_concurrency {
        cfg.concurrency = c.max(1);
        cfg.concurrent = true;
    }
    if let Some(r) = tcp_retries {
        cfg.retries = r;
    }
    if let Some(rate) = tcp_max_rate {
        cfg.max_rate = Some(rate.max(1));
    }
    if let Some(j) = tcp_jitter_ms {
        cfg.jitter_ms = Some(j.min(200));
    }
    if let Some(order) = tcp_scan_order {
        cfg.scan_order = match order {
            TcpScanOrderArg::Serial => crate::cores::host::TcpScanOrder::Serial,
            TcpScanOrderArg::Random => crate::cores::host::TcpScanOrder::Random,
            TcpScanOrderArg::Interleave => crate::cores::host::TcpScanOrder::Interleave,
        };
    }
    if tcp_adaptive_backpressure {
        cfg.adaptive_backpressure = true;
    }
    cfg
}

pub(in crate::cli::app) fn turbo_phase1_config(
    mut cfg: crate::cores::host::TcpConfig,
) -> crate::cores::host::TcpConfig {
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(800).min(500));
    cfg.timeout_seconds = 1;
    cfg.concurrent = true;
    cfg.concurrency = cfg.concurrency.max(3072);
    cfg.retries = 0;
    cfg
}

pub(in crate::cli::app) fn turbo_phase2_verify_config(
    baseline: crate::cores::host::TcpConfig,
) -> crate::cores::host::TcpConfig {
    let mut cfg = baseline;
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(1000).max(1200));
    cfg.timeout_seconds = cfg.timeout_ms.unwrap_or(1200) / 1000;
    cfg.concurrent = true;
    cfg.concurrency = cfg.concurrency.clamp(128, 1024);
    cfg.retries = cfg.retries.max(1);
    cfg
}

pub(in crate::cli::app) fn turbo_phase2_verify_config_adaptive(
    baseline: crate::cores::host::TcpConfig,
    filtered_ratio: f64,
) -> crate::cores::host::TcpConfig {
    let mut cfg = baseline;
    let timeout_floor = if filtered_ratio >= 0.7 {
        1600
    } else if filtered_ratio >= 0.45 {
        1300
    } else {
        1100
    };
    cfg.timeout_ms = Some(cfg.timeout_ms.unwrap_or(1000).max(timeout_floor));
    cfg.timeout_seconds = std::cmp::max(1, cfg.timeout_ms.unwrap_or(timeout_floor) / 1000);
    cfg.concurrent = true;
    cfg.concurrency = if filtered_ratio >= 0.7 {
        cfg.concurrency.clamp(512, 1536)
    } else {
        cfg.concurrency.clamp(768, 2048)
    };
    cfg.retries = cfg.retries.max(1);
    cfg
}

pub(in crate::cli::app) fn merge_verified_tcp_subset(
    first: &mut HostScanResult,
    second: &HostScanResult,
    verified_ports: &[u16],
) {
    for &port in verified_ports {
        let status = if second.is_port_open(port) {
            crate::cores::host::PortStatus::Open
        } else if second.is_port_filtered(port) {
            crate::cores::host::PortStatus::Filtered
        } else {
            crate::cores::host::PortStatus::Closed
        };
        first.overwrite_port_status(port, status);
    }
    for detail in second.open_port_details() {
        first.merge_open_port_detail(detail.clone());
    }
}

pub(in crate::cli::app) fn prioritized_filtered_ports(filtered: &[u16]) -> Vec<u16> {
    // Common service ports worth a deterministic second look in adaptive mode.
    const PRIORITY: &[u16] = &[
        20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445,
        465, 587, 636, 873, 902, 912, 993, 995, 1433, 1521, 2049, 2179, 2375, 2376, 3306, 3389,
        4712, 5040, 5357, 5432, 5601, 5672, 5900, 6379, 6443, 7001, 7680, 7897, 8080, 8083, 8443,
        8888, 9000, 9012, 9013, 9200, 11211, 27017,
    ];
    let set: BTreeSet<u16> = filtered.iter().copied().collect();
    PRIORITY
        .iter()
        .filter(|p| set.contains(p))
        .copied()
        .collect()
}

pub(in crate::cli::app) fn sample_ports_for_autotune(ports: &[u16], limit: usize) -> Vec<u16> {
    if ports.is_empty() {
        return Vec::new();
    }
    if ports.len() <= limit {
        return ports.to_vec();
    }
    let stride = (ports.len() / limit.max(1)).max(1);
    let mut sampled = Vec::with_capacity(limit.min(ports.len()));
    for offset in 0..stride.min(16) {
        let mut idx = offset;
        while idx < ports.len() && sampled.len() < limit {
            sampled.push(ports[idx]);
            idx += stride;
        }
        if sampled.len() >= limit {
            break;
        }
    }
    sampled.sort_unstable();
    sampled.dedup();
    sampled
}

pub(in crate::cli::app) fn udp_config_for_profile(
    profile: ScanProfile,
) -> crate::cores::host::UdpConfig {
    match profile {
        ScanProfile::LowNoise => crate::cores::host::UdpConfig {
            send_timeout_seconds: 3,
            receive_timeout_seconds: 4,
            concurrent: true,
            concurrency: 6,
            probe_data: vec![0x00, 0x01],
            max_retries: 2,
            delay_ms: Some(80),
        },
        ScanProfile::Balanced => crate::cores::host::UdpConfig {
            send_timeout_seconds: 2,
            receive_timeout_seconds: 3,
            concurrent: true,
            concurrency: 32,
            probe_data: vec![0x00, 0x01, 0x02, 0x03],
            max_retries: 1,
            delay_ms: None,
        },
        ScanProfile::Aggressive => crate::cores::host::UdpConfig {
            send_timeout_seconds: 1,
            receive_timeout_seconds: 2,
            concurrent: true,
            concurrency: 128,
            probe_data: vec![0x00, 0x01, 0x02, 0x03],
            max_retries: 0,
            delay_ms: None,
        },
    }
}

pub(in crate::cli::app) fn parse_ports_flags(ports: &[String]) -> Result<Vec<u16>, RustpenError> {
    let merged = ports.join(",");
    crate::cores::host::parse_ports(&merged)
}

pub(in crate::cli::app) fn require_root_for_raw_scan(action: &str) -> Result<(), RustpenError> {
    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Err(RustpenError::ScanError(format!(
                "{action} requires root or CAP_NET_RAW"
            )));
        }
    }
    Ok(())
}

pub(in crate::cli::app) fn resolve_target_ip(host: &str) -> Result<std::net::IpAddr, RustpenError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    let addrs = (host, 0)
        .to_socket_addrs()
        .map_err(|e| RustpenError::InvalidHost(e.to_string()))?;
    addrs
        .map(|a| a.ip())
        .next()
        .ok_or_else(|| RustpenError::InvalidHost("no resolved ip".to_string()))
}

pub(in crate::cli::app) fn load_probe_engine_if_requested(
    service_detect: bool,
    probes_file: Option<PathBuf>,
) -> Result<Option<std::sync::Arc<ServiceProbeEngine>>, RustpenError> {
    if !service_detect {
        return Ok(None);
    }
    let path = resolve_service_probe_file_path(probes_file)?;
    let engine = ServiceProbeEngine::from_nmap_file(path)?;
    Ok(Some(std::sync::Arc::new(engine)))
}

fn resolve_service_probe_file_path(probes_file: Option<PathBuf>) -> Result<PathBuf, RustpenError> {
    let env_probe = std::env::var("RSCAN_NMAP_SERVICE_PROBES").ok();
    resolve_service_probe_file_path_with(probes_file, env_probe, default_nmap_service_probe_paths())
}

fn resolve_service_probe_file_path_with(
    probes_file: Option<PathBuf>,
    env_probe: Option<String>,
    candidates: Vec<PathBuf>,
) -> Result<PathBuf, RustpenError> {
    if let Some(path) = probes_file {
        return Ok(path);
    }

    if let Some(path) = env_probe {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Ok(p);
        }
    }

    if let Some(path) = candidates.iter().find(|path| path.is_file()).cloned() {
        return Ok(path);
    }

    let searched = candidates
        .into_iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(RustpenError::ParseError(format!(
        "--service-detect enabled but nmap-service-probes not found; pass --probes-file or set RSCAN_NMAP_SERVICE_PROBES (searched: {searched})"
    )))
}

fn default_nmap_service_probe_paths() -> Vec<PathBuf> {
    let mut out = vec![
        PathBuf::from("/usr/share/nmap/nmap-service-probes"),
        PathBuf::from("/usr/local/share/nmap/nmap-service-probes"),
        PathBuf::from("/opt/homebrew/share/nmap/nmap-service-probes"),
        PathBuf::from("/opt/local/share/nmap/nmap-service-probes"),
        PathBuf::from("/data/data/com.termux/files/usr/share/nmap/nmap-service-probes"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        out.push(
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("nmap")
                .join("nmap-service-probes"),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_service_probe_prefers_explicit_path() {
        let tmp = std::env::temp_dir().join("rscan_probe_explicit.txt");
        std::fs::write(&tmp, "Probe TCP NULL q||\n").unwrap();
        let out = resolve_service_probe_file_path_with(Some(tmp.clone()), None, vec![])
            .expect("explicit path should be accepted");
        assert_eq!(out, tmp);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn resolve_service_probe_uses_env_when_set() {
        let tmp = std::env::temp_dir().join("rscan_probe_env.txt");
        std::fs::write(&tmp, "Probe TCP NULL q||\n").unwrap();
        let out =
            resolve_service_probe_file_path_with(None, Some(tmp.display().to_string()), vec![])
                .expect("env path should be accepted");
        assert_eq!(out, tmp);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn resolve_service_probe_uses_first_existing_candidate() {
        let tmp = std::env::temp_dir().join("rscan_probe_candidate.txt");
        std::fs::write(&tmp, "Probe TCP NULL q||\n").unwrap();
        let out = resolve_service_probe_file_path_with(
            None,
            None,
            vec![PathBuf::from("/nonexistent/probes"), tmp.clone()],
        )
        .expect("candidate path should be discovered");
        assert_eq!(out, tmp);
        let _ = std::fs::remove_file(&tmp);
    }
}

pub(in crate::cli::app) fn probe_engine_stats_line(
    engine: &std::sync::Arc<ServiceProbeEngine>,
) -> String {
    let stats = engine.load_stats();
    format!(
        "probe-engine loaded: probes={} rules={} skipped_rules={}",
        stats.probes, stats.loaded_rules, stats.skipped_rules
    )
}

fn is_queue_backpressure(err: &RustpenError) -> bool {
    matches!(err, RustpenError::Generic(msg) if msg.contains("no available capacity"))
}

fn drain_ready_results(
    rx: &mut tokio::sync::mpsc::Receiver<EngineScanResult>,
    out: &mut Vec<EngineScanResult>,
) {
    while let Ok(item) = rx.try_recv() {
        out.push(item);
    }
}

async fn submit_with_backpressure(
    engine: &impl ScanEngine,
    rx: &mut tokio::sync::mpsc::Receiver<EngineScanResult>,
    out: &mut Vec<EngineScanResult>,
    job: ScanJob,
) -> Result<(), RustpenError> {
    loop {
        match engine.submit(job.clone()) {
            Ok(()) => {
                drain_ready_results(rx, out);
                return Ok(());
            }
            Err(err) if is_queue_backpressure(&err) => match rx.recv().await {
                Some(item) => out.push(item),
                None => return Err(err),
            },
            Err(err) => return Err(err),
        }
    }
}

pub(in crate::cli::app) async fn run_engine_host_scan(
    host: &str,
    ports: &[u16],
    scan_type: ScanType,
    probe_engine: Option<std::sync::Arc<ServiceProbeEngine>>,
    profile: ScanProfile,
    syn_mode: Option<SynMode>,
) -> Result<Vec<EngineScanResult>, RustpenError> {
    let target_ip = resolve_target_ip(host)?;
    let mut out = Vec::new();
    match scan_type {
        ScanType::Connect | ScanType::UdpProbe | ScanType::Dns => {
            let tuning = async_engine_tuning(profile);
            let mut engine = AsyncConnectEngine::new_with_probe(1024, tuning.workers, probe_engine);
            let mut rx = engine.take_results()?;
            for &p in ports {
                let protocol = match scan_type {
                    ScanType::Connect => crate::cores::host::Protocol::Tcp,
                    ScanType::Dns => crate::cores::host::Protocol::Dns,
                    _ => crate::cores::host::Protocol::Udp,
                };
                let mut job = ScanJob::new(target_ip, protocol, scan_type.clone())
                    .with_port(p)
                    .with_timeout_ms(tuning.timeout_ms)
                    .with_retries(tuning.retries);
                if let Some(d) = tuning.retry_delay_ms {
                    job = job.with_retry_delay_ms(d);
                }
                submit_with_backpressure(&engine, &mut rx, &mut out, job).await?;
            }
            let expected = ports.len();
            drop(engine);
            while out.len() < expected {
                match rx.recv().await {
                    Some(r) => out.push(r),
                    None => break,
                }
            }
        }
        ScanType::Syn | ScanType::IcmpEcho | ScanType::Arp => {
            require_root_for_raw_scan("raw packet scan")?;
            let tuning = raw_engine_tuning(profile);
            let mut engine = RawPacketEngine::new_with_probe(
                1024,
                tuning.workers,
                tuning.max_in_flight,
                probe_engine,
            );
            let mut rx = engine.take_results()?;
            for &p in ports {
                let mut job = ScanJob::new(
                    target_ip,
                    crate::cores::host::Protocol::Tcp,
                    scan_type.clone(),
                )
                .with_port(p)
                .with_timeout_ms(tuning.timeout_ms)
                .with_retries(tuning.retries);
                if matches!(scan_type, ScanType::Syn) {
                    job = match syn_mode.unwrap_or(SynMode::VerifyFiltered) {
                        SynMode::Strict => job.with_tag("syn_mode:strict"),
                        SynMode::VerifyFiltered => job.with_tag("syn_mode:verify-filtered"),
                    };
                }
                if let Some(d) = tuning.retry_delay_ms {
                    job = job.with_retry_delay_ms(d);
                }
                submit_with_backpressure(&engine, &mut rx, &mut out, job).await?;
            }
            let expected = ports.len();
            drop(engine);
            while out.len() < expected {
                match rx.recv().await {
                    Some(r) => out.push(r),
                    None => break,
                }
            }
        }
    }
    out.sort_by_key(|r| r.port.unwrap_or(0));
    Ok(out)
}
