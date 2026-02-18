use std::time::{Duration, Instant};

use crate::cores::engine::scan_job::ScanJob;
use crate::cores::engine::scan_result::{ScanResult, ScanStatus};
use crate::cores::host::Protocol;
use crate::cores::host::arp_scan::{ArpConfig, ArpScanner};

pub(crate) async fn scan_arp(job: ScanJob) -> ScanResult {
    let target = job.target_ip;
    let start = Instant::now();
    let target_v4 = match target {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => {
            return ScanResult::new(job.target_ip, Protocol::Arp, ScanStatus::Unknown)
                .with_meta("engine", "raw")
                .with_meta("scan_type", "arp")
                .with_meta("reason", "arp_only_supports_ipv4");
        }
    };

    let cidr = format!("{}/32", target_v4);
    let cfg = ArpConfig {
        interface: None,
        timeout: Duration::from_millis(job.timeout_ms.max(1)),
    };
    let scanner = ArpScanner::new(cfg);
    match scanner.scan_cidr(&cidr).await {
        Ok(hosts) => {
            let alive = hosts.iter().any(|h| h.ip == target_v4);
            let mut out = ScanResult::new(
                job.target_ip,
                Protocol::Arp,
                if alive {
                    ScanStatus::Open
                } else {
                    ScanStatus::Filtered
                },
            )
            .with_latency_ms(start.elapsed().as_millis() as u64)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "arp");
            if let Some(h) = hosts.iter().find(|h| h.ip == target_v4) {
                out = out.with_meta("mac", h.mac.to_string());
                out = out.with_meta("interface", h.interface.clone());
            }
            out
        }
        Err(e) => ScanResult::new(job.target_ip, Protocol::Arp, ScanStatus::Error)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "arp")
            .with_meta("error", e.to_string()),
    }
}
