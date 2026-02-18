use std::time::Instant;

use crate::cores::host::syn_scan::{SynConfig, SynScanner};
use crate::cores::host::{PortScanner, Protocol};

use crate::cores::engine::scan_job::ScanJob;
use crate::cores::engine::scan_result::{ScanResult, ScanStatus};

use super::super::backends::syn::SynBackend;
use super::super::util::map_port_status;
use std::sync::Arc;

pub(crate) async fn scan_syn(job: ScanJob, backend: Option<Arc<SynBackend>>) -> ScanResult {
    let Some(port) = job.port else {
        return ScanResult::new(job.target_ip, Protocol::Tcp, ScanStatus::Error)
            .with_meta("engine", "raw")
            .with_meta("error", "missing_port");
    };

    // Prefer unified backend (single channel + rx loop). Fallback to legacy SynScanner if not available.
    if let Some(backend) = backend {
        match job.target_ip {
            std::net::IpAddr::V4(v4) => {
                let start = Instant::now();
                let status = backend
                    .scan_v4(
                        v4,
                        port,
                        job.timeout_ms,
                        job.retries,
                        job.retry_delay_ms,
                        None,
                    )
                    .await;
                return ScanResult::new(job.target_ip, Protocol::Tcp, status)
                    .with_port(port)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_meta("engine", "raw")
                    .with_meta("scan_type", "syn_backend");
            }
            std::net::IpAddr::V6(v6) => {
                let start = Instant::now();
                let status = backend
                    .scan_v6(
                        v6,
                        port,
                        job.timeout_ms,
                        job.retries,
                        job.retry_delay_ms,
                        None,
                    )
                    .await;
                return ScanResult::new(job.target_ip, Protocol::Tcp, status)
                    .with_port(port)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_meta("engine", "raw")
                    .with_meta("scan_type", "syn_backend");
            }
        }
    }

    let scanner = SynScanner::new(SynConfig {
        timeout_seconds: std::cmp::max(1, job.timeout_ms / 1000),
        concurrent: false,
        concurrency: 1,
        source_port: 0,
    });

    let start = Instant::now();
    match scanner.scan_port(job.target_ip, port).await {
        Ok(r) => {
            let status = map_port_status(
                r.is_port_open(port),
                r.get_port_detail(port).map(|d| d.status),
            );
            ScanResult::new(job.target_ip, Protocol::Tcp, status)
                .with_port(port)
                .with_latency_ms(start.elapsed().as_millis() as u64)
                .with_meta("engine", "raw")
                .with_meta("scan_type", "syn_legacy")
        }
        Err(e) => ScanResult::new(job.target_ip, Protocol::Tcp, ScanStatus::Error)
            .with_port(port)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "syn_legacy")
            .with_meta("error", e.to_string()),
    }
}
