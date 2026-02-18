use std::time::Instant;

use crate::cores::host::udp_scanner::{UdpConfig, UdpScanner};
use crate::cores::host::{PortScanner, Protocol};

use crate::cores::engine::scan_job::ScanJob;
use crate::cores::engine::scan_result::{ScanResult, ScanStatus};

use super::super::util::map_port_status;
use crate::cores::engine::raw_engine::backends::udp::UdpBackend;
use std::net::IpAddr;
use std::sync::Arc;

pub(crate) async fn scan_udp(
    job: ScanJob,
    dns_probe: bool,
    udp_backend: Option<Arc<UdpBackend>>,
) -> ScanResult {
    let port = job.port.unwrap_or(if dns_probe { 53 } else { 0 });
    if port == 0 {
        return ScanResult::new(job.target_ip, Protocol::Udp, ScanStatus::Error)
            .with_meta("engine", "raw")
            .with_meta("error", "missing_port");
    }

    if let Some(backend) = udp_backend {
        let payload = job.payload.clone().unwrap_or_else(|| {
            if dns_probe {
                UdpConfig::dns_probe().probe_data
            } else {
                UdpConfig::default().probe_data
            }
        });
        let start = Instant::now();
        let reply = match job.target_ip {
            IpAddr::V4(remote_ip) => {
                backend
                    .probe_v4(
                        remote_ip,
                        port,
                        &payload,
                        job.timeout_ms,
                        job.retries,
                        job.retry_delay_ms,
                        None,
                    )
                    .await
            }
            IpAddr::V6(remote_ip) => {
                backend
                    .probe_v6(
                        remote_ip,
                        port,
                        &payload,
                        job.timeout_ms,
                        job.retries,
                        job.retry_delay_ms,
                        None,
                    )
                    .await
            }
        };

        let mut out = ScanResult::new(
            job.target_ip,
            if dns_probe {
                Protocol::Dns
            } else {
                Protocol::Udp
            },
            reply.status,
        )
        .with_port(port)
        .with_latency_ms(start.elapsed().as_millis() as u64)
        .with_meta("engine", "raw")
        .with_meta(
            "scan_type",
            if dns_probe {
                "dns_backend"
            } else {
                "udp_backend"
            },
        );
        if let Some(p) = reply.payload {
            out = out.with_response(p);
        }
        return out;
    }

    let mut cfg = if dns_probe {
        UdpConfig::dns_probe()
    } else {
        UdpConfig::default()
    };
    cfg.send_timeout_seconds = std::cmp::max(1, job.timeout_ms / 1000);
    cfg.receive_timeout_seconds = std::cmp::max(1, job.timeout_ms / 1000);
    cfg.max_retries = job.retries;
    cfg.concurrent = false;
    cfg.concurrency = 1;
    if let Some(payload) = &job.payload {
        cfg.probe_data = payload.clone();
    }

    let scanner = UdpScanner::new(cfg);
    let start = Instant::now();
    match scanner.scan_port(job.target_ip, port).await {
        Ok(r) => {
            let detail = r.get_port_detail(port);
            let status = map_port_status(r.is_port_open(port), detail.map(|d| d.status));
            let mut out = ScanResult::new(
                job.target_ip,
                if dns_probe {
                    Protocol::Dns
                } else {
                    Protocol::Udp
                },
                status,
            )
            .with_port(port)
            .with_latency_ms(start.elapsed().as_millis() as u64)
            .with_meta("engine", "raw")
            .with_meta(
                "scan_type",
                if dns_probe {
                    "dns_legacy"
                } else {
                    "udp_legacy"
                },
            );
            if let Some(d) = detail {
                if let Some(b) = &d.banner {
                    out = out.with_response(b.as_bytes().to_vec());
                }
            }
            out
        }
        Err(e) => ScanResult::new(
            job.target_ip,
            if dns_probe {
                Protocol::Dns
            } else {
                Protocol::Udp
            },
            ScanStatus::Error,
        )
        .with_port(port)
        .with_meta("engine", "raw")
        .with_meta(
            "scan_type",
            if dns_probe {
                "dns_legacy"
            } else {
                "udp_legacy"
            },
        )
        .with_meta("error", e.to_string()),
    }
}
