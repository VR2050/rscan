use std::time::Instant;

use super::super::backends::icmp::IcmpBackend;
use crate::cores::engine::scan_job::ScanJob;
use crate::cores::engine::scan_result::{ScanResult, ScanStatus};
use crate::cores::host::Protocol;
use std::sync::Arc;

pub(crate) async fn scan_icmp(job: ScanJob, backend: Option<Arc<IcmpBackend>>) -> ScanResult {
    if let Some(backend) = backend {
        match job.target_ip {
            std::net::IpAddr::V4(v4) => {
                let start = Instant::now();
                let status = backend
                    .echo_v4(v4, job.timeout_ms, job.retries, job.retry_delay_ms, 0x1234)
                    .await;
                return ScanResult::new(job.target_ip, Protocol::Icmp, status)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_meta("engine", "raw")
                    .with_meta("scan_type", "icmp_backend");
            }
            std::net::IpAddr::V6(v6) => {
                let start = Instant::now();
                let status = backend
                    .echo_v6(v6, job.timeout_ms, job.retries, job.retry_delay_ms, 0x1234)
                    .await;
                return ScanResult::new(job.target_ip, Protocol::Icmp, status)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_meta("engine", "raw")
                    .with_meta("scan_type", "icmp_backend");
            }
        }
    }

    let target = job.target_ip;
    let timeout_ms = job.timeout_ms.max(1);
    let retries = job.retries;
    let start = Instant::now();

    let result =
        tokio::task::spawn_blocking(move || icmp_echo_blocking(target, timeout_ms, retries)).await;

    match result {
        Ok(Ok(())) => ScanResult::new(job.target_ip, Protocol::Icmp, ScanStatus::Open)
            .with_latency_ms(start.elapsed().as_millis() as u64)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "icmp_legacy"),
        Ok(Err(e)) => ScanResult::new(job.target_ip, Protocol::Icmp, ScanStatus::Filtered)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "icmp_legacy")
            .with_meta("error", e),
        Err(e) => ScanResult::new(job.target_ip, Protocol::Icmp, ScanStatus::Error)
            .with_meta("engine", "raw")
            .with_meta("scan_type", "icmp_legacy")
            .with_meta("error", e.to_string()),
    }
}

fn icmp_echo_blocking(
    target: std::net::IpAddr,
    timeout_ms: u64,
    retries: u32,
) -> Result<(), String> {
    use pnet::packet::Packet;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes, checksum};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::transport::TransportProtocol::Ipv4;
    use pnet::transport::{TransportChannelType, icmp_packet_iter, transport_channel};
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    let target_v4 = match target {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err("icmp_echo_ipv6_not_supported_yet".to_string()),
    };

    let (mut tx, mut rx) = transport_channel(
        1024,
        TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .map_err(|e| format!("transport_channel_failed: {e}"))?;

    for attempt in 0..=retries {
        let mut buf = [0u8; 64];
        let mut pkt = MutableEchoRequestPacket::new(&mut buf)
            .ok_or_else(|| "build_icmp_packet_failed".to_string())?;
        pkt.set_icmp_type(IcmpTypes::EchoRequest);
        pkt.set_identifier(0x1234);
        pkt.set_sequence_number(attempt as u16);
        pkt.set_payload(&[0x13, 0x37, 0xAA, 0x55]);
        let icmp_packet =
            IcmpPacket::new(pkt.packet()).ok_or_else(|| "icmp_packet_parse_failed".to_string())?;
        let csum = checksum(&icmp_packet);
        pkt.set_checksum(csum);

        tx.send_to(pkt, IpAddr::V4(target_v4))
            .map_err(|e| format!("icmp_send_failed: {e}"))?;

        let mut iter = icmp_packet_iter(&mut rx);
        let end_at = Instant::now() + Duration::from_millis(timeout_ms);
        while Instant::now() < end_at {
            match iter.next_with_timeout(Duration::from_millis(50)) {
                Ok(Some((packet, src))) => {
                    if src == IpAddr::V4(target_v4)
                        && packet.get_icmp_type() == IcmpTypes::EchoReply
                    {
                        return Ok(());
                    }
                }
                Ok(None) => {}
                Err(e) => return Err(format!("icmp_recv_failed: {e}")),
            }
        }
    }

    Err("icmp_timeout".to_string())
}
