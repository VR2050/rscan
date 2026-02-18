use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};

use crate::cores::engine::scan_result::ScanStatus;

use super::dispatcher::CorrKey;
use super::hub::RawPacketHub;
use super::local_addr::{local_ipv4_for_destination, local_ipv6_for_destination};

pub(crate) struct SynBackend {
    hub: Arc<RawPacketHub>,
}

impl SynBackend {
    pub(crate) fn new(hub: Arc<RawPacketHub>) -> Result<Self, String> {
        if !hub.has_tcp() {
            return Err("raw hub has no tcp channels".to_string());
        }
        Ok(Self { hub })
    }

    pub(crate) async fn scan_v4(
        &self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        source_port: Option<u16>,
    ) -> ScanStatus {
        let Some(tx_v4) = self.hub.tcp_sender_for(IpAddr::V4(remote_ip)) else {
            return ScanStatus::Error;
        };
        let dispatcher = self.hub.dispatcher();
        for attempt in 0..=retries {
            let local_port = source_port.unwrap_or_else(|| choose_src_port(remote_port, attempt));
            let key = CorrKey::Tcp {
                remote_ip: IpAddr::V4(remote_ip),
                remote_port,
                local_port,
            };
            let rx_done = dispatcher.register(key.clone());
            if send_syn_v4(&tx_v4, remote_ip, remote_port, local_port).is_err() {
                dispatcher.remove(&key);
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), rx_done).await {
                Ok(Ok(reply)) => return reply.status,
                Ok(Err(_)) => {
                    dispatcher.remove(&key);
                }
                Err(_) => {
                    dispatcher.remove(&key);
                }
            }
            if attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }

        ScanStatus::Filtered
    }

    pub(crate) async fn scan_v6(
        &self,
        remote_ip: Ipv6Addr,
        remote_port: u16,
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        source_port: Option<u16>,
    ) -> ScanStatus {
        let Some(tx_v6) = self.hub.tcp_sender_for(IpAddr::V6(remote_ip)) else {
            return ScanStatus::Error;
        };
        let dispatcher = self.hub.dispatcher();
        for attempt in 0..=retries {
            let local_port = source_port.unwrap_or_else(|| choose_src_port(remote_port, attempt));
            let key = CorrKey::Tcp {
                remote_ip: IpAddr::V6(remote_ip),
                remote_port,
                local_port,
            };
            let rx_done = dispatcher.register(key.clone());
            if send_syn_v6(&tx_v6, remote_ip, remote_port, local_port).is_err() {
                dispatcher.remove(&key);
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), rx_done).await {
                Ok(Ok(reply)) => return reply.status,
                Ok(Err(_)) => {
                    dispatcher.remove(&key);
                }
                Err(_) => {
                    dispatcher.remove(&key);
                }
            }
            if attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }

        ScanStatus::Filtered
    }
}

fn choose_src_port(remote_port: u16, attempt: u32) -> u16 {
    // Deterministic but varying per attempt, no extra dependencies.
    let base = 40000u16;
    let span = 20000u16;
    let v = remote_port
        .wrapping_mul(37)
        .wrapping_add(attempt as u16 * 101);
    base + (v % span)
}

fn send_syn_v4(
    tx: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_port: u16,
) -> Result<(), String> {
    let local_ip = local_ipv4_for_destination(remote_ip).map_err(|e| e.to_string())?;
    let seq_num: u32 = 0x1234_0000u32 ^ (local_port as u32) ^ (remote_port as u32);

    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet =
        MutableTcpPacket::new(&mut tcp_buffer[..]).ok_or("tcp_packet alloc failed")?;
    tcp_packet.set_source(local_port);
    tcp_packet.set_destination(remote_port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    let checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &local_ip, &remote_ip);
    tcp_packet.set_checksum(checksum);

    let mut guard = tx.lock().unwrap();
    guard
        .send_to(&tcp_packet.to_immutable(), IpAddr::V4(remote_ip))
        .map_err(|e| format!("send_to failed: {e}"))?;
    Ok(())
}

fn send_syn_v6(
    tx: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv6Addr,
    remote_port: u16,
    local_port: u16,
) -> Result<(), String> {
    let local_ip = local_ipv6_for_destination(remote_ip).map_err(|e| e.to_string())?;
    let seq_num: u32 = 0x1234_0000u32 ^ (local_port as u32) ^ (remote_port as u32);

    let mut tcp_buffer = [0u8; 20];
    let mut tcp_packet =
        MutableTcpPacket::new(&mut tcp_buffer[..]).ok_or("tcp_packet alloc failed")?;
    tcp_packet.set_source(local_port);
    tcp_packet.set_destination(remote_port);
    tcp_packet.set_sequence(seq_num);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    let checksum =
        pnet::packet::tcp::ipv6_checksum(&tcp_packet.to_immutable(), &local_ip, &remote_ip);
    tcp_packet.set_checksum(checksum);

    let mut guard = tx.lock().unwrap();
    guard
        .send_to(&tcp_packet.to_immutable(), IpAddr::V6(remote_ip))
        .map_err(|e| format!("send_to failed: {e}"))?;
    Ok(())
}

// local address selection lives in backends::local_addr
