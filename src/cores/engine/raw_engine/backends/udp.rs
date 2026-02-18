use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::packet::udp::MutableUdpPacket;

use crate::cores::engine::scan_result::ScanStatus;

#[derive(Debug)]
pub(crate) struct UdpReply {
    pub(crate) status: ScanStatus,
    pub(crate) payload: Option<Vec<u8>>,
}

use super::dispatcher::CorrKey;
use super::hub::RawPacketHub;
use super::local_addr::{local_ipv4_for_destination, local_ipv6_for_destination};

pub(crate) struct UdpBackend {
    port_seq: AtomicU16,
    hub: Arc<RawPacketHub>,
}

impl UdpBackend {
    pub(crate) fn new(hub: Arc<RawPacketHub>) -> Result<Self, String> {
        if !hub.has_udp() {
            return Err("raw hub has no udp channels".to_string());
        }
        Ok(Self {
            port_seq: AtomicU16::new(40000),
            hub,
        })
    }

    pub(crate) async fn probe_v4(
        &self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        payload: &[u8],
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        source_port: Option<u16>,
    ) -> UdpReply {
        let Some(tx_udp_v4) = self.hub.udp_sender_for(IpAddr::V4(remote_ip)) else {
            return UdpReply {
                status: ScanStatus::Error,
                payload: None,
            };
        };
        let dispatcher = self.hub.dispatcher();

        for _attempt in 0..=retries {
            let local_port = source_port.unwrap_or_else(|| self.next_src_port());
            let key = CorrKey::Udp {
                remote_ip: IpAddr::V4(remote_ip),
                remote_port,
                local_port,
            };
            let rx_done = dispatcher.register(key.clone());

            let payload_vec = payload.to_vec();
            if send_udp_v4(&tx_udp_v4, remote_ip, remote_port, local_port, &payload_vec).is_err() {
                dispatcher.remove(&key);
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), rx_done).await {
                Ok(Ok(reply)) => {
                    return UdpReply {
                        status: reply.status,
                        payload: reply.payload,
                    };
                }
                Ok(Err(_)) => {
                    dispatcher.remove(&key);
                }
                Err(_) => {
                    dispatcher.remove(&key);
                }
            }
            if _attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }

        UdpReply {
            status: ScanStatus::Filtered,
            payload: None,
        }
    }

    pub(crate) async fn probe_v6(
        &self,
        remote_ip: Ipv6Addr,
        remote_port: u16,
        payload: &[u8],
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        source_port: Option<u16>,
    ) -> UdpReply {
        let Some(tx_udp_v6) = self.hub.udp_sender_for(IpAddr::V6(remote_ip)) else {
            return UdpReply {
                status: ScanStatus::Error,
                payload: None,
            };
        };
        let dispatcher = self.hub.dispatcher();

        for _attempt in 0..=retries {
            let local_port = source_port.unwrap_or_else(|| self.next_src_port());
            let key = CorrKey::Udp {
                remote_ip: IpAddr::V6(remote_ip),
                remote_port,
                local_port,
            };
            let rx_done = dispatcher.register(key.clone());

            let payload_vec = payload.to_vec();
            if send_udp_v6(&tx_udp_v6, remote_ip, remote_port, local_port, &payload_vec).is_err() {
                dispatcher.remove(&key);
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(timeout_ms.max(1)), rx_done).await {
                Ok(Ok(reply)) => {
                    return UdpReply {
                        status: reply.status,
                        payload: reply.payload,
                    };
                }
                Ok(Err(_)) => {
                    dispatcher.remove(&key);
                }
                Err(_) => {
                    dispatcher.remove(&key);
                }
            }
            if _attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }

        UdpReply {
            status: ScanStatus::Filtered,
            payload: None,
        }
    }

    fn next_src_port(&self) -> u16 {
        // Keep ports in a high ephemeral range and avoid extra deps for randomness.
        let v = self.port_seq.fetch_add(1, Ordering::Relaxed);
        let base = 40000u16;
        let span = 20000u16;
        base + (v % span)
    }
}

fn send_udp_v4(
    tx_udp: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    local_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let local_ip = local_ipv4_for_destination(remote_ip).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 8 + payload.len()];
    let mut pkt = MutableUdpPacket::new(&mut buf).ok_or("udp_packet alloc failed")?;
    pkt.set_source(local_port);
    pkt.set_destination(remote_port);
    pkt.set_length((8 + payload.len()) as u16);
    pkt.set_payload(payload);
    let csum = pnet::packet::udp::ipv4_checksum(&pkt.to_immutable(), &local_ip, &remote_ip);
    pkt.set_checksum(csum);

    let mut guard = tx_udp.lock().unwrap();
    guard
        .send_to(pkt, IpAddr::V4(remote_ip))
        .map_err(|e| format!("udp send_to failed: {e}"))?;
    Ok(())
}

fn send_udp_v6(
    tx_udp: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv6Addr,
    remote_port: u16,
    local_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let local_ip = local_ipv6_for_destination(remote_ip).map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; 8 + payload.len()];
    let mut pkt = MutableUdpPacket::new(&mut buf).ok_or("udp_packet alloc failed")?;
    pkt.set_source(local_port);
    pkt.set_destination(remote_port);
    pkt.set_length((8 + payload.len()) as u16);
    pkt.set_payload(payload);
    let csum = pnet::packet::udp::ipv6_checksum(&pkt.to_immutable(), &local_ip, &remote_ip);
    pkt.set_checksum(csum);

    let mut guard = tx_udp.lock().unwrap();
    guard
        .send_to(pkt, IpAddr::V6(remote_ip))
        .map_err(|e| format!("udp send_to failed: {e}"))?;
    Ok(())
}

// local address selection lives in backends::local_addr
