use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::packet::Packet;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, checksum};
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, checksum as checksum_v6};

use crate::cores::engine::scan_result::ScanStatus;

use super::dispatcher::CorrKey;
use super::hub::RawPacketHub;
use super::local_addr::local_ipv6_for_destination;

pub(crate) struct IcmpBackend {
    seq: AtomicU64,
    hub: Arc<RawPacketHub>,
}

impl IcmpBackend {
    pub(crate) fn new(hub: Arc<RawPacketHub>) -> Result<Self, String> {
        if !hub.has_icmp() {
            return Err("raw hub has no icmp channels".to_string());
        }
        Ok(Self {
            seq: AtomicU64::new(1),
            hub,
        })
    }

    pub(crate) async fn echo_v4(
        &self,
        remote_ip: Ipv4Addr,
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        ident: u16,
    ) -> ScanStatus {
        let Some(tx_v4) = self.hub.icmp_sender_for(IpAddr::V4(remote_ip)) else {
            return ScanStatus::Error;
        };
        let dispatcher = self.hub.dispatcher();
        for _attempt in 0..=retries {
            let seq = (self.seq.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
            let key = CorrKey::IcmpEcho {
                remote_ip: IpAddr::V4(remote_ip),
                ident,
                seq,
            };
            let rx_done = dispatcher.register(key.clone());
            if send_echo_v4(&tx_v4, remote_ip, ident, seq).is_err() {
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
            if _attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }
        ScanStatus::Filtered
    }

    pub(crate) async fn echo_v6(
        &self,
        remote_ip: Ipv6Addr,
        timeout_ms: u64,
        retries: u32,
        retry_delay_ms: Option<u64>,
        ident: u16,
    ) -> ScanStatus {
        let Some(tx_v6) = self.hub.icmp_sender_for(IpAddr::V6(remote_ip)) else {
            return ScanStatus::Error;
        };
        let dispatcher = self.hub.dispatcher();
        for _attempt in 0..=retries {
            let seq = (self.seq.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
            let key = CorrKey::IcmpEcho {
                remote_ip: IpAddr::V6(remote_ip),
                ident,
                seq,
            };
            let rx_done = dispatcher.register(key.clone());
            if send_echo_v6(&tx_v6, remote_ip, ident, seq).is_err() {
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
            if _attempt < retries {
                if let Some(d) = retry_delay_ms {
                    tokio::time::sleep(Duration::from_millis(d.max(1))).await;
                }
            }
        }
        ScanStatus::Filtered
    }
}

fn send_echo_v4(
    tx: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv4Addr,
    ident: u16,
    seq: u16,
) -> Result<(), String> {
    let mut buf = [0u8; 64];
    let mut pkt = MutableEchoRequestPacket::new(&mut buf)
        .ok_or_else(|| "build_icmp_packet_failed".to_string())?;
    pkt.set_icmp_type(IcmpTypes::EchoRequest);
    pkt.set_identifier(ident);
    pkt.set_sequence_number(seq);
    pkt.set_payload(&[0x13, 0x37, 0xAA, 0x55]);

    let icmp_packet =
        IcmpPacket::new(pkt.packet()).ok_or_else(|| "icmp_packet_parse_failed".to_string())?;
    let csum = checksum(&icmp_packet);
    pkt.set_checksum(csum);

    let mut guard = tx.lock().unwrap();
    guard
        .send_to(pkt, IpAddr::V4(remote_ip))
        .map_err(|e| format!("icmp send_to failed: {e}"))?;
    Ok(())
}

fn send_echo_v6(
    tx: &Arc<Mutex<pnet::transport::TransportSender>>,
    remote_ip: Ipv6Addr,
    ident: u16,
    seq: u16,
) -> Result<(), String> {
    let local_ip = local_ipv6_for_destination(remote_ip).map_err(|e| e.to_string())?;

    let mut buf = [0u8; 64];
    let mut pkt = MutableEchoRequestPacketV6::new(&mut buf)
        .ok_or_else(|| "build_icmpv6_packet_failed".to_string())?;
    pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
    pkt.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));
    pkt.set_identifier(ident);
    pkt.set_sequence_number(seq);
    pkt.set_payload(&[0x13, 0x37, 0xAA, 0x55]);

    let icmp_packet =
        Icmpv6Packet::new(pkt.packet()).ok_or_else(|| "icmpv6_packet_parse_failed".to_string())?;
    let csum = checksum_v6(&icmp_packet, &local_ip, &remote_ip);
    pkt.set_checksum(csum);

    let mut guard = tx.lock().unwrap();
    guard
        .send_to(pkt, IpAddr::V6(remote_ip))
        .map_err(|e| format!("icmpv6 send_to failed: {e}"))?;
    Ok(())
}
// local address selection lives in backends::local_addr
