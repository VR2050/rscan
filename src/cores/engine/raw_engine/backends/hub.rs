use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::udp::UdpPacket;
use pnet::transport::TransportProtocol::Ipv4 as TPIpv4;
use pnet::transport::TransportProtocol::Ipv6 as TPIpv6;
use pnet::transport::{
    TransportChannelType, icmp_packet_iter, icmpv6_packet_iter, tcp_packet_iter, transport_channel,
    udp_packet_iter,
};

use crate::cores::engine::scan_result::ScanStatus;

use super::dispatcher::{CorrKey, DispatchReply, Dispatcher};

pub(crate) struct RawPacketHub {
    running: Arc<AtomicBool>,
    dispatcher: Dispatcher,

    tcp_v4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
    tcp_v6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,

    udp_v4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
    udp_v6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,

    icmp_v4: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
    icmp_v6: Option<Arc<Mutex<pnet::transport::TransportSender>>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HubStats {
    pub(crate) has_tcp: bool,
    pub(crate) has_udp: bool,
    pub(crate) has_icmp: bool,
    pub(crate) dispatcher_inflight: usize,
}

impl RawPacketHub {
    pub(crate) fn new() -> Result<Self, String> {
        let dispatcher = Dispatcher::new();
        let running = Arc::new(AtomicBool::new(true));

        let mut any = false;

        let tcp_v4 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv4(IpNextHeaderProtocols::Tcp)),
        )
        .ok()
        .map(|(tx, rx)| {
            any = true;
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_tcp_rx_loop(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        let tcp_v6 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv6(IpNextHeaderProtocols::Tcp)),
        )
        .ok()
        .map(|(tx, rx)| {
            any = true;
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_tcp_rx_loop(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        let udp_v4 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv4(IpNextHeaderProtocols::Udp)),
        )
        .ok()
        .map(|(tx, rx)| {
            any = true;
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_udp_rx_loop(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        let udp_v6 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv6(IpNextHeaderProtocols::Udp)),
        )
        .ok()
        .map(|(tx, rx)| {
            any = true;
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_udp_rx_loop(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        // ICMP channels are optional (improves classification), do not require for "any".
        let icmp_v4 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv4(IpNextHeaderProtocols::Icmp)),
        )
        .ok()
        .map(|(tx, rx)| {
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_icmp_rx_loop_v4(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        let icmp_v6 = transport_channel(
            4096,
            TransportChannelType::Layer4(TPIpv6(IpNextHeaderProtocols::Icmpv6)),
        )
        .ok()
        .map(|(tx, rx)| {
            let tx = Arc::new(Mutex::new(tx));
            Self::spawn_icmp_rx_loop_v6(Arc::clone(&running), dispatcher.clone(), rx);
            tx
        });

        if !any && icmp_v4.is_none() && icmp_v6.is_none() {
            return Err("transport_channel failed for all protocols".to_string());
        }

        Ok(Self {
            running,
            dispatcher,
            tcp_v4,
            tcp_v6,
            udp_v4,
            udp_v6,
            icmp_v4,
            icmp_v6,
        })
    }

    pub(crate) fn dispatcher(&self) -> Dispatcher {
        self.dispatcher.clone()
    }

    pub(crate) fn tcp_sender_for(
        &self,
        ip: IpAddr,
    ) -> Option<Arc<Mutex<pnet::transport::TransportSender>>> {
        match ip {
            IpAddr::V4(_) => self.tcp_v4.clone(),
            IpAddr::V6(_) => self.tcp_v6.clone(),
        }
    }

    pub(crate) fn udp_sender_for(
        &self,
        ip: IpAddr,
    ) -> Option<Arc<Mutex<pnet::transport::TransportSender>>> {
        match ip {
            IpAddr::V4(_) => self.udp_v4.clone(),
            IpAddr::V6(_) => self.udp_v6.clone(),
        }
    }

    pub(crate) fn icmp_sender_for(
        &self,
        ip: IpAddr,
    ) -> Option<Arc<Mutex<pnet::transport::TransportSender>>> {
        match ip {
            IpAddr::V4(_) => self.icmp_v4.clone(),
            IpAddr::V6(_) => self.icmp_v6.clone(),
        }
    }

    pub(crate) fn has_tcp(&self) -> bool {
        self.tcp_v4.is_some() || self.tcp_v6.is_some()
    }

    pub(crate) fn has_udp(&self) -> bool {
        self.udp_v4.is_some() || self.udp_v6.is_some()
    }

    pub(crate) fn has_icmp(&self) -> bool {
        self.icmp_v4.is_some() || self.icmp_v6.is_some()
    }

    pub(crate) fn stats(&self) -> HubStats {
        HubStats {
            has_tcp: self.has_tcp(),
            has_udp: self.has_udp(),
            has_icmp: self.has_icmp(),
            dispatcher_inflight: self.dispatcher.inflight_len(),
        }
    }

    fn spawn_tcp_rx_loop(
        running: Arc<AtomicBool>,
        dispatcher: Dispatcher,
        mut rx: pnet::transport::TransportReceiver,
    ) {
        tokio::task::spawn_blocking(move || {
            let mut iter = tcp_packet_iter(&mut rx);
            while running.load(Ordering::Relaxed) {
                match iter.next_with_timeout(Duration::from_millis(50)) {
                    Ok(Some((packet, ip))) => {
                        let key = CorrKey::Tcp {
                            remote_ip: ip,
                            remote_port: packet.get_source(),
                            local_port: packet.get_destination(),
                        };
                        let flags = packet.get_flags();
                        let status = if flags & (TcpFlags::SYN | TcpFlags::ACK)
                            == (TcpFlags::SYN | TcpFlags::ACK)
                        {
                            ScanStatus::Open
                        } else if flags & TcpFlags::RST == TcpFlags::RST {
                            ScanStatus::Closed
                        } else {
                            continue;
                        };
                        let _ = dispatcher.fulfill(
                            &key,
                            DispatchReply {
                                status,
                                payload: None,
                            },
                        );
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
        });
    }

    fn spawn_udp_rx_loop(
        running: Arc<AtomicBool>,
        dispatcher: Dispatcher,
        mut rx: pnet::transport::TransportReceiver,
    ) {
        tokio::task::spawn_blocking(move || {
            let mut iter = udp_packet_iter(&mut rx);
            while running.load(Ordering::Relaxed) {
                match iter.next_with_timeout(Duration::from_millis(50)) {
                    Ok(Some((packet, src))) => {
                        let key = CorrKey::Udp {
                            remote_ip: src,
                            remote_port: packet.get_source(),
                            local_port: packet.get_destination(),
                        };
                        let payload = packet.payload();
                        let payload = if payload.is_empty() {
                            None
                        } else {
                            Some(payload[..std::cmp::min(payload.len(), 2048)].to_vec())
                        };
                        let _ = dispatcher.fulfill(
                            &key,
                            DispatchReply {
                                status: ScanStatus::Open,
                                payload,
                            },
                        );
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
        });
    }

    fn spawn_icmp_rx_loop_v4(
        running: Arc<AtomicBool>,
        dispatcher: Dispatcher,
        mut rx: pnet::transport::TransportReceiver,
    ) {
        tokio::task::spawn_blocking(move || {
            let mut iter = icmp_packet_iter(&mut rx);
            while running.load(Ordering::Relaxed) {
                match iter.next_with_timeout(Duration::from_millis(50)) {
                    Ok(Some((packet, src))) => {
                        let remote_ip = match src {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => continue,
                        };
                        if packet.get_icmp_type() == IcmpTypes::EchoReply {
                            let data = packet.packet();
                            if data.len() < 8 {
                                continue;
                            }
                            let ident = u16::from_be_bytes([data[4], data[5]]);
                            let seq = u16::from_be_bytes([data[6], data[7]]);
                            let key = CorrKey::IcmpEcho {
                                remote_ip: IpAddr::V4(remote_ip),
                                ident,
                                seq,
                            };
                            let _ = dispatcher.fulfill(
                                &key,
                                DispatchReply {
                                    status: ScanStatus::Open,
                                    payload: None,
                                },
                            );
                            continue;
                        }

                        if packet.get_icmp_type() != IcmpTypes::DestinationUnreachable {
                            continue;
                        }
                        // Destination Unreachable: code 3 == Port Unreachable.
                        if packet.get_icmp_code().0 != 3 {
                            continue;
                        }

                        let Some(icmp) = IcmpPacket::new(packet.packet()) else {
                            continue;
                        };
                        let Some(ipv4) = Ipv4Packet::new(icmp.payload()) else {
                            continue;
                        };
                        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                            continue;
                        }
                        let ip_hlen = (ipv4.get_header_length() as usize) * 4;
                        let ip_bytes = ipv4.packet();
                        if ip_bytes.len() < ip_hlen + 8 {
                            continue;
                        }
                        let Some(udp) = UdpPacket::new(&ip_bytes[ip_hlen..]) else {
                            continue;
                        };

                        let key = CorrKey::Udp {
                            remote_ip: IpAddr::V4(ipv4.get_destination()),
                            remote_port: udp.get_destination(),
                            local_port: udp.get_source(),
                        };
                        let _ = dispatcher.fulfill(
                            &key,
                            DispatchReply {
                                status: ScanStatus::Closed,
                                payload: None,
                            },
                        );
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
        });
    }

    fn spawn_icmp_rx_loop_v6(
        running: Arc<AtomicBool>,
        dispatcher: Dispatcher,
        mut rx: pnet::transport::TransportReceiver,
    ) {
        tokio::task::spawn_blocking(move || {
            let mut iter = icmpv6_packet_iter(&mut rx);
            while running.load(Ordering::Relaxed) {
                match iter.next_with_timeout(Duration::from_millis(50)) {
                    Ok(Some((packet, src))) => {
                        let remote_ip = match src {
                            IpAddr::V4(_) => continue,
                            IpAddr::V6(v6) => v6,
                        };
                        if packet.get_icmpv6_type() == Icmpv6Types::EchoReply {
                            let data = packet.packet();
                            if data.len() < 8 {
                                continue;
                            }
                            let ident = u16::from_be_bytes([data[4], data[5]]);
                            let seq = u16::from_be_bytes([data[6], data[7]]);
                            let key = CorrKey::IcmpEcho {
                                remote_ip: IpAddr::V6(remote_ip),
                                ident,
                                seq,
                            };
                            let _ = dispatcher.fulfill(
                                &key,
                                DispatchReply {
                                    status: ScanStatus::Open,
                                    payload: None,
                                },
                            );
                            continue;
                        }

                        if packet.get_icmpv6_type() != Icmpv6Types::DestinationUnreachable {
                            continue;
                        }
                        // ICMPv6 Destination Unreachable: code 4 == Port Unreachable.
                        if packet.get_icmpv6_code().0 != 4 {
                            continue;
                        }

                        let Some(icmp) = Icmpv6Packet::new(packet.packet()) else {
                            continue;
                        };
                        let Some(ipv6) = Ipv6Packet::new(icmp.payload()) else {
                            continue;
                        };
                        if ipv6.get_next_header() != IpNextHeaderProtocols::Udp {
                            continue;
                        }
                        let ip_bytes = ipv6.packet();
                        if ip_bytes.len() < 40 + 8 {
                            continue;
                        }
                        let Some(udp) = UdpPacket::new(&ip_bytes[40..]) else {
                            continue;
                        };

                        let key = CorrKey::Udp {
                            remote_ip: IpAddr::V6(ipv6.get_destination()),
                            remote_port: udp.get_destination(),
                            local_port: udp.get_source(),
                        };
                        let _ = dispatcher.fulfill(
                            &key,
                            DispatchReply {
                                status: ScanStatus::Closed,
                                payload: None,
                            },
                        );
                    }
                    Ok(None) => continue,
                    Err(_) => continue,
                }
            }
        });
    }
}

impl Drop for RawPacketHub {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

// Future: ipv6-based local address selection may need interface scoping for link-local.
#[allow(dead_code)]
fn _ensure_ipv6_types_linked(_v6: Ipv6Addr, _v4: Ipv4Addr) {}
