// src/cores/host/arp_scan.rs

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::errors::RustpenError;
use ipnetwork::Ipv4Network;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

/// ARP 扫描发现的主机信息
#[derive(Debug, Clone)]
pub struct ArpHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub interface: String,
}

/// ARP 扫描配置
#[derive(Debug, Clone)]
pub struct ArpConfig {
    pub interface: Option<String>, // 指定接口名称（例如 eth0），如果为 None 则自动选择非回环接口
    pub timeout: Duration,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            interface: None,
            timeout: Duration::from_secs(2),
        }
    }
}

/// ARP 扫描器
pub struct ArpScanner {
    config: ArpConfig,
}

impl ArpScanner {
    pub fn new(config: ArpConfig) -> Self {
        Self { config }
    }

    /// 扫描给定的 IPv4 网络（CIDR），返回发现的 IP->MAC 列表
    pub async fn scan_cidr(&self, cidr: &str) -> Result<Vec<ArpHost>, RustpenError> {
        // 解析 CIDR
        let net: Ipv4Network = cidr
            .parse::<Ipv4Network>()
            .map_err(|e| RustpenError::ParseError(e.to_string()))?;

        // 生成可探测主机列表（跳过网络地址和广播，兼容 /32 和 /31）
        let network_addr = net.network();
        let prefix = net.prefix();
        let mut targets: Vec<Ipv4Addr> = Vec::new();
        let net_u32: u32 = network_addr.into();
        let host_bits = 32u32.saturating_sub(prefix as u32);
        if prefix == 32 {
            targets.push(network_addr);
        } else if prefix == 31 {
            // 两个地址，通常点对点，包含两者
            targets.push(std::net::Ipv4Addr::from(net_u32));
            targets.push(std::net::Ipv4Addr::from(net_u32 + 1));
        } else if host_bits > 1 {
            let broadcast = net_u32 + ((1u64 << host_bits) as u32) - 1;
            for i in (net_u32 + 1)..broadcast {
                targets.push(std::net::Ipv4Addr::from(i));
            }
        }

        if targets.is_empty() {
            return Ok(vec![]);
        }

        // datalink 操作是阻塞的；放到 blocking 线程
        let cfg = self.config.clone();
        let hosts = tokio::task::spawn_blocking(move || Self::scan_on_interface(&cfg, &targets))
            .await
            .map_err(|e| RustpenError::Generic(format!("spawn_blocking failed: {e:?}")))??;

        Ok(hosts)
    }

    fn choose_interface(maybe_name: &Option<String>) -> Result<NetworkInterface, RustpenError> {
        let interfaces = datalink::interfaces();
        if let Some(name) = maybe_name {
            if let Some(iface) = interfaces.into_iter().find(|i| i.name == *name) {
                return Ok(iface);
            } else {
                return Err(RustpenError::ScanError(format!("找不到接口: {}", name)));
            }
        }

        // 自动选择：非回环、有 MAC 且有 IPv4 地址
        interfaces
            .into_iter()
            .find(|i| !i.is_loopback() && i.mac.is_some() && i.ips.iter().any(|ip| ip.is_ipv4()))
            .ok_or_else(|| RustpenError::ScanError("没有可用的网络接口用于 ARP 扫描".to_string()))
    }

    fn scan_on_interface(
        cfg: &ArpConfig,
        targets: &[Ipv4Addr],
    ) -> Result<Vec<ArpHost>, RustpenError> {
        let iface = Self::choose_interface(&cfg.interface)?;
        let src_mac = iface
            .mac
            .ok_or_else(|| RustpenError::ScanError("接口没有 MAC 地址".to_string()))?;
        let src_ip = iface
            .ips
            .iter()
            .find_map(|ip| {
                if ip.is_ipv4() {
                    match ip.ip() {
                        std::net::IpAddr::V4(v4) => Some(v4),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| RustpenError::ScanError("接口没有 IPv4 地址".to_string()))?;

        // 打开 datalink 通道（带读超时，避免 rx.next() 长时间阻塞）
        let dl_cfg = datalink::Config {
            read_timeout: Some(Duration::from_millis(50)),
            ..Default::default()
        };
        let (mut tx, mut rx) = match datalink::channel(&iface, dl_cfg) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(RustpenError::ScanError(
                    "未能打开以太网通道(非以太网)".to_string(),
                ));
            }
            Err(e) => return Err(RustpenError::Io(e)),
        };

        // 发送请求到所有目标
        let mut unique_targets: HashSet<Ipv4Addr> = HashSet::new();
        for &t in targets.iter() {
            // 跳过本机地址
            if t == src_ip {
                continue;
            }
            unique_targets.insert(t);
        }

        // 发送 ARP 请求
        for &t in unique_targets.iter() {
            let mut buffer = [0u8; 42]; // ethernet(14) + arp(28)
            {
                let mut eth = MutableEthernetPacket::new(&mut buffer[..]).ok_or_else(|| {
                    RustpenError::ScanError("构造以太网帧失败".to_string())
                })?;
                eth.set_destination(MacAddr::broadcast());
                eth.set_source(src_mac);
                eth.set_ethertype(EtherTypes::Arp);

                let mut arp = MutableArpPacket::new(eth.payload_mut()).ok_or_else(|| {
                    RustpenError::ScanError("构造 ARP 包失败".to_string())
                })?;
                arp.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp.set_protocol_type(EtherTypes::Ipv4);
                arp.set_hw_addr_len(6);
                arp.set_proto_addr_len(4);
                arp.set_operation(ArpOperations::Request);
                arp.set_sender_hw_addr(src_mac);
                arp.set_sender_proto_addr(src_ip);
                arp.set_target_hw_addr(MacAddr::zero());
                arp.set_target_proto_addr(t);
            }

            // 发送，忽略单次发送错误
            let _ = tx.send_to(&buffer, None);
        }

        // 接收回复直到超时
        let mut found: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
        let start = Instant::now();
        while start.elapsed() < cfg.timeout {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth) = EthernetPacket::new(packet)
                        && eth.get_ethertype() == EtherTypes::Arp
                        && let Some(arp) = ArpPacket::new(eth.payload())
                        && arp.get_operation() == ArpOperations::Reply
                    {
                        let sender_ip = arp.get_sender_proto_addr();
                        let sender_mac = arp.get_sender_hw_addr();
                        if unique_targets.contains(&sender_ip) {
                            found.entry(sender_ip).or_insert(sender_mac);
                        }
                    }
                }
                Err(_) => {
                    // 忽略超时读取错误，继续直到总体 timeout
                }
            }
        }

        // 构造结果
        let mut res: Vec<ArpHost> = found
            .into_iter()
            .map(|(ip, mac)| ArpHost {
                ip,
                mac,
                interface: iface.name.clone(),
            })
            .collect();
        // 排序以保证稳定性
        res.sort_by_key(|h| h.ip);
        Ok(res)
    }
}

impl Default for ArpScanner {
    fn default() -> Self {
        Self::new(ArpConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 该测试为手动/集成测试（需要root与局域网环境），被忽略以避免 CI 失败
    #[tokio::test]
    #[ignore]
    async fn integration_scan_local_net() {
        let scanner = ArpScanner::default();
        // 请在本地替换为实际网段，例如 "192.168.1.0/24"
        let _ = scanner.scan_cidr("192.168.1.0/24").await.unwrap();
    }
}
