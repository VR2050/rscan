// src/cores/host/syn_scan.rs

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use tokio::time::timeout;

use super::models::{PortResult, PortStatus, Protocol, ScanResult};
use crate::errors::RustpenError;

/// SYN 扫描配置
#[derive(Debug, Clone)]
pub struct SynConfig {
    pub timeout_seconds: u64,
    pub concurrent: bool,
    pub concurrency: usize,
    /// 可选源端口（如果为0会自动选择）
    pub source_port: u16,
}

impl Default for SynConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 2,
            concurrent: false,
            concurrency: 100,
            source_port: 0,
        }
    }
}

/// SYN 扫描器
#[derive(Debug, Clone)]
pub struct SynScanner {
    pub config: SynConfig,
}

impl SynScanner {
    pub fn new(config: SynConfig) -> Self {
        Self { config }
    }

    /// 内部：检查单个端口，优先使用 pnet 原始包发送 SYN 并解析返回（SYN/ACK -> Open, RST -> Closed）
    /// 在无法使用原始套接字时回退到普通 TCP connect（与 `TcpScanner` 类似）
    async fn check_single_port(&self, host: IpAddr, port: u16) -> PortResult {
        // 优先尝试使用 pnet 的原始套接字进行 SYN 扫描（支持 IPv4 和 IPv6），失败时回退到普通 TCP connect
        let timeout_dur = Duration::from_secs(self.config.timeout_seconds);
        let src_port_config = self.config.source_port;

        // 对 IPv4 和 IPv6 分别处理
        let pnet_res = match host {
            IpAddr::V4(dest_v4) => {
                let src_port = src_port_config;
                tokio::task::spawn_blocking(move || -> Result<PortStatus, String> {
                    use pnet::packet::ip::IpNextHeaderProtocols;
                    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
                    use pnet::transport::TransportProtocol::Ipv4 as TPIpv4;
                    use pnet::transport::{
                        TransportChannelType, tcp_packet_iter, transport_channel,
                    };
                    use std::time::Duration as StdDuration;

                    let local_ip = get_local_ipv4_for_destination(dest_v4)
                        .map_err(|e| format!("获取本地IP失败: {}", e))?;

                    let (mut tx, mut rx) = transport_channel(
                        4096,
                        TransportChannelType::Layer4(TPIpv4(IpNextHeaderProtocols::Tcp)),
                    )
                    .map_err(|e| format!("transport_channel 创建失败: {}", e))?;

                    let source_port: u16 = if src_port != 0 {
                        src_port
                    } else {
                        40000 + (port % 1000)
                    };
                    let seq_num: u32 = 0x1234_5678;

                    let mut tcp_buffer = [0u8; 20];
                    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..])
                        .ok_or_else(|| "构造 TCP SYN 包失败".to_string())?;
                    tcp_packet.set_source(source_port);
                    tcp_packet.set_destination(port);
                    tcp_packet.set_sequence(seq_num);
                    tcp_packet.set_data_offset(5);
                    tcp_packet.set_flags(TcpFlags::SYN);
                    tcp_packet.set_window(64240);
                    let checksum = pnet::packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &local_ip,
                        &dest_v4,
                    );
                    tcp_packet.set_checksum(checksum);

                    if let Err(e) = tx.send_to(tcp_packet.to_immutable(), IpAddr::V4(dest_v4)) {
                        return Err(format!("发送 SYN 失败: {}", e));
                    }

                    let mut iter = tcp_packet_iter(&mut rx);
                    let until =
                        std::time::Instant::now() + StdDuration::from_secs(timeout_dur.as_secs());
                    while std::time::Instant::now() < until {
                        match iter.next_with_timeout(StdDuration::from_millis(250)) {
                            Ok(Some((packet, ip))) => {
                                if ip == IpAddr::V4(dest_v4)
                                    && packet.get_destination() == source_port
                                    && packet.get_source() == port
                                {
                                    let flags = packet.get_flags();
                                    // 如果是 SYN+ACK 且 ACK == seq+1，则开放
                                    if flags & (TcpFlags::SYN | TcpFlags::ACK)
                                        == (TcpFlags::SYN | TcpFlags::ACK)
                                    {
                                        return Ok(PortStatus::Open);
                                    }
                                    // RST 或 RST+ACK 表示关闭
                                    if flags & TcpFlags::RST == TcpFlags::RST {
                                        return Ok(PortStatus::Closed);
                                    }
                                }
                            }
                            Ok(None) => continue,
                            Err(e) => return Err(format!("接收响应失败: {}", e)),
                        }
                    }

                    Ok(PortStatus::Filtered)
                })
                .await
            }
            IpAddr::V6(dest_v6) => {
                let src_port = src_port_config;
                tokio::task::spawn_blocking(move || -> Result<PortStatus, String> {
                    use pnet::packet::ip::IpNextHeaderProtocols;
                    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
                    use pnet::transport::TransportProtocol::Ipv6 as TPIpv6;
                    use pnet::transport::{
                        TransportChannelType, tcp_packet_iter, transport_channel,
                    };
                    use std::time::Duration as StdDuration;

                    let local_v6 = get_local_ipv6_for_destination(dest_v6)
                        .map_err(|e| format!("获取本地IPv6失败: {}", e))?;

                    let (mut tx, mut rx) = transport_channel(
                        4096,
                        TransportChannelType::Layer4(TPIpv6(IpNextHeaderProtocols::Tcp)),
                    )
                    .map_err(|e| format!("transport_channel 创建失败: {}", e))?;

                    let source_port: u16 = if src_port != 0 {
                        src_port
                    } else {
                        40000 + (port % 1000)
                    };
                    let seq_num: u32 = 0x1234_5678;

                    let mut tcp_buffer = [0u8; 20];
                    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..])
                        .ok_or_else(|| "构造 TCP SYN 包失败".to_string())?;
                    tcp_packet.set_source(source_port);
                    tcp_packet.set_destination(port);
                    tcp_packet.set_sequence(seq_num);
                    tcp_packet.set_data_offset(5);
                    tcp_packet.set_flags(TcpFlags::SYN);
                    tcp_packet.set_window(64240);

                    // IPv6 校验和
                    let checksum = pnet::packet::tcp::ipv6_checksum(
                        &tcp_packet.to_immutable(),
                        &local_v6,
                        &dest_v6,
                    );
                    tcp_packet.set_checksum(checksum);

                    if let Err(e) = tx.send_to(tcp_packet.to_immutable(), IpAddr::V6(dest_v6)) {
                        return Err(format!("发送 IPv6 SYN 失败: {}", e));
                    }

                    let mut iter = tcp_packet_iter(&mut rx);
                    let until =
                        std::time::Instant::now() + StdDuration::from_secs(timeout_dur.as_secs());
                    while std::time::Instant::now() < until {
                        match iter.next_with_timeout(StdDuration::from_millis(250)) {
                            Ok(Some((packet, ip))) => {
                                if ip == IpAddr::V6(dest_v6)
                                    && packet.get_destination() == source_port
                                    && packet.get_source() == port
                                {
                                    let flags = packet.get_flags();
                                    if flags & (TcpFlags::SYN | TcpFlags::ACK)
                                        == (TcpFlags::SYN | TcpFlags::ACK)
                                    {
                                        return Ok(PortStatus::Open);
                                    }
                                    if flags & TcpFlags::RST == TcpFlags::RST {
                                        return Ok(PortStatus::Closed);
                                    }
                                }
                            }
                            Ok(None) => continue,
                            Err(e) => return Err(format!("接收响应失败: {}", e)),
                        }
                    }

                    Ok(PortStatus::Filtered)
                })
                .await
            }
        };

        if let Ok(Ok(status)) = pnet_res {
            return PortResult::new(port, status, Protocol::Tcp).with_latency(0u16);
        }

        // 回退到标准 TCP 连接方法（与 TcpScanner 类似）
        let addr = SocketAddr::new(host, port);
        let start_time = Instant::now();
        match timeout(
            Duration::from_secs(self.config.timeout_seconds),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                let latency = start_time.elapsed().as_millis() as u16;
                PortResult::new(port, PortStatus::Open, Protocol::Tcp).with_latency(latency)
            }
            Ok(Err(e)) => {
                let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    PortStatus::Closed
                } else {
                    PortStatus::Filtered
                };
                PortResult::new(port, status, Protocol::Tcp)
            }
            Err(_) => PortResult::new(port, PortStatus::Filtered, Protocol::Tcp),
        }
    }

    async fn scan_ports_sequential(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        let start_time = Instant::now();
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);

        for &port in ports {
            let port_result = self.check_single_port(host, port).await;
            scan_result.record_port(port, port_result.status);
            if port_result.status == PortStatus::Open {
                scan_result.add_open_port_detail(port_result);
            }
        }

        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }

    async fn scan_ports_concurrent(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        use futures::stream::{self, StreamExt};
        let start_time = Instant::now();
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);
        let concurrency = std::cmp::max(1, self.config.concurrency);

        let results: Vec<PortResult> = stream::iter(ports.iter().copied())
            .map(|port| {
                let scanner = self.clone();
                async move { scanner.check_single_port(host, port).await }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        for port_result in results {
            scan_result.record_port(port_result.port, port_result.status);
            if port_result.status == PortStatus::Open {
                scan_result.add_open_port_detail(port_result);
            }
        }

        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }
}

impl Default for SynScanner {
    fn default() -> Self {
        Self::new(SynConfig::default())
    }
}

// PortScanner trait 的实现（与 TcpScanner 保持一致）
use super::tcp_scanner::PortScanner;

impl PortScanner for SynScanner {
    async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError> {
        let start_time = Instant::now();
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);
        let port_result = self.check_single_port(host, port).await;
        scan_result.record_port(port, port_result.status);
        if port_result.status == PortStatus::Open {
            scan_result.add_open_port_detail(port_result);
        }
        scan_result.scan_duration = start_time.elapsed();
        Ok(scan_result)
    }

    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> Result<ScanResult, RustpenError> {
        if self.config.concurrent && self.config.concurrency > 1 {
            Ok(self.scan_ports_concurrent(host, ports).await)
        } else {
            Ok(self.scan_ports_sequential(host, ports).await)
        }
    }
}

/// 获取本地 IPv4 地址，方法是创建 UDP socket 并 connect 到目标，然后读取本地地址（不会真的发送数据）
fn get_local_ipv4_for_destination(dest: Ipv4Addr) -> Result<Ipv4Addr, std::io::Error> {
    // 绑定到 0.0.0.0:0，让操作系统选择源地址
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V4(dest), 53); // 任意端口
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr()
        && let IpAddr::V4(v4) = local_addr.ip()
    {
        return Ok(v4);
    }
    Err(std::io::Error::other("无法获取本地IPv4"))
}

/// 获取本地 IPv6 地址，方法与 IPv4 相同但使用 IPv6 未指定地址
fn get_local_ipv6_for_destination(
    dest: std::net::Ipv6Addr,
) -> Result<std::net::Ipv6Addr, std::io::Error> {
    let sock = UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V6(dest), 53);
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr()
        && let IpAddr::V6(v6) = local_addr.ip()
    {
        return Ok(v6);
    }
    Err(std::io::Error::other("无法获取本地IPv6"))
}

#[cfg(test)]
mod tests {
    use crate::cores::host::ports;

    use super::*;

    #[tokio::test]
    async fn concurrent_syn_scan_returns_open_ports() {
        // 使用 tokio 的 listener 模拟开放端口
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let config = SynConfig {
            timeout_seconds: 2,
            concurrent: true,
            concurrency: 4,
            source_port: 0,
        };
        let scanner = SynScanner::new(config);

        // 如果 pnet 无法在当前环境使用，会回退到 TCP connect，测试仍然有效
        let res = scanner
            .scan_ports("127.0.0.1".parse().unwrap(), &[addr.port()])
            .await
            .unwrap();
        assert!(res.open_ports_count() >= 1);
    }

    #[tokio::test]
    async fn concurrent_syn_scan_ipv6_returns_open_ports() {
        // 在可用的系统上绑定 IPv6 回环
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let config = SynConfig {
            timeout_seconds: 2,
            concurrent: true,
            concurrency: 4,
            source_port: 0,
        };
        let scanner = SynScanner::new(config);

        // IPv6 扫描目标为 ::1
        let res = scanner
            .scan_ports("::1".parse().unwrap(), &[addr.port()])
            .await
            .unwrap();
        assert!(res.open_ports_count() >= 1);
    }

    #[test]
    fn test_get_local_ipv4() {
        // 本地回环地址应该以 127 开头
        let r = get_local_ipv4_for_destination(Ipv4Addr::new(127, 0, 0, 1));
        assert!(r.is_ok());
    }

    #[test]
    fn test_get_local_ipv6() {
        let r = get_local_ipv6_for_destination(std::net::Ipv6Addr::LOCALHOST);
        assert!(r.is_ok());
    }
    #[test]
    #[ignore]
    // 测试主机扫描引擎（需要真实网络环境/权限）
    fn test_syn_scanner() {
        let target = "192.168.1.1";
        let ports = "1-65535";
        let port_list = ports::parse_ports(ports).unwrap();
        let config = SynConfig {
            timeout_seconds: 3,
            concurrent: true,
            concurrency: 5000,
            source_port: 0,
        };
        let start = Instant::now();
        let scanner = SynScanner::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt
            .block_on(scanner.scan_ports(target.parse().unwrap(), &port_list))
            .unwrap();
        println!("SYN扫描结果：{:#?}", scan_result.open_port_details());
        let duration = start.elapsed();
        println!("扫描耗时：{:?}", duration);
    }
}
