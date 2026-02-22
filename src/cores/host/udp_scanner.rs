// src/cores/host/scanner/udp_scanner.rs
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::models::{PortResult, PortStatus, Protocol, ScanResult};
use crate::errors::RustpenError;

/// UDP扫描配置
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// 发送超时时间（秒）
    pub send_timeout_seconds: u64,

    /// 接收超时时间（秒）
    pub receive_timeout_seconds: u64,

    /// 是否启用并发扫描
    pub concurrent: bool,

    /// 并发连接数（如果启用并发）
    pub concurrency: usize,

    /// 发送的探测数据
    pub probe_data: Vec<u8>,

    /// 最大重试次数
    pub max_retries: u32,

    /// 每个端口扫描间隔（毫秒）
    pub delay_ms: Option<u64>,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            send_timeout_seconds: 2,
            receive_timeout_seconds: 3,
            concurrent: false,
            concurrency: 50,
            probe_data: vec![0x00, 0x01, 0x02, 0x03], // 简单的探测数据
            max_retries: 1,
            delay_ms: None,
        }
    }
}

impl UdpConfig {
    /// DNS服务探测（端口53）
    pub fn dns_probe() -> Self {
        // DNS查询：example.com的A记录查询
        let dns_query = vec![
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // example
            0x03, b'c', b'o', b'm', // com
            0x00, // Null terminator
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];

        Self {
            send_timeout_seconds: 3,
            receive_timeout_seconds: 5,
            concurrent: false,
            concurrency: 10,
            probe_data: dns_query,
            max_retries: 2,
            delay_ms: Some(100), // DNS服务器通常需要限制请求频率
        }
    }

    /// NTP服务探测（端口123）
    pub fn ntp_probe() -> Self {
        // NTP客户端模式请求（简化版本）
        let ntp_request = vec![
            0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        Self {
            send_timeout_seconds: 3,
            receive_timeout_seconds: 5,
            concurrent: false,
            concurrency: 10,
            probe_data: ntp_request,
            max_retries: 1,
            delay_ms: None,
        }
    }

    /// SNMP服务探测（端口161）
    pub fn snmp_probe() -> Self {
        // SNMP GET请求（社区字符串public，OID 1.3.6.1.2.1.1.1.0）
        let snmp_request = vec![
            0x30, 0x29, // SEQUENCE length 41
            0x02, 0x01, 0x00, // INTEGER version 0 (SNMPv1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // OCTET STRING "public"
            0xA0, 0x1C, // GetRequest PDU
            0x02, 0x01, 0x00, // request-id 0
            0x02, 0x01, 0x00, // error-status 0
            0x02, 0x01, 0x00, // error-index 0
            0x30, 0x11, // SEQUENCE length 17
            0x30, 0x0F, // SEQUENCE length 15
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID
            0x05, 0x00, // NULL value
        ];

        Self {
            send_timeout_seconds: 3,
            receive_timeout_seconds: 5,
            concurrent: false,
            concurrency: 10,
            probe_data: snmp_request,
            max_retries: 1,
            delay_ms: Some(50), // SNMP服务器可能有速率限制
        }
    }

    /// 创建快速扫描配置（扫描常见UDP端口）
    pub fn fast_scan() -> Self {
        Self {
            send_timeout_seconds: 1,
            receive_timeout_seconds: 2,
            concurrent: true,
            concurrency: 100,
            probe_data: vec![0x00], // 简单的单字节探测
            max_retries: 0,
            delay_ms: None,
        }
    }
}

/// UDP扫描器
#[derive(Debug, Clone)]
pub struct UdpScanner {
    pub config: UdpConfig,
}

impl UdpScanner {
    pub fn new(config: UdpConfig) -> Self {
        Self { config }
    }

    /// 根据目标 host 创建适当的本地 socket（支持 IPv4/IPv6）
    async fn create_udp_socket_for_host(&self, host: IpAddr) -> Result<UdpSocket, RustpenError> {
        let bind_addr = match host {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(RustpenError::Io)?;
        socket.set_ttl(64).map_err(RustpenError::Io)?;
        Ok(socket)
    }

    /// 检查单个UDP端口
    async fn check_single_port(&self, host: IpAddr, port: u16) -> PortResult {
        // 保持向后兼容：默认行为为为每次调用创建 socket（被新的并发/顺序方法替换）
        match self.create_udp_socket_for_host(host).await {
            Ok(socket) => {
                self.check_single_port_with_socket(host, port, &socket)
                    .await
            }
            Err(_) => PortResult::new(port, PortStatus::Error, Protocol::Udp),
        }
    }

    /// 使用指定的 socket 执行一次端口检查（支持重试）
    async fn check_single_port_with_socket(
        &self,
        host: IpAddr,
        port: u16,
        socket: &UdpSocket,
    ) -> PortResult {
        let start_time = Instant::now();
        let target_addr = SocketAddr::new(host, port);

        let mut attempts = 0u32;
        loop {
            attempts += 1;

            // 发送探测数据
            let send_res = timeout(
                Duration::from_secs(self.config.send_timeout_seconds),
                socket.send_to(&self.config.probe_data, &target_addr),
            )
            .await;

            match send_res {
                Ok(Ok(_)) => { /* sent */ }
                Ok(Err(_)) => return PortResult::new(port, PortStatus::Error, Protocol::Udp),
                Err(_) => {
                    // 发送超时
                    if attempts > self.config.max_retries {
                        return PortResult::new(port, PortStatus::Filtered, Protocol::Udp);
                    } else {
                        continue;
                    }
                }
            }

            // 接收响应
            let mut buffer = [0u8; 1024];
            let recv_res = timeout(
                Duration::from_secs(self.config.receive_timeout_seconds),
                socket.recv_from(&mut buffer),
            )
            .await;

            match recv_res {
                Ok(Ok((size, _))) => {
                    let latency = start_time.elapsed().as_millis() as u16;

                    let banner = if size > 0 {
                        let response = String::from_utf8_lossy(&buffer[..size]);
                        let cleaned: String = response
                            .chars()
                            .filter(|c| c.is_ascii() && !c.is_ascii_control())
                            .take(200)
                            .collect();

                        if !cleaned.is_empty() {
                            Some(cleaned)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let mut result = PortResult::new(port, PortStatus::Open, Protocol::Udp)
                        .with_latency(latency);
                    if let Some(b) = banner {
                        result = result.with_banner(b);
                    }
                    return result;
                }
                Ok(Err(_)) => return PortResult::new(port, PortStatus::Error, Protocol::Udp),
                Err(_) => {
                    // 超时
                    if attempts > self.config.max_retries {
                        return PortResult::new(port, PortStatus::Filtered, Protocol::Udp);
                    } else {
                        continue;
                    }
                }
            }
        }
    }

    /// 顺序扫描多个UDP端口
    async fn scan_ports_sequential(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        let start_time = Instant::now();

        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Udp);

        // 顺序扫描每个端口
        for &port in ports {
            let port_result = self.check_single_port(host, port).await;

            scan_result.record_port(port, port_result.status);

            if port_result.status == PortStatus::Open {
                scan_result.add_open_port_detail(port_result);
            }

            // 如果配置了延迟，等待一下
            if let Some(delay_ms) = self.config.delay_ms {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }

        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }

    /// 并发扫描多个UDP端口
    async fn scan_ports_concurrent(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        use futures::stream::{self, StreamExt};

        let start_time = Instant::now();

        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Udp);

        let concurrency = std::cmp::max(1, self.config.concurrency);

        // IMPORTANT:
        // Do NOT share a single UdpSocket across concurrent tasks that each call recv_from().
        // The receive side becomes racy and replies may be consumed by the wrong task.
        // Use per-task ephemeral sockets for correctness (higher overhead, but deterministic).
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

impl Default for UdpScanner {
    fn default() -> Self {
        Self::new(UdpConfig::default())
    }
}

/// 实现PortScanner trait
impl super::PortScanner for UdpScanner {
    async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError> {
        let start_time = Instant::now();

        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Udp);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::host::tcp_scanner::PortScanner;

    #[tokio::test]
    async fn udp_scan_detects_open_port_concurrently() {
        // 创建 UDP 服务端并回显
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, addr) = server.recv_from(&mut buf).await.unwrap();
                let _ = server.send_to(&buf[..len], &addr).await;
            }
        });

        let config = UdpConfig {
            send_timeout_seconds: 1,
            receive_timeout_seconds: 1,
            concurrent: true,
            concurrency: 2,
            probe_data: vec![0x01],
            max_retries: 1,
            delay_ms: None,
        };

        let scanner = UdpScanner::new(config);
        let res = scanner
            .scan_ports("127.0.0.1".parse().unwrap(), &[port])
            .await
            .unwrap();

        assert_eq!(res.open_ports_count(), 1);
    }

    #[test]
    #[ignore]
    // 靶机 UDP 扫描测试（需要真实网络环境）
    fn test_udp_scanner() {
        let target = "192.168.1.1";
        let ports = "1-65535";
        println!("测试UDP端口扫描，目标主机：{}，端口：{}", target, ports);
        let port_vec = vec![53, 67, 68, 123, 161];
        let config = UdpConfig {
            send_timeout_seconds: 2,
            receive_timeout_seconds: 3,
            concurrent: true,
            concurrency: 50,
            probe_data: vec![0x00, 0x01, 0x02, 0x03],
            max_retries: 1,
            delay_ms: Some(10),
        };
        let scanner = UdpScanner::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt
            .block_on(scanner.scan_ports(target.parse().unwrap(), &port_vec))
            .unwrap();
        println!("UDP扫描结果：{:#?}", scan_result.open_port_details());
    }
}
