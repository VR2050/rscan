// src/cores/netscan_en/scanner/manager.rs
use std::net::IpAddr;
use tokio::net::lookup_host;

use crate::errors::RustpenError;
use super::tcp_scanner::{TcpScanner, TcpConfig};
use super::udp_scanner::{UdpScanner, UdpConfig};
use super::syn_scan::{SynScanner, SynConfig};
use super::models::{ScanResult, Protocol};
use super::PortScanner;

/// 扫描管理器 - 同时支持TCP、UDP 和可选的 SYN 扫描
pub struct ScanManager {
    tcp_scanner: TcpScanner,
    udp_scanner: Option<UdpScanner>,
    syn_scanner: Option<SynScanner>,
}

impl ScanManager {
    /// 创建新的扫描管理器（仅TCP）
    pub fn new(config: TcpConfig) -> Self {
        Self {
            tcp_scanner: TcpScanner::new(config),
            udp_scanner: None,
            syn_scanner: None,
        }
    }
    
    /// 创建支持TCP和UDP的扫描管理器
    pub fn new_with_udp(tcp_config: TcpConfig, udp_config: Option<UdpConfig>) -> Self {
        let udp_scanner = udp_config.map(UdpScanner::new);
        
        Self {
            tcp_scanner: TcpScanner::new(tcp_config),
            udp_scanner,
            syn_scanner: None,
        }
    }

    /// 创建支持 TCP + UDP + 可选 SYN 的扫描管理器
    pub fn new_with_syn(tcp_config: TcpConfig, syn_config: Option<SynConfig>) -> Self {
        let syn_scanner = syn_config.map(SynScanner::new);
        Self {
            tcp_scanner: TcpScanner::new(tcp_config),
            udp_scanner: None,
            syn_scanner,
        }
    }
    
    /// 使用默认配置
    pub fn default() -> Self {
        Self::new(TcpConfig::default())
    }
    
    /// 使用完整默认配置（TCP + UDP）
    pub fn full_default() -> Self {
        Self::new_with_udp(TcpConfig::default(), Some(UdpConfig::default()))
    }
    
    /// 启用UDP扫描
    pub fn enable_udp(&mut self, config: UdpConfig) {
        self.udp_scanner = Some(UdpScanner::new(config));
    }
    
    /// 禁用UDP扫描
    pub fn disable_udp(&mut self) {
        self.udp_scanner = None;
    }
    
    /// UDP扫描是否启用
    pub fn is_udp_enabled(&self) -> bool {
        self.udp_scanner.is_some()
    }

    /// 启用 SYN 扫描
    pub fn enable_syn(&mut self, config: SynConfig) {
        self.syn_scanner = Some(SynScanner::new(config));
    }

    /// 禁用 SYN 扫描
    pub fn disable_syn(&mut self) {
        self.syn_scanner = None;
    }

    /// SYN 扫描是否启用
    pub fn is_syn_enabled(&self) -> bool {
        self.syn_scanner.is_some()
    }
    
    /// 解析主机名
    pub async fn resolve_host(&self, host: &str) -> Result<IpAddr, RustpenError> {
        // 尝试直接解析为IP
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }
        
        // DNS解析
        match lookup_host(format!("{}:0", host)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    Ok(addr.ip())
                } else {
                    Err(RustpenError::InvalidHost(host.to_string()))
                }
            }
            Err(e) => Err(RustpenError::NetworkError(e.to_string())),
        }
    }
    
    /// === TCP 扫描方法 ===
    
    /// 执行TCP扫描
    pub async fn tcp_scan(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Result<ScanResult, RustpenError> {
        let ip = self.resolve_host(host).await?;
        self.tcp_scanner.scan_ports(ip, ports).await
    }
    
    /// 扫描单个TCP端口
    pub async fn tcp_scan_port(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ScanResult, RustpenError> {
        let ip = self.resolve_host(host).await?;
        self.tcp_scanner.scan_port(ip, port).await
    }
    
    /// 快速扫描常见TCP端口
    pub async fn quick_tcp_scan(&self, host: &str) -> Result<ScanResult, RustpenError> {
        use super::ports::common_ports;
        
        let ip = self.resolve_host(host).await?;
        self.tcp_scanner.scan_ports(ip, &common_ports()).await
    }
    
    /// === UDP 扫描方法 ===
    
    /// 执行UDP扫描（如果已启用）
    pub async fn udp_scan(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Result<ScanResult, RustpenError> {
        let udp_scanner = self.udp_scanner.as_ref()
            .ok_or_else(|| RustpenError::ScanError("UDP扫描未启用".to_string()))?;
        
        let ip = self.resolve_host(host).await?;
        udp_scanner.scan_ports(ip, ports).await
    }
    
    /// 扫描单个UDP端口（如果已启用）
    pub async fn udp_scan_port(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ScanResult, RustpenError> {
        let udp_scanner = self.udp_scanner.as_ref()
            .ok_or_else(|| RustpenError::ScanError("UDP扫描未启用".to_string()))?;
        
        let ip = self.resolve_host(host).await?;
        udp_scanner.scan_port(ip, port).await
    }
    
    /// 快速扫描常见UDP端口
    pub async fn quick_udp_scan(&self, host: &str) -> Result<ScanResult, RustpenError> {
        let common_udp_ports = vec![
            53,     // DNS
            67, 68, // DHCP
            69,     // TFTP
            123,    // NTP
            161,    // SNMP
            162,    // SNMP trap
            500,    // IPSec/IKE
            514,    // Syslog
            520,    // RIP
            1900,   // UPnP/SSDP
            5353,   // mDNS
            5355,   // LLMNR
        ];
        
        self.udp_scan(host, &common_udp_ports).await
    }

    /// === SYN 扫描方法 ===

    /// 执行SYN扫描（如果已启用）
    pub async fn syn_scan(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Result<ScanResult, RustpenError> {
        let syn_scanner = self.syn_scanner.as_ref()
            .ok_or_else(|| RustpenError::ScanError("SYN扫描未启用".to_string()))?;
        
        let ip = self.resolve_host(host).await?;
        syn_scanner.scan_ports(ip, ports).await
    }

    /// 扫描单个 SYN 端口（如果已启用）
    pub async fn syn_scan_port(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ScanResult, RustpenError> {
        let syn_scanner = self.syn_scanner.as_ref()
            .ok_or_else(|| RustpenError::ScanError("SYN扫描未启用".to_string()))?;
        
        let ip = self.resolve_host(host).await?;
        syn_scanner.scan_port(ip, port).await
    }

    /// 快速扫描常见 TCP 端口 使用 SYN
    pub async fn quick_syn_scan(&self, host: &str) -> Result<ScanResult, RustpenError> {
        use super::ports::common_ports;
        let ip = self.resolve_host(host).await?;
        let syn_scanner = self.syn_scanner.as_ref().ok_or_else(|| RustpenError::ScanError("SYN扫描未启用".to_string()))?;
        syn_scanner.scan_ports(ip, &common_ports()).await
    }
    
    /// 扫描DNS服务器
    pub async fn scan_dns_server(&self, host: &str) -> Result<ScanResult, RustpenError> {
        let config = UdpConfig::dns_probe();
        let ip = self.resolve_host(host).await?;
        let scanner = UdpScanner::new(config);
        scanner.scan_ports(ip, &[53]).await
    }

    
    /// 扫描NTP服务器
    pub async fn scan_ntp_server(&self, host: &str) -> Result<ScanResult, RustpenError> {
        let config = UdpConfig::ntp_probe();
        let ip = self.resolve_host(host).await?;
        let scanner = UdpScanner::new(config);
        scanner.scan_ports(ip, &[123]).await
    }
    
    /// 扫描SNMP服务
    pub async fn scan_snmp_service(&self, host: &str) -> Result<ScanResult, RustpenError> {
        let config = UdpConfig::snmp_probe();
        let ip = self.resolve_host(host).await?;
        let scanner = UdpScanner::new(config);
        scanner.scan_ports(ip, &[161]).await
    }
    
    /// === 组合扫描方法 ===
    
    /// 同时扫描TCP和UDP端口
    pub async fn scan_both_protocols(
        &self,
        host: &str,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> Result<(ScanResult, ScanResult), RustpenError> {
        let ip = self.resolve_host(host).await?;
        
        // 同时执行TCP和UDP扫描
        let tcp_future = self.tcp_scanner.scan_ports(ip, tcp_ports);
        
        if let Some(udp_scanner) = &self.udp_scanner {
            let (tcp_result, udp_result) = tokio::try_join!(
                tcp_future,
                udp_scanner.scan_ports(ip, udp_ports)
            )?;
            
            Ok((tcp_result, udp_result))
        } else {
            // 如果UDP未启用，返回TCP结果并提供一个空的UDP结果对象
            let tcp_result = tcp_future.await?;
            let udp_empty = ScanResult::new("".to_string(), ip, Protocol::Udp);
            Ok((tcp_result, udp_empty))
        }
    }
    
    /// 扫描相同的端口（TCP和UDP都扫）
    pub async fn scan_ports_all_protocols(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Result<(ScanResult, ScanResult), RustpenError> {
        self.scan_both_protocols(host, ports, ports).await
    }
    
    /// 快速扫描所有协议
    pub async fn quick_scan_all(&self, host: &str) -> Result<(Option<ScanResult>, Option<ScanResult>), RustpenError> {
        use super::ports::common_ports;
        
        let ip = self.resolve_host(host).await?;
        
        let tcp_ports = common_ports();
        let tcp_result = self.tcp_scanner.scan_ports(ip, &tcp_ports).await.ok();
        
        let udp_result = if let Some(udp_scanner) = &self.udp_scanner {
            let udp_ports = vec![53, 123, 161, 500, 514, 5353];
            udp_scanner.scan_ports(ip, &udp_ports).await.ok()
        } else {
            None
        };
        
        Ok((tcp_result, udp_result))
    }
    
    /// ARP 扫描方法（对局域网 CIDR 扫描 IP->MAC）
    pub async fn arp_scan_cidr(&self, cidr: &str) -> Result<Vec<super::ArpHost>, RustpenError> {
        let scanner = super::ArpScanner::default();
        scanner.scan_cidr(cidr).await
    }

    /// === 配置访问器 ===
    
    /// 获取TCP配置
    pub fn tcp_config(&self) -> &TcpConfig {
        &self.tcp_scanner.config
    }
    
    /// 获取UDP配置（如果已启用）
    pub fn udp_config(&self) -> Option<&UdpConfig> {
        self.udp_scanner.as_ref().map(|s| &s.config)
    }
    
    /// 设置TCP配置
    pub fn set_tcp_config(&mut self, config: TcpConfig) {
        self.tcp_scanner = TcpScanner::new(config);
    }
    
    /// 设置UDP配置
    pub fn set_udp_config(&mut self, config: UdpConfig) {
        self.udp_scanner = Some(UdpScanner::new(config));
    }
    
    /// === 兼容性方法 ===
    
    /// 兼容旧版本的快速扫描（只扫描TCP）
    pub async fn quick_scan(&self, host: &str) -> Result<ScanResult, RustpenError> {
        self.quick_tcp_scan(host).await
    }
    
    /// 扫描指定端口（自动判断协议）
    pub async fn scan_port(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> Result<ScanResult, RustpenError> {
        match protocol {
            Protocol::Tcp => self.tcp_scan_port(host, port).await,
            Protocol::Udp => self.udp_scan_port(host, port).await,
        }
    }
    
    /// 合并多个扫描结果
    pub fn merge_results(&self, results: Vec<ScanResult>) -> Option<ScanResult> {
        if results.is_empty() {
            return None;
        }
        
        let mut merged = results[0].clone();
        
        for result in results.iter().skip(1) {
            // 简单合并：只合并开放端口
            for detail in result.open_port_details() {
                if !merged.open_port_details().iter().any(|r| r.port == detail.port && r.protocol == detail.protocol) {
                    merged.add_open_port_detail(detail.clone());
                }
            }
        }
        
        Some(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::netscan_en::models::Protocol;

    #[tokio::test]
    async fn scan_both_protocols_udp_disabled_returns_tcp_result() {
        // 使用 tokio 的异步 listener 模拟开放端口
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // 在后台接受一次连接以保持端口开放
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let manager = ScanManager::default();
        let ports = vec![addr.port()];

        let (tcp_res, udp_res) = manager.scan_both_protocols("127.0.0.1", &ports, &[]).await.unwrap();

        // TCP 结果应包含开放端口，UDP 结果应为空且协议为 UDP
        assert_eq!(tcp_res.open_ports_count(), 1);
        assert_eq!(udp_res.total_scanned, 0);
        assert!(matches!(udp_res.protocol, Protocol::Udp));
    }

    #[tokio::test]
    async fn syn_scan_via_manager_when_enabled_returns_open_port() {
        // 启动监听器模拟开放端口
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let mut manager = ScanManager::default();
        manager.enable_syn(SynConfig::default());

        let res = manager.syn_scan("127.0.0.1", &[addr.port()]).await.unwrap();
        assert!(res.open_ports_count() >= 1);
    }

    #[tokio::test]
    async fn syn_scan_ipv6_via_manager_when_enabled_returns_open_port() {
        // IPv6 回环监听
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let mut manager = ScanManager::default();
        manager.enable_syn(SynConfig::default());

        let res = manager.syn_scan("::1", &[addr.port()]).await.unwrap();
        assert!(res.open_ports_count() >= 1);
    }
}