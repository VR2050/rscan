//! modules::port_scan - wrapper over cores::host for higher-level usage
//!
//! 提供一个简单的 `HostScanner` API，便于上层模块或 CLI 调用。
//!
//! 用途：
//! - 将低层扫描器（TCP/UDP/SYN/ARP）封装为更易用的异步 API
//! - 提供稳定的返回类型（`ScanResult`）供 CLI / UI 使用
//!
//! 示例：
//! ```rust
//! use rscan::modules::HostScanner;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let scanner = HostScanner::default();
//!     let res = scanner.scan_tcp("127.0.0.1", &[22, 80, 443]).await?;
//!     println!("开放端口: {:?}", res.open_ports());
//!     Ok(())
//! }
//! ```

use crate::cores::host::{ScanManager, ScanResult};
use crate::errors::RustpenError;

/// 模块级主机扫描器封装，内部复用 `ScanManager`。
pub struct HostScanner {
    manager: ScanManager,
}

impl HostScanner {
    /// 使用默认配置创建模块扫描器
    pub fn new() -> Self {
        Self {
            manager: ScanManager::default(),
        }
    }

    /// 创建使用自定义 `ScanManager` 的封装（便于测试/注入）
    pub fn with_manager(manager: ScanManager) -> Self {
        Self { manager }
    }

    /// 扫描 TCP 端口
    pub async fn scan_tcp(&self, host: &str, ports: &[u16]) -> Result<ScanResult, RustpenError> {
        self.manager.tcp_scan(host, ports).await
    }

    /// 扫描 UDP 端口（若 manager 未启用 UDP，将返回错误）
    /// 扫描 UDP 端口
    ///
    /// 如果 `ScanManager` 未启用 UDP（未使用 `new_with_udp` 或 `enable_udp`），将返回 `RustpenError::ScanError`。
    ///
    /// Example:
    /// ```rust,no_run
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let manager = rscan::cores::host::ScanManager::new_with_udp(rscan::cores::host::TcpConfig::default(), Some(rscan::cores::host::UdpConfig::default()));
    ///     let scanner = rscan::modules::HostScanner::with_manager(manager);
    ///     let res = scanner.scan_udp("127.0.0.1", &[53]).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn scan_udp(&self, host: &str, ports: &[u16]) -> Result<ScanResult, RustpenError> {
        self.manager.udp_scan(host, ports).await
    }

    /// 使用 SYN 扫描（若 manager 未启用 SYN，将返回错误）
    /// 使用 SYN 扫描（在无法使用原始套接字时回退到 TCP connect）
    ///
    /// Example:
    /// ```rust,no_run
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let manager = rscan::cores::host::ScanManager::new_with_syn(rscan::cores::host::TcpConfig::default(), Some(rscan::cores::host::SynConfig::default()));
    ///     let scanner = rscan::modules::HostScanner::with_manager(manager);
    ///     let res = scanner.scan_syn("127.0.0.1", &[22]).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn scan_syn(&self, host: &str, ports: &[u16]) -> Result<ScanResult, RustpenError> {
        self.manager.syn_scan(host, ports).await
    }

    /// 快速扫描常用端口（TCP）
    pub async fn quick_tcp(&self, host: &str) -> Result<ScanResult, RustpenError> {
        self.manager.quick_tcp_scan(host).await
    }

    /// 通过 ARP 扫描 CIDR（局域网主机发现）
    pub async fn arp_scan_cidr(
        &self,
        cidr: &str,
    ) -> Result<Vec<crate::cores::host::ArpHost>, RustpenError> {
        self.manager.arp_scan_cidr(cidr).await
    }
}

impl Default for HostScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn scan_tcp_single_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let scanner = HostScanner::default();
        let res = scanner.scan_tcp("127.0.0.1", &[addr.port()]).await.unwrap();
        assert_eq!(res.open_ports_count(), 1);
    }

    #[tokio::test]
    async fn quick_tcp_on_local_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let scanner = HostScanner::default();
        // quick_tcp scans common ports; we ensure at least no panic and returns Ok
        let _ = scanner.quick_tcp("127.0.0.1").await.unwrap();
    }

    // ARP 测试需要实际网络权限，忽略以避免 CI 失败
    #[tokio::test]
    #[ignore]
    async fn arp_integration_test() {
        let scanner = HostScanner::default();
        let _ = scanner.arp_scan_cidr("192.168.1.0/24").await.unwrap();
    }

    // UDP 测试：在本地启动 UDP 服务并验证 HostScanner 能发现开放端口
    #[tokio::test]
    async fn hostscanner_udp_open_port() {
        use crate::cores::host::{ScanManager, TcpConfig, UdpConfig};

        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, addr) = server.recv_from(&mut buf).await.unwrap();
                let _ = server.send_to(&buf[..len], &addr).await;
            }
        });

        let manager = ScanManager::new_with_udp(TcpConfig::default(), Some(UdpConfig::default()));
        let scanner = HostScanner::with_manager(manager);
        let res = scanner.scan_udp("127.0.0.1", &[port]).await.unwrap();
        assert_eq!(res.open_ports_count(), 1);
    }

    // SYN 测试：在本地启动 TCP listener，并使用 Syn 扫描（回退到 TCP connect）验证开放端口
    #[tokio::test]
    async fn hostscanner_syn_detects_open_port() {
        use crate::cores::host::{ScanManager, SynConfig, TcpConfig};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let manager = ScanManager::new_with_syn(TcpConfig::default(), Some(SynConfig::default()));
        let scanner = HostScanner::with_manager(manager);
        let res = scanner.scan_syn("127.0.0.1", &[port]).await.unwrap();
        assert_eq!(res.open_ports_count(), 1);
    }

    #[tokio::test]
    async fn scan_udp_without_enabling_returns_error() {
        let scanner = HostScanner::default();
        let err = scanner.scan_udp("127.0.0.1", &[12345]).await.unwrap_err();
        assert!(matches!(err, RustpenError::ScanError(_)));
    }

    #[tokio::test]
    async fn hostscanner_udp_filtered_when_no_server() {
        use crate::cores::host::{ScanManager, TcpConfig, UdpConfig};

        let mut cfg = UdpConfig::default();
        cfg.send_timeout_seconds = 1;
        cfg.receive_timeout_seconds = 1;
        cfg.concurrent = false;

        let manager = ScanManager::new_with_udp(TcpConfig::default(), Some(cfg));
        let scanner = HostScanner::with_manager(manager);
        let res = scanner.scan_udp("127.0.0.1", &[65010]).await.unwrap();
        assert_eq!(res.total_scanned, 1);
        assert_eq!(res.open_ports_count(), 0);
    }

    #[tokio::test]
    async fn hostscanner_syn_closed_port() {
        use crate::cores::host::{ScanManager, SynConfig, TcpConfig};

        let port = 65001u16; // 高端口，通常未使用
        let manager = ScanManager::new_with_syn(TcpConfig::default(), Some(SynConfig::default()));
        let scanner = HostScanner::with_manager(manager);
        let res = scanner.scan_syn("127.0.0.1", &[port]).await.unwrap();
        assert_eq!(res.open_ports_count(), 0);
    }
}
