// src/cores/netscan_en/scanner/tcp_scanner.rs
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::errors::RustpenError;
use super::models::{PortResult, PortStatus, Protocol, ScanResult};

/// TCP扫描配置
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// 连接超时时间（秒）
    pub timeout_seconds: u64,
    /// 是否启用并发扫描
    pub concurrent: bool,
    /// 并发连接数（如果启用并发）
    pub concurrency: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 3,
            concurrent: false,
            concurrency: 100,
        }
    }
}

/// TCP扫描器
#[derive(Debug, Clone)]
pub struct TcpScanner {
    pub config: TcpConfig,
}

impl TcpScanner {
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }
    
    pub fn default() -> Self {
        Self::new(TcpConfig::default())
    }
    
    /// 内部方法：检查单个TCP端口
    async fn check_single_port(&self, host: IpAddr, port: u16) -> PortResult {
        let addr = SocketAddr::new(host, port);
        let start_time = Instant::now();
        
        match timeout(
            Duration::from_secs(self.config.timeout_seconds),
            TcpStream::connect(&addr)
        ).await {
            Ok(Ok(_stream)) => {
                // 连接成功 - 端口开放
                let latency = start_time.elapsed().as_millis() as u16;
                PortResult::new(port, PortStatus::Open, Protocol::Tcp)  // 修复：添加Protocol参数
                    .with_latency(latency)
            }
            Ok(Err(e)) => {
                // 连接失败，判断具体原因
                let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    PortStatus::Closed
                } else {
                    PortStatus::Filtered
                };
                PortResult::new(port, status, Protocol::Tcp)  // 修复：添加Protocol参数
            }
            Err(_) => {
                // 连接超时
                PortResult::new(port, PortStatus::Filtered, Protocol::Tcp)  // 修复：添加Protocol参数
            }
        }
    }
    
    /// 顺序扫描多个端口
    async fn scan_ports_sequential(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        let start_time = Instant::now();
        
        let mut scan_result = ScanResult::new(
            host.to_string(),
            host,
            Protocol::Tcp,
        );
        
        // 顺序扫描每个端口
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
    
    /// 并发扫描多个端口
    async fn scan_ports_concurrent(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        use futures::stream::{self, StreamExt};
        
        let start_time = Instant::now();
        
        let mut scan_result = ScanResult::new(
            host.to_string(),
            host,
            Protocol::Tcp,
        );

        // 使用 buffer_unordered 控制并发，避免一次性分配所有任务
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

/// 端口扫描器trait - 使用Rust原生异步trait
pub trait PortScanner: Send + Sync {
    fn scan_port(
        &self,
        host: IpAddr,
        port: u16,
    ) -> impl std::future::Future<Output = Result<ScanResult, RustpenError>> + Send;
    
    fn scan_ports(
        &self,
        host: IpAddr,
        ports: &[u16],
    ) -> impl std::future::Future<Output = Result<ScanResult, RustpenError>> + Send;
}

impl PortScanner for TcpScanner {
    async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError> {
        let start_time = Instant::now();

        let mut scan_result = ScanResult::new(
            host.to_string(),
            host,
            Protocol::Tcp,
        );

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
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn concurrent_scan_returns_open_ports() {
        // 启动两个 listener
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = l2.local_addr().unwrap().port();

        // 后台接收连接以保持端口开放
        tokio::spawn(async move { let _ = l1.accept().await; });
        tokio::spawn(async move { let _ = l2.accept().await; });

        let config = TcpConfig { timeout_seconds: 2, concurrent: true, concurrency: 2 };
        let scanner = TcpScanner::new(config);

        let res = scanner.scan_ports("127.0.0.1".parse().unwrap(), &[p1, p2]).await.unwrap();
        assert_eq!(res.open_ports_count(), 2);
    }
}


#[cfg(test)]
pub mod test{
    use crate::cores::netscan_en::ports;

    use super::*;
    #[test]
   //测试主机扫描引擎
    fn test_tcp_scanner(){
        let target="192.168.128.56";
        let ports="22,80,443,8080";
        let port_list=ports::parse_ports(ports).unwrap();
        let config=TcpConfig{
            timeout_seconds:3,
            concurrent:true,
            concurrency:100,
        };
        let scanner=TcpScanner::new(config);
        let rt=tokio::runtime::Runtime::new().unwrap();
        let scan_result=rt.block_on(scanner.scan_ports(target.parse().unwrap(),&port_list)).unwrap();
        println!("TCP扫描结果：{:#?}",scan_result.open_port_details());
    }
    //并发扫描测试
    #[test]
    fn test_tcp_scanner_concurrent(){
        let target="192.168.128.56";
        let ports="22,80,443,8080,3306,5432,6379,27017,11211,9200";
        let port_list=ports::parse_ports(ports).unwrap();
        let config=TcpConfig{
            timeout_seconds:3,
            concurrent:true,
            concurrency:50,
        };
        let scanner=TcpScanner::new(config);
        let rt=tokio::runtime::Runtime::new().unwrap();
        let scan_result=rt.block_on(scanner.scan_ports(target.parse().unwrap(),&port_list)).unwrap();
        println!("并发TCP扫描结果：{:#?}",scan_result.open_port_details());
    }   

    
}