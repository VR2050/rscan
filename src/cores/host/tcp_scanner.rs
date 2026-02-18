// src/cores/host/scanner/tcp_scanner.rs

// 导入标准库
use std::net::{IpAddr, SocketAddr}; // IP地址和套接字地址
use std::time::{Duration, Instant}; // 时间相关类型

// 导入Tokio异步运行时
use tokio::net::TcpStream; // 异步TCP流
use tokio::time::timeout; // 异步超时包装器

// 导入项目内部模块
use super::models::{PortResult, PortStatus, Protocol, ScanResult};
use crate::errors::RustpenError; // 自定义错误类型 // 数据模型

/// TCP扫描配置 - 控制扫描行为参数
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// 连接超时时间（秒）
    pub timeout_seconds: u64,
    /// 是否启用并发扫描
    pub concurrent: bool,
    /// 并发连接数（如果启用并发）
    pub concurrency: usize,
}

// 为TcpConfig提供默认值
impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 100, // 默认3秒超时
            concurrent: false,    // 默认禁用并发
            concurrency: 1000,    // 默认100并发连接
        }
    }
}

/// TCP扫描器 - 主要扫描功能实现
#[derive(Debug, Clone)]
pub struct TcpScanner {
    pub config: TcpConfig, // 扫描配置
}

impl TcpScanner {
    /// 使用指定配置创建扫描器
    pub fn new(config: TcpConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建扫描器
    pub fn default() -> Self {
        Self::new(TcpConfig::default())
    }

    /// 内部方法：检查单个TCP端口
    async fn check_single_port(&self, host: IpAddr, port: u16) -> PortResult {
        // 构建套接字地址
        let addr = SocketAddr::new(host, port);
        let start_time = Instant::now(); // 记录开始时间，用于计算延迟

        // 使用tokio::timeout包装连接操作，避免无限等待
        match timeout(
            Duration::from_millis(self.config.timeout_seconds),
            // TcpStream::connect(&addr)
            async {
                let stream = TcpStream::connect(&addr).await?;
                // ⭐ 关键：启用 TCP_NODELAY
                stream.set_nodelay(true)?;
                Ok::<_, std::io::Error>(stream)
            },
        )
        .await
        {
            Ok(Ok(_stream)) => {
                // 情况1：连接成功（超时内成功建立连接）
                // 端口开放，计算连接延迟
                let latency = start_time.elapsed().as_millis() as u16;
                PortResult::new(port, PortStatus::Open, Protocol::Tcp) // 修复：添加Protocol参数
                    .with_latency(latency) // 添加延迟信息
            }
            Ok(Err(e)) => {
                // 情况2：连接失败（在超时内立即失败）
                // 根据错误类型判断端口状态
                let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    // 连接被拒绝 - 端口明确关闭
                    PortStatus::Closed
                } else {
                    // 其他错误（如网络不可达）- 端口可能被过滤
                    PortStatus::Filtered
                };
                PortResult::new(port, status, Protocol::Tcp) // 修复：添加Protocol参数
            }
            Err(_) => {
                // 情况3：连接超时（超过timeout_seconds仍未连接）
                // 端口可能被防火墙过滤或服务响应慢
                PortResult::new(port, PortStatus::Filtered, Protocol::Tcp) // 修复：添加Protocol参数
            }
        }
    }

    /// 顺序扫描多个端口 - 逐个端口扫描（单线程）
    async fn scan_ports_sequential(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        let start_time = Instant::now(); // 记录整个扫描开始时间

        // 创建扫描结果容器
        let mut scan_result = ScanResult::new(
            host.to_string(), // 主机名
            host,             // IP地址
            Protocol::Tcp,    // 扫描协议类型
        );

        // 顺序扫描每个端口
        for &port in ports {
            // 异步检查单个端口
            let port_result = self.check_single_port(host, port).await;

            // 记录端口状态到结果中
            scan_result.record_port(port, port_result.status);

            // 如果端口开放，保存详细信息
            if port_result.status == PortStatus::Open {
                scan_result.add_open_port_detail(port_result);
            }
        }

        // 计算整个扫描耗时
        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }

    /// 并发扫描多个端口 - 同时扫描多个端口（多任务）
    async fn scan_ports_concurrent(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        // 导入futures库的流处理功能
        use futures::stream::{self, StreamExt};

        let start_time = Instant::now(); // 记录整个扫描开始时间

        // 创建扫描结果容器
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);

        // 使用 buffer_unordered 控制并发，避免一次性分配所有任务
        // 确保并发数至少为1
        let concurrency = std::cmp::max(1, self.config.concurrency);

        // 创建端口流，使用buffer_unordered实现并发控制
        let results: Vec<PortResult> = stream::iter(ports.iter().copied())
            .map(|port| {
                // 克隆扫描器以便在异步任务中使用
                let scanner = self.clone();
                // 为每个端口创建异步检查任务
                async move { scanner.check_single_port(host, port).await }
            })
            // 控制最大并发任务数，保持concurrency个任务同时运行
            .buffer_unordered(concurrency)
            // 收集所有结果
            .collect()
            .await;

        // 处理所有端口扫描结果
        for port_result in results {
            // 记录端口状态
            scan_result.record_port(port_result.port, port_result.status);

            // 如果端口开放，保存详细信息
            if port_result.status == PortStatus::Open {
                scan_result.add_open_port_detail(port_result);
            }
        }

        // 计算整个扫描耗时
        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }
}

/// 端口扫描器trait - 定义统一的扫描接口
// 使用Rust原生异步trait（不依赖async_trait库）
pub trait PortScanner: Send + Sync {
    /// 扫描单个端口
    fn scan_port(
        &self,
        host: IpAddr,
        port: u16,
    ) -> impl std::future::Future<Output = Result<ScanResult, RustpenError>> + Send;

    /// 扫描多个端口
    fn scan_ports(
        &self,
        host: IpAddr,
        ports: &[u16],
    ) -> impl std::future::Future<Output = Result<ScanResult, RustpenError>> + Send;
}

// 为TcpScanner实现PortScanner trait
impl PortScanner for TcpScanner {
    /// 实现单个端口扫描
    async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError> {
        let start_time = Instant::now(); // 记录开始时间

        // 创建扫描结果容器
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);

        // 检查单个端口
        let port_result = self.check_single_port(host, port).await;

        // 记录结果
        scan_result.record_port(port, port_result.status);

        // 如果端口开放，保存详细信息
        if port_result.status == PortStatus::Open {
            scan_result.add_open_port_detail(port_result);
        }

        // 计算扫描耗时
        scan_result.scan_duration = start_time.elapsed();
        Ok(scan_result)
    }

    /// 实现多个端口扫描
    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> Result<ScanResult, RustpenError> {
        // 根据配置选择扫描模式
        if self.config.concurrent && self.config.concurrency > 1 {
            // 并发扫描模式
            Ok(self.scan_ports_concurrent(host, ports).await)
        } else {
            // 顺序扫描模式
            Ok(self.scan_ports_sequential(host, ports).await)
        }
    }
}

// 测试模块
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // 测试并发扫描功能
    #[tokio::test]
    async fn concurrent_scan_returns_open_ports() {
        // 启动两个TCP监听器，用于模拟开放端口
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port(); // 获取动态分配的第一个端口
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = l2.local_addr().unwrap().port(); // 获取动态分配的第二个端口

        // 后台接收连接以保持端口开放（避免监听器关闭）
        tokio::spawn(async move {
            let _ = l1.accept().await;
        });
        tokio::spawn(async move {
            let _ = l2.accept().await;
        });

        // 创建启用并发的扫描器
        let config = TcpConfig {
            timeout_seconds: 500,
            concurrent: true,
            concurrency: 2,
        };
        let scanner = TcpScanner::new(config);

        // 扫描两个已知开放端口
        let res = scanner
            .scan_ports("127.0.0.1".parse().unwrap(), &[p1, p2])
            .await
            .unwrap();

        // 验证两个端口都被检测为开放
        assert_eq!(res.open_ports_count(), 2);
    }
}

#[cfg(test)]
pub mod test {
    use crate::cores::host::ports;

    use super::*;
    #[test]
    //测试主机扫描引擎
    fn test_tcp_scanner() {
        let target = "192.168.1.1";
        let ports = "1-65535";
        let port_list = ports::parse_ports(ports).unwrap();
        let config = TcpConfig {
            timeout_seconds: 100,
            concurrent: true,
            concurrency: 1000,
        };
        let start = Instant::now();

        let scanner = TcpScanner::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt
            .block_on(scanner.scan_ports(target.parse().unwrap(), &port_list))
            .unwrap();
        println!("TCP扫描结果：{:#?}", scan_result.open_port_details());
        let duration = start.elapsed();
        println!("扫描耗时：{:?}", duration);
    }
    //并发扫描测试
    #[test]
    fn test_tcp_scanner_concurrent() {
        let target = "192.168.1.1";
        let ports = "22,80,443,8080,3306,5432,6379,27017,11211,9200";
        let port_list = ports::parse_ports(ports).unwrap();
        let config = TcpConfig {
            timeout_seconds: 500,
            concurrent: true,
            concurrency: 50,
        };
        let scanner = TcpScanner::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt
            .block_on(scanner.scan_ports(target.parse().unwrap(), &port_list))
            .unwrap();
        println!("并发TCP扫描结果：{:#?}", scan_result.open_port_details());
    }
}
