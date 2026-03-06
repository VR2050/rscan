// src/cores/host/scanner/tcp_scanner.rs

// 导入标准库
use std::net::{IpAddr, SocketAddr}; // IP地址和套接字地址
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH}; // 时间相关类型

// 导入Tokio异步运行时
use tokio::net::TcpStream; // 异步TCP流
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout}; // 异步超时包装器

// 导入项目内部模块
use super::models::{PortResult, PortStatus, Protocol, ScanResult};
use crate::errors::RustpenError; // 自定义错误类型 // 数据模型

/// TCP扫描配置 - 控制扫描行为参数
#[derive(Debug, Clone)]
pub struct TcpConfig {
    /// 连接超时时间（秒）
    pub timeout_seconds: u64,
    /// 连接超时时间（毫秒），优先级高于 timeout_seconds
    pub timeout_ms: Option<u64>,
    /// 是否启用并发扫描
    pub concurrent: bool,
    /// 并发连接数（如果启用并发）
    pub concurrency: usize,
    /// 连接失败后的重试次数（0 表示不重试）
    pub retries: u32,
    /// 全局速率上限（端口/秒），None 表示不限制
    pub max_rate: Option<u32>,
    /// 发送抖动（毫秒），用于平滑流量特征
    pub jitter_ms: Option<u64>,
    /// 端口调度顺序
    pub scan_order: TcpScanOrder,
    /// 自适应背压（filtered 偏高时自动增加小延迟）
    pub adaptive_backpressure: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpScanOrder {
    Serial,
    Random,
    Interleave,
}

// 为TcpConfig提供默认值
impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 3, // 默认3秒超时
            timeout_ms: None,
            concurrent: false, // 默认禁用并发
            concurrency: 1000, // 默认100并发连接
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: TcpScanOrder::Serial,
            adaptive_backpressure: false,
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

    fn mix64(mut x: u64) -> u64 {
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^= x >> 33;
        x
    }

    fn now_seed() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    fn prepare_port_plan(&self, ports: &[u16]) -> Vec<u16> {
        let mut out = ports.to_vec();
        match self.config.scan_order {
            TcpScanOrder::Serial => out,
            TcpScanOrder::Random => {
                if out.len() <= 1 {
                    return out;
                }
                let mut seed = Self::mix64(Self::now_seed() ^ out.len() as u64);
                for i in (1..out.len()).rev() {
                    seed = Self::mix64(seed.wrapping_add(i as u64));
                    let j = (seed as usize) % (i + 1);
                    out.swap(i, j);
                }
                out
            }
            TcpScanOrder::Interleave => {
                out.sort_unstable();
                let stride = 8usize.min(out.len().max(1));
                let mut interleaved = Vec::with_capacity(out.len());
                for offset in 0..stride {
                    let mut i = offset;
                    while i < out.len() {
                        interleaved.push(out[i]);
                        i += stride;
                    }
                }
                interleaved
            }
        }
    }

    fn worker_base_gap_ms(&self, worker_count: usize) -> Option<u64> {
        let rate = self.config.max_rate?;
        if rate == 0 {
            return None;
        }
        let ms = ((1000.0 * worker_count as f64) / rate as f64).round() as u64;
        Some(ms.max(1))
    }

    fn jitter_for(worker_id: usize, seq: u64, jitter_max_ms: u64) -> u64 {
        if jitter_max_ms == 0 {
            return 0;
        }
        let seed = Self::mix64((worker_id as u64).wrapping_mul(0x9e3779b97f4a7c15) ^ seq);
        seed % (jitter_max_ms + 1)
    }

    async fn maybe_pace_probe(
        base_gap_ms: Option<u64>,
        jitter_ms: Option<u64>,
        worker_id: usize,
        seq: u64,
        adaptive_delay_ms: u64,
    ) {
        let mut total_ms = adaptive_delay_ms;
        if let Some(base) = base_gap_ms {
            total_ms = total_ms.saturating_add(base);
        }
        if let Some(jit) = jitter_ms {
            total_ms = total_ms.saturating_add(Self::jitter_for(worker_id, seq, jit));
        }
        if total_ms > 0 {
            sleep(Duration::from_millis(total_ms)).await;
        }
    }

    fn timeout_duration(&self) -> Duration {
        if let Some(ms) = self.config.timeout_ms {
            Duration::from_millis(ms.max(1))
        } else {
            Duration::from_secs(self.config.timeout_seconds.max(1))
        }
    }

    async fn check_single_port_once(host: IpAddr, port: u16, timeout_dur: Duration) -> PortResult {
        let addr = SocketAddr::new(host, port);
        let start_time = Instant::now();
        match timeout(timeout_dur, async {
            let stream = TcpStream::connect(&addr).await?;
            stream.set_nodelay(true)?;
            Ok::<_, std::io::Error>(stream)
        })
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

    /// 内部方法：检查单个TCP端口
    async fn check_single_port(&self, host: IpAddr, port: u16) -> PortResult {
        let timeout_dur = self.timeout_duration();
        let mut attempts = 0_u32;
        loop {
            let result = Self::check_single_port_once(host, port, timeout_dur).await;
            if result.status == PortStatus::Open || result.status == PortStatus::Closed {
                return result;
            }
            if attempts >= self.config.retries {
                return result;
            }
            attempts += 1;
        }
    }

    /// 顺序扫描多个端口 - 逐个端口扫描（单线程）
    async fn scan_ports_sequential(&self, host: IpAddr, ports: &[u16]) -> ScanResult {
        let start_time = Instant::now(); // 记录整个扫描开始时间
        let port_plan = self.prepare_port_plan(ports);

        // 创建扫描结果容器
        let mut scan_result = ScanResult::new(
            host.to_string(), // 主机名
            host,             // IP地址
            Protocol::Tcp,    // 扫描协议类型
        );

        // 顺序扫描每个端口
        let base_gap_ms = self.worker_base_gap_ms(1);
        for (seq, &port) in port_plan.iter().enumerate() {
            Self::maybe_pace_probe(base_gap_ms, self.config.jitter_ms, 0, seq as u64, 0).await;
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
        let start_time = Instant::now(); // 记录整个扫描开始时间

        // 创建扫描结果容器
        let mut scan_result = ScanResult::new(host.to_string(), host, Protocol::Tcp);

        let port_plan = self.prepare_port_plan(ports);
        let total_ports = port_plan.len();
        if total_ports == 0 {
            scan_result.scan_duration = start_time.elapsed();
            return scan_result;
        }
        // 固定 worker 池 + 无锁索引分发，减少大量 Future 组合器开销
        let worker_count = std::cmp::max(1, self.config.concurrency).min(total_ports);
        let timeout_dur = self.timeout_duration();
        let retries = self.config.retries;
        let base_gap_ms = self.worker_base_gap_ms(worker_count);
        let jitter_ms = self.config.jitter_ms;
        let adaptive_backpressure = self.config.adaptive_backpressure;
        let ports = Arc::new(port_plan);
        let index = Arc::new(AtomicUsize::new(0));
        let mut workers = JoinSet::new();
        for worker_id in 0..worker_count {
            let ports = Arc::clone(&ports);
            let index = Arc::clone(&index);
            workers.spawn(async move {
                let mut local = Vec::with_capacity((ports.len() / worker_count).max(8));
                let mut seq = 0_u64;
                let mut adaptive_delay_ms = 0_u64;
                loop {
                    let i = index.fetch_add(1, Ordering::Relaxed);
                    if i >= ports.len() {
                        break;
                    }
                    let port = ports[i];
                    Self::maybe_pace_probe(
                        base_gap_ms,
                        jitter_ms,
                        worker_id,
                        seq,
                        adaptive_delay_ms,
                    )
                    .await;
                    let mut attempts = 0_u32;
                    let result = loop {
                        let result = Self::check_single_port_once(host, port, timeout_dur).await;
                        if result.status == PortStatus::Open || result.status == PortStatus::Closed
                        {
                            break result;
                        }
                        if attempts >= retries {
                            break result;
                        }
                        attempts += 1;
                    };
                    if adaptive_backpressure {
                        adaptive_delay_ms = match result.status {
                            PortStatus::Filtered => (adaptive_delay_ms + 2).min(40),
                            PortStatus::Error => (adaptive_delay_ms + 4).min(60),
                            PortStatus::Open | PortStatus::Closed => {
                                adaptive_delay_ms.saturating_sub(2)
                            }
                        };
                    }
                    seq = seq.wrapping_add(1);
                    local.push(result);
                }
                local
            });
        }
        while let Some(joined) = workers.join_next().await {
            if let Ok(local_results) = joined {
                for port_result in local_results {
                    // 记录端口状态
                    scan_result.record_port(port_result.port, port_result.status);

                    // 如果端口开放，保存详细信息
                    if port_result.status == PortStatus::Open {
                        scan_result.add_open_port_detail(port_result);
                    }
                }
            }
        }

        // 计算整个扫描耗时
        scan_result.scan_duration = start_time.elapsed();
        scan_result
    }
}

impl Default for TcpScanner {
    fn default() -> Self {
        Self::new(TcpConfig::default())
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
            timeout_seconds: 1,
            timeout_ms: None,
            concurrent: true,
            concurrency: 2,
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: TcpScanOrder::Serial,
            adaptive_backpressure: false,
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
    #[ignore]
    // 测试主机扫描引擎（需要真实网络环境）
    fn test_tcp_scanner() {
        let target = "192.168.1.1";
        let ports = "1-65535";
        let port_list = ports::parse_ports(ports).unwrap();
        let config = TcpConfig {
            timeout_seconds: 1,
            timeout_ms: None,
            concurrent: true,
            concurrency: 1000,
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: TcpScanOrder::Serial,
            adaptive_backpressure: false,
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
    #[test]
    #[ignore]
    // 并发扫描测试（需要真实网络环境）
    fn test_tcp_scanner_concurrent() {
        let target = "192.168.1.1";
        let ports = "22,80,443,8080,3306,5432,6379,27017,11211,9200";
        let port_list = ports::parse_ports(ports).unwrap();
        let config = TcpConfig {
            timeout_seconds: 1,
            timeout_ms: None,
            concurrent: true,
            concurrency: 50,
            retries: 0,
            max_rate: None,
            jitter_ms: None,
            scan_order: TcpScanOrder::Serial,
            adaptive_backpressure: false,
        };
        let scanner = TcpScanner::new(config);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let scan_result = rt
            .block_on(scanner.scan_ports(target.parse().unwrap(), &port_list))
            .unwrap();
        println!("并发TCP扫描结果：{:#?}", scan_result.open_port_details());
    }
}
