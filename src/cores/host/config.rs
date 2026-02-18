// src/cores/host/scanner/config.rs
use std::time::Duration;

/// 扫描配置
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// 连接超时时间
    pub timeout: Duration,

    /// 最大并发连接数
    pub concurrency: usize,

    /// 最大重试次数
    pub max_retries: u32,

    /// 是否尝试抓取banner信息
    pub banner_grab: bool,

    /// 端口扫描间隔（防止触发防火墙）
    pub delay: Option<Duration>,

    /// 服务识别模式
    pub service_detection: ServiceDetectionMode,
}

/// 服务识别模式
#[derive(Debug, Clone)]
pub enum ServiceDetectionMode {
    None, // 不识别服务
    Fast, // 快速识别（基于端口）
    Full, // 完整识别（尝试连接获取banner）
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            concurrency: 100,
            max_retries: 1,
            banner_grab: false,
            delay: None,
            service_detection: ServiceDetectionMode::Fast,
        }
    }
}

impl ScanConfig {
    /// 创建快速扫描配置
    pub fn fast_scan() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            concurrency: 200,
            banner_grab: false,
            ..Default::default()
        }
    }

    /// 创建详细扫描配置
    pub fn detailed_scan() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            concurrency: 50,
            banner_grab: true,
            service_detection: ServiceDetectionMode::Full,
            ..Default::default()
        }
    }

    /// 创建隐身扫描配置
    pub fn stealth_scan() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            concurrency: 10,
            delay: Some(Duration::from_millis(100)),
            ..Default::default()
        }
    }
}
