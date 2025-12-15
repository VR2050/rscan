// src/cores/netscan_en/models.rs
use std::net::IpAddr;
use std::time::Duration;
use bitvec::prelude::*;
use serde::{Serialize, Deserialize};

/// 端口状态 - 使用u8表示，更高效
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    Closed = 0,     // 关闭
    Open = 1,       // 开放
    Filtered = 2,   // 被过滤
    Error = 3,      // 错误/超时
}

impl PortStatus {
    pub fn is_open(&self) -> bool {
        matches!(self, PortStatus::Open)
    }
}

/// 协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// 极简端口结果 - 只存储必要信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    pub protocol: Protocol,          // 新增字段
    pub latency_ms: Option<u16>,     // u16足够表示0-65535ms
    pub banner: Option<Box<str>>,    // Box<str>比String节省内存
}

impl PortResult {
    #[inline]
    pub fn new(port: u16, status: PortStatus, protocol: Protocol) -> Self {  // 改为3个参数
        Self {
            port,
            status,
            protocol,                 // 新增初始化
            latency_ms: None,
            banner: None,
        }
    }
    
    pub fn with_latency(mut self, latency_ms: u16) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }
    
    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner.into_boxed_str());
        self
    }
    
    /// 是否为TCP端口
    pub fn is_tcp(&self) -> bool {
        self.protocol == Protocol::Tcp
    }
    
    /// 是否为UDP端口
    pub fn is_udp(&self) -> bool {
        self.protocol == Protocol::Udp
    }
}

/// 高效的扫描结果 - 使用位图和向量分离存储
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: Box<str>,           // Box<str>节省内存
    pub ip: IpAddr,
    pub protocol: Protocol,
    
    // 使用位图存储端口状态，65536位 = 8KB
    open_ports: BitVec,      // 1=开放, 0=未开放
    scanned_ports: BitVec,   // 1=已扫描, 0=未扫描
    
    // 只存储开放端口的详细信息
    open_port_details: Vec<PortResult>,
    
    // 扫描统计
    pub scan_duration: Duration,
    pub total_scanned: u32,
    pub errors: u32,
}

impl ScanResult {
    pub fn new(host: String, ip: IpAddr, protocol: Protocol) -> Self {
        Self {
            host: host.into_boxed_str(),
            ip,
            protocol,
            open_ports: bitvec![0; 65536],
            scanned_ports: bitvec![0; 65536],
            open_port_details: Vec::with_capacity(100), // 预分配
            scan_duration: Duration::default(),
            total_scanned: 0,
            errors: 0,
        }
    }
    
    /// 记录端口结果 - O(1)操作
    #[inline]
    pub fn record_port(&mut self, port: u16, status: PortStatus) {
        self.scanned_ports.set(port as usize, true);
        self.total_scanned += 1;
        
        if status == PortStatus::Open {
            self.open_ports.set(port as usize, true);
        } else if status == PortStatus::Error {
            self.errors += 1;
        }
    }
    
    /// 添加开放端口的详细信息
    #[inline]
    pub fn add_open_port_detail(&mut self, result: PortResult) {
        if result.status == PortStatus::Open {
            self.open_port_details.push(result);
        }
    }
    
    /// 检查端口是否开放 - O(1)
    #[inline]
    pub fn is_port_open(&self, port: u16) -> bool {
        *self.open_ports.get(port as usize).as_deref().unwrap_or(&false)
    }
    
    /// 获取所有开放端口 - 延迟计算
    pub fn open_ports(&self) -> Vec<u16> {
        self.open_ports.iter_ones()
            .map(|i| i as u16)
            .collect()
    }
    
    /// 获取开放端口数量 - O(1)
    pub fn open_ports_count(&self) -> usize {
        self.open_ports.count_ones()
    }
    
    /// 获取开放端口的详细信息
    pub fn open_port_details(&self) -> &[PortResult] {
        &self.open_port_details
    }

    pub fn get_port_detail(&self, port: u16) -> Option<&PortResult> {
        self.open_port_details().iter()
            .find(|result| result.port == port)
    }
    
    /// 按协议过滤开放端口
    pub fn open_port_details_by_protocol(&self, protocol: Protocol) -> Vec<&PortResult> {
        self.open_port_details.iter()
            .filter(|r| r.protocol == protocol)
            .collect()
    }
    
    /// 转换为JSON友好格式
    pub fn to_json(&self) -> ScanResultJson {
        ScanResultJson {
            host: self.host.to_string(),
            ip: self.ip.to_string(),
            protocol: format!("{:?}", self.protocol),
            open_ports: self.open_ports(),
            open_ports_count: self.open_ports_count(),
            details: self.open_port_details.iter()
                .map(|p| PortResultJson {
                    port: p.port,
                    protocol: format!("{:?}", p.protocol),
                    latency_ms: p.latency_ms,
                    banner: p.banner.as_ref().map(|s| s.to_string()),
                })
                .collect(),
            scan_duration_ms: self.scan_duration.as_millis() as u64,
            total_scanned: self.total_scanned,
            errors: self.errors,
        }
    }
}

/// JSON输出结构
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResultJson {
    pub host: String,
    pub ip: String,
    pub protocol: String,
    pub open_ports: Vec<u16>,
    pub open_ports_count: usize,
    pub details: Vec<PortResultJson>,
    pub scan_duration_ms: u64,
    pub total_scanned: u32,
    pub errors: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PortResultJson {
    pub port: u16,
    pub protocol: String,
    pub latency_ms: Option<u16>,
    pub banner: Option<String>,
}