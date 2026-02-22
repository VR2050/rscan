// src/cores/host/models.rs

// 导入标准库和第三方库依赖
use bitvec::prelude::*; // 位图操作库，用于高效存储端口状态
use serde::{Deserialize, Serialize};
use std::net::IpAddr; // IP地址类型（IPv4/IPv6）
use std::time::Duration; // 时间间隔类型 // 序列化/反序列化支持

/// 端口状态 - 使用u8表示，更高效
// #[repr(u8)] 确保枚举在内存中占用1字节而不是默认的4字节
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortStatus {
    Closed = 0,   // 端口关闭
    Open = 1,     // 端口开放
    Filtered = 2, // 端口被防火墙过滤
    Error = 3,    // 扫描时发生错误/超时
}

impl PortStatus {
    /// 便捷方法：检查端口是否开放
    pub fn is_open(&self) -> bool {
        matches!(self, PortStatus::Open)
    }
}

/// 协议类型 - 支持TCP和UDP扫描
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,  // 传输控制协议
    Udp,  // 用户数据报协议
    Icmp, // Internet 控制报文协议
    Arp,  // 地址解析协议
    Dns,  // DNS 探测（基于 UDP/TCP，但语义上单列）
}

/// 极简端口结果 - 只存储必要信息，优化内存使用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,                // 端口号 (0-65535)
    pub status: PortStatus,       // 端口状态
    pub protocol: Protocol,       // 新增字段：扫描协议类型
    pub latency_ms: Option<u16>,  // 延迟毫秒数，u16足够表示0-65535ms
    pub banner: Option<Box<str>>, // Box<str>比String节省内存（避免容量字段）
}

impl PortResult {
    /// 构造函数 - 内联以提高性能
    #[inline]
    pub fn new(port: u16, status: PortStatus, protocol: Protocol) -> Self {
        // 改为3个参数
        Self {
            port,
            status,
            protocol,         // 新增初始化
            latency_ms: None, // 延迟初始为None
            banner: None,     // Banner初始为None
        }
    }

    /// 链式调用：设置延迟
    pub fn with_latency(mut self, latency_ms: u16) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// 链式调用：设置Banner信息
    pub fn with_banner(mut self, banner: String) -> Self {
        // 将String转换为Box<str>，移除容量字段节省内存
        self.banner = Some(banner.into_boxed_str());
        self
    }

    /// 便捷方法：是否为TCP端口
    pub fn is_tcp(&self) -> bool {
        self.protocol == Protocol::Tcp
    }

    /// 便捷方法：是否为UDP端口
    pub fn is_udp(&self) -> bool {
        self.protocol == Protocol::Udp
    }

    /// 便捷方法：是否为ICMP
    pub fn is_icmp(&self) -> bool {
        self.protocol == Protocol::Icmp
    }

    /// 便捷方法：是否为ARP
    pub fn is_arp(&self) -> bool {
        self.protocol == Protocol::Arp
    }

    /// 便捷方法：是否为DNS
    pub fn is_dns(&self) -> bool {
        self.protocol == Protocol::Dns
    }
}

/// 高效的扫描结果 - 使用位图和向量分离存储，平衡内存和访问效率
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub host: Box<str>,     // Box<str>节省内存（主机名或域名）
    pub ip: IpAddr,         // 解析后的IP地址
    pub protocol: Protocol, // 本次扫描使用的协议类型

    // 使用位图存储端口状态，65536位 = 8KB，固定大小，高效查询
    open_ports: BitVec,    // 位图：1=开放, 0=未开放
    scanned_ports: BitVec, // 位图：1=已扫描, 0=未扫描

    // 只存储开放端口的详细信息，避免为关闭端口浪费内存
    open_port_details: Vec<PortResult>,

    // 扫描统计信息
    pub scan_duration: Duration, // 扫描总耗时
    pub total_scanned: u32,      // 总扫描端口数
    pub errors: u32,             // 错误数量
}

impl ScanResult {
    /// 创建新的扫描结果实例
    pub fn new(host: String, ip: IpAddr, protocol: Protocol) -> Self {
        Self {
            host: host.into_boxed_str(), // 转换为Box<str>节省内存
            ip,
            protocol,
            // 初始化两个65536位的位图（对应所有可能的端口）
            open_ports: bitvec![0; 65536],
            scanned_ports: bitvec![0; 65536],
            // 预分配容量，假设通常开放端口不超过100个
            open_port_details: Vec::with_capacity(100),
            scan_duration: Duration::default(),
            total_scanned: 0,
            errors: 0,
        }
    }

    /// 记录端口结果 - O(1)操作，非常高效
    #[inline]
    pub fn record_port(&mut self, port: u16, status: PortStatus) {
        // 标记端口已扫描
        self.scanned_ports.set(port as usize, true);
        self.total_scanned += 1;

        // 根据状态更新相应位图
        if status == PortStatus::Open {
            self.open_ports.set(port as usize, true);
        } else if status == PortStatus::Error {
            self.errors += 1;
        }
        // 注意：这里不存储关闭/过滤端口的详细信息
    }

    /// 添加开放端口的详细信息（包含Banner、延迟等）
    #[inline]
    pub fn add_open_port_detail(&mut self, result: PortResult) {
        // 只存储开放端口的详细信息
        if result.status == PortStatus::Open {
            self.open_port_details.push(result);
        }
    }

    /// 合并一个开放端口详情到当前结果，保持位图与统计字段一致。
    pub fn merge_open_port_detail(&mut self, result: PortResult) {
        if result.status != PortStatus::Open {
            return;
        }
        let idx = result.port as usize;
        let was_scanned = *self.scanned_ports.get(idx).as_deref().unwrap_or(&false);
        if !was_scanned {
            self.scanned_ports.set(idx, true);
            self.total_scanned += 1;
        }
        self.open_ports.set(idx, true);
        if !self
            .open_port_details
            .iter()
            .any(|r| r.port == result.port && r.protocol == result.protocol)
        {
            self.open_port_details.push(result);
        }
    }

    /// 检查端口是否开放 - O(1)位图查询
    #[inline]
    pub fn is_port_open(&self, port: u16) -> bool {
        // 安全地获取位图值，默认返回false
        *self
            .open_ports
            .get(port as usize)
            .as_deref()
            .unwrap_or(&false)
    }

    /// 获取所有开放端口列表 - 延迟计算（按需生成）
    pub fn open_ports(&self) -> Vec<u16> {
        // 遍历位图中所有为1的位（开放端口）
        self.open_ports
            .iter_ones()
            .map(|i| i as u16) // 将索引转换为端口号
            .collect()
    }

    /// 获取开放端口数量 - O(1)位图计数
    pub fn open_ports_count(&self) -> usize {
        self.open_ports.count_ones()
    }

    /// 获取开放端口的详细信息（只读引用）
    pub fn open_port_details(&self) -> &[PortResult] {
        &self.open_port_details
    }

    /// 获取特定端口的详细信息
    pub fn get_port_detail(&self, port: u16) -> Option<&PortResult> {
        // 线性搜索（因为开放端口通常很少）
        self.open_port_details()
            .iter()
            .find(|result| result.port == port)
    }

    /// 按协议过滤开放端口详情
    pub fn open_port_details_by_protocol(&self, protocol: Protocol) -> Vec<&PortResult> {
        self.open_port_details
            .iter()
            .filter(|r| r.protocol == protocol)
            .collect()
    }

    /// 转换为JSON友好格式（用于输出/序列化）
    pub fn to_json(&self) -> ScanResultJson {
        ScanResultJson {
            host: self.host.to_string(),               // Box<str>转回String
            ip: self.ip.to_string(),                   // IpAddr转为字符串
            protocol: format!("{:?}", self.protocol),  // 枚举转字符串
            open_ports: self.open_ports(),             // 计算开放端口列表
            open_ports_count: self.open_ports_count(), // 开放端口数量
            details: self
                .open_port_details
                .iter() // 转换详细信息
                .map(|p| PortResultJson {
                    port: p.port,
                    protocol: format!("{:?}", p.protocol),
                    latency_ms: p.latency_ms,
                    banner: p.banner.as_ref().map(|s| s.to_string()), // Box<str>转String
                })
                .collect(),
            scan_duration_ms: self.scan_duration.as_millis() as u64, // 转为毫秒
            total_scanned: self.total_scanned,
            errors: self.errors,
        }
    }
}

/// JSON输出结构 - 用于序列化和网络传输
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResultJson {
    pub host: String,                 // 主机名
    pub ip: String,                   // IP地址字符串
    pub protocol: String,             // 协议字符串
    pub open_ports: Vec<u16>,         // 开放端口列表
    pub open_ports_count: usize,      // 开放端口数量
    pub details: Vec<PortResultJson>, // 端口详细信息
    pub scan_duration_ms: u64,        // 扫描耗时（毫秒）
    pub total_scanned: u32,           // 总扫描数
    pub errors: u32,                  // 错误数
}

/// 端口结果的JSON表示（简化版，不包含状态字段）
#[derive(Debug, Serialize, Deserialize)]
pub struct PortResultJson {
    pub port: u16,               // 端口号
    pub protocol: String,        // 协议字符串
    pub latency_ms: Option<u16>, // 延迟（可选）
    pub banner: Option<String>,  // Banner信息（可选）
}
