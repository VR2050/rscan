use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum ScanType {
    Connect,
    Syn,
    UdpProbe,
    IcmpEcho,
    Arp,
    Dns,
}

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub target_ip: IpAddr,
    pub protocol: crate::cores::host::Protocol,
    pub port: Option<u16>,
    pub scan_type: ScanType,
    pub payload: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub retries: u32,
    /// Optional delay between retries (best-effort pacing).
    pub retry_delay_ms: Option<u64>,
    pub tags: Vec<String>,
}

impl ScanJob {
    pub fn new(
        target_ip: IpAddr,
        protocol: crate::cores::host::Protocol,
        scan_type: ScanType,
    ) -> Self {
        Self {
            target_ip,
            protocol,
            port: None,
            scan_type,
            payload: None,
            timeout_ms: 1000,
            retries: 0,
            retry_delay_ms: None,
            tags: Vec::new(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    pub fn with_retry_delay_ms(mut self, delay_ms: u64) -> Self {
        self.retry_delay_ms = Some(delay_ms);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}
