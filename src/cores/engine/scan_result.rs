use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
    Error,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target_ip: IpAddr,
    pub port: Option<u16>,
    pub protocol: crate::cores::host::Protocol,
    pub status: ScanStatus,
    pub latency_ms: Option<u64>,
    pub response: Option<Vec<u8>>,
    pub metadata: Vec<(String, String)>,
}

impl ScanResult {
    pub fn new(
        target_ip: IpAddr,
        protocol: crate::cores::host::Protocol,
        status: ScanStatus,
    ) -> Self {
        Self {
            target_ip,
            port: None,
            protocol,
            status,
            latency_ms: None,
            response: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_latency_ms(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_response(mut self, response: Vec<u8>) -> Self {
        self.response = Some(response);
        self
    }

    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }
}
