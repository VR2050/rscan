use crate::cores::netscan_en::config::ScanConfig;
use crate::cores::netscan_en::models::{PortResult, ScanResult};
use crate::errors::RustpenError;
use serde::{Deserialize, Serialize};
use std::fmt::format;
use std::net::{IpAddr, TcpListener};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::lookup_host;
use tokio::net::tcp::ReuniteError;
//端口扫描trait
pub trait PortScanner {
    async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError>;
    async fn scan_ports(&self, host: IpAddr, ports: &[u16]) -> Result<ScanResult, RustpenError>;
}

#[derive(Debug,Clone)]
pub struct TcpScanner {
    timeout_seconds: u64,
}
impl TcpScanner {
    pub fn new(timeout_seconds: u64) -> Self {
        Self { timeout_seconds }
    }
    pub fn default()->Self{
        Self { timeout_seconds: 3 }
    }
}

// impl PortScanner for TcpScanner{
//     async fn scan_port(&self, host: IpAddr, port: u16) -> Result<ScanResult, RustpenError> {
        
//     }
// }
pub struct UdpScanner;
pub struct SynScanner;

//想定一个插件trait,比如一些延时扫描、随机绕过扫描，waf探测啥的
pub trait Plugin {
    // todo
}
fn parse_ports(ports: &str) -> Result<Vec<u16>, RustpenError> {
    let mut result = Vec::new();

    // 校验并返回合法端口，否则报错
    let validate = |s: &str| -> Result<u16, RustpenError> {
        let port = s.parse().map_err(|_| RustpenError::InvalidPort {
            input: s.to_string(),
        })?;
        if port == 0 || port > 65535 {
            Err(RustpenError::InvalidPort {
                input: s.to_string(),
            })
        } else {
            Ok(port)
        }
    };

    for part in ports.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if part.contains('-') {
            let range: Vec<_> = part.split('-').collect();
            if range.len() != 2 {
                return Err(RustpenError::InvalidPort {
                    input: part.to_string(),
                });
            }
            let start = validate(range[0])?;
            let end = validate(range[1])?;
            if start > end {
                return Err(RustpenError::InvalidPort {
                    input: part.to_string(),
                });
            }
            result.extend(start..=end);
        } else {
            result.push(validate(part)?);
        }
    }

    result.sort_unstable();
    result.dedup();
    Ok(result)
}

// fn parse_hosts(host:&str)

pub mod tests {}
