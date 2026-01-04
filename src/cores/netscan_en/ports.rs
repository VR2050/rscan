// src/cores/netscan_en/scanner/ports.rs
use crate::errors::RustpenError;

/// 解析端口字符串
pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>, RustpenError> {
    let mut ports = Vec::new();
    
    for part in ports_str.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if part.contains('-') {
            // 处理端口范围
            let range: Vec<_> = part.split('-').collect();
            if range.len() != 2 {
                return Err(RustpenError::InvalidPort {
                    input: part.to_string(),
                });
            }
            
            let start = parse_single_port(range[0])?;
            let end = parse_single_port(range[1])?;
            
            if start > end {
                return Err(RustpenError::InvalidPort {
                    input: part.to_string(),
                });
            }
            
            ports.extend(start..=end);
        } else {
            // 处理单个端口
            let port = parse_single_port(part)?;
            ports.push(port);
        }
    }
    
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_single_port(port_str: &str) -> Result<u16, RustpenError> {
    let port = port_str.parse().map_err(|_| RustpenError::InvalidPort {
        input: port_str.to_string(),
    })?;
    
    if port == 0 {
        Err(RustpenError::InvalidPort {
            input: port_str.to_string(),
        })
    } else {
        Ok(port)
    }
}

/// 获取常见端口列表
pub fn common_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
    ]
}

//解析扫描目标
// pub fn parse_addresses()
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_single_and_range() {
        assert_eq!(parse_ports("22").unwrap(), vec![22]);
        assert_eq!(parse_ports("20-22").unwrap(), vec![20,21,22]);
        assert_eq!(parse_ports("22,80,1000-1002").unwrap(), vec![22,80,1000,1001,1002]);
    }

    #[test]
    fn parse_ports_invalid() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("bad").is_err());
    }
}