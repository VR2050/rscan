use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};

use crate::errors::RustpenError;

const MAX_EXPANDED_TARGETS: usize = 4096;

/// Parse a target expression into a deduplicated IP list.
///
/// Supported input (comma-separated):
/// - Single IP: `192.168.1.1`
/// - Hostname: `example.com`
/// - CIDR: `192.168.1.0/24`
pub fn parse_targets(input: &str) -> Result<Vec<IpAddr>, RustpenError> {
    let mut out = BTreeSet::new();
    for raw in input.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        parse_one_target(token, &mut out)?;
    }
    if out.is_empty() {
        return Err(RustpenError::MissingArgument {
            arg: "targets".to_string(),
        });
    }
    Ok(out.into_iter().collect())
}

fn parse_one_target(token: &str, out: &mut BTreeSet<IpAddr>) -> Result<(), RustpenError> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        out.insert(ip);
        return Ok(());
    }

    if let Ok(net) = token.parse::<IpNetwork>() {
        match net {
            IpNetwork::V4(v4) => insert_ipv4_network(v4, out)?,
            IpNetwork::V6(v6) => insert_ipv6_network(v6, out)?,
        }
        return Ok(());
    }

    let mut resolved = (token, 0)
        .to_socket_addrs()
        .map_err(|_| RustpenError::InvalidHost(token.to_string()))?;
    if let Some(addr) = resolved.next() {
        out.insert(addr.ip());
        for extra in resolved {
            out.insert(extra.ip());
        }
        return Ok(());
    }
    Err(RustpenError::InvalidHost(token.to_string()))
}

fn insert_ipv4_network(net: Ipv4Network, out: &mut BTreeSet<IpAddr>) -> Result<(), RustpenError> {
    let hosts = expand_ipv4_network_hosts(net);
    if hosts.len() > MAX_EXPANDED_TARGETS {
        return Err(RustpenError::ParseError(format!(
            "too many targets in CIDR {}, max={}",
            net, MAX_EXPANDED_TARGETS
        )));
    }
    for ip in hosts {
        out.insert(IpAddr::V4(ip));
    }
    Ok(())
}

fn insert_ipv6_network(net: Ipv6Network, out: &mut BTreeSet<IpAddr>) -> Result<(), RustpenError> {
    // Avoid exploding huge IPv6 prefixes. Only allow /128 and /127 expansion.
    if net.prefix() < 127 {
        return Err(RustpenError::ParseError(format!(
            "ipv6 cidr {} is too broad; only /127 or /128 are supported",
            net
        )));
    }

    let base = net.network();
    out.insert(IpAddr::V6(base));
    if net.prefix() == 127 {
        let n: u128 = base.into();
        out.insert(IpAddr::V6((n + 1).into()));
    }
    Ok(())
}

fn expand_ipv4_network_hosts(net: Ipv4Network) -> Vec<std::net::Ipv4Addr> {
    let network_addr = net.network();
    let prefix = net.prefix();
    let mut targets = Vec::new();
    let net_u32: u32 = network_addr.into();
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if prefix == 32 {
        targets.push(network_addr);
    } else if prefix == 31 {
        targets.push(std::net::Ipv4Addr::from(net_u32));
        targets.push(std::net::Ipv4Addr::from(net_u32 + 1));
    } else if host_bits > 1 {
        let broadcast = net_u32 + ((1u64 << host_bits) as u32) - 1;
        for i in (net_u32 + 1)..broadcast {
            targets.push(std::net::Ipv4Addr::from(i));
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_targets_single_ip() {
        let r = parse_targets("127.0.0.1").unwrap();
        assert_eq!(r, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_targets_ipv4_cidr() {
        let r = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.contains(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(r.contains(&"192.168.1.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_targets_empty_fails() {
        assert!(parse_targets(" , ").is_err());
    }
}
