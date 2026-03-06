use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};

static V4_LOCAL_CACHE: OnceLock<Mutex<HashMap<Ipv4Addr, Ipv4Addr>>> = OnceLock::new();
static V6_LOCAL_CACHE: OnceLock<Mutex<HashMap<Ipv6Addr, Ipv6Addr>>> = OnceLock::new();

pub(crate) fn local_ipv4_for_destination(dest: Ipv4Addr) -> Result<Ipv4Addr, std::io::Error> {
    let cache = V4_LOCAL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(v4) = guard.get(&dest).copied()
    {
        return Ok(v4);
    }

    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V4(dest), 53);
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr()
        && let IpAddr::V4(v4) = local_addr.ip()
    {
        if let Ok(mut guard) = cache.lock() {
            guard.insert(dest, v4);
        }
        return Ok(v4);
    }
    Err(std::io::Error::other("cannot get local ipv4"))
}

pub(crate) fn local_ipv6_for_destination(dest: Ipv6Addr) -> Result<Ipv6Addr, std::io::Error> {
    let cache = V6_LOCAL_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock()
        && let Some(v6) = guard.get(&dest).copied()
    {
        return Ok(v6);
    }

    // Use a connected UDP socket to let the kernel select the outbound interface.
    // For link-local destinations, callers may need to provide an interface scope; we don't handle that here yet.
    let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V6(dest), 53);
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr()
        && let IpAddr::V6(v6) = local_addr.ip()
    {
        if let Ok(mut guard) = cache.lock() {
            guard.insert(dest, v6);
        }
        return Ok(v6);
    }
    Err(std::io::Error::other("cannot get local ipv6"))
}
