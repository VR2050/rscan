use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

pub(crate) fn local_ipv4_for_destination(dest: Ipv4Addr) -> Result<Ipv4Addr, std::io::Error> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V4(dest), 53);
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr() {
        if let IpAddr::V4(v4) = local_addr.ip() {
            return Ok(v4);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "cannot get local ipv4",
    ))
}

pub(crate) fn local_ipv6_for_destination(dest: Ipv6Addr) -> Result<Ipv6Addr, std::io::Error> {
    // Use a connected UDP socket to let the kernel select the outbound interface.
    // For link-local destinations, callers may need to provide an interface scope; we don't handle that here yet.
    let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    let addr = SocketAddr::new(IpAddr::V6(dest), 53);
    sock.connect(addr)?;
    if let Ok(local_addr) = sock.local_addr() {
        if let IpAddr::V6(v6) = local_addr.ip() {
            return Ok(v6);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "cannot get local ipv6",
    ))
}
