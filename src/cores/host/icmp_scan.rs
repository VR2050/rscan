#[cfg(test)]
pub mod tests {
    use pnet::transport::{TransportChannelType, icmp_packet_iter};
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::transport::TransportProtocol::Ipv4;

    #[test]
    fn test_icmp() {
        let remote_addr = IpAddr::from_str("127.0.0.1").unwrap();
        let (mut tx, mut rx) = match pnet::transport::transport_channel(
            1024,
            TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp)),
        ) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => {
                eprintln!("跳过 ICMP 测试：创建通道失败（需要原始套接字权限）：{}", e);
                return;
            }
        };
        use pnet::packet::icmp::IcmpPacket;

        let mut icmp_data = [0u8; 64];
        icmp_data[0] = 8; // Type: Echo Request

        icmp_data[1] = 0; // Code

        // 简单校验和设为 0（实际应计算，但许多系统会自动填充）

        icmp_data[2] = 0;

        icmp_data[3] = 0;

        icmp_data[4] = 1; // Identifier

        icmp_data[5] = 2;

        // Sequence

        // Wrap the raw data in an IcmpPacket
        if let Some(packet) = IcmpPacket::new(&icmp_data) {
            // 发送
            match tx.send_to(packet, remote_addr) {
                Ok(_) => println!("ICMP 包已发送"),

                Err(e) => eprintln!("发送失败: {}", e),
            }

            // 接收响应

            let mut iter = icmp_packet_iter(&mut rx);

            if let Ok(Some((packet, _))) = iter.next_with_timeout(Duration::from_secs(2)) {
                println!("收到 ICMP 响应！类型: {:?}", packet.get_icmp_type());
                println!("hello world");
            } else {
                println!("超时或无响应");
            }
        }
    }
}
