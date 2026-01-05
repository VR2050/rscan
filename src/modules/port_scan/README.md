# modules::port_scan

模块 `port_scan` 为上层提供了主机扫描（TCP/UDP/SYN/ARP）的简单封装，内部复用 `cores::netscan_en` 提供的扫描器。

Features:
- HostScanner: 简单异步 API（scan_tcp, scan_udp, scan_syn, quick_tcp, arp_scan_cidr）
- 已包含单元测试（本地 listener 模拟）和集成测试（需特权，标记为 `#[ignore]`）

示例（Rust）:

```rust
use modules::HostScanner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = HostScanner::default();
    let res = scanner.scan_tcp("127.0.0.1", &[22, 80, 443]).await?;
    println!("开放端口: {:?}", res.open_ports());
    Ok(())
}
```

CLI 示例（占位）:

```
# rscan port tcp --host 192.168.1.5 --ports 22,80,443
# 输出(JSON): {"host":"192.168.1.5","open_ports":[22,80]}
```

运行测试:

```sh
cargo test -p rscan
# ARP/原始套接字相关的测试会被标记为 ignored
```
