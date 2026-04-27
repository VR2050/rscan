# rscan Linux Offline Pack (Debian / Ubuntu)

## Included
- bin/rscan
- bin/zellij (v0.44.1, zellij-x86_64-unknown-linux-musl.tar.gz)
- run-rscan-cli.sh
- run-rscan-tui-zellij.sh


## Quick Start
1. 解压并进入目录
2. CLI: `./run-rscan-cli.sh --help`
3. TUI + zellij: `./run-rscan-tui-zellij.sh`

## Notes
- 该包设计为离线运行，不依赖运行期在线下载。
- 对于 SYN/ARP/ICMP 等原始包能力，建议 root 或配置 `CAP_NET_RAW`。
- 若提示 glibc 版本过低，请在更低版本 Debian/Ubuntu 环境构建 `rscan` 后用 `RSCAN_BIN` 重新打包。
