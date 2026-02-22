# rscan - 高性能网络扫描与安全检测工具

rscan 是一个基于 Rust 编写的高性能网络扫描与安全检测工具，支持主机发现、端口扫描、Web 指纹识别、目录爆破、漏洞探测等多种功能。适用于渗透测试、资产测绘和网络安全评估场景。

> **注意**: 本项目目前仍处于开发阶段，正在持续完善中

## 特性

- **高性能**: 基于 Rust 异步运行时，支持高并发网络扫描
- **多功能**: 支持 TCP、UDP、SYN、ARP 等多种扫描模式
- **模块化设计**: 清晰的架构，便于功能扩展
- **跨平台**: 支持 Linux、macOS 和 Windows
- **内存安全**: 使用 Rust 语言保证内存安全，避免常见漏洞

## Demo

以下是一些 rscan 的使用示例：

### 主机扫描示例

```bash
# TCP 扫描（指定端口列表）
rscan host tcp --host 192.168.1.1 --ports 22,80,443 --output json

# 快速 TCP 扫描（常用端口）
rscan host quick --host 127.0.0.1 --output raw

# UDP 扫描
rscan host udp --host 192.168.1.1 --ports 53,161 --output json

# SYN 扫描（需要 root 权限）
sudo rscan host syn --host 192.168.1.1 --ports 1-1000 --output json

# ARP 扫描（局域网主机发现）
rscan host arp --cidr 192.168.1.0/24 --output json
```

### Web 扫描示例

```bash
# 目录扫描
rscan web dir --base http://example.com --paths /admin,/login,/api --output csv

# Fuzz 扫描
rscan web fuzz --url http://example.com/FUZZ --keywords admin,login,backup --output raw

# DNS 扫描（子域名枚举）
rscan web dns --domain example.com --words www,api,dev --output json
```

## 安装

### 从源码构建

```bash
# 克隆项目
git clone https://github.com/your-username/rscan.git
cd rscan

# 构建项目
cargo build --release

# 运行测试
cargo test
```

### 从 Cargo 安装

```bash
cargo install rscan
```

## 使用方法

### 端口范围支持

rscan 支持灵活的端口表示法：

```bash
# 单个端口
--ports 80

# 端口范围
--ports 1-1000

# 多个端口和范围
--ports 22,80,443,1000-2000
```

更多 CLI 示例见 `CLI_USAGE.md`。

## 架构

rscan 采用模块化架构设计：

- **核心能力层 (`src/cores`)**: 主机扫描、Web 抓取/爬虫、异步与原始包引擎
- **功能模块层 (`src/modules`)**: 端口扫描、Web 扫描、漏洞检测、逆向、shell 生成
- **命令行接口层 (cli)**: 提供用户交互接口

### 核心功能

1. **网络扫描引擎 (`cores::host` / `cores::engine`)**:
   - TCP 扫描（全连接扫描）
   - UDP 扫描
   - SYN 扫描（半开扫描）
   - ARP 扫描
   - ICMP 扫描

2. **Web 扫描引擎 (`cores::web` + `modules::web_scan`)**:
   - 目录扫描
   - 子域名枚举
   - Web 指纹识别

3. **模块层 (`src/modules`)**:
   - 端口扫描
   - Web 扫描
   - 漏洞检测
   - Shell 生成

项目目录结构说明见 `docs/PROJECT_STRUCTURE.md`。

## 性能优化

rscan 在性能方面做了多项优化：

- **并发控制**: 使用信号量控制并发数，避免系统资源耗尽
- **内存效率**: 使用位图存储端口状态，减少内存占用
- **批量处理**: 支持对大量端口进行分批处理
- **异步 I/O**: 使用 Tokio 异步运行时实现高并发网络请求

## 项目状态

本项目目前仍在开发和完善中，以下是一些正在进行的工作：

- [ ] 完善错误处理机制
- [ ] 增加更多扫描模块
- [ ] 优化性能和内存使用
- [ ] 增加更多输出格式
- [ ] 完善文档和示例

## 安全说明

- 请仅在授权范围内使用此工具
- 遵守当地法律法规
- 不要对未授权的系统进行扫描
- SYN/ARP/ICMP 等原始包扫描需要 root 或 CAP_NET_RAW 权限，使用时需谨慎

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进 rscan。

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](./LICENSE) 文件。

## 致谢

- 感谢 Rust 社区提供的优秀库和工具
- 感谢 nmap 等开源扫描工具的启发
