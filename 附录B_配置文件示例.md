# 附录B 配置文件示例

> 说明：本项目主要采用“命令参数 + 环境变量”配置方式。以下示例可直接用于实验记录与复现实验。

## B.1 Host扫描参数示例

```bash
rscan host tcp \
  --host 192.168.8.145 \
  --ports 1-1024 \
  --profile aggressive \
  --tcp-timeout-ms 700 \
  --tcp-concurrency 1024 \
  --tcp-mode turbo-adaptive \
  --tcp-scan-order interleave \
  --tcp-adaptive-backpressure \
  --output json
```

## B.2 Web扫描参数示例

### B.2.1 目录扫描

```bash
rscan web dir \
  --base http://192.168.8.145 \
  --paths / --paths /robots.txt --paths /admin --paths /login \
  --concurrency 12 \
  --timeout-ms 2500 \
  --max-retries 1 \
  --status-min 200 --status-max 499 \
  --no-follow-redirect \
  --output raw
```

### B.2.2 Fuzz扫描

```bash
rscan web fuzz \
  --url http://target/FUZZ \
  --keywords admin,login \
  --keywords-file ./wordlists/common.txt \
  --preset api \
  --summary --summary-top 10 \
  --concurrency 32 \
  --output raw
```

## B.3 Reverse环境变量示例

```bash
# 指定 Ghidra 运行时
export RSCAN_GHIDRA_HOME=/home/vr2050/RUST/rscan_codex/third_party/ghidra_core_headless_x86_min

# 动态分析参数
export RSCAN_REVERSE_DYNAMIC=1
export RSCAN_REVERSE_DYNAMIC_TIMEOUT_MS=1500
export RSCAN_REVERSE_DYNAMIC_SYSCALLS=ptrace,prctl,seccomp
export RSCAN_REVERSE_DYNAMIC_BLOCKLIST=pause,cmd.exe
```

对应命令：

```bash
rscan reverse analyze --input ./easy --dynamic
```

## B.4 Zellij/TUI配置示例

```bash
# 启用 zellij managed runtime
export RSCAN_ZELLIJ=1
export RSCAN_ZELLIJ_SESSION=rscan

# 启动统一 TUI
cargo run -- tui --workspace /home/vr2050/RUST/rscan_codex
```

## B.5 基准与门禁脚本示例

### B.5.1 Web三工具对比

```bash
./scripts/web_bench_compare.sh \
  http://192.168.8.145 \
  /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  50
```

### B.5.2 Web回归门禁

```bash
./scripts/ci_web_bench_gate.sh \
  http://192.168.8.145 \
  /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  50 \
  /tmp/rscan_web_bench_baseline_ms.txt \
  15
```

