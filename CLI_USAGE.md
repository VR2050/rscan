# rscan CLI 使用示例

简短示例展示 rscan 常见的命令用法（更多细节可通过 `rscan --help` 或 `rscan <subcommand> --help` 查看）。

基本格式：

- rscan host <tcp|udp|syn|quick|arp> ...
- rscan web <dir|fuzz|dns> ...
- rscan vuln <lint|scan|container-audit|system-guard|stealth-check> ...

示例：

- TCP 扫描（指定端口列表）：

```bash
rscan host tcp --host 1.2.3.4 --ports 22,80,443 --output json
```

- 低噪声主机扫描（降低并发、提高超时与重试）：

```bash
rscan host tcp --host 1.2.3.4 --ports 22,80,443 --profile low-noise --output json
```

- 高速全端口扫描（借鉴 rustscan 的“高并发 + 短超时”思路，可按网络质量调节）：

```bash
rscan host tcp \
  --host 192.168.9.104 \
  --ports 1-65535 \
  --profile aggressive \
  --tcp-concurrency 2048 \
  --tcp-timeout-ms 700 \
  --tcp-retries 0 \
  --output json
```

- 两阶段高速扫描（先 turbo 发现，再对 filtered 端口定向复核）：

```bash
rscan host tcp \
  --host 192.168.9.104 \
  --ports 1-65535 \
  --profile aggressive \
  --tcp-mode turbo-verify \
  --output json
```

- 高速且低噪声可控（顺序扰动 + 速率上限 + 抖动 + 自适应背压）：

```bash
rscan host tcp \
  --host 192.168.9.104 \
  --ports 1-65535 \
  --profile aggressive \
  --tcp-mode turbo-adaptive \
  --tcp-scan-order interleave \
  --tcp-max-rate 9500 \
  --tcp-jitter-ms 2 \
  --tcp-adaptive-backpressure \
  --output json
```

- 自动调参后再全端口（先小样本选参数，再执行完整扫描）：

```bash
rscan host tcp \
  --host 192.168.9.104 \
  --ports 1-65535 \
  --profile aggressive \
  --tcp-mode turbo-adaptive \
  --tcp-auto-tune \
  --tcp-scan-order interleave \
  --tcp-adaptive-backpressure \
  --output json
```

- 快速 TCP 扫描（常用端口）：

```bash
rscan host quick --host 127.0.0.1 --output raw
```

- UDP 扫描并写入文件：

```bash
rscan host udp --host 127.0.0.1 --ports 53 --output json --out /tmp/udp_scan.json
```

- ARP 扫描一个网段（CIDR）：

```bash
rscan host arp --cidr 192.168.1.0/24 --output json
```

- SYN 扫描模式切换（`strict` 更快，`verify-filtered` 更完整）：

```bash
sudo rscan host syn \
  --host 192.168.9.104 \
  --ports 1-1024 \
  --profile aggressive \
  --syn-mode strict \
  --output json
```

- Web 目录扫描（指定 base URL 和路径列表）：

```bash
rscan web dir --base http://example.com --paths /admin --paths /login --output csv
```

- 低噪声 Web 扫描（适合减少告警噪声）：

```bash
rscan web dir --base http://example.com --paths /admin --profile low-noise --output json
```

- Web fuzz（URL 模板需包含 `FUZZ`）：

```bash
rscan web fuzz --url http://example.com/FUZZ --keywords admin,login --output raw
```

- Web fuzz 增强模式（关键词文件 + 变换组合）：

```bash
rscan web fuzz \
  --url http://example.com/FUZZ \
  --keywords admin \
  --keywords-file ./wordlists/common.txt \
  --kw-transform raw,url-encode,double-url-encode,path-wrap \
  --keyword-prefix test- \
  --keyword-max-len 64 \
  --output raw
```

- Web fuzz 预设模式（快速覆盖 API/Path/Param 形态）：

```bash
rscan web fuzz \
  --url http://example.com/FUZZ \
  --keywords user,login \
  --preset api \
  --summary \
  --summary-top 10 \
  --content-len-min 50 \
  --output raw
```

- Web 高速模式（`smart-fast`，更快但会减少部分边缘命中）：

```bash
rscan web fuzz \
  --url http://example.com/FUZZ \
  --keywords-file ./wordlists/common.txt \
  --smart-fast \
  --output raw
```

- Web 更激进高速模式（`smart-fast-strict`，默认压到 `200-399`）：

```bash
rscan web fuzz \
  --url http://example.com/FUZZ \
  --keywords-file ./wordlists/common.txt \
  --smart-fast-strict \
  --output raw
```

- Web 目录扫描同样支持 `--smart-fast`：

```bash
rscan web dir \
  --base http://example.com \
  --paths /admin --paths /login \
  --smart-fast
```

- 三工具公平基准（rscan/ffuf/gobuster）：

```bash
./scripts/web_bench_compare.sh http://192.168.9.104:8083 /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt 50
```

- CI 回归门禁（默认允许相对历史基线最多退化 15%）：

```bash
./scripts/ci_web_bench_gate.sh http://192.168.9.104:8083 /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt 50 /tmp/rscan_web_bench_baseline_ms.txt 15
```

- 子域名爆破（DNS）：

```bash
rscan web dns --domain example.com --words www,api,dev --output json
```

- 子域名爆破支持词表文件（可与 `--words` 混用）：

```bash
rscan web dns \
  --domain example.com \
  --words www \
  --words-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --output raw
```

- 子域名发现模式开关：
粗略发现（仅 DNS 可解析）：
```bash
rscan web dns \
  --domain example.com \
  --words-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --discovery-mode rough \
  --output raw
```
精准发现（DNS + HTTP/HTTPS 可访问，默认）：
```bash
rscan web dns \
  --domain example.com \
  --words-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --discovery-mode precise \
  --status-min 200 --status-max 399 \
  --output raw
```

- 漏洞扫描（按严重度/标签过滤模板）：

```bash
rscan vuln scan \
  --targets https://example.com \
  --templates ./rules \
  --severity high,critical \
  --tag cve,rce \
  --output json
```

- 容器/K8s 清单安全审计（仅检测高风险配置）：

```bash
rscan vuln container-audit \
  --manifests ./k8s-manifests \
  --output raw
```

- 本机安全查杀/防护基线体检（AV/EDR、防火墙、审计）：

```bash
rscan vuln system-guard --output raw
```

- 隐蔽扫描防护检测（低噪声 vs 突发请求行为差异）：

```bash
rscan vuln stealth-check \
  --target https://example.com \
  --low-noise-requests 10 \
  --burst-requests 40 \
  --burst-concurrency 20 \
  --variant-requests 12 \
  --variant-concurrency 6 \
  --output raw
```

- 分片/重组稳健性审计（防御评估，非绕过）：

```bash
rscan vuln fragment-audit \
  --target http://192.168.9.104 \
  --requests-per-tier 6 \
  --payload-min-bytes 1024 \
  --payload-max-bytes 24576 \
  --payload-step-bytes 4096 \
  --concurrency 4 \
  --timeout-ms 4000 \
  --output json
```

- 高级变体探测说明（防御向）：
  - 内置 `path-encoding` / `query-noise` / `header-noise` / `method-options` / `method-get` 五类探测变体，用于评估目标 anti-scan 策略对不同流量形态的敏感度。  
  - `--no-advanced-checks` 可关闭高级变体探测。  
  - 不包含 `IP fragmentation`、`IDS/EDR bypass` 等攻击型绕过实现。
  - 输出包含 `protection_score`（防护强度评分）与 `confidence`（样本置信度）以及自动加固建议。

- Nuclei 常见占位符兼容（安全子集）：
  - 路径模板中的 `{{BaseURL}}`、`{{RootURL}}`、`{{Hostname}}`、`{{Host}}`、`{{Port}}` 会自动渲染。  
  - 仅支持安全请求方法（GET/HEAD）。

提示：

- 输出格式支持 `raw`、`json`、`csv`；默认 `raw`。  
- `host tcp` 支持 `--tcp-mode standard|turbo|turbo-verify|turbo-adaptive`：`turbo` 优先速度，`turbo-verify` 偏准确，`turbo-adaptive` 会按 filtered 比例自适应复核。  
- `host tcp` 还支持 `--tcp-max-rate`、`--tcp-jitter-ms`、`--tcp-scan-order serial|random|interleave`、`--tcp-adaptive-backpressure` 用于低噪声与稳定性控制。  
- 部分命令支持将逐行流式输出写入文件：使用 `--stream_to /path/to/file`（仅 web 子命令中的某些操作）。  
- `web dir|fuzz|dns` 支持 `--no-dedupe` 显式关闭去重（默认去重开启）。  
- 查看子命令详细用法：`rscan host tcp --help` 或 `rscan web dir --help`。
