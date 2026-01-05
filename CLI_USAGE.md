# rscan CLI 使用示例

简短示例展示 rscan 常见的命令用法（更多细节可通过 `rscan --help` 或 `rscan <subcommand> --help` 查看）。

基本格式：

- rscan host <tcp|udp|syn|quick|arp> ...
- rscan web <dir|fuzz|dns> ...

示例：

- TCP 扫描（指定端口列表）：

```bash
rscan host tcp --host 1.2.3.4 --ports 22,80,443 --output json
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

- Web 目录扫描（指定 base URL 和路径列表）：

```bash
rscan web dir --base http://example.com --paths /admin --paths /login --output csv
```

- Web fuzz（URL 模板需包含 `FUZZ`）：

```bash
rscan web fuzz --url http://example.com/FUZZ --keywords admin,login --output raw
```

- 子域名爆破（DNS）：

```bash
rscan web dns --domain example.com --words www,api,dev --output json
```

提示：

- 输出格式支持 `raw`、`json`、`csv`；默认 `raw`。  
- 部分命令支持将逐行流式输出写入文件：使用 `--stream_to /path/to/file`（仅 web 子命令中的某些操作）。  
- 查看子命令详细用法：`rscan host tcp --help` 或 `rscan web dir --help`。
