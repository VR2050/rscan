# 附录A 核心API接口文档

> 说明：本项目为命令行/终端工作台系统，核心“接口”以 CLI 子命令与参数协议为主，同时通过任务目录与结构化输出形成可复用的数据接口。

## A.1 顶层命令接口

基本入口：

```bash
rscan <command> [subcommand] [options]
```

顶层命令：

1. `host`：主机与端口扫描
2. `web`：Web 目录/Fuzz/DNS/Crawl/Live
3. `vuln`：漏洞检测与防护审计
4. `reverse`：逆向分析与反编译任务
5. `tui`：统一终端控制台（Ratatui）

## A.2 Host接口

### A.2.1 `host quick`

```bash
rscan host quick --host <HOST> [--profile low-noise|balanced|aggressive] [--output raw|json]
```

返回：常用端口快速探测结果。

### A.2.2 `host tcp`

```bash
rscan host tcp --host <HOST> --ports <PORTS> \
  [--profile ...] [--tcp-timeout-ms N] [--tcp-concurrency N] \
  [--tcp-mode standard|turbo|turbo-verify|turbo-adaptive] \
  [--tcp-scan-order serial|random|interleave] [--output raw|json]
```

返回：TCP 端口状态、开放端口列表、可选服务指纹信息。

### A.2.3 `host udp`

```bash
rscan host udp --host <HOST> --ports <PORTS> [--profile ...] [--output raw|json]
```

返回：UDP 端口探测结果。

### A.2.4 `host syn`

```bash
rscan host syn --host <HOST> --ports <PORTS> [--profile ...] [--output raw|json]
```

说明：通常需要 root/CAP_NET_RAW。

### A.2.5 `host arp`

```bash
rscan host arp --cidr <CIDR> [--profile ...] [--output raw|json]
```

返回：网段主机发现结果。

## A.3 Web接口

### A.3.1 `web dir`

```bash
rscan web dir --base <URL> --paths <PATH> [--paths <PATH> ...] \
  [--concurrency N] [--timeout-ms N] [--max-retries N] \
  [--status-min N] [--status-max N] [--no-follow-redirect] \
  [--smart-fast|--smart-fast-strict] [--output raw|json|csv]
```

返回：路径扫描命中记录与状态码信息。

### A.3.2 `web fuzz`

```bash
rscan web fuzz --url <URL_WITH_FUZZ> [--keywords a,b] [--keywords-file <FILE>] \
  [--preset api|path|param] [--summary] [--summary-top N] \
  [--concurrency N] [--output raw|json|csv]
```

返回：Fuzz 请求命中、聚类摘要（可选）。

### A.3.3 `web dns`

```bash
rscan web dns --domain <DOMAIN> [--words a,b] [--words-file <FILE>] \
  [--discovery-mode rough|precise] [--output raw|json|csv]
```

返回：子域发现结果。

### A.3.4 `web crawl`

```bash
rscan web crawl --seeds <URL> [--max-depth N] [--max-pages N] [--concurrency N] \
  [--obey-robots] [--output raw|json|csv]
```

返回：爬取入口与链接发现结果。

### A.3.5 `web live`

```bash
rscan web live --urls <URLS> [--method GET|POST|...] [--concurrency N] [--output raw|json|csv]
```

返回：URL 可达性探测结果。

## A.4 Vuln接口

```bash
rscan vuln lint <templates_path>
rscan vuln scan <target> [templates_dir] [--severity ...] [--tag ...]
rscan vuln container-audit <manifests_path>
rscan vuln system-guard
rscan vuln stealth-check <target>
rscan vuln fragment-audit <target>
```

返回：漏洞匹配记录、防护审计统计、风险提示。

## A.5 Reverse接口

### A.5.1 分析与计划

```bash
rscan reverse analyze --input <FILE> [--dynamic ...]
rscan reverse decompile-plan --input <FILE> --engine <objdump|radare2|ghidra|jadx>
```

### A.5.2 作业执行与管理

```bash
rscan reverse decompile-run --input <FILE> --engine <...> --mode <index|function|full> --workspace <DIR>
rscan reverse jobs --workspace <DIR>
rscan reverse job-status --job <JOB_ID> --workspace <DIR>
rscan reverse job-logs --job <JOB_ID> --workspace <DIR>
rscan reverse job-artifacts --job <JOB_ID> --workspace <DIR>
```

### A.5.3 结果查询

```bash
rscan reverse job-functions --job <JOB_ID> --workspace <DIR>
rscan reverse job-show --job <JOB_ID> --name <FUNC>
rscan reverse job-search --job <JOB_ID> --keyword <KW>
```

## A.6 TUI与任务数据接口

### A.6.1 TUI入口

```bash
rscan tui [--workspace <DIR>] [--refresh-ms <N>]
```

### A.6.2 任务目录协议

典型路径：

1. `tasks/<task_id>/meta.json`
2. `tasks/<task_id>/events.jsonl`
3. `tasks/<task_id>/stdout.log`
4. `tasks/<task_id>/stderr.log`

逆向作业路径：

1. `jobs/<job_id>/meta.json`
2. `jobs/<job_id>/stdout.log`
3. `jobs/<job_id>/stderr.log`
4. `reverse_out/<job_id>/...`

### A.6.3 输出格式

主要输出格式：

1. `raw`
2. `json`
3. `csv`

