# TUI 使用说明

本文聚焦统一 `TUI` 控制面，而不是各模块的完整 CLI 细节。目标是回答三个问题：

- 如何启动与理解 `TUI`
- 如何在 `TUI` 中创建 `host / web / vuln / reverse` 任务
- 为什么某个任务显示 `100%` 但结果为空，以及该如何判断

## 启动方式

```bash
# 默认启动统一 TUI
cargo run -- tui

# 显式启用 zellij managed layout
RSCAN_ZELLIJ=1 cargo run -- tui
```

managed layout 固定为 4 个 tab：

- `Control`：统一控制面，负责命令输入、任务列表、结果聚合
- `Work`：项目、最近任务、脚本运行的原生工作台
- `Inspect`：任务详情、日志预览、artifact/shell 跳转
- `Reverse`：reverse surface 与完整 reverse viewer 的桥接层

## 核心面板

`Control` tab 中最关键的是这几个 pane：

- `Dashboard`：总体摘要、zellij pane registry、最近 runtime 绑定
- `Tasks`：所有任务的状态视图
- `Launcher`：预置 launcher 命令示例
- `Results`：聚合后的结果列表与详情

其中 `Tasks` 看任务生命周期，`Results` 看最终可展示结果，两者相互补充。

## 命令模式

进入命令模式后，可以直接输入短命令。`TUI` 会把它们翻译成底层 CLI 参数，再交给原有任务引擎执行。

### 通用行为

- 新任务启动时会立即写入占位 `meta.json`，不会再出现“列表里没有任务，突然 100%”的假象
- 提交命令后，焦点会优先跳到最新任务
- 顶层补全优先补父级命令：`host`、`web`、`vuln`、`reverse`
- 父级命令确定后，再补子命令与常用 flags
- dotted alias 仍可用，适合高频输入

### host

支持的分支：

- `host quick`
- `host tcp`
- `host udp`
- `host syn`
- `host arp`

对应 alias：

- `h.quick`
- `h.tcp`
- `h.udp`
- `h.syn`
- `h.arp`

已接入的常用参数：

- `--profile low-noise|balanced|aggressive`
- `--service-detect`
- `--probes-file <path>`
- `--syn-mode strict|verify-filtered`

示例：

```bash
h.quick 192.168.8.145 --profile balanced
h.tcp 192.168.8.145 22,80,443 --service-detect
h.udp 192.168.8.145 53,161 --profile aggressive --probes-file /tmp/probes.txt
h.syn 192.168.8.145 22,80,443 --profile low-noise --syn-mode strict
h.arp 192.168.8.0/24 --profile balanced
```

### web

支持的分支：

- `web dir`
- `web fuzz`
- `web dns`
- `web crawl`
- `web live`

对应 alias：

- `w.dir`
- `w.fuzz`
- `w.dns`
- `w.crawl`
- `w.live`

已接入的常用参数：

- 通用：`--profile`、`--concurrency`、`--timeout-ms`、`--max-retries`
- HTTP：`--header`、`--status-min`、`--status-max`、`--method`
- `dir`：`--recursive`、`--recursive-depth`
- `fuzz`：`--keywords-file`
- `dns`：`--words-file`、`--discovery-mode rough|precise`
- `crawl`：`--max-depth`、`--max-pages`、`--obey-robots`
- `live`：`--method`、`--concurrency`

示例：

```bash
w.dir https://example.com /,/admin --profile aggressive --recursive --recursive-depth 3
w.fuzz https://example.com/FUZZ admin,login --header "Authorization: Bearer xxx"
w.dns example.com www,api,dev --words-file ./subs.txt --discovery-mode precise
w.crawl https://example.com --max-depth 2 --max-pages 200
w.live https://example.com,https://example.org --method GET --concurrency 32
```

### vuln

支持的分支：

- `vuln lint`
- `vuln scan`
- `vuln container-audit`
- `vuln system-guard`
- `vuln stealth-check`
- `vuln fragment-audit`

对应 alias：

- `v.lint`
- `v.scan`
- `v.ca`
- `v.sg`
- `v.sc`
- `v.fa`

已接入的常用参数：

- `scan`：`--severity`、`--tag`、`--concurrency`、`--timeout-ms`
- `stealth-check`：`--timeout-ms`、`--low-noise-requests`、`--burst-requests`、`--burst-concurrency`
- `fragment-audit`：`--timeout-ms`、`--concurrency`、`--requests-per-tier`、`--payload-min-bytes`、`--payload-max-bytes`、`--payload-step-bytes`

说明：

- `v.scan <target>` 如果没有显式给模板目录，`TUI` 会自动准备内置安全模板目录
- `v.sg` 不需要目标参数

示例：

```bash
v.lint ./nuclei-templates
v.scan https://example.com --severity high,critical --tag cve,rce --concurrency 16 --timeout-ms 4500
v.ca ./k8s
v.sg
v.sc https://example.com --burst-concurrency 20 --timeout-ms 3000
v.fa https://example.com --concurrency 8 --requests-per-tier 10
```

### reverse

支持的分支：

- `reverse analyze`
- `reverse plan`
- `reverse run`
- `reverse jobs`
- `reverse job-status`
- `reverse job-logs`
- `reverse job-artifacts`
- `reverse job-functions`
- `reverse job-show`
- `reverse job-search`
- `reverse job-clear`
- `reverse job-prune`
- `reverse job-doctor`
- `reverse debug-script`

对应 alias：

- `r.analyze`
- `r.plan`
- `r.run`
- `r.jobs`
- `r.status`
- `r.logs`
- `r.artifacts`
- `r.funcs`
- `r.show`
- `r.search`
- `r.clear`
- `r.prune`
- `r.doctor`
- `r.debug`

已接入的常用参数：

- `analyze`：`--rules-file`、`--dynamic`、`--dynamic-timeout-ms`、`--dynamic-syscalls`、`--dynamic-blocklist`
- `plan`：`--output-dir`
- `run`：`--deep`、`--rust-first`、`--no-rust-first`、`--timeout-secs`
- `job-logs`：`--stream stdout|stderr|both`
- `job-search`：`--max`
- `job-clear`：`--all`
- `job-prune`：`--keep`、`--older-than-days`、`--include-running`
- `debug-script`：`--profile pwngdb|pwndbg`、`--pwndbg-init`

示例：

```bash
r.analyze /bin/ls --dynamic --dynamic-timeout-ms 5000
r.plan /bin/ls ghidra --output-dir /tmp/rev-plan
r.run /bin/ls ghidra full --deep --no-rust-first --timeout-secs 90
r.jobs
r.status <job_id>
r.logs <job_id> --stream both
r.search <job_id> crypto --max 10
r.debug /bin/ls /tmp/ls.gdb pwndbg
```

## 命令补全

当前补全策略是：

1. 先补父级命令，如 `host / web / vuln / reverse`
2. 再补分支，如 `web crawl`、`vuln stealth-check`
3. 再补高频 flags，如 `--timeout-ms`、`--severity`、`--stream`

这比旧版“上来就塞占位符”更稳，但仍有一个已知限制：

- 某些位置仍会补出 `<job_id>`、`<host>` 这类占位符文本，它们是提示，不是自动发现的真实值

## Results 面板与结果诊断

`Results` 现在不会再把“成功但无内容”的任务伪装成正常结果，而是会区分三种状态：

- `artifact-ready`
  含义：已经发现可预览 artifact，右侧详情能直接展示结构化结果
- `logs-only`
  含义：还没有可预览 artifact，但任务日志里已有可看的输出
- `empty`
  含义：任务状态已结束，但目前既无 artifact，也没有可展示日志内容

在列表和详情中会看到诸如：

- `res:artifact`
- `res:logs`
- `res:empty`
- `result-state: artifact-ready|logs-only|empty`

### 为什么任务显示 100% 却没有展示任何结果

这通常是以下几类情况：

1. 任务真的成功了，但模块只写了状态，没有写 artifact，也没有 stdout 结果摘要。
2. 任务失败得很快，`stderr` 里有错误，但没有结构化 artifact。
3. 某个命令只创建了 reverse/job/task 记录，真正的可展示产物还没生成完。

现在 `TUI` 的行为是：

- 启动时先写占位 meta，避免“凭空 100%”
- 若只有日志，会明确显示 `logs-only`
- 若什么都没有，会明确显示 `empty`

也就是说，看到 `100%` 但右侧空，不再代表 `TUI` 一定坏了，而是代表“这个任务没有生成可展示结果”，需要看日志或 artifact 诊断区继续追

## 与原生 pane 的联动

在 `Tasks / Results` 中可以直接把当前任务送进 zellij 原生 pane：

- `L`：打开日志 pane
- `W`：打开 task shell
- `A`：打开 artifact shell

命令模式也支持：

- `zlogs <task_id>`
- `zshell <task_id>`
- `zart <task_id>`
- `zrev`
- `zfocus <control|work|inspect|reverse>`

详情面板会显示最近 runtime 绑定：

- `session`
- `tab`
- `pane`
- `cwd`
- `command`

这让你能判断“当前看到的任务”到底绑定到哪个原生 pane。

## Launcher 面板

`Launcher` 已同步更新为覆盖高频场景的示例入口，包含：

- `host`：`quick / tcp / udp / syn / arp`
- `web`：`dir / fuzz / dns / crawl / live`
- `vuln`：`lint / scan / container-audit / system-guard / stealth-check / fragment-audit`
- `reverse`：`analyze / plan / run / jobs / status / logs / artifacts / funcs / show / search / clear / prune / doctor / debug`

如果一时记不住命令，优先从 `Launcher` 里选，再微调参数即可。

## 已知限制

- `TUI` 当前接的是高频主链和关键 flags，不是 CLI 的每一个冷门参数
- 某些扫描方式本身仍受环境权限限制，例如 `host syn` 需要 root 或 `CAP_NET_RAW`
- reverse 的部分能力依赖外部引擎环境，如 Ghidra / JADX / radare2

## 推荐排障顺序

当你怀疑 `TUI` 没显示结果时，按这个顺序看：

1. 去 `Tasks` 看状态是不是 `Succeeded / Failed / Running`
2. 去 `Results` 看 `result-state` 是 `artifact-ready / logs-only / empty`
3. 若是 `logs-only`，直接按 `L` 或用 `zlogs <task_id>`
4. 若是 `artifact-ready`，按 `A` 看 artifact shell
5. 若是 `empty`，优先怀疑底层命令没有产出展示内容，而不是 UI 没刷新
