# rscan | 高性能网络与逆向安全扫描工具

rscan 是用 Rust 编写的多合一安全扫描器，覆盖主机/端口探测、Web 目录与指纹识别、漏洞 PoC/Fuzz、以及二进制逆向分析（集成 Ghidra）。项目面向渗透测试、资产测绘与自动化安全评估场景，强调高并发、模块化和可扩展。

> 状态：活跃开发中（2026-03-03）。接口随时可能调整，生产使用请留意版本变更。

## 能力概览
- **主机/端口扫描**：TCP/UDP 全连接、SYN 半开、快速常用端口、ARP/ICMP 主机发现。
- **服务指纹**：兼容 nmap probes 风格的 banner 采集与指纹识别，自动写入扫描元数据。
- **Web 侧**：目录/路径爆破、关键字 Fuzz、子域名枚举 (DNS)、基础指纹识别与抓取。
- **漏洞与 PoC**：模块化 PoC、Fuzz 攻击模板 (`src/modules/vuln_check/`)，可按需扩展规则 (`rules/`)。
- **逆向分析**：静态分析、反编译、TUI/控制台、任务化批处理、轻量动态（strace 抽样），内置精简版 Ghidra 运行时。
- **输出与集成**：raw/json/csv，多数命令支持文件输出或流式写入；结构化结果方便二次处理。
- **性能特性**：Tokio 异步 + Rayon 并行，位图端口状态、批量探测、并发信号量控制。

## 快速开始
### 环境要求
- Rust 1.80+（edition 2024）
- Linux/macOS/Windows 均可运行；SYN/ARP/ICMP 等原始包扫描需 root 或 `CAP_NET_RAW`。
- 逆向模块如需全量 Ghidra 能力，可设置 `RSCAN_GHIDRA_HOME` 指向完整 Ghidra；仓库已自带精简版：`third_party/ghidra_core_headless_x86_min`。

### 从源码构建（推荐）
```bash
git clone https://github.com/your-username/rscan.git
cd rscan
cargo build --release
```
可选：将 `target/release` 加入 PATH 或执行 `cargo install --path .` 进行本地安装。

### 运行最小示例
```bash
# 快速端口扫描（常用端口）
rscan host quick --host 127.0.0.1 --output raw

# 指定端口 TCP 全连接
sudo rscan host tcp --host 192.168.1.1 --ports 22,80,443 --output json

# Web 目录爆破
rscan web dir --base http://example.com --paths /admin --paths /login --output csv

# 子域名枚举
rscan web dns --domain example.com --words www,api,dev --output json
```
更多命令见 `CLI_USAGE.md` 或 `rscan --help`。

### 端口与并发控制
- 端口支持单值、范围与混合：`--ports 80`、`--ports 1-1000`、`--ports 22,80,443,1000-2000`。
- 使用 `--concurrency`（若子命令支持）配合内置信号量，避免资源耗尽；大范围扫描会自动分批。

### 输出与日志
- 输出格式：`raw`（默认）/`json`/`csv`。部分 Web/逆向命令支持 `--stream_to <file>` 持续写入。
- 结果会携带元数据（banner、service/version/confidence 等）便于后处理。

## 逆向模块速览
来自 `docs/REVERSE_USAGE.md` 的常用流程：
- 静态分析：`rscan reverse analyze ./easy`
- 反编译（全量/索引/单函数）：`rscan reverse decompile-run --input ./easy --engine ghidra --mode full`
- 控制台：`rscan reverse console ./easy`；TUI：追加 `--tui`
- 任务管理：`reverse job-status/job-logs/job-artifacts/job-functions/job-show/job-search`
- 动态采样：`rscan reverse analyze --input ./easy --dynamic`（或 `RSCAN_REVERSE_DYNAMIC=1`）
- Ghidra 配置：`RSCAN_GHIDRA_HOME=/path/to/ghidra`；若未设置则回退到内置精简版。

更多快捷键、环境变量与脚本生成请见 `docs/REVERSE_USAGE.md`。

## 架构与模块解剖
- **CLI 层** (`src/cli/`)：基于 clap 的子命令/参数解析，负责把用户输入转换为内部任务描述。
- **核心能力层** (`src/cores/`):
  - `host`：原始包与套接字扫描引擎，封装 TCP/UDP/SYN/ARP/ICMP 等探测策略。
  - `web`：请求调度、抓取与解析（使用 `reqwest`、`scraper`），为目录/指纹/子域枚举提供基座。
  - `engine`：统一的 `ScanResult` 数据模型、并发/节流控制、结果汇聚与输出格式化。
- **模块层** (`src/modules/`):
  - `port_scan`：端口扫描 + 服务探测，调用 `service_probe` 进行 banner 指纹识别。
  - `web_scan`：目录爆破、Fuzz、DNS 枚举；支持流式输出与多格式写盘。
  - `vuln_check`：PoC/Fuzz 模板引擎，包含 `scanner.rs` 统筹与 `safe_templates.rs`、`fuzz_attack.rs` 等扩展点。
  - `reverse`：逆向任务编排、TUI/控制台交互、与外部反编译引擎的桥接。
  - `shell_generation`：生成恶意或测试用 payload/shell 片段。
- **服务层** (`src/services/`)：`service_probe` 负责解析 nmap 式 probe 文件，输出 `ProbeResult` 并富化扫描结果元数据。
- **规则与数据**：`rules/` 用于自定义 PoC/探针；`third_party/` 持有 Ghidra 精简运行时等外部依赖。
- **文档与基准**：`docs/` 提供结构与逆向使用说明；`benches/` 存放性能基准脚本。
完整目录说明见 `docs/PROJECT_STRUCTURE.md`。

## 模块功能详情
- **Host / Port Scan**
  - 探测：TCP/UDP 全连接，SYN 半开，ICMP/ARP 主机发现，常用端口快速模式。
  - 并发：Tokio + 自定义信号量，批量切片端口范围避免 file descriptor 爆炸。
  - 识别：结合 `service_probe` 的 banner 指纹；将 `service`、`service_version`、`service_confidence` 写入结果元数据。
- **Web Scan**
  - 目录爆破：多路径输入、重试与响应过滤；支持 csv/json/raw 输出。
  - Fuzz：`FUZZ` 占位符替换关键字，支持粗暴枚举与命中收集。
  - DNS/子域：基于词典的并发解析，输出 JSON 以便后续资产测绘。
- **Vuln Check / PoC**
  - 模板：`rules/` + `safe_templates.rs` 提供安全默认值，便于添加新漏洞探测规则。
  - Fuzz：`fuzz_attack.rs` 允许自定义 payload 生成与响应匹配逻辑。
  - 结果：统一写入 `ScanResult`，可与端口/服务信息联动。
- **Shell Generation**
  - 生成常见语言/平台的 shellcode 或反连片段，方便渗透测试验证。

## 模块深度介绍与用法提示
- **Host 模块 (`src/cores/host/`, `src/modules/port_scan/`)**
  - 扫描类型：`tcp`（全连接）、`udp`、`syn`（半开，需 root/CAP_NET_RAW）、`quick`（精选常用端口）、`arp`、`icmp`。
  - 端口输入：单值/范围/组合皆可；默认随机化端口顺序以降低被防护设备识别。
  - 探测优化：端口列表批量拆分 + 信号量限流；`socket2` 调优连接超时；位图记录状态减少内存。
  - 指纹联动：扫描响应交由 `service_probe` 匹配 nmap 样式规则，产出 `banner_text` 和 service/version。
  - 适用场景：内网资产盘点、弱口令/PoC 前的服务分类、端口基线检查。

- **Web 模块 (`src/modules/web_scan/`)**
  - `dir` 目录/路径爆破：支持多 `--paths`、自定义词典、失败重试；可按状态码/长度过滤响应。
  - `fuzz` 关键字替换：URL 中 `FUZZ` 占位符自动展开；适合接口/文件名穷举。
  - `dns` 子域爆破：并发 DNS 解析，支持自定义词表；输出结构化 JSON，方便喂入下一步扫描。
  - 抓取与指纹：`cores::web` 负责请求与解析，可拓展指纹规则（见 `web` 引擎）。
  - 适用场景：攻防演练入口收集、目录泄露探测、子域资产补全。

- **Vulnerability Check 模块 (`src/modules/vuln_check/`)**
  - 结构：`scanner.rs` 调度；`safe_templates.rs` 定义安全默认模板；`fuzz_attack.rs` 负责 payload 生成；`poc_scan.rs` 定义 PoC 执行逻辑。
  - 规则存放：`rules/`（YAML/JSON 皆可），可按协议/服务分类扩展；支持简易匹配与响应断言。
  - 流程：载入规则 → 根据端口/服务元数据筛选 → 发送探测请求 → 依据正则/状态码/特征串判断 → 写入 `ScanResult`。
  - 适用场景：批量 PoC 验证、Fuzz 穷举、与端口扫描联动的自动化漏洞初筛。

- **Reverse 模块 (`src/modules/reverse/`)**
  - 入口命令：`reverse analyze`（静态信息）、`reverse decompile-run`（执行反编译任务，支持 full/index/function）、`reverse decompile-plan`（生成外部脚本）、`reverse decompile-batch`（批处理）、`reverse console`/`--tui`（交互）。
  - 引擎选择：优先环境变量指定 Ghidra；否则使用仓库内置精简版。可生成 ida/radare/jadx 命令计划以便外部跑。
  - 任务模型：每次反编译形成 job，产物/日志/索引存储于 workspace；`job-status`/`job-logs`/`job-artifacts`/`job-functions`/`job-search` 统一管理。
  - 索引与搜索：Tantivy 建索引 (`project_index.jsonl`)，支持跨 job 搜索字符串/函数签名/伪代码。
  - 交互特性：TUI 多窗格、快捷键丰富（见 `docs/REVERSE_USAGE.md`），支持行内注释、调用/引用图导出、函数级别重编译。
  - 动态补充：`--dynamic` 开启 strace 抽样，可配置 syscall 白/黑名单及超时；适合快速行为线索收集。
  - 适用场景：恶意样本 triage、批量固件/二进制索引、函数级差分分析、快速伪代码导出。

- **Shell Generation 模块 (`src/modules/shell_generation/`)**
  - 能力：生成常见平台/语言的反连或命令执行片段，便于渗透验证或 CTF 工具链；可与漏洞模块串联自动下发 payload。
  - 安全提示：默认仅输出文本片段，不自动执行。

- **Service Probe 服务层 (`src/services/service_probe.rs`)**
  - 兼容 nmap probe 语法：支持 `Probe`、`ports`、`rarity`、`fallback`、`match`/`softmatch` 等指令。
  - 输出：`ProbeResult` 与 `ServiceFingerprint`（含信心值）；可独立调用或在端口扫描链路自动触发。
  - 扩展：放置自定义 nmap-service-probes 文本即可热加载（需要在调用侧指明路径）。

- **Engine & ScanResult (`src/cores/engine/`)**
  - 统一数据结构：`ScanResult` 携带 host/port/protocol/response/meta；`with_meta` 便捷增添键值。
  - 并发控制：基于信号量的任务门控；支持批量队列化端口列表。
  - 输出层：格式化为 raw/json/csv；支持流式写入文件。

## 逆向模块详解
- **子命令设计**：`reverse analyze/decompile-run/decompile-plan/decompile-batch/console/TUI/job-*` 覆盖从单次分析到批处理的全链路。
- **引擎桥接**：默认优先 `RSCAN_GHIDRA_HOME` 或 `RSCAN_GHIDRA_HEADLESS`，回退到仓库内置精简版 `third_party/ghidra_core_headless_x86_min`；也可生成 ida/radare/jadx 等脚本。
- **任务化调度**：
  - `decompile-run` 支持 `full`/`index`/`function` 模式；索引模式保存函数与外部引用，单函数模式提升速度。
  - `decompile-batch` 并发处理多文件，带任务上限与状态查询。
  - `job-status/job-logs/job-artifacts` 统一管理产物与日志。
- **交互体验**：
  - 控制台：命令式操作 `use/jobs/functions/show/search/index/graph/decompile`。
  - TUI：多窗格浏览（Jobs/Functions/Right/Strings），快捷键见 `docs/REVERSE_USAGE.md`，支持行内注释与搜索。
- **分析与索引**：
  - Tantivy 索引跨任务全文检索 (`project_index.jsonl`)，可快速搜字符串/函数。
  - 支持增量索引与缓存复用（`RSCAN_GHIDRA_PROJECT_CACHE` / `RSCAN_GHIDRA_REUSE_PROJECT`）。
- **动态选项**：
  - 轻量动态：`--dynamic` 或 `RSCAN_REVERSE_DYNAMIC=1` 启用 strace 抽样，支持黑名单、超时、syscall 列表配置。
  - 资源控制：`RSCAN_GHIDRA_TIMEOUT_SECS`、`RSCAN_GHIDRA_MAX_FUNC_SIZE`、`RSCAN_GHIDRA_ONLY_NAMED` 等限制开关。
- **输出与互操作**：
  - 伪代码、函数列表、调用/引用图（DOT）导出；`job-artifacts` 统一收集。
  - `reverse debug-script` / `gdb-plugin` 生成调试脚本，辅助动态调试。

## 运行配置与环境变量速查
- **通用**：`RUST_LOG` 控制日志；`RSCAN_LOG_STYLE=plain` 便于收集。
- **网络扫描**：根据子命令使用 `--concurrency`、`--timeout` 等参数（查看 `--help`）。
- **逆向**：
  - 引擎：`RSCAN_GHIDRA_HOME`、`RSCAN_GHIDRA_HEADLESS`、`RSCAN_GHIDRA_NO_ANALYSIS`、`RSCAN_GHIDRA_SKIP_DECOMPILE`、`RSCAN_GHIDRA_INCREMENTAL`。
  - 动态：`RSCAN_REVERSE_DYNAMIC_TIMEOUT_MS`、`RSCAN_REVERSE_DYNAMIC_SYSCALLS`、`RSCAN_REVERSE_DYNAMIC_BLOCKLIST`。
- **输出**：`--output raw|json|csv`，部分命令支持 `--stream_to <file>` 持续写入。

## 性能与资源策略
- 扫描端：批量切分端口列表，信号量限制并发；位图结构存储端口状态降低内存。
- Web 端：请求并发受 `--concurrency` 控制；对大量路径支持分批。
- 逆向端：Ghidra 任务可复用缓存，索引增量更新避免全量重跑；支持设定超时和最大函数大小防止卡死。

## 典型工作流示例
- **资产测绘**：`rscan host quick` 获取存活+常用端口 → `rscan host tcp/udp` 全端口 → `rscan web dns/dir` 枚举 Web 面 → 导出 json 喂给后续资产系统。
- **服务识别与漏洞验证**：扫描后基于 `service` 元数据筛选 → 使用 `vuln_check` PoC/Fuzz 针对性探测 → 结果写入统一输出便于归档。
- **恶意样本快速 triage**：`reverse analyze` 获取基础信息 → `reverse decompile-run --mode index` 建索引 → 控制台/TUI 搜索可疑字符串/函数 → 需要时切换 `full` 导出伪代码或调用图。
- **批量反编译**：`reverse decompile-batch ./samples --engine ghidra --mode full --max-jobs N`，配合 `job-status/job-logs` 监控与重跑失败任务。

## TUI 一体化改造建议（规划）
- **统一任务视图**：在现有逆向 TUI 框架上增加 Host/Web/Vuln/Shell 任务列表与详情 Pane，复用 job 概念，支持跨模块过滤与状态同步。
- **模块化 Pane**：为各模块定制右侧信息窗格，如端口开放矩阵、HTTP 响应摘要、PoC 命中详情、payload 预览/复制。
- **即席操作**：在 TUI 中直接触发常用子命令（扫描、重试、导出、流式写盘），并以日志 Pane 实时流式展示 stdout/stderr。
- **配置与模板编辑**：提供内嵌表单或快捷键打开 `rules/`、词典、探针文件，支持快速增删改并热加载。
- **结果导出与回放**：在 TUI 内一键导出当前筛选结果为 json/csv；支持读取历史 job 进行回放和对比。
- **键位与可用性**: 继续沿用 `j/k` 导航和多窗格切换；为网络扫描补充状态码/耗时排序、速率限速开关、并发阈值热调节。
- **远程/离线模式**：支持通过 RPC 连接远程扫描节点；离线模式加载本地结果浏览和检索，不必重复扫描。

## 开发者指南
- 代码质量：`cargo fmt`、`cargo clippy --all-targets --all-features`。
- 测试：`cargo test`；性能基准位于 `benches/`（使用 `cargo bench`）。
- 运行期产物：`jobs/、reverse_out/、workspace/` 等为输出目录，已在 `.gitignore` 中忽略。
- 贡献：欢迎 Issue/PR，提交前请附带最小复现和期望行为。

## 路线图（持续更新）
- 更完善的错误处理与可观测性
- 丰富 Web/漏洞扫描插件与输出格式
- 优化高并发下的内存占用与限速策略
- 提升逆向任务调度与跨任务索引体验

## 许可证
MIT，详见 `LICENSE`。

## 使用须知
- 仅在授权范围内使用；遵守当地法律法规。
- 原始包扫描（SYN/ARP/ICMP）与部分动态分析需要管理员权限，谨慎执行。
