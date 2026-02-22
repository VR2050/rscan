# rscan Reverse 使用文档

本说明覆盖逆向模块的常用命令、TUI/控制台交互、Ghidra 运行时配置、缓存与索引、动态检测开关等。

**快速开始**
1. 静态分析

```bash
rscan reverse analyze --input ./easy
```

2. 反编译（Ghidra，任务化）

```bash
RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min \
rscan reverse decompile-run --input ./easy --engine ghidra --mode full
```

3. 交互控制台

```bash
rscan reverse console --input ./easy
```

4. TUI（需要 TTY）

```bash
rscan reverse console --input ./easy --tui
```

**命令概览**
1. `reverse analyze`  
   静态分析（ELF/PE/APK），输出格式、加固信息与安全线索。
2. `reverse decompile-plan`  
   生成外部引擎的命令计划（当前支持 objdump/radare2/ghidra/ida/jadx）。
3. `reverse decompile-run`  
   运行反编译任务（支持 `full/index/function`）。
4. `reverse decompile-batch`  
   批量运行反编译，支持并发上限。
5. `reverse jobs/job-status/job-logs/job-artifacts`  
   任务列表与日志/产物查询。
6. `reverse job-functions/job-show/job-search`  
   函数列表、伪代码查看、关键字搜索。
7. `reverse job-doctor`  
   校验任务产物完整性。
8. `reverse malware-triage`  
   IOC 与行为线索分析。
9. `reverse shell-audit`  
   Shell 文本或二进制字符串审计。
10. `reverse debug-script`  
    生成 GDB 调试脚本。
11. `reverse gdb-plugin`  
    生成 GDB Python 插件。
12. `reverse ida-script/ghidra-script/ghidra-index-script/ghidra-function-script`  
    生成外部批量脚本。
13. `reverse backend-status`  
    外部引擎可用性检测。

**参数优化与别名**
为减少参数记忆成本，提供以下常用别名：
1. `--job` 等价 `--id`（用于 `job-status/job-logs/job-artifacts/job-functions/job-show/job-search/job-doctor`）
2. `--name` 等价 `--function`（用于 `job-show`）
3. `--keyword` 等价 `--query`（用于 `job-search`）
4. `--input` 等价 `--file`（用于 `analyze/decompile-run/decompile-plan/console/debug-script/malware-triage/shell-audit`）
5. `decompile-batch` 支持 `--input` 作为 `--inputs` 的别名

支持位置参数（更简洁的调用）：
1. `rscan reverse analyze ./easy`
2. `rscan reverse decompile-run ./easy --mode full`
3. `rscan reverse decompile-batch ./a ./b ./c`
4. `rscan reverse job-status <job_id>`
5. `rscan reverse job-show <job_id> <name_or_ea>`
6. `rscan reverse job-search <job_id> <keyword>`
7. `rscan reverse console ./easy`

**平台与架构支持**
1. 平台
1. Linux：完整支持（静态/反编译/控制台/TUI/轻量动态）
2. Windows：静态/反编译可用（需外部 Ghidra），动态不支持
3. macOS：静态/反编译可用（需外部 Ghidra），动态不支持
2. 架构
1. 内置精简版 Ghidra：`x86/x64`  
2. 其它架构：需外部完整 Ghidra 运行时（通过 `RSCAN_GHIDRA_HOME` 指定）

**反编译任务示例**
1. 索引模式（函数+外部引用）

```bash
RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min \
rscan reverse decompile-run --input ./easy --engine ghidra --mode index --workspace /tmp/rscan_reverse_ws
```

2. 单函数模式

```bash
RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min \
rscan reverse decompile-run --input ./easy --engine ghidra --mode function --function main --workspace /tmp/rscan_reverse_ws
```

3. 全量伪代码

```bash
RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min \
rscan reverse decompile-run --input ./easy --engine ghidra --mode full --workspace /tmp/rscan_reverse_ws
```

**交互控制台**
控制台用于快速查询和管理反编译任务。

常用命令：
1. `help`：查看命令列表
2. `jobs`：列出任务
3. `use <job_id>`：切换当前任务
4. `functions`：列出函数
5. `show <name|ea>`：查看函数伪代码
6. `search <keyword>`：伪代码搜索
7. `index`：加载/刷新工程索引
8. `graph`：导出调用/引用图（DOT）
9. `decompile [full|index|function <name>]`：触发新任务

**TUI 快捷键**
1. `j/k` 或 `↑/↓`：移动
2. `h/l` 或 `←/→`：切换焦点（Jobs/Functions/Right/Strings）
3. `b` 或 `Backspace`：返回左侧
4. `Tab`：循环切换焦点
5. `Enter`：跳转/查看
6. `/`：过滤（名称/地址/签名）
7. `s`：搜索（伪代码/调用/外部引用）
8. `S`：字符串搜索（从二进制提取的字符串）
9. `c`：注释当前函数
10. `;`：给当前伪代码行添加注释
11. `C`：清除当前函数/行注释
12. `PageUp/PageDown/Home/End`：快速滚动
13. `x`：清空过滤/搜索
14. `g`：跳转（函数或地址）
15. `o`：打开当前选中的 job/函数（等同 Enter）
16. `D`：删除 job（会提示输入确认或 job_id）
17. `1..6`：切换 Tab（新增 Asm）
18. `r`：刷新
19. `R`：刷新并重建索引
20. `:`：命令模式（`filter/goto/grep/find/search/strings/index/reindex/refresh/graph/open/delete/job/note/note-line/decompile/tab`）
21. `d`：触发反编译（提示输入）。示例：
    `full`
    `index`
    `function main`
    `main noasm`
    `function . only-named`

**Strings 窗口**
右侧新增 `Strings` 窗口，显示二进制字符串列表，支持 `S` 或 `:strings <kw>` 搜索。

注意：TUI 需要 TTY，非 TTY 场景会自动回退到交互控制台。

**缓存与索引**
1. 工程级缓存  
   默认启用 Ghidra 项目缓存与复用（无需设置环境变量）。如需关闭可用 `RSCAN_GHIDRA_PROJECT_CACHE=0` 或 `RSCAN_GHIDRA_REUSE_PROJECT=0`。
2. 索引增量更新  
   仅扫描新增 job，避免全量扫描。
3. 跨作业全文检索  
   通过 tantivy 索引 `project_index.jsonl` 实现。

**调用图/引用图导出**
在控制台或 TUI 中使用 `graph` 导出 DOT 文件。  
如需定制输出路径，可以在命令模式中附加输出路径。

**行内注释（伪代码/汇编）**
1. 选中伪代码或汇编行后按 `;` 输入注释
2. 或使用命令：`:note-line <line> <text>`，清除使用 `:note-line <line> clear`

**动态检测（轻量）**
默认不执行动态检测。启用后会使用 `strace` 做轻量 syscall 采样。

启用方式：

```bash
RSCAN_REVERSE_DYNAMIC=1 rscan reverse analyze --input ./easy
```

或者直接用 CLI 参数：

```bash
rscan reverse analyze --input ./easy --dynamic
```

可选环境变量：
1. `RSCAN_REVERSE_DYNAMIC_TIMEOUT_MS`：超时控制（默认 1500ms）
2. `RSCAN_REVERSE_DYNAMIC_SYSCALLS`：自定义 syscall 列表  
   例：`ptrace,prctl,seccomp`
3. `RSCAN_REVERSE_DYNAMIC_BLOCKLIST`：字符串黑名单命中则跳过动态执行  
   例：`pause,cmd.exe`

等价的 CLI 参数：
1. `--dynamic-timeout-ms`
2. `--dynamic-syscalls`
3. `--dynamic-blocklist`

**Ghidra 运行时配置**
1. 指定运行时

```bash
RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min rscan reverse backend-status
```

2. 内置精简版运行时

默认优先级：`RSCAN_GHIDRA_HEADLESS` / `RSCAN_GHIDRA_HOME` > 内置精简版 > 系统 PATH。  
本仓库已内置精简版，位置为：

```
third_party/ghidra_core_headless_x86_min
```

2. 控制分析参数（环境变量）
1. `RSCAN_GHIDRA_NO_ANALYSIS`：跳过自动分析
2. `RSCAN_GHIDRA_SKIP_DECOMPILE`：跳过反编译，仅导出函数信息
3. `RSCAN_GHIDRA_INCREMENTAL`：启用增量
4. `RSCAN_GHIDRA_TIMEOUT_SECS`：单任务超时
5. `RSCAN_GHIDRA_MAX_FUNC_SIZE`：最大函数大小限制
6. `RSCAN_GHIDRA_ONLY_NAMED`：仅处理命名函数

**常见问题**
1. TUI 无法启动  
   需要真实 TTY，非交互环境会自动回退。
2. `shell-audit` 报 UTF‑8 错误  
   已支持二进制输入，使用 `--input` 读取即可。
3. 动态分析卡顿或副作用  
   使用 `RSCAN_REVERSE_DYNAMIC_BLOCKLIST` 或缩短超时。
