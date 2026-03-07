# Android 逆向模块 Rust 化计划（保留工业级反编译后端）

## 目标
- 保持 `Ghidra/JADX` 在反编译场景的工业级能力。
- 将可 Rust 化的高频分析路径前移到本地引擎，降低后端调用频率与整体开销。
- 输出统一的可检索结果模型，便于后续 TUI/任务系统复用。

## 范围（当前阶段）
1. APK 索引（entries / `classes*.dex` / native libs / manifest 标记）。
2. 轻量静态画像（permissions、cleartext、exported hint、endpoint/IOC）。
3. DEX 字符串索引与敏感 API 命中。
4. Native `.so` 架构/导入函数快速审计。
5. 统一报告结构（CLI 输出与后续 IR 对接）。

## 里程碑

### M1 已完成（MVP 可用）
- 新增 `reverse android-analyze` CLI 子命令。
- 实现 APK/Dex/Native 三路并行静态分析（单进程内）。
- 输出 `AndroidReverseReport` JSON。

验收：
- `cargo check` 通过。
- `rscan reverse android-analyze -i <apk> -o json` 可输出报告。

### M2 进行中（准确性与可用性）
- 收紧 endpoint/domain 提取规则，降低资源字符串噪声。
- 增加 analyzer 单元测试（提取质量、风险分封顶）。
- 进一步改善 `AndroidManifest.xml` 为 binary AXML 时的字段识别率（启发式增强）。

验收：
- 噪声域名显著下降（样本基线对比）。
- 新增测试全部通过，且不影响现有 reverse 功能。

### M3 下一阶段（与 Reverse IR/任务系统对接）
- 将 Android 报告映射到 `ReverseIrDoc` 或可检索 artifact。
- 对接 job/workspace，使 Android 分析结果可统一浏览与检索。
- 补充原始证据引用（字符串来源、dex 文件、so 路径）。

验收：
- `reverse jobs` 可查看 Android 分析工件。
- TUI 或搜索接口可检索 Android IOC/endpoint/API 命中。

### M4 后续增强（性能与工程化）
- 优化字符串提取与正则匹配路径（减少重复扫描与临时分配）。
- 支持增量缓存（同一 APK 重复分析快速返回）。
- 加入 benchmark（文件大小、dex 数量维度）。

验收：
- 在同等样本集上，Rust 侧静态分析耗时稳定下降。
- 性能回归可通过 benchmark 检测。

## 架构原则
- Rust 负责：索引、规则匹配、画像、IOC 归并、报告模型。
- 后端工具负责：高精度反编译与高级语义恢复。
- 能在 Rust 侧完成的分析不依赖外部后端；需要语义还原时再调用 `Ghidra/JADX`。

## 风险与对策
- 风险：binary AXML 解析不足导致 package/component 准确度不稳。  
  对策：先强化启发式，后续引入轻量 AXML decode 路径（避免重依赖）。
- 风险：endpoint 抽取误报偏高。  
  对策：URL 优先、host 校验、后缀黑名单、测试样本回归。
- 风险：输出字段增长导致 CLI 可读性下降。  
  对策：保留 `json` 作为主格式，并逐步补充摘要视图。

## 本轮完成情况（2026-03-06）
- 已完成 `M1`。
- `M2` 已落地第一步：endpoint/domain 噪声过滤增强 + 单元测试补齐。
