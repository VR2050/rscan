**改造计划（仅规划，不执行）**  
版本：`v0.1`  
日期：`2026-03-03`  
状态：`规划完成，暂不实施`

本计划满足你的要求：  
1. 保持并兼容现有 CLI。  
2. 后续新增统一 TUI 多模块多面板。  
3. 增加 Script 窗口，支持 Rust/Python 脚本编写与运行。  
4. 可在 Alacritty + Zellij 中高效使用。  
5. 当前仅输出计划，不做代码改动。

**当前基线（作为改造参考）**
- CLI 主入口：[app.rs](/home/vr2050/RUST/rscan_codex/src/cli/app.rs)
- 统一任务模型：[task.rs](/home/vr2050/RUST/rscan_codex/src/cores/engine/task.rs)
- 统一 TUI（preview）：[app.rs](/home/vr2050/RUST/rscan_codex/src/tui/app.rs)
- 逆向专用 TUI（成熟）：[console.rs](/home/vr2050/RUST/rscan_codex/src/modules/reverse/console.rs)
- 模块入口聚合：[mod.rs](/home/vr2050/RUST/rscan_codex/src/modules/mod.rs)

---

**一、总目标与约束**
1. CLI 行为向后兼容，已有子命令参数语义不破坏。  
2. TUI 改造走“统一框架 + 可插拔面板”，避免重复实现。  
3. Script 窗口先实现 MVP，再逐步增强编辑能力。  
4. 性能目标优先级高于 UI 花哨效果。  
5. 先完成核心模块稳定化，再启动本计划。

---

**二、启动门槛（后续开始前必须满足）**
1. `cargo test` 全绿，关键模块失败率为 0。  
2. `host/web/vuln/reverse` 核心功能接口冻结一版（至少一周不再大改签名）。  
3. 任务数据协议在 [TASK_SCHEMA.md](/home/vr2050/RUST/rscan_codex/docs/TASK_SCHEMA.md) 固化并通过样例验证。  
4. 逆向任务产物路径与状态字段稳定，不再频繁变动。  
5. 约定性能基线（启动时间、刷新延迟、内存占用）作为回归指标。

---

**三、分阶段实施路线图（详细）**

| 阶段 | 范围 | 主要产物 | 验收标准 | 预计工作量 |
|---|---|---|---|---|
| Phase 0 | 核心模块稳定化前置 | 基线报告、兼容性清单 | CLI 回归通过，接口冻结 | 1-2 周 |
| Phase 1 | 统一 TUI 架构重构 | `AppState`、`Pane` 抽象、事件循环重组 | 原 preview TUI 能跑，渲染稳定 | 1 周 |
| Phase 2 | 任务总线完善 | Task/Event 写入规范落地、进度事件接入 | host/web/vuln/reverse 都有中间事件 | 1 周 |
| Phase 3 | 多模块多面板 | Dashboard/Host/Web/Vuln/Reverse/Artifacts/Logs | 可跨模块导航、筛选、查看详情 | 1-2 周 |
| Phase 4 | Script 窗口 MVP | 编辑器+运行器+输出面板 | `.py/.rs` 新建/保存/运行/停止可用 | 1-2 周 |
| Phase 5 | CLI 扩展（可选但建议） | `rscan script ...` 子命令 | 非 TUI 场景也能用脚本能力 | 3-5 天 |
| Phase 6 | Alacritty + Zellij 适配 | zellij layout、快捷键说明、compact/full 模式 | 分屏工作流可复用，键位冲突可控 | 3-5 天 |
| Phase 7 | 性能与压测优化 | 虚拟列表、脏区刷新、背压机制 | 大日志/大任务下无明显卡顿 | 1 周 |
| Phase 8 | 回归、文档、发布 | 测试矩阵、使用文档、迁移说明 | 回归全通过，文档完整 | 3-5 天 |

---

**四、模块级详细改造清单**

| 工作包 | 涉及文件 | 设计要点 | 风险 | 验收点 |
|---|---|---|---|---|
| WP-A CLI 兼容层 | [app.rs](/home/vr2050/RUST/rscan_codex/src/cli/app.rs) | 保持旧命令不变，只新增不破坏 | 参数冲突 | 现有 CLI 用例全部通过 |
| WP-B TUI 核心框架 | [app.rs](/home/vr2050/RUST/rscan_codex/src/tui/app.rs) | 状态机拆分，Pane 插件化 | 重构期间功能回退 | preview 功能不丢失 |
| WP-C 任务协议统一 | [task.rs](/home/vr2050/RUST/rscan_codex/src/cores/engine/task.rs), [TASK_SCHEMA.md](/home/vr2050/RUST/rscan_codex/docs/TASK_SCHEMA.md) | 统一 `status/progress/log/artifacts` | 旧任务数据兼容 | 历史任务可读，新任务字段完整 |
| WP-D ReversePane 接入 | [console.rs](/home/vr2050/RUST/rscan_codex/src/modules/reverse/console.rs) | 复用成熟逻辑，避免重写 | 耦合过高 | reverse 体验不退化 |
| WP-E Host/Web/Vuln Pane | [mod.rs](/home/vr2050/RUST/rscan_codex/src/modules/mod.rs) 及各模块 | 面板统一交互模型 | 不同模块风格不一致 | 交互键位统一 |
| WP-F Script Pane | 新增 `src/tui/panes/script_*` | 轻量编辑 + 异步运行 + 输出流 | 编辑器能力过重 | MVP 功能闭环 |
| WP-G Script Runner | 新增 `src/modules/script_runner/*` | Python/Rust 执行器、可取消任务 | 命令注入与安全 | 白名单执行、路径隔离 |
| WP-H CLI Script 子命令 | [app.rs](/home/vr2050/RUST/rscan_codex/src/cli/app.rs) | `script run/new/list` | 与现有命令冲突 | help 文档完整 |
| WP-I 性能优化 | TUI 全局 | 虚拟滚动、限帧、背压 | 优化过度引入复杂度 | 指标达到目标 |

---

**五、Script 窗口专项设计（Rust/Python）**

**1) MVP 功能**
1. 新建脚本：`new.py`、`new.rs` 模板生成。  
2. 打开与保存：支持 `workspace/scripts/`。  
3. 运行与停止：异步子进程，支持中止。  
4. 输出面板：stdout/stderr 分色显示，支持清屏。  
5. 任务记录：每次运行生成 `task`，写事件流。  

**2) 执行策略**
1. Python：`python3 <file>`。  
2. Rust：优先 `rust-script`，后备 `cargo run` 临时工程。  
3. 禁止默认网络/高危命令联动，后续可选授权开关。  
4. 运行器全程异步，UI 主线程不阻塞。  

**3) 后续增强（非 MVP）**
1. 语法高亮。  
2. 基础补全。  
3. 断点/调试桥接。  
4. 脚本模板市场。  

---

**六、性能目标（量化）**
1. TUI 冷启动小于 `800ms`。  
2. 空闲 CPU 占用小于 `5%`。  
3. 1 万行日志滚动时键盘响应小于 `50ms`。  
4. 1000 任务元信息加载小于 `300ms`。  
5. 连续运行脚本 30 分钟无明显内存泄漏。  

---

**七、测试与验收计划**
1. 单元测试：Pane 状态机、事件解析、脚本运行器。  
2. 集成测试：CLI 与 TUI 并存场景、任务落盘一致性。  
3. 回归测试：现有 `host/web/reverse/vuln` 命令行为。  
4. 终端兼容测试：Alacritty 单窗、Zellij 多 pane、SSH 远程终端。  
5. 压测：大日志、高并发任务刷新、连续脚本执行。  

---

**八、风险与缓解**
1. 风险：重构 TUI 导致 reverse 体验退化。  
缓解：先封装 `ReversePane` 适配层，禁止一次性重写。  
2. 风险：Script 编辑器过度复杂影响进度。  
缓解：先做 MVP 文本编辑，延后 IDE 化能力。  
3. 风险：任务协议字段膨胀导致兼容问题。  
缓解：版本化 `TaskMeta.extra`，保持核心字段稳定。  
4. 风险：性能优化后代码复杂度升高。  
缓解：优先可测优化点，所有优化配基准测试。  

---

**九、里程碑（Go/No-Go）**
1. M1：Phase 1+2 完成后评审，确认统一框架稳定。  
2. M2：Phase 3 完成后评审，确认多模块多面板达标。  
3. M3：Phase 4+5 完成后评审，确认 Script 能力可用。  
4. M4：Phase 6+7 完成后评审，确认终端适配与性能目标达成。  
5. M5：Phase 8 完成后发布。  

---

**十、当前结论**
1. 这个方案可行。  
2. 不会破坏现有 CLI。  
3. 可以实现你要的 Script 窗口（Rust/Python）。  
4. 现在按你的要求“先规划不实施”，本计划已完成并可作为后续执行蓝图。  

如果你后续要启动，我可以按这个计划先输出一份“Phase 0 完成检查清单模板”，用于你确认核心模块已优化完毕后再开工。