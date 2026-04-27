# 第五章 TUI界面与Zellij集成实现

本章围绕 `rscan_codex` 终端交互层展开，说明统一 TUI 如何与 Zellij 原生运行时协同。系统遵循“CLI 负责真实执行、TUI 负责编排与可视化、Zellij 负责终端工作区承载”的分工原则，在不改变既有命令语义的前提下，实现跨模块任务统一调度、逆向专用工作区交互与高性能终端渲染。

## 5.1 TUI架构设计

### 5.1.1 Ratatui框架应用

统一 TUI 基于 `Ratatui + Crossterm` 实现，入口位于 `src/tui/app.rs`。系统通过 `Terminal<CrosstermBackend>` 建立渲染循环，并在同一事件通道中处理键盘、粘贴、鼠标输入。

与传统“命令执行后逐行打印”的 CLI 交互相比，Ratatui 的声明式布局使系统能够在单终端窗口内并行呈现任务列表、任务详情、结果摘要、脚本输出和状态栏，显著提升多任务场景下的信息密度与可操作性。

主循环采用“状态轮询 + 条件渲染”机制。每个 Tick 内依次执行：

1. 终端输出轮询与性能采样（`poll_terminal_output`、`poll_perf_refresh`）。
2. 脚本完成检测与任务刷新（`poll_script_completion`、`poll_task_refresh`）。
3. 状态行推送与渲染缓存更新（`push_status_line`、`refresh_render_caches`）。
4. 通过 `should_draw_frame()` 判定是否重绘。

轮询周期根据活跃度动态切换：终端高活跃约 `16ms`、任务活跃约 `120ms`、空闲使用基础刷新间隔。该机制在保证实时性的同时，避免无效重绘造成闪烁和 CPU 浪费。

系统提供双模式适配：

1. 非 Zellij 管理模式：启用内置 mini terminal 与浮动控制台。
2. Zellij 管理模式：TUI 退化为控制平面，真实执行与日志跟随交由原生 pane。

![图5-1 统一TUI控制面主界面](./images/ch5/fig5-1-control-main.png)

图5-1 截图位置：`Control` tab 中的主界面全屏，需包含顶部 Header、中部主 pane、底部状态栏。

### 5.1.2 状态管理与渲染分离

系统在 `src/tui/app_state/` 与 `src/tui/render/` 之间建立了明确分层：

1. `AppState` 负责业务状态、输入状态、任务索引、缓存键和轮询节奏控制。
2. `RenderCtx` 作为只读快照，将状态层映射为渲染输入。
3. `draw_frame` 与 `render/panes/*` 仅负责 UI 组合与绘制，不直接改写业务状态。

该分层带来三方面收益：

1. 可维护性：状态更新与视觉渲染职责解耦，便于持续迭代。
2. 可测试性：签名计算、缓存键、列表构建等逻辑可在无终端环境单测。
3. 性能可控：通过 `task_signature`、`live_serial`、`render_serial` 精确判定“重算/重绘时机”。

具体实现上，`should_draw_frame()` 使用 `frame_render_signature` 对关键 UI 状态哈希；签名未变化即跳过整帧绘制。同时各 pane 拥有独立缓存序列，避免局部变化触发全局文本重建。

### 5.1.3 多面板布局设计

统一 TUI 支持三种主布局：`Single`、`SplitLeftTasks`、`TriPanel`。布局调度位于 `src/tui/render.rs`，具体内容由 `src/tui/render/panes/*` 子模块渲染。

核心 pane 包括：

1. `Dashboard`：全局任务统计、模块分布、运行时与 pane registry 概览。
2. `Tasks`：任务状态表格与生命周期视图。
3. `Results`：终态任务聚合、结果状态与诊断摘要。
4. `Projects`：项目切换、模板选择与管理。
5. `Scripts`：脚本文件管理、输出回显与运行状态。
6. `Launcher`：命令模板与快捷启动入口。

在 Zellij 管理模式下，TUI 与 `Control / Work / Inspect / Reverse` 四 tab 协同：`Control` 维持统一调度视图，`Work/Inspect/Reverse` 承载原生任务操作，形成“结构化控制 + 原生终端执行”的混合工作流。

![图5-2 多面板布局与功能区域](./images/ch5/fig5-2-tripanel-layout.png)

图5-2 截图位置：`Control` tab 切到 `TriPanel` 布局，确保左中右三栏（Tasks/Center/Results）同时可见。

## 5.2 Zellij深度集成实现

### 5.2.1 原生Pane管理机制

Zellij 集成主要封装在 `src/tui/zellij.rs`、`src/tui/zellij_layout.rs`、`src/tui/zellij_query.rs`。系统完成了会话探测、布局引导、tab 补齐与 pane 打开能力。

启动时自动生成 `.rscan/zellij/*.kdl` 布局资产，并维护四个托管 tab：

1. `Control`：运行 `rscan tui`。
2. `Work`：运行 work hub，并保留原生 shell 工作入口。
3. `Inspect`：运行 inspect hub，并保留原生 shell 入口。
4. `Reverse`：运行 reverse surface。

pane 打开统一走 `zellij action new-pane --cwd ... [--name ...]`。命名策略（如 `logs-xxxx`、`task-xxxx`、`art-xxxx`）为后续复用、聚焦与追踪提供了稳定锚点。

![图5-3 Zellij托管布局（四Tab）](./images/ch5/fig5-3-zellij-tabs.png)

图5-3 截图位置：Zellij 顶部 tab-bar 需完整展示 `Control/Work/Inspect/Reverse` 四个 tab 名称。

### 5.2.2 任务运行时绑定设计

为将任务元数据与原生 pane 上下文关联，系统引入 `TaskRuntimeBinding`，并写入：

1. 普通任务：`TaskMeta.extra.runtime`。
2. reverse 主作业：`jobs/<id>/task-runtime.json`。

绑定字段包括：

1. `backend / session / tab / pane_name`
2. `role`（如 `inspect-logs`、`task-shell`）
3. `cwd / command`

该机制使 TUI 从“只下发命令”的壳层，升级为“可感知运行态”的控制面：详情面板可展示任务当前绑定的原生 runtime，`zlogs/zshell/zart/zfocus` 也可基于该上下文执行可追踪跳转。

![图5-4 任务运行时绑定详情](./images/ch5/fig5-4-runtime-binding.png)

图5-4 截图位置：`Tasks` 或 `Results` 右侧详情区，需清晰看到 `runtime.backend/session/tab/pane/role/cwd/command` 字段。

### 5.2.3 Pane复用与生命周期管理

系统采用“实时布局探测 + 本地注册表回退”的复用链路：

1. 优先通过 `zellij action dump-layout` 判断命名 pane 是否已存在。
2. 若实时布局不可得，则读取 `.rscan/zellij/panes.json` 作为 soft hint。
3. 命中后优先聚焦目标 tab，避免重复创建 pane。

`zellij_registry::record_pane()` 在日志/产物/shell pane 打开后记录最近信息（tab、cwd、role、command、更新时间），并在 `Dashboard` 提供摘要展示。该机制可减少 pane 泄漏与重复开窗，提升工作区连续性。

生命周期策略上，pane 不是任务真相源；系统真相仍由任务目录与 job 元数据定义。pane 仅承担“观察/操作界面”角色，从架构层面规避 UI 状态漂移。

## 5.3 交互体验优化

### 5.3.1 智能命令补全系统

命令输入位于 `src/tui/input/command/`，支持历史导航、撤销重做、粘贴与多级补全。补全策略采用分层语义：

1. 一级补全：`host/web/vuln/reverse` 与 `zrun/zlogs/zshell/zart/zrev/zfocus`。
2. 二级补全：父命令下子命令（如 `web crawl`、`reverse run`）。
3. 三级补全：场景 flags（如 `--severity`、`--stream`、`--timeout-ms`）。

系统兼容短别名（如 `h.quick`、`w.dir`、`r.run`），并通过 completion seed 管理候选轮换，降低上下文变化时的补全错位。

### 5.3.2 实时结果展示链

结果链路从任务落盘开始：

1. 命令触发后即写占位 `meta.json` 与日志文件，避免“任务突变式出现”。
2. `poll_task_refresh()` 周期刷新 `tasks/` 与 `jobs/`。
3. reverse 主作业通过 `load_reverse_jobs_as_tasks()` 映射为统一 `TaskView`。
4. `Results` 基于状态机输出 `artifact-ready/logs-only/non-previewable-artifact/empty/launching`。
5. 详情区融合事件尾部、stdout/stderr tail 与 artifact 片段完成诊断展示。

该链路实现“任务启动-执行-产出-诊断”的闭环可视化。reverse 作业接入统一任务视图后，用户可在同一入口观察主机扫描、Web 扫描、漏洞检测与逆向分析结果。

### 5.3.3 缓存机制与性能优化

系统性能优化主要体现在四层：

1. 轮询节流：按活跃度动态切换 tick（16ms/120ms/基础刷新）。
2. 数据缓存：任务表、结果列表、脚本面板、项目面板、mini console 使用独立 cache key 与 render serial。
3. 帧级去重：`frame_render_signature` 对尺寸、输入模式、序列号和核心状态哈希，签名不变则不重绘。
4. I/O 优化：日志预览采用尾部读取策略（如 `read_last_lines_fast`），避免大文件全量加载。

上述策略使系统在高频任务变更时保持响应，在空闲状态下降低资源占用，满足终端工具长期驻留要求。

## 5.4 逆向工作区专用视图

### 5.4.1 文件浏览器实现

逆向文件浏览由 `reverse_surface` 与 `reverse_picker` 协同提供：

1. 本地浏览模式：Ratatui 列表浏览目录、过滤样本、路径跳转。
2. Zellij 原生模式：通过 `zellij pipe -p filepicker` 拉起 `strider` filepicker。

样本发现策略基于 `src/tui/reverse_workbench_fs.rs`：

1. 递归扫描 `binaries/samples/inputs` 与项目浅层目录。
2. 过滤 `.git/.rscan/tasks/reverse_out/node_modules/target` 等非目标目录。
3. 基于扩展名、可执行位与目录语义识别“可能逆向输入”。
4. 按修改时间排序并限制候选数量。

该机制支持“路径直输 + 列表浏览 + 原生 filepicker”三种入口互补，降低样本定位成本。

![图5-5 Reverse Surface与文件选择](./images/ch5/fig5-5-reverse-surface-filepicker.png)

图5-5 截图位置：`Reverse` tab 中 `reverse surface` 主界面；若可行，截图时同时展示 filepicker 浮窗或其选择结果提示行。

### 5.4.2 代码查看器设计

代码查看器复用 `src/modules/reverse/console.rs`，采用“函数列表 + 多 Tab 详情 + 字符串侧栏”结构：

1. 左侧 `Functions` 列表用于函数定位。
2. 右侧支持 `Pseudocode/Calls/Xrefs/Externals/Strings/Asm` 多视图切换。
3. 支持过滤、搜索、跳转、注释、命令模式与作业切换。

为避免重型自动流程干扰，系统将“样本选择”与“查看器打开”解耦：`reverse surface` 仅在收到显式 viewer 请求时拉起查看器，不再因目标变化自动触发分析。

![图5-6 Reverse Viewer多Tab详情](./images/ch5/fig5-6-reverse-viewer-tabs.png)

图5-6 截图位置：完整 reverse viewer 界面，需包含左侧函数列表与右侧任一详情 Tab（推荐 `Pseudocode`）。

### 5.4.3 任务与结果关联展示

逆向工作区通过提示文件维持跨视图一致性：

1. `.rscan/reverse/active_project.txt`：当前项目语义。
2. `.rscan/reverse/selected_target.txt`：当前样本语义。
3. `.rscan/reverse/open_viewer.txt`：查看器打开请求。

在此基础上，`load_reverse_jobs_as_tasks()` 将 reverse 主作业投影为 `TaskView`，并附带运行时绑定、产物目录与日志路径。最终实现：

1. `Reverse` tab 中的 full/index 作业可在 `Control` 的 `Tasks/Results` 统一查看。
2. `L/W/A` 与 `zlogs/zshell/zart` 可直接将 reverse job 派送至原生 pane。
3. `Work/Inspect/Reverse` 共用 project/target 上下文。

## 5.5 截图清单与采集说明

建议统一放在：`images/ch5/`（或论文资产目录 `reports/thesis_fig_assets/ch5/`），然后按下表命名。

| 图号 | 建议文件名 | 在文中插入位置 | 具体截哪里 |
|---|---|---|---|
| 图5-1 | `fig5-1-control-main.png` | 5.1.1 后 | `Control` tab 全屏主界面（Header + 主pane + Footer） |
| 图5-2 | `fig5-2-tripanel-layout.png` | 5.1.3 后 | `Control` tab 切到 `TriPanel`，确保三栏同时可见 |
| 图5-3 | `fig5-3-zellij-tabs.png` | 5.2.1 后 | Zellij 顶部 tab-bar，清晰显示四 tab：Control/Work/Inspect/Reverse |
| 图5-4 | `fig5-4-runtime-binding.png` | 5.2.2 后 | `Tasks/Results` 详情区 runtime 字段（backend/session/tab/pane/cwd/command） |
| 图5-5 | `fig5-5-reverse-surface-filepicker.png` | 5.4.1 后 | `Reverse` tab 的 reverse surface（含 filepicker 提示或浮窗） |
| 图5-6 | `fig5-6-reverse-viewer-tabs.png` | 5.4.2 后 | reverse viewer（左 Functions + 右侧 Pseudocode/Asm 等 Tab） |

推荐截图流程：

```bash
# 1) 启动统一 TUI（普通模式）
cargo run -- tui

# 2) 启动 Zellij 托管模式（用于图5-3/5-5/5-6）
RSCAN_ZELLIJ=1 cargo run -- tui
```

## 本章小结

本章给出了统一 TUI 与 Zellij 深度集成的实现路径。通过状态-渲染解耦、原生 pane 编排、运行时绑定、结果链路可视化与逆向专用工作区设计，系统在终端环境下实现了接近 IDE 的多任务协作体验，并保持 CLI 语义稳定与工程可维护性，为后续测试评估与应用验证奠定了基础。
