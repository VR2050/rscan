# rscan x zellij Native Integration

## Goal

在保持现有 CLI 语义不变的前提下，让统一 TUI 成为 `control plane`，让 zellij 成为原生 `workspace manager`：

- CLI 继续负责真正的模块执行与任务落盘
- TUI 负责调度、筛选、概览、状态聚合
- zellij 负责真实 shell、日志跟随、artifact 探查、reverse 工作区

这意味着系统的“真相源”仍然是磁盘状态，而不是某个 pane 内存状态：

- 普通模块继续写 `tasks/<id>/meta.json + events.jsonl + logs`
- reverse decompile jobs 继续写 `jobs/<id>/meta.json + reverse_out/<id>/...`
- TUI 只做聚合与映射，不篡改 CLI / reverse 子系统本体

## Managed Tabs

统一使用 4 个 managed tabs：

- `Control`
  - 上方运行 `rscan tui`
  - 下方保留一个真实 workspace shell
- `Work`
  - 上方运行 `rscan pane --kind work --workspace <root_ws>`，作为 `ratatui` work-native hub
  - 下方保留真实 work shell
- `Inspect`
  - 上方运行 `rscan pane --kind inspect --workspace <root_ws>`，作为 `ratatui` inspect-native hub
  - 下方保留真实 inspect shell
- `Reverse`
  - 运行 `rscan reverse surface --workspace <root_ws>`，作为 reverse project / target / analysis surface，并在需要时承载完整 reverse TUI（Functions / Pseudocode / Asm / Strings / Global Strings）
  - 目标选择不再依赖自家 `reverse picker`，统一改成在 surface 内直接拉起 zellij 原生 `filepicker`
  - reverse shell 不再默认常驻；需要时由 `zrev` 或任务动作临时打开

## Runtime Binding

`TaskMeta.extra.runtime` 作为当前任务的最近原生运行时绑定：

```json
{
  "backend": "zellij",
  "session": "rscan",
  "tab": "Inspect",
  "pane_name": "logs-65f1c123",
  "role": "inspect-logs",
  "cwd": "/abs/workspace/projects/default/tasks/task-65f1c123",
  "command": "tail -n 80 -F events.jsonl stdout.log stderr.log"
}
```

用途：

- 让任务可回到最近一次相关 pane/workspace
- 让 TUI detail/result 面板知道当前任务和哪类原生 runtime 绑定
- 为后续 plugin 层接入预留稳定协议

## Native Surface In TUI

这层集成现在不再只是“命令能打开 pane”，而是已经把 native runtime 反向显影到 TUI：

- `Dashboard`
  - 直接读取 `.rscan/zellij/panes.json`
  - 展示当前 native pane registry 摘要
  - 展示最近一次被记录的 pane 绑定（tab / pane name / role / cwd）
- `Tasks / Results` 详情面板
  - 展示 `runtime.backend / session / tab / pane / role / cwd / command`
  - 若 registry 中有对应 pane 记录，也会展示最近记住的 `registry.tab / registry.cwd`

这让统一 TUI 更接近真正的 workbench，而不是一个“只会发命令、不知道原生工作区长什么样”的控制壳。

## Key Flows

### Structured Task Flow

1. 用户在 TUI 中执行 `host/web/vuln/reverse` 命令
2. `rscan` 子进程继续走原有 CLI
3. CLI 写 `tasks/<id>/...`
4. TUI 从任务目录刷新状态
5. 用户在 `Tasks / Results` 中用原生动作把该任务送入 zellij pane

### Reverse Job Flow

1. 用户在 TUI 中执行 `r.run <input> [engine] [mode]`
2. CLI 仍走原有 `reverse decompile-run --workspace <project>`
3. reverse 子系统写入 `jobs/<id>/meta.json` 与 `reverse_out/<id>/...`
4. TUI 将 reverse job 映射为 synthetic `TaskView`
5. reverse job 与普通任务一起进入 `Dashboard / Tasks / Results`
6. `L/W/A` 与 `zlogs/zshell/zart` 对 reverse job 仍可直接落到 zellij 原生 pane

### Reverse Workspace Flow

1. 用户进入 `Reverse` tab 后直接看到 `reverse surface`
2. `reverse surface` 内支持：
   - `Enter`：若当前还没有 target，则直接拉起 zellij 原生 `filepicker`；若已有 target，则打开 viewer
   - `p` / `F4`：无论当前是否已有 target，都直接拉起 zellij 原生 `filepicker`
   - 选中文件后会为样本绑定或创建独立 reverse project，并请求打开 viewer；若当前 target 还没有可复用主分析，则自动补一条 `index` job
   - `f`：显式发 `reverse decompile-run --engine ghidra --mode full`
   - `a`：立即执行 `reverse analyze`
   - `i`：后台发 `reverse decompile-run --mode index`
   - `c`：清空当前 target
3. `reverse surface` 监视 `.rscan/reverse/open_viewer.txt`；只有收到显式打开请求时才进入完整 reverse TUI，不再因目标变化就擅自 auto-open / auto-index
4. 完整 reverse TUI 内部沿用 `Functions / Pseudocode / Asm / Strings / Global Strings` 状态机与快捷键，但不再在打开时自动跑 `index`
5. full/index job 会继续写入 project 的 `jobs/` 与 `reverse_out/`
6. Control TUI 继续从磁盘聚合这些 reverse jobs，统一显示在 `Tasks / Results`；聚合时同样只映射样本级 primary jobs，保持 “一个样本一个主任务” 的体验
7. 当前激活 project、当前目标与 viewer 打开请求会同步写入 `.rscan/reverse/active_project.txt`、`.rscan/reverse/selected_target.txt`、`.rscan/reverse/open_viewer.txt`，让 `Work / Inspect / Reverse` 共用同一 project/target 语义

### Work Workspace Flow

1. 用户进入 `Work` tab 时，上方不再是 line-command shell，而是 `Projects / Recent Tasks / Scripts` 三栏 `ratatui` hub
2. `Projects` 中移动选择会立即同步 `.rscan/reverse/active_project.txt` 对应的 active project，使 `Work / Inspect / Reverse` 共用同一 project 语义
3. `Enter` 按焦点执行：
   - project -> 在 `Work` 打开 project shell
   - task -> 在 `Work` 打开 task shell
   - script -> 在 `Work` 新开原生 command pane 跑脚本
4. `b` 可直接把焦点压到下方真实 shell，保持“原生工作台 + 原生终端”双层结构

### Inspect Workspace Flow

1. 用户进入 `Inspect` tab 时，上方默认是 `Projects / Tasks / Detail + Log Preview` 三栏 `ratatui` hub
2. `Projects` 选择同样会同步 active project，确保 inspect 看的是当前 workspace 语义而不是孤立 pane
3. `Tasks` 选择会实时刷新 detail 与日志尾部预览，减少“先开 pane 才知道是不是我要的任务”的往返
4. `Enter/L` 可直接开日志 pane，`A` 开 artifact pane，`W` 开 task shell，`F` 轮换 `all/running/failed/succeeded`

### Native Pane Actions

- `L`
  - 当前任务在 `Inspect` 打开日志跟随 pane
- `W`
  - 当前任务在 `Work` 打开 task shell
  - 若任务为 `reverse`，则默认落到 `Reverse`
- `A`
  - 当前任务在 `Inspect` 打开 artifact shell
- `zrun <cmd>`
  - 在 `Work` 中打开一次性命令 pane
- `zlogs <task_id>`
  - 直接在命令模式中打开指定任务日志 pane
- `zshell <task_id>`
  - 直接打开指定任务 shell
- `zart <task_id>`
  - 直接打开指定任务 artifact shell
- `zrev`
  - 打开 reverse workspace shell
- `zfocus <tab>`
  - 直接聚焦 `Control / Work / Inspect / Reverse`

### Pane Reuse

- 对语义固定且带稳定 `pane name` 的动作，优先走“先查现有 pane，再决定是否新开”
- 当前实现优先基于 `zellij action dump-layout` 做命名 pane 探测
- 命名 pane 的最近一次元信息会写入 `.rscan/zellij/panes.json`
- 当 live layout 暂时查不到对应 pane 时，会用 registry 里的最近绑定作为 soft hint，优先聚焦到记录中的 tab，而不是继续盲目新开 pane
- 由于 zellij CLI 目前没有按 pane name 精确聚焦的原生命令，复用动作当前是：
  - 找到同名 pane 所在 tab
  - 直接聚焦到该 tab
  - 避免继续重复开 pane
- 真正的“精确聚焦到某个 pane”若要再前进一步，后续更适合交给 plugin 层处理

### Workspace vs Cwd

- zellij managed layout / tab 资产始终挂在 project root 的 `.rscan/zellij/`
- 具体 pane 的 `cwd` 可以是：
  - `tasks/<id>/`
  - `jobs/<id>/`
  - `reverse_out/<job_id>/`
- 这意味着“session/layout 所属 workspace”与“pane 当前工作目录”现在被显式分离，不再互相污染

## Design Rules

- 不把“每个模块一个 tab”当目标
- 不让 pane 成为状态真相源
- 不把当前 `ratatui` 控制面整体重写成 zellij plugin
- 优先做 pane orchestration，再考虑 plugin 化增强

## Near-Term Roadmap

1. 已完成：统一 `tasks/` 与 `extra.runtime`
2. 已完成：稳定 `Tasks / Results` 的原生 pane 动作
3. 已完成：桥接 reverse `jobs/` 到统一任务表面
4. 已完成：把 pane registry 与 runtime binding 抬入 Dashboard / Detail 面板
5. 下一步：继续提升 pane 复用 / focus 体验，减少“tab 已对但 pane 不够精准”的落差
6. 后续再视需要引入 zellij plugin，做事件感知、精确 pane 聚焦与快捷键胶水
