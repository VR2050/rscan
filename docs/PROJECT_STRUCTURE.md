# 项目目录结构（更新于 2026-03-07）

## 核心源码
- `src/main.rs`：CLI 入口
- `src/lib.rs`：库入口与公共导出
- `src/cli/`：命令解析与分发
- `src/cores/`：底层能力（主机扫描、Web 抓取、扫描引擎）
- `src/modules/`：模块封装（端口、Web、漏洞、逆向、shell 生成）
- `src/services/`：跨模块服务（如 `service_probe`）
- `src/tui/`：统一 TUI（已完成分层重构）

## TUI 子结构（当前）
- `src/tui/app.rs`：主循环与终端生命周期（精简编排层）
- `src/tui/app_state.rs`：状态结构与子模块挂载
- `src/tui/app_state/init.rs`：状态初始化
- `src/tui/app_state/runtime.rs`：运行时维护（索引刷新、状态推送、脚本完成处理）
- `src/tui/app_state/render_ctx.rs`：`AppState -> RenderCtx` 映射
- `src/tui/app_state/dispatch/`：按键分发
- `src/tui/render.rs`：渲染入口编排
- `src/tui/render/header.rs`：顶部栏渲染
- `src/tui/render/mini_console.rs`：底部控制台渲染
- `src/tui/render/panes/`：六大 pane 渲染（Dashboard/Tasks/Launcher/Scripts/Results/Projects）
- `src/tui/input/`：非 normal 输入模式处理
- `src/tui/normal_global.rs`：全局快捷键路由
- `src/tui/normal_panes/`：各 pane 的 normal 模式按键处理
- `src/tui/view.rs`：文本行构建与布局辅助

## 工程与文档
- `Cargo.toml`：Rust 依赖与构建配置
- `README.md`：项目总览与近期更新
- `CLI_USAGE.md`：CLI 快速示例
- `docs/`：补充文档（本文件）
- `benches/`：基准测试

## 规则与数据
- `rules/`：规则模板目录（YAML/JSON）
- `workspace/`：建议的任务与输出工作目录

## 本地运行产物（已忽略）
以下目录/文件属于运行期产物，不建议提交：
- `jobs/`
- `reverse_out/`
- `reverse_ws_test/`
- `out.txt`
- `pseudocode.jsonl`
- `easy`
