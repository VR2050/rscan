# 附录D 项目源码结构说明

## D.1 顶层结构

项目根目录关键内容：

1. `src/`：核心源码。
2. `docs/`：项目文档。
3. `scripts/`：基准、门禁、冒烟脚本。
4. `benches/`：基准测试代码（Criterion）。
5. `third_party/`：外部依赖运行时（如精简 Ghidra）。

## D.2 源码分层

### D.2.1 CLI层（`src/cli/`）

职责：参数解析、子命令路由、输出组织、任务入口。

### D.2.2 核心层（`src/cores/`）

1. `host/`：主机与端口探测引擎。
2. `web/`：Web 请求、抓取与解析基础能力。
3. `engine/`：统一扫描模型与执行框架。

### D.2.3 模块层（`src/modules/`）

1. `port_scan/`：端口扫描模块。
2. `web_scan/`：目录/Fuzz/DNS/Crawl/Live 模块。
3. `vuln_check/`：漏洞检测与防护审计模块。
4. `reverse/`：逆向分析与反编译任务模块。
5. `shell_generation/`：Shell 生成模块。

### D.2.4 服务层（`src/services/`）

1. `service_probe.rs`：服务指纹探测能力。

### D.2.5 TUI层（`src/tui/`）

1. 统一 TUI 状态与渲染。
2. Zellij 原生集成（layout/query/registry）。
3. reverse/work/inspect 原生 hub 与工作区视图。

## D.3 关键数据目录

1. `tasks/`：任务目录（meta/events/logs）。
2. `jobs/`：逆向作业目录。
3. `reverse_out/`：逆向产物目录。
4. `.rscan/`：运行期元数据（如 zellij/reverse hints）。

## D.4 典型调用链

1. 用户命令进入 `CLI`。
2. 路由到 `cores/modules` 执行。
3. 结果写入 `tasks/jobs/reverse_out`。
4. `TUI` 聚合读取并可视化。
5. `Zellij` 提供原生 pane 承载日志/任务 shell/产物探索。

