# 项目目录结构

## 核心源码

- `src/main.rs`：CLI 入口
- `src/lib.rs`：库入口与公共导出
- `src/cli/`：命令解析与分发
- `src/cores/`：底层能力（主机扫描、Web 抓取、扫描引擎）
- `src/modules/`：模块封装（端口、Web、漏洞、逆向、shell 生成）
- `src/services/`：跨模块服务（如 service probe）

## 工程与文档

- `Cargo.toml`：Rust 依赖与构建配置
- `README.md`：项目总览
- `CLI_USAGE.md`：CLI 快速示例
- `docs/`：补充文档（本文件）
- `benches/`：基准测试

## 规则与数据

- `rules/`：规则模板目录（可放 YAML/JSON）

## 本地运行产物（已忽略）

以下目录/文件属于运行期产物，不建议提交：

- `jobs/`
- `reverse_out/`
- `reverse_ws_test/`
- `out.txt`
- `pseudocode.jsonl`
- `easy`

建议将扫描输出统一写到单独工作目录，例如：`./workspace/`。
