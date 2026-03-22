# Task 元数据与事件流约定（TUI/任务统一层）

## 目录结构
默认工作区：`<workspace>/tasks/<task_id>/`

- `meta.json`：任务元信息（`TaskMeta`）
- `events.jsonl`：任务事件流（`TaskEvent`，一行一条 JSON）
- `stdout.log` / `stderr.log`：可选，落盘原始日志
- 产物文件（依模块而定，如扫描结果、pseudocode、csv/json 等）

## TaskMeta（meta.json）
```jsonc
{
  "id": "task-65f1c...",
  "kind": "host",            // host | web | vuln | reverse | shell | other
  "tags": ["192.168.0.1"],   // 便于筛选/分组
  "status": "running",       // queued | running | succeeded | failed | canceled
  "created_at": 1710000000,
  "started_at": 1710000001,
  "ended_at": null,
  "progress": 12.5,          // 可选，0~100
  "note": "quick scan",
  "artifacts": ["workspace/tasks/task-.../result.json"],
  "logs": ["workspace/tasks/task-.../stdout.log"],
  "extra": {
    "concurrency": 200,
    "runtime": {
      "backend": "zellij-task-engine",
      "session": "rscan",
      "tab": "Control",
      "pane_name": "rscan-control",
      "role": "task-engine",
      "cwd": "/abs/workspace/project",
      "command": null
    }
  } // 模块自定义字段
}
```

## TaskEvent（events.jsonl）
```jsonc
{"ts":1710000002,"level":"info","kind":"log","message":"start scan","data":null}
{"ts":1710000003,"level":"info","kind":"progress","message":null,"data":12.5}
{"ts":1710000004,"level":"warn","kind":"log","message":"timeout host=1.1.1.1","data":null}
{"ts":1710000005,"level":"info","kind":"metric","message":"qps","data":{"host":220.3}}
{"ts":1710000006,"level":"info","kind":"control","message":"throttle=150","data":null}
```

### 字段说明
- `ts`：epoch 秒
- `level`：info/warn/error/debug
- `kind`：log | progress | metric | control
- `message`：简短文本
- `data`：可选结构化数据（数字/对象）

## extra.runtime 约定（zellij/native 编排）
- `backend`：运行时后端，如 `task-engine`、`zellij-task-engine`、`script-runner`、`zellij`
- `session`：zellij session 名
- `tab`：当前推荐关联 tab，如 `Control`、`Work`、`Inspect`、`Reverse`
- `pane_name`：最近一次关联 pane 的逻辑名
- `role`：该 pane/运行时承担的职责，如 `task-engine`、`inspect-logs`、`task-shell`
- `cwd`：建议工作目录
- `command`：若该 pane 由命令驱动，则记录启动命令

说明：
- `extra.runtime` 是“当前最相关运行时绑定”，不是完整审计历史。
- 当 TUI 把任务送进 zellij 原生 pane（如日志跟随、artifact shell）时，可以覆盖更新该绑定。
- 后续若需要历史轨迹，可再引入 `extra.runtime_history`，当前先保持协议轻量稳定。

## 用法建议
- 各子命令启动时创建任务目录，写入初始 `meta.json`（status=queued/running）。
- 过程中追加 `events.jsonl`，同时根据需要刷新 `meta.json` 的 `progress/status`.
- 结束时写 `ended_at` 和最终 `status`，并确保产物路径写入 `artifacts`。
- TUI 读取 `tasks/` 目录即可显示列表/详情/日志，无需侵入模块业务逻辑。
- 若启用 zellij-native 工作台，则同步维护 `extra.runtime`，保证任务能回到原生 pane/workspace。
