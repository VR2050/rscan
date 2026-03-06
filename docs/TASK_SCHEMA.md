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
  "extra": { "concurrency": 200 } // 模块自定义字段
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

## 用法建议
- 各子命令启动时创建任务目录，写入初始 `meta.json`（status=queued/running）。
- 过程中追加 `events.jsonl`，同时根据需要刷新 `meta.json` 的 `progress/status`.
- 结束时写 `ended_at` 和最终 `status`，并确保产物路径写入 `artifacts`。
- TUI 读取 `tasks/` 目录即可显示列表/详情/日志，无需侵入模块业务逻辑。
