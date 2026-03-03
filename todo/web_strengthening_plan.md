# Web 模块加强计划

## 目标
在保留现有 CLI 功能的基础上，提升抓取稳健性、扫描准确度、资产指纹能力与可视化/结果结构化，后续可接入 TUI 浏览。

## 优先级与里程碑
- P0（本周可落地）
  - 抓取稳健性：fetcher 增加超时/重试/限速、UA/代理配置；编码探测与内容类型校验。
  - 输出结构统一：定义 web 结果 schema（URL、状态、长度、指纹、风险、证据）；dir/fuzz/dns 统一输出。
- P1（1–2 周）
  - 指纹插件接口：favicon hash、title/响应头/JS 库识别；技术栈字段写入结果。
  - 目录/模糊扫描精度：404/403 baseline、自适应字典、响应长度+特征码误报过滤；并发/速率参数化。
  - 爬虫策略：深度/广度配额、域/路径白名单、robots.txt 软/硬模式；MIME 过滤（仅 HTML/JS/JSON）。
- P2（2–4 周）
  - 安全探针：基础 XSS/LFI/SSRF 模板，命中后记录风险等级与证据片段。
  - TLS/HTTP 细节：SNI/ALPN、证书信息导出、重定向策略可配，H2/H3 回落。
  - 认证/会话：cookie jar、Bearer/Basic、自定义头；可加载浏览器 cookie。
- P3（后续）
  - TUI 视图：资产/端点列表、过滤/搜索、指纹与风险高亮；保留 CLI。
  - 回归测试：本地 mock HTTP 服务覆盖重定向、压缩、分块、错误码等场景。

## 任务拆分
- fetcher 强化
  - 添加全局/每请求超时、重试、最大并发/速率、代理、UA 配置。
  - 自动编码识别（Content-Type + 探测），非文本时跳过解析。
- 结果 schema
  - 统一结构：`url,status,len,title,favicon_hash,tech,headers_snip,fingerprint,risk,evidence`。
  - dir/fuzz/dns/指纹写入同一 JSONL/CSV。
- 指纹插件
  - 插件 trait + 内置规则（favicon mmh3、header/title/JS 关键字）。
- 目录/模糊扫描
  - 基线探测 404/403；响应长度/关键词过滤；字典可配置，支持“自适应追加”。
- 爬虫
  - 深度/广度限制；域/路径白名单；robots 软/硬模式；MIME 过滤。
- 安全探针
  - 小型 payload 模板（XSS, LFI, SSRF）；命中后保存响应片段与标记。
- TLS/HTTP/认证
  - SNI/ALPN、证书信息；重定向策略；cookie/Basic/Bearer/自定义头注入。
- TUI
  - 资产列表、风险高亮、过滤；可选导出（CSV/JSON）。
- 测试
  - httpmock/httptest 场景：重定向、压缩、分块、403/404 基线、指纹命中、payload 误报。

## 交付物
- 代码改动（fetcher/scan/指纹/输出格式/TUI 入口）。
- 文档：配置示例、使用示例、字段说明。
- 测试：集成/单元覆盖关键路径。
