# modules::web_scan

提供模块级别的爬虫封装 `WebScanner`，包装了 cores 中的 `Crawler`，以便在更高层进行集成测试与 CLI 暴露。

示例：

```rust
use modules::WebScanner;

let cfg = modules::web_scan::WebScanConfig::default();
let ws = WebScanner::new(cfg)?;
let res = ws.scan(vec!["http://example.com".to_string()]).await?;
```