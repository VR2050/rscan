# 美人如花.apK 技术评估报告（静态）

- 生成时间：2026-04-23 21:48:15
- 样本路径：`/home/vr2050/RUST/rscan_codex/违法apk/美人如花.apK`
- SHA256：`df34a2bf02e883a2a3285ec8aa054fa8ee37daf189f1f148b71edbc1a93ea602`
- 文件大小：`68830316` bytes
- 熵值：`7.962985`
- triage 置信值：`malware_confidence=44`
- 包名：`com.nearbubble`

## 1. 分析方法与产物

本次仅做技术链路与静态风险评估，不做识别率类统计结论。

- `rscan reverse analyze --output json`
- `rscan reverse malware-triage --output json`
- `rscan reverse android-analyze --output json`

产物目录：`/home/vr2050/RUST/rscan_codex/reports/ch6_reverse_case_meirenruhua_20260423_214528`

## 2. 关键技术发现（本轮）

1. **网络与传输面**：`uses_cleartext_traffic=true`，存在明文传输风险提示。
2. **权限面较宽**：权限总数 `56`，危险权限 `7` 个。
3. **组件暴露面**：`exported_components=26`。
4. **综合评分**：`score.total=100`。
5. **加壳/混淆迹象**（analyze）：高熵（`7.963`）及混淆提示。

### 2.1 危险权限（节选）

- `android.permission.ACCESS_COARSE_LOCATION`
- `android.permission.ACCESS_FINE_LOCATION`
- `android.permission.CAMERA`
- `android.permission.QUERY_ALL_PACKAGES`
- `android.permission.RECORD_AUDIO`
- `android.permission.REQUEST_INSTALL_PACKAGES`
- `android.permission.SYSTEM_ALERT_WINDOW`

### 2.2 敏感 API 命中（节选）

- `WebView`: 265
- `loadUrl`: 38
- `DexClassLoader`: 28
- `getDeviceId`: 18
- `TelephonyManager`: 16
- `addJavascriptInterface`: 8
- `getImei`: 7
- `AccessibilityService`: 6

### 2.3 组件统计（forensics）

- activities: `239`
- services: `28`
- receivers: `8`
- providers: `11`
- exported_activities: `12`
- exported_services: `9`
- exported_receivers: `4`
- exported_providers: `1`

## 3. 工程结论（用于论文6.4.3）

- 本项目 reverse 链路对 `美人如花.apK` **可执行且可产出结构化结果**。
- 当前仓库仍无公开样本集统一归档与识别率统计口径，因此本节保持“链路可执行”结论，不给识别率数据。
