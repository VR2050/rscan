# rscan 项目算法分析

## 1. 概览

本项目的算法体系以“工程实战”导向为主，核心是并发扫描、协议判定、指纹去重、规则匹配和启发式评分，不依赖复杂机器学习模型。

---

## 2. Web 扫描与爬取算法

### 2.1 BFS 爬虫与 Frontier 管理
- 使用 `VecDeque` 作为队列，按广度优先（BFS）扩展链接。
- 使用 `visited` 集合避免重复抓取。
- 通过 `max_depth` 和 `max_pages` 控制搜索空间。
- 代码位置：
  - `src/cores/web/crawl.rs`（`crawl` 主流程）

### 2.2 Robots 协议与主机节流
- 解析 `robots.txt` 中 `User-agent: *`、`Disallow`、`Crawl-delay`。
- 缓存每个 host 的 robots 策略，减少重复请求。
- 使用 `last_access` + delay 实现每主机请求间隔控制（politeness）。
- 代码位置：
  - `src/cores/web/crawl.rs`
  - `src/cores/web/scheduler.rs`

### 2.3 URL 调度与去重
- URL 规范化（去 fragment）后去重。
- 支持每主机最大页数限制（`max_pages_per_host`）。
- 若主机限速未到，任务回队并延迟再取。
- 代码位置：
  - `src/cores/web/scheduler.rs`

### 2.4 HTTP 重试与退避策略
- 对超时、5xx、429 做重试。
- 429 优先使用 `Retry-After`；否则指数退避。
- 批量请求使用 `buffer_unordered` 提升吞吐。
- 代码位置：
  - `src/cores/web/fetcher.rs`

---

## 3. 目录/Fuzz/子域扫描算法

### 3.1 目录递归展开
- 递归词典路径展开（按层组合词表）。
- 请求层面去重（避免重复 URL）。
- 代码位置：
  - `src/modules/web_scan/dir_scan.rs`

### 3.2 Wildcard 识别与过滤
- 先发探测请求生成 wildcard 样本签名。
- 通过状态码、长度容差、标题、simhash 相似度识别伪命中。
- 代码位置：
  - `src/modules/web_scan/common.rs`
  - `src/modules/web_scan/dir_scan.rs`
  - `src/modules/web_scan/fuzz_scan.rs`

### 3.3 响应近似去重（SimHash）
- 文本标准化后计算 `simhash64`。
- 通过 `Hamming distance` 判断近重复。
- 对短响应和 401/403 特殊放宽，避免误杀有效发现。
- 代码位置：
  - `src/modules/web_scan/common.rs`

### 3.4 自适应速率控制
- 按 chunk 扫描，统计节流信号（429/5xx 比例）。
- 节流高时增大 delay，正常时减小 delay。
- 属于工程型反馈控制（类似 AIMD 思路）。
- 代码位置：
  - `src/modules/web_scan/dir_scan.rs`
  - `src/modules/web_scan/fuzz_scan.rs`

### 3.5 子域爆破与验证
- 并发 `lookup_host` 做子域解析筛选。
- HTTP 失败时回退 HTTPS 验证可用性。
- 代码位置：
  - `src/modules/web_scan/dns_scan.rs`

---

## 4. 主机探测与端口扫描算法

### 4.1 目标解析与 CIDR 展开
- 支持单 IP、域名、CIDR。
- IPv4 网段按主机地址展开（处理 `/31`、`/32` 边界）。
- IPv6 限制只允许 `/127`、`/128`，防止爆炸扩展。
- 代码位置：
  - `src/cores/host/targets.rs`

### 4.2 TCP Connect 扫描
- 端口状态判定：
  - 连接成功 => Open
  - `ConnectionRefused` => Closed
  - 超时/其他错误 => Filtered
- 支持重试、并发、进度回调。
- 代码位置：
  - `src/cores/host/tcp_scanner.rs`

### 4.3 端口调度顺序算法
- `Serial`：顺序扫描。
- `Random`：基于混洗（Fisher-Yates 风格）打散端口序。
- `Interleave`：跨步交织降低局部连续探测特征。
- 代码位置：
  - `src/cores/host/tcp_scanner.rs`

### 4.4 并发执行模型
- 固定 worker 池 + `AtomicUsize` 无锁索引分发任务。
- 可配置 `max_rate`、`jitter`、自适应背压。
- 代码位置：
  - `src/cores/host/tcp_scanner.rs`

### 4.5 SYN 原始包扫描
- 手工构造 TCP SYN 包并计算校验和。
- 响应判定：
  - `SYN+ACK` => Open
  - `RST` => Closed
  - 无响应 => Filtered
- 原始套接字不可用时回退 TCP connect。
- 代码位置：
  - `src/cores/host/syn_scan.rs`
  - `src/cores/engine/raw_engine/methods/syn.rs`

### 4.6 UDP 探测
- 发送探针 payload，按响应/超时/错误判定状态。
- 支持 DNS/NTP/SNMP 特化探针。
- 并发模式下每任务独立 socket，避免 `recv_from` 竞争。
- 代码位置：
  - `src/cores/host/udp_scanner.rs`
  - `src/cores/engine/raw_engine/methods/udp.rs`

### 4.7 ICMP/ARP 探测
- ICMP Echo 请求/响应判定主机可达性。
- ARP 扫描构造广播帧收集 `IP->MAC`。
- 代码位置：
  - `src/cores/engine/raw_engine/methods/icmp.rs`
  - `src/cores/host/arp_scan.rs`
  - `src/cores/engine/raw_engine/methods/arp.rs`

---

## 5. 逆向分析算法

### 5.1 文件格式识别
- 基于魔数和结构特征识别 ELF/PE/APK。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`

### 5.2 Shannon Entropy 与字符串提取
- 统计字节频率计算 Shannon entropy。
- 提取 ASCII 字符串（最小长度+最大条数限制）。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`
  - `src/modules/reverse/android/strings.rs`

### 5.3 关键词规则匹配
- 在 imports/strings 上做大小写归一化包含匹配。
- 汇总 anti-debug、可疑导入、可疑字符串命中。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`
  - `src/modules/reverse/rules.rs`

### 5.4 Packer/壳识别与家族推断
- 依据 section 名、关键字符串、高熵、小导入表做壳提示。
- 在多语料（sections/strings/indicators）中匹配家族特征。
- 计算 packer 置信度（0-100）。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`

### 5.5 恶意风险分数
- 由 entropy、anti-debug、可疑导入/字符串、packer 命中加权合成。
- 结果裁剪到 0-100。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`

### 5.6 Android 风险评分
- 对危险权限、导出组件、明文流量、敏感 API 命中等加权评分。
- 输出总分 + 维度分解 + 说明。
- 代码位置：
  - `src/modules/reverse/android/scoring.rs`

### 5.7 动态行为轻量探测（可选）
- 基于 `strace` 抽样 syscalls（ptrace/prctl/seccomp）做动态信号补充。
- 代码位置：
  - `src/modules/reverse/analyzer.rs`

---

## 6. 漏洞扫描与防护评估算法

### 6.1 模板匹配引擎
- 支持 `status` / `word` / `header` matcher。
- 支持 `and/or` 组合条件，产出命中证据。
- 代码位置：
  - `src/modules/vuln_check/scanner.rs`

### 6.2 并发 fuzz 攻击
- `FUZZ` 占位符替换 payload 并发请求。
- 汇总状态码与响应长度。
- 代码位置：
  - `src/modules/vuln_check/fuzz_attack.rs`

### 6.3 防护统计指标
- 聚合成功率、阻断率、超时率、网络错误率。
- 延迟样本排序后计算平均值和 `p95`。
- 代码位置：
  - `src/modules/vuln_check/defense_audit.rs`

---

## 7. 检索与索引算法

### 7.1 Tantivy 倒排索引
- 将 reverse 索引数据构建成全文检索索引（name/signature/all）。
- 查询阶段使用 `QueryParser + TopDocs` 返回候选函数。
- 代码位置：
  - `src/modules/reverse/console.rs`

---

## 8. 总结

该项目的“核心算法画像”是：

1. 高并发网络扫描调度（BFS/队列/限速/退避/重试）
2. 协议级探测判定（SYN/UDP/ICMP/ARP）
3. 指纹与近似算法（simhash + Hamming）
4. 基于规则与启发式的安全分析评分（entropy + keyword + weighted score）
5. 工程化检索能力（Tantivy）

整体特点是：可解释、可配置、易落地，适合安全扫描与逆向分析的生产场景。
