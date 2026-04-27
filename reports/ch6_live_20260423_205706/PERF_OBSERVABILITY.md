# PERF Observability Evidence

Generated: 2026-04-23 20:57:47 +0800

## src/tui/perf.rs
3:pub(crate) fn read_cpu_stat() -> Option<(u64, u64)> {
4:    let text = fs::read_to_string("/proc/stat").ok()?;
21:pub(crate) fn read_meminfo() -> Option<(u64, u64)> {
22:    let text = fs::read_to_string("/proc/meminfo").ok()?;
47:pub(crate) fn read_proc_rss_mb() -> Option<u64> {
50:        if line.starts_with("VmRSS:") {
62:pub(crate) fn read_loadavg() -> Option<String> {

## src/tui/render/perf.rs
48:        Line::from(format!("CPU  {}", cpu)),
49:        Line::from(format!("MEM  {}", mem)),
50:        Line::from(format!("RSS  {}", rss)),
51:        Line::from(format!("LOAD {}", load)),
60:        .title("PERF");
