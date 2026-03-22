use std::fs;

pub(crate) fn read_cpu_stat() -> Option<(u64, u64)> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let nums = parts
        .filter_map(|v| v.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if nums.len() < 4 {
        return None;
    }
    let idle = nums.get(3).copied().unwrap_or(0) + nums.get(4).copied().unwrap_or(0);
    let total: u64 = nums.iter().sum();
    Some((total, idle))
}

pub(crate) fn read_meminfo() -> Option<(u64, u64)> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    for line in text.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        } else if line.starts_with("MemAvailable:") {
            avail_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    if total_kb == 0 {
        return None;
    }
    let used_kb = total_kb.saturating_sub(avail_kb);
    Some((used_kb / 1024, total_kb / 1024))
}

pub(crate) fn read_proc_rss_mb() -> Option<u64> {
    let text = fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if line.starts_with("VmRSS:") {
            let kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            return Some(kb / 1024);
        }
    }
    None
}

pub(crate) fn read_loadavg() -> Option<String> {
    let text = fs::read_to_string("/proc/loadavg").ok()?;
    let mut it = text.split_whitespace();
    let a = it.next()?;
    let b = it.next()?;
    let c = it.next()?;
    Some(format!("{a} {b} {c}"))
}
