use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;
use crate::errors::RustpenError;

/// Scheduler 配置
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub per_host_delay: Duration,
    pub max_depth: usize,
    pub max_pages_per_host: Option<usize>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            per_host_delay: Duration::from_millis(200),
            max_depth: 5,
            max_pages_per_host: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FrontierItem {
    pub url: String,
    pub depth: usize,
}

/// 简单的 URL Frontier / Scheduler
#[derive(Debug)]
pub struct Scheduler {
    config: SchedulerConfig,
    queue: Mutex<VecDeque<FrontierItem>>,
    visited: Mutex<HashSet<String>>,
    host_last_access: Mutex<HashMap<String, Instant>>,
    host_counters: Mutex<HashMap<String, usize>>,
}

impl Scheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            config,
            queue: Mutex::new(VecDeque::new()),
            visited: Mutex::new(HashSet::new()),
            host_last_access: Mutex::new(HashMap::new()),
            host_counters: Mutex::new(HashMap::new()),
        }
    }

    /// 添加 URL（自动规范化并去重）
    pub async fn add_url(&self, raw: &str, depth: usize) -> Result<bool, RustpenError> {
        if depth > self.config.max_depth {
            return Ok(false);
        }

        let url = match Url::parse(raw) {
            Ok(u) => u,
            Err(_) => return Err(RustpenError::InvalidHost(raw.to_string())),
        };

        let mut seen = self.visited.lock().await;
        // Normalize by removing fragment
        let mut normalized = url.clone();
        normalized.set_fragment(None);
        let normalized_s = normalized.as_str().to_string();

        if seen.contains(&normalized_s) {
            return Ok(false);
        }

        // per-host limit
        if let Some(limit) = self.config.max_pages_per_host {
            let host = url.host_str().unwrap_or_default().to_string();
            let mut counters = self.host_counters.lock().await;
            let cnt = counters.get(&host).copied().unwrap_or(0);
            if cnt >= limit {
                return Ok(false);
            }
            counters.insert(host, cnt + 1);
        }

        seen.insert(normalized_s.clone());
        drop(seen);

        let mut q = self.queue.lock().await;
        q.push_back(FrontierItem { url: normalized_s, depth });
        Ok(true)
    }

    /// 弹出下一个可用 URL（如果因主机速率被延迟，将会等待）
    pub async fn next_url(&self) -> Option<FrontierItem> {
        loop {
            let mut q = self.queue.lock().await;
            let maybe = q.pop_front();
            drop(q);

            if let Some(item) = maybe {
                let host = match Url::parse(&item.url) {
                    Ok(u) => u.host_str().unwrap_or_default().to_string(),
                    Err(_) => continue,
                };

                // 检查延时
                let mut last = self.host_last_access.lock().await;
                let now = Instant::now();
                if let Some(t) = last.get(&host) {
                    let elapsed = now.duration_since(*t);
                    if elapsed < self.config.per_host_delay {
                        // 还需等待，将任务放回队列末尾并等待一小段时间
                        let mut q = self.queue.lock().await;
                        q.push_back(item);
                        drop(q);
                        drop(last);
                        tokio::time::sleep(self.config.per_host_delay - elapsed).await;
                        continue;
                    }
                }

                last.insert(host, Instant::now());
                drop(last);
                return Some(item);
            } else {
                // 队列为空
                return None;
            }
        }
    }

    /// 获取队列长度（用于测试/观察）
    pub async fn queue_len(&self) -> usize {
        let q = self.queue.lock().await;
        q.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn scheduler_add_and_next_respects_delay() {
        let cfg = SchedulerConfig { per_host_delay: Duration::from_millis(200), max_depth: 3, max_pages_per_host: None };
        let s = Scheduler::new(cfg);

        s.add_url("http://example.com/a", 1).await.unwrap();
        s.add_url("http://example.com/b", 1).await.unwrap();

        let start = Instant::now();
        let first = s.next_url().await.unwrap();
        assert!(first.url.ends_with("/a") || first.url.ends_with("/b"));

        let second = s.next_url().await.unwrap();
        let elapsed = start.elapsed();
        // second should be delayed at least per_host_delay (allow small slack)
        assert!(elapsed >= Duration::from_millis(180));

        assert!(second.url.ends_with("/a") || second.url.ends_with("/b"));
    }

    #[tokio::test]
    async fn scheduler_dedups_and_depth_limit() {
        let cfg = SchedulerConfig::default();
        let s = Scheduler::new(cfg);

        assert!(s.add_url("http://example.org/", 1).await.unwrap());
        // duplicate
        assert!(!s.add_url("http://example.org/#frag", 2).await.unwrap());
        // too deep
        assert!(!s.add_url("http://example.org/x", 999).await.is_err());
    }
}
