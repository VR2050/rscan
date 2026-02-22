use crate::cores::web::{Fetcher, Parser};
use crate::errors::RustpenError;
use futures::future::join_all;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

/// Crawl 配置
#[derive(Debug, Clone)]
pub struct CrawlConfig {
    pub max_depth: usize,
    pub concurrency: usize,
    pub max_pages: Option<usize>,
    /// 是否尊重 robots.txt
    pub obey_robots: bool,
    /// 默认的每主机请求间隔（毫秒），当 robots.txt 没有提供 crawl-delay 时使用
    pub default_host_delay_ms: u64,
}

impl Default for CrawlConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            concurrency: 4,
            max_pages: Some(100),
            obey_robots: true,
            default_host_delay_ms: 500,
        }
    }
}

/// 简单的 robots 策略：仅支持 User-agent: * 的 Disallow 和 Crawl-delay
#[derive(Debug, Clone)]
pub struct RobotsPolicy {
    pub disallow: Vec<String>,
    pub crawl_delay_ms: Option<u64>,
    pub fetched_at: Instant,
}

impl RobotsPolicy {
    pub fn allows(&self, path: &str) -> bool {
        for d in &self.disallow {
            if d == "/" {
                return false;
            }
            if d.is_empty() {
                continue;
            }
            if path.starts_with(d) {
                return false;
            }
        }
        true
    }
}

/// 爬虫实例，负责调度 Fetcher + Parser，并缓存 robots.txt
#[derive(Clone)]
pub struct Crawler {
    pub fetcher: Fetcher,
    pub config: CrawlConfig,
    robots_cache: Arc<RwLock<HashMap<String, RobotsPolicy>>>,
}

impl Crawler {
    pub fn new(fetcher: Fetcher, config: CrawlConfig) -> Self {
        Self {
            fetcher,
            config,
            robots_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 执行并发爬取：从 seeds 开始，广度优先并发执行，返回已抓取 URL 列表
    /// 实现细节：会启动 `config.concurrency` 个 worker，每个 worker 从共享 frontier 弹出任务并处理；
    /// 为了 politeness，会维护每个 host 的 `last_access`，在发起请求前等待 `crawl-delay` 或 `default_host_delay_ms`。
    pub async fn crawl(&self, seeds: Vec<String>) -> Result<Vec<String>, RustpenError> {
        use tokio::sync::Mutex;

        let frontier = Arc::new(Mutex::new(VecDeque::new()));
        for s in seeds {
            frontier.lock().await.push_back((s, 0));
        }

        let visited = Arc::new(Mutex::new(HashSet::<String>::new()));
        let fetched = Arc::new(Mutex::new(Vec::<String>::new()));
        let last_access = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));

        // Worker closure
        let mut handles = Vec::new();
        for _ in 0..self.config.concurrency {
            let frontier = frontier.clone();
            let visited = visited.clone();
            let fetched = fetched.clone();
            let last_access = last_access.clone();
            let fetcher = self.fetcher.clone();
            let robots_cache = self.robots_cache.clone();
            let cfg = self.config.clone();

            let h = tokio::spawn(async move {
                loop {
                    // pop a job
                    let job = {
                        let mut flock = frontier.lock().await;
                        let vlock = visited.lock().await;
                        let mut found = None;
                        while let Some((u, d)) = flock.pop_front() {
                            if vlock.contains(&u) {
                                continue;
                            }
                            found = Some((u, d));
                            break;
                        }
                        found
                    };

                    let (url_s, depth) = match job {
                        Some(j) => j,
                        None => break, // no more jobs
                    };

                    // max_pages guard
                    if let Some(max_pages) = cfg.max_pages {
                        let fetched_len = fetched.lock().await.len();
                        if fetched_len >= max_pages {
                            break;
                        }
                    }

                    // parse url
                    let parsed_url = match Url::parse(&url_s) {
                        Ok(u) => u,
                        Err(_) => {
                            visited.lock().await.insert(url_s.clone());
                            continue;
                        }
                    };

                    // robots check & per-host delay
                    if cfg.obey_robots {
                        if let Some(pol) = {
                            // use robots_cache clone
                            let cache = robots_cache.read().await;
                            cache.get(parsed_url.host_str().unwrap_or("")).cloned()
                        } {
                            let path = parsed_url.path();
                            if !pol.allows(path) {
                                visited.lock().await.insert(url_s.clone());
                                continue;
                            }
                        } else {
                            // not cached: fetch via fetcher and parse
                            if cfg.obey_robots {
                                let scheme = parsed_url.scheme();
                                let host = parsed_url.host_str().unwrap_or("");
                                let port_str = match parsed_url.port() {
                                    Some(p) => format!(":{}", p),
                                    None => "".to_string(),
                                };
                                let robots_url =
                                    format!("{}://{}{}{}", scheme, host, port_str, "/robots.txt");
                                if let Ok(r) = fetcher.fetch(&robots_url).await
                                    && r.status == 200
                                {
                                    let txt = String::from_utf8_lossy(&r.body).to_string();
                                    // parse similarly to fetch_robots_for but inline to avoid borrowing issues
                                    let mut disallow = Vec::new();
                                    let mut crawl_delay = None;
                                    let mut in_group = false;
                                    for line in txt.lines() {
                                        let ln = line.trim();
                                        if ln.is_empty() || ln.starts_with('#') {
                                            continue;
                                        }
                                        let parts: Vec<&str> = ln.splitn(2, ':').collect();
                                        if parts.len() != 2 {
                                            continue;
                                        }
                                        let key = parts[0].trim().to_lowercase();
                                        let val = parts[1].trim();
                                        if key == "user-agent" {
                                            in_group = val == "*";
                                        } else if key == "disallow" && in_group {
                                            disallow.push(val.to_string());
                                        } else if key == "crawl-delay"
                                            && in_group
                                            && let Ok(sec) = val.parse::<u64>()
                                        {
                                            crawl_delay = Some(sec * 1000);
                                        }
                                    }
                                    let policy = RobotsPolicy {
                                        disallow,
                                        crawl_delay_ms: crawl_delay,
                                        fetched_at: Instant::now(),
                                    };
                                    // cache it
                                    let mut c = robots_cache.write().await;
                                    c.insert(
                                        parsed_url.host_str().unwrap_or("").to_string(),
                                        policy.clone(),
                                    );

                                    if !policy.allows(parsed_url.path()) {
                                        visited.lock().await.insert(url_s.clone());
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    // Enforce per-host delay using last_access
                    let host = parsed_url.host_str().unwrap_or("").to_string();
                    let delay_ms = {
                        let cache = robots_cache.read().await;
                        cache
                            .get(&host)
                            .and_then(|p| p.crawl_delay_ms)
                            .unwrap_or(cfg.default_host_delay_ms)
                    };

                    // wait until enough time has elapsed since last_access
                    {
                        let mut la = last_access.lock().await;
                        if let Some(prev) = la.get(&host) {
                            let elapsed = prev.elapsed();
                            if elapsed.as_millis() < delay_ms as u128 {
                                let wait_ms = delay_ms as i128 - elapsed.as_millis() as i128;
                                if wait_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(wait_ms as u64)).await;
                                }
                            }
                        }
                        la.insert(host.clone(), Instant::now());
                    }

                    // fetch
                    match fetcher.fetch(&url_s).await {
                        Ok(resp) => {
                            fetched.lock().await.push(url_s.clone());
                            visited.lock().await.insert(url_s.clone());

                            // expand links
                            if depth < cfg.max_depth
                                && let Ok(parsed) = Parser::parse(
                                    &url_s,
                                    std::str::from_utf8(&resp.body).unwrap_or(""),
                                )
                            {
                                let mut f = frontier.lock().await;
                                let v = visited.lock().await;
                                for link in parsed.links {
                                    if let Ok(lu) = Url::parse(&link)
                                        && (lu.scheme() == "http" || lu.scheme() == "https")
                                        && !v.contains(&link)
                                    {
                                        f.push_back((link, depth + 1));
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            visited.lock().await.insert(url_s.clone());
                            continue;
                        }
                    }
                }
            });
            handles.push(h);
        }

        // wait for workers
        let _ = join_all(handles).await;

        let res = fetched.lock().await.clone();
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;

    #[tokio::test]
    async fn crawl_obeys_robots_txt() {
        // robots disallow /secret
        let robots = "User-agent: *\nDisallow: /secret\n";

        let route = warp::path::end()
            .map(|| warp::reply::html("<a href=\"/open\">open</a><a href=\"/secret\">secret</a>"));
        let secret = warp::path("secret").map(|| warp::reply::html("secret"));
        let open = warp::path("open").map(|| warp::reply::html("open"));
        let robots_route = warp::path("robots.txt")
            .map(move || warp::reply::with_status(robots, warp::http::StatusCode::OK));

        let (addr, server) = warp::serve(route.or(secret).or(open).or(robots_route))
            .bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);

        let cfg = Fetcher::new(crate::cores::web::FetcherConfig {
            timeout: Duration::from_secs(5),
            user_agent: None,
            max_retries: 0,
            accept_invalid_certs: false,
            per_host_concurrency: 2,
            default_headers: None,
            honor_retry_after: true,
            backoff_base_ms: 100,
            backoff_max_ms: 10_000,
        })
        .unwrap();
        let crawl_cfg = CrawlConfig {
            max_depth: 1,
            concurrency: 1,
            max_pages: Some(10),
            obey_robots: true,
            default_host_delay_ms: 1,
        };
        let crawler = Crawler::new(cfg, crawl_cfg);

        let seeds = vec![base.clone()];
        let res = crawler.crawl(seeds).await.unwrap();
        // should fetch base and /open but not /secret
        assert!(res.iter().any(|u| u == &base || u == &format!("{}/", base))); // root was fetched
        assert!(res.iter().any(|u| u == &format!("{}/open", base)));
        assert!(res.iter().all(|u| !u.ends_with("/secret")));
    }

    #[tokio::test]
    async fn crawl_ignores_robots_when_disabled() {
        let robots = "User-agent: *\nDisallow: /secret\n";

        let route = warp::path::end()
            .map(|| warp::reply::html("<a href=\"/open\">open</a><a href=\"/secret\">secret</a>"));
        let secret = warp::path("secret").map(|| warp::reply::html("secret"));
        let open = warp::path("open").map(|| warp::reply::html("open"));
        let robots_route = warp::path("robots.txt")
            .map(move || warp::reply::with_status(robots, warp::http::StatusCode::OK));

        let (addr, server) = warp::serve(route.or(secret).or(open).or(robots_route))
            .bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);

        let cfg = Fetcher::new(crate::cores::web::FetcherConfig {
            timeout: Duration::from_secs(5),
            user_agent: None,
            max_retries: 0,
            accept_invalid_certs: false,
            per_host_concurrency: 2,
            default_headers: None,
            honor_retry_after: true,
            backoff_base_ms: 100,
            backoff_max_ms: 10_000,
        })
        .unwrap();
        let crawl_cfg = CrawlConfig {
            max_depth: 1,
            concurrency: 1,
            max_pages: Some(10),
            obey_robots: false,
            default_host_delay_ms: 1,
        };
        let crawler = Crawler::new(cfg, crawl_cfg);

        let seeds = vec![base.clone()];
        let res = crawler.crawl(seeds).await.unwrap();
        // should fetch base, /open and /secret
        assert!(res.iter().any(|u| u == &base || u == &format!("{}/", base)));
        assert!(res.iter().any(|u| u == &format!("{}/open", base)));
        assert!(res.iter().any(|u| u == &format!("{}/secret", base)));
    }
}
