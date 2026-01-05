use crate::errors::RustpenError;
use crate::cores::web_en::crawl::{Crawler, CrawlConfig};
use crate::cores::web_en::FetcherConfig as CoreFetcherConfig;
use crate::cores::web_en::Fetcher;

/// 模块层的配置：封装 core 的 FetcherConfig 和 CrawlConfig 常用字段
#[derive(Debug, Clone)]
pub struct WebScanConfig {
    pub max_depth: usize,
    pub concurrency: usize,
    pub max_pages: Option<usize>,
    pub obey_robots: bool,
    pub default_host_delay_ms: u64,
    pub fetcher: CoreFetcherConfig,
}

impl Default for WebScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 2,
            concurrency: 4,
            max_pages: Some(100),
            obey_robots: true,
            default_host_delay_ms: 500,
            fetcher: CoreFetcherConfig::default(),
        }
    }
}

/// WebScanner：模块层对外 API（异步）
#[derive(Clone)]
pub struct WebScanner {
    crawler: Crawler,
}

impl WebScanner {
    pub fn new(cfg: WebScanConfig) -> Result<Self, RustpenError> {
        let fetcher = Fetcher::new(cfg.fetcher).map_err(|e| e)?;
        let crawl_cfg = CrawlConfig {
            max_depth: cfg.max_depth,
            concurrency: cfg.concurrency,
            max_pages: cfg.max_pages,
            obey_robots: cfg.obey_robots,
            default_host_delay_ms: cfg.default_host_delay_ms,
        };
        let crawler = Crawler::new(fetcher, crawl_cfg);
        Ok(Self { crawler })
    }

    /// 异步扫描入口，返回已抓取 URL 列表
    pub async fn scan(&self, seeds: Vec<String>) -> Result<Vec<String>, RustpenError> {
        self.crawler.crawl(seeds).await
    }

    /// Module-level helpers integration (convenience wrappers over module functions)
    pub async fn dir_scan(&self, base: &str, paths: &[&str], cfg: Option<crate::modules::web_scan::ModuleScanConfig>) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_dir_scan(base, paths, cfg).await
    }

    pub fn dir_scan_stream(&self, base: &str, paths: Vec<String>, cfg: Option<crate::modules::web_scan::ModuleScanConfig>) -> tokio::sync::mpsc::Receiver<Result<crate::modules::web_scan::ModuleScanResult, RustpenError>> {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_dir_scan_stream(base, paths, cfg)
    }

    pub fn dir_scan_with_callback<F>(&self, base: &str, paths: Vec<String>, cfg: Option<crate::modules::web_scan::ModuleScanConfig>, cb: F) -> tokio::task::JoinHandle<()>
    where F: Fn(crate::modules::web_scan::ModuleScanResult) + Send + Sync + 'static {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_dir_scan_with_callback(base, paths, cfg, cb)
    }

    pub async fn fuzz_scan(&self, url_with_fuzz: &str, keywords: &[&str], cfg: Option<crate::modules::web_scan::ModuleScanConfig>) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_fuzz_scan(url_with_fuzz, keywords, cfg).await
    }

    pub fn fuzz_scan_stream(&self, url_with_fuzz: &str, keywords: Vec<String>, cfg: Option<crate::modules::web_scan::ModuleScanConfig>) -> tokio::sync::mpsc::Receiver<Result<crate::modules::web_scan::ModuleScanResult, RustpenError>> {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_fuzz_scan_stream(url_with_fuzz, keywords, cfg)
    }

    pub async fn subdomain_burst(&self, base_domain: &str, words: &[&str], cfg: Option<crate::modules::web_scan::ModuleScanConfig>) -> Result<Vec<crate::modules::web_scan::ModuleScanResult>, RustpenError> {
        let cfg = cfg.unwrap_or_else(|| crate::modules::web_scan::ModuleScanConfig::default());
        crate::modules::web_scan::run_subdomain_burst(base_domain, words, cfg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;
    use std::time::Duration;

    #[tokio::test]
    async fn webscanner_basic_crawl() {
        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/a\">a</a>"));
        let a = warp::path("a").map(|| warp::reply::html("ok"));
        let (addr, server) = warp::serve(route.or(a)).bind_ephemeral(([127,0,0,1], 0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);

        let cfg = WebScanConfig { max_depth: 1, concurrency: 1, max_pages: Some(10), obey_robots: false, default_host_delay_ms: 1, fetcher: CoreFetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 } };
        let ws = WebScanner::new(cfg).unwrap();
        let res = ws.scan(vec![base.clone()]).await.unwrap();
        assert!(res.iter().any(|u| u == &base || u == &format!("{}/", base)));
        assert!(res.iter().any(|u| u == &format!("{}/a", base)));
    }

    #[tokio::test]
    async fn webscanner_respects_robots() {
        let robots = "User-agent: *\nDisallow: /x\n";

        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/x\">x</a><a href=\"/y\">y</a>"));
        let x = warp::path("x").map(|| warp::reply::html("secret"));
        let y = warp::path("y").map(|| warp::reply::html("ok"));
        let robots_route = warp::path("robots.txt").map(move || warp::reply::with_status(robots.clone(), warp::http::StatusCode::OK));

        let (addr, server) = warp::serve(route.or(x).or(y).or(robots_route)).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);

        let cfg = WebScanConfig { max_depth: 1, concurrency: 1, max_pages: Some(10), obey_robots: true, default_host_delay_ms: 1, fetcher: CoreFetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 } };
        let ws = WebScanner::new(cfg).unwrap();
        let res = ws.scan(vec![base.clone()]).await.unwrap();
        assert!(res.iter().any(|u| u == &base || u == &format!("{}/", base)));
        assert!(res.iter().any(|u| u == &format!("{}/y", base)));
        assert!(res.iter().all(|u| !u.ends_with("/x")));
    }

    #[tokio::test]
    async fn webscanner_dir_scan_integration() {
        use crate::modules::web_scan::ModuleScanConfig;
        let route = warp::path!(String).map(|s: String| warp::reply::html(format!("you asked {}", s)));
        let root = warp::path::end().map(|| warp::reply::html("root"));
        let (addr, server) = warp::serve(route.or(root)).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);

        let base = format!("http://{}", addr);
        let cfg = WebScanConfig { max_depth: 1, concurrency: 1, max_pages: Some(10), obey_robots: false, default_host_delay_ms: 1, fetcher: CoreFetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 } };
        let ws = WebScanner::new(cfg).unwrap();

        let mcfg = ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 2, timeout_ms: Some(5000), max_retries: Some(0), status_min: None, status_max: None, per_host_concurrency_override: None, dedupe_results: true, output_format: None };
        let res = ws.dir_scan(&base, &["/a","/b"], Some(mcfg)).await.unwrap();
        assert!(res.iter().any(|r| r.url.contains("/a") || r.url.contains("/b") || r.url == base || r.url == format!("{}/", base)));
    }

    #[tokio::test]
    async fn webscanner_fuzz_and_dns_integration() {
        use crate::modules::web_scan::ModuleScanConfig;
        // fuzz test
        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/FUZZ.html\">FUZZ</a>"));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let cfg = WebScanConfig { max_depth: 1, concurrency: 1, max_pages: Some(10), obey_robots: false, default_host_delay_ms: 1, fetcher: CoreFetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 } };
        let ws = WebScanner::new(cfg).unwrap();

        let mcfg = ModuleScanConfig::default();
        let res = ws.fuzz_scan(&format!("{}/FUZZ.html", base), &["test","a"], Some(mcfg)).await.unwrap();
        assert!(res.iter().any(|r| !r.url.contains("FUZZ")));

        // dns (subdomain) test
        let handler = warp::any().map(|| warp::reply::with_status("ok", warp::http::StatusCode::OK));
        let (addr2, server2) = warp::serve(handler).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server2);
        let domain = format!("127.0.0.1:{}", addr2.port());
        // words 'a' should result in http://a.DOMAIN being requested and succeeded
        let res2 = ws.subdomain_burst(&domain, &["a"], None).await.unwrap();
        assert!(!res2.is_empty());
    }
}

