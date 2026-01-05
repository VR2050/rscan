use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use reqwest::{Client, Response, Method, header::HeaderMap};
use crate::errors::RustpenError;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Semaphore};
use futures::stream::{self, StreamExt};
use bytes::Bytes;

/// Fetcher 配置
#[derive(Debug, Clone)]
pub struct FetcherConfig {
    pub timeout: Duration,
    pub user_agent: Option<String>,
    pub max_retries: u32,
    pub accept_invalid_certs: bool,
    /// per-host concurrency limit
    pub per_host_concurrency: usize,
    /// 可选默认 headers，会设置到 reqwest Client 的 default_headers
    pub default_headers: Option<HeaderMap>,
    /// 是否尊重服务器返回的 Retry-After 头（对于 429 响应）
    pub honor_retry_after: bool,
    /// backoff 参数（单位毫秒），用于指数退避
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            user_agent: Some("rscan-fetcher/0.1".to_string()),
            max_retries: 1,
            accept_invalid_certs: false,
            per_host_concurrency: 2,
            default_headers: None,
            honor_retry_after: true,
            backoff_base_ms: 100,
            backoff_max_ms: 10_000,
        }
    }
}

/// Fetch 返回的标准化结构
#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// 更灵活的请求结构
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub url: String,
    pub method: Method,
    pub headers: Option<HeaderMap>,
    pub body: Option<Bytes>,
    /// 单次请求超时时间（毫秒），None 使用 FetcherConfig.timeout
    pub timeout_ms: Option<u64>,
    /// 覆盖 FetcherConfig.max_retries
    pub max_retries: Option<u32>,
}

/// 简单的 HTTP fetcher 封装
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: Client,
    pub config: FetcherConfig,
    per_host_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
}

impl Fetcher {
    pub fn new(config: FetcherConfig) -> Result<Self, RustpenError> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(config.accept_invalid_certs);

        if let Some(ua) = &config.user_agent {
            builder = builder.user_agent(ua);
        }

        if let Some(hdrs) = &config.default_headers {
            builder = builder.default_headers(hdrs.clone());
        }

        let client = builder.build().map_err(|e| RustpenError::NetworkError(e.to_string()))?;

        Ok(Self { client, config, per_host_semaphores: Arc::new(RwLock::new(HashMap::new())), })
    }

    /// 构造一个标准化的 FetchRequest
    pub fn build_request(url: &str) -> FetchRequest {
        FetchRequest {
            url: url.to_string(),
            method: Method::GET,
            headers: None,
            body: None,
            timeout_ms: None,
            max_retries: None,
        }
    }

    /// 抓取 URL 并返回标准结构
    pub async fn fetch(&self, url: &str) -> Result<FetchResponse, RustpenError> {
        let req = FetchRequest {
            url: url.to_string(),
            method: Method::GET,
            headers: None,
            body: None,
            timeout_ms: None,
            max_retries: None,
        };
        // 默认使用 config 中的 max_retries
        self.fetch_with_request(req).await
    }

    /// 使用更灵活的请求结构进行抓取（支持 method/headers/body/timeout/retry）
    /// 使用更灵活的请求结构进行抓取（支持 method/headers/body/timeout/retry）
    ///
    /// 行为说明：
    /// - 如果 `timeout_ms` 被设置，单次请求会在该超时后视为失败并根据 `max_retries` 重试；超时最终会返回 `RustpenError::TargetUnreachable`。
    /// - 对于 HTTP 5xx 响应视为可重试错误；当重试次数耗尽后会返回 `RustpenError::NetworkError`。
    pub async fn fetch_with_request(&self, req: FetchRequest) -> Result<FetchResponse, RustpenError> {
        // 按 host 限流
        let url = req.url.clone();
        let parsed = url::Url::parse(&url).map_err(|e| RustpenError::NetworkError(e.to_string()))?;
        let host = parsed.host_str().ok_or_else(|| RustpenError::NetworkError("no host".to_string()))?.to_string();

        // get or create semaphore for host
        let sem_arc = {
            let mut map = self.per_host_semaphores.write().await;
            map.entry(host.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.per_host_concurrency)))
                .clone()
        };

        // Acquire permit (owned so it's released on drop)
        let _permit = sem_arc.acquire_owned().await.map_err(|e| RustpenError::NetworkError(e.to_string()))?;

        let max_retries = req.max_retries.unwrap_or(self.config.max_retries);
        let mut attempts: u32 = 0;

        loop {
            attempts += 1;

            let mut builder = self.client.request(req.method.clone(), &req.url);
            if let Some(h) = &req.headers {
                builder = builder.headers(h.clone());
            }
            if let Some(b) = &req.body {
                // Bytes implements Into<Body>
                builder = builder.body(b.clone());
            }

            let send_fut = builder.send();
            let res = if let Some(ms) = req.timeout_ms {
                let dur = Duration::from_millis(ms);
                match tokio::time::timeout(dur, send_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        // timeout
                        if attempts > max_retries { return Err(RustpenError::TargetUnreachable{ url: req.url.clone() }); }
                        tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                        continue;
                    }
                }
            } else {
                send_fut.await
            };

            match res {
                Ok(resp) => {
                    // 处理 429 Retry-After（优先）和 5xx
                    if resp.status().as_u16() == 429 {
                        if attempts > max_retries {
                            return Err(RustpenError::NetworkError(format!("too many 429 responses")));
                        }

                        // 尝试解析 Retry-After 头
                        if self.config.honor_retry_after {
                            if let Some(ra) = resp.headers().get("retry-after") {
                                if let Ok(s) = ra.to_str() {
                                    if let Some(dur) = Self::parse_retry_after_seconds_or_date(s) {
                                        tokio::time::sleep(dur).await;
                                        continue;
                                    }
                                }
                            }
                        }

                        // 如果没有可用的 Retry-After，则退回到指数退避
                        let backoff = Self::exponential_backoff_ms(self.config.backoff_base_ms, self.config.backoff_max_ms, attempts);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        continue;
                    }

                    if resp.status().is_server_error() {
                        if attempts > max_retries {
                            return Err(RustpenError::NetworkError(format!("server error {}", resp.status())));
                        }
                        let backoff = Self::exponential_backoff_ms(self.config.backoff_base_ms, self.config.backoff_max_ms, attempts);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                        continue;
                    }

                    return Ok(Self::normalize_response(&req.url, resp).await?);
                }
                Err(e) => {
                    if attempts > max_retries {
                        return Err(RustpenError::NetworkError(e.to_string()));
                    }
                    let backoff = Self::exponential_backoff_ms(self.config.backoff_base_ms, self.config.backoff_max_ms, attempts);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    continue;
                }
            }
        }
    }

    /// 批量并发抓取。返回与传入顺序无关的结果集合（尽快返回完成的任务）
    pub async fn fetch_many<I>(&self, reqs: I, concurrency: usize) -> Vec<Result<FetchResponse, RustpenError>>
    where
        I: IntoIterator<Item = FetchRequest>,
    {
        stream::iter(reqs)
            .map(|r| {
                let this = self.clone();
                async move { this.fetch_with_request(r).await }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await
    }

    async fn normalize_response(url: &str, resp: Response) -> Result<FetchResponse, RustpenError> {
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = resp.bytes().await.map_err(|e| RustpenError::NetworkError(e.to_string()))?;

        Ok(FetchResponse {
            url: url.to_string(),
            status,
            headers,
            body,
        })
    }

    // Helper: exponential backoff calculation. attempts starts at 1 for first try.
    fn exponential_backoff_ms(base: u64, max: u64, attempts: u32) -> u64 {
        // base * 2^(attempts-1)
        let exp = attempts.saturating_sub(1);
        let mul = 1u128.checked_shl(exp).unwrap_or(0) as u128; // safe bound
        let mut backoff = (base as u128).saturating_mul(mul) as u64;
        if backoff == 0 {
            backoff = base;
        }
        std::cmp::min(backoff, max)
    }

    // Helper: parse Retry-After header value (either seconds or HTTP-date). Returns duration from now.
    fn parse_retry_after_seconds_or_date(s: &str) -> Option<std::time::Duration> {
        // try parse as integer seconds
        if let Ok(sec) = s.trim().parse::<u64>() {
            return Some(std::time::Duration::from_secs(sec));
        }

        // try parse as HTTP-date
        if let Ok(t) = httpdate::parse_http_date(s) {
            let now = std::time::SystemTime::now();
            if t > now {
                if let Ok(dur) = t.duration_since(now) {
                    return Some(dur);
                }
            } else {
                return Some(std::time::Duration::from_secs(0));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;

    #[tokio::test]
    async fn fetcher_gets_body_and_headers() {
        // 启动一个本地 warp 服务
        let route = warp::path::end().map(|| warp::reply::with_header("ok", "x-test", "1"));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);

        let cfg = FetcherConfig { timeout: Duration::from_secs(2), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 };
        let fetcher = Fetcher::new(cfg).unwrap();

        let resp = fetcher.fetch(&url).await.unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.headers.iter().any(|(k, v)| k.to_lowercase() == "x-test" && v == "1"));
        assert_eq!(resp.body, Bytes::from_static(b"ok"));
    }

    #[tokio::test]
    async fn fetch_many_respects_per_host_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let cur = current.clone();
        let mx = max_seen.clone();
        // handler increments current concurrency, records max, sleeps, then decrements
        let route = warp::any().and_then(move || {
            let cur = cur.clone();
            let mx = mx.clone();
            async move {
                let v = cur.fetch_add(1, Ordering::SeqCst) + 1;
                // update max
                loop {
                    let prev = mx.load(Ordering::SeqCst);
                    if v <= prev { break; }
                    if mx.compare_exchange(prev, v, Ordering::SeqCst, Ordering::SeqCst).is_ok() { break; }
                }
                // sleep to force overlap
                tokio::time::sleep(Duration::from_millis(200)).await;
                cur.fetch_sub(1, Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
            }
        });

        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);
        let cfg = FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 };
        let fetcher = Fetcher::new(cfg).unwrap();

        // create 6 requests to same host
        let mut reqs = Vec::new();
        for _ in 0..6 {
            reqs.push(Fetcher::build_request(&url));
        }

        let results = fetcher.fetch_many(reqs, 6).await;
        // all should be ok
        assert_eq!(results.len(), 6);
        assert!(results.iter().all(|r| r.is_ok()));

        // max concurrent observed should be <= per_host_concurrency
        let mv = max_seen.load(Ordering::SeqCst);
        assert!(mv <= 2, "max concurrent seen {} exceeds per-host limit", mv);
    }
}
