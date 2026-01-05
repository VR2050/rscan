// Tests for Retry-After handling

#[cfg(test)]
mod retry_after_tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[tokio::test]
    async fn fetch_honors_retry_after_seconds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();

        let route = warp::path::end().and_then(move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // first request -> 429 with Retry-After: 0
                    let mut rep = warp::reply::with_status("too many", warp::http::StatusCode::TOO_MANY_REQUESTS).into_response();
                    rep.headers_mut().insert("retry-after", warp::http::header::HeaderValue::from_static("0"));
                    Ok::<_, std::convert::Infallible>(rep)
                } else {
                    // second request -> ok
                    Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
                }
            }
        });

        let (addr, server) = warp::serve(route).bind_ephemeral(([127,0,0,1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);
        let cfg = FetcherConfig { timeout: std::time::Duration::from_secs(5), user_agent: None, max_retries: 1, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 1, backoff_max_ms: 10 };
        let fetcher = Fetcher::new(cfg).unwrap();

        let req = FetchRequest::build(&url);
        let res = fetcher.fetch_with_request(req).await.unwrap();
        assert_eq!(res.status, 200);
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn fetch_honors_retry_after_date() {
        use httpdate::fmt_http_date;
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();

        let route = warp::path::end().and_then(move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // set Retry-After to now + 1 second
                    let when = std::time::SystemTime::now() + std::time::Duration::from_secs(1);
                    let mut rep = warp::reply::with_status("wait", warp::http::StatusCode::TOO_MANY_REQUESTS).into_response();
                    rep.headers_mut().insert("retry-after", warp::http::header::HeaderValue::from_str(&fmt_http_date(when)).unwrap());
                    Ok::<_, std::convert::Infallible>(rep)
                } else {
                    Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
                }
            }
        });

        let (addr, server) = warp::serve(route).bind_ephemeral(([127,0,0,1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);
        let cfg = FetcherConfig { timeout: std::time::Duration::from_secs(5), user_agent: None, max_retries: 1, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 1, backoff_max_ms: 10 };
        let fetcher = Fetcher::new(cfg).unwrap();

        let req = FetchRequest::build(&url);
        let before = std::time::Instant::now();
        let res = fetcher.fetch_with_request(req).await.unwrap();
        let elapsed = before.elapsed();
        assert_eq!(res.status, 200);
        // elapsed should be at least ~1 second (allow small slack)
        assert!(elapsed >= std::time::Duration::from_millis(900));
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }
}
