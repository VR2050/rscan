// Additional tests for Fetcher: timeout and retry

#[cfg(test)]
mod extra {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[tokio::test]
    async fn fetch_respects_timeout_ms_and_returns_target_unreachable() {
        // server that delays response
        let route = warp::path::end().and_then(|| async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            Ok::<_, std::convert::Infallible>(warp::reply::with_status("slow", warp::http::StatusCode::OK))
        });

        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);
        let cfg = FetcherConfig { timeout: std::time::Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 1, backoff_max_ms: 10 };
        let fetcher = Fetcher::new(cfg).unwrap();

        let mut req = FetchRequest::build(&url);
        req.timeout_ms = Some(100); // 100ms timeout
        let err = fetcher.fetch_with_request(req).await.unwrap_err();
        match err {
            crate::errors::RustpenError::TargetUnreachable{ url: _ } => {},
            _ => panic!("expected TargetUnreachable on timeout"),
        }
    }

    #[tokio::test]
    async fn fetch_retries_on_5xx_and_succeeds() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();

        let route = warp::path::end().and_then(move || {
            let c = c.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // first request -> server error
                    Ok::<_, std::convert::Infallible>(warp::reply::with_status("err", warp::http::StatusCode::INTERNAL_SERVER_ERROR))
                } else {
                    // second request -> ok
                    Ok::<_, std::convert::Infallible>(warp::reply::with_status("ok", warp::http::StatusCode::OK))
                }
            }
        });

        let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
        tokio::spawn(server);

        let url = format!("http://{}", addr);
        let cfg = FetcherConfig { timeout: std::time::Duration::from_secs(5), user_agent: None, max_retries: 1, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 1, backoff_max_ms: 10 };
        let fetcher = Fetcher::new(cfg).unwrap();

        let req = FetchRequest::build(&url);
        let res = fetcher.fetch_with_request(req).await.unwrap();
        assert_eq!(res.status, 200);

        // ensure the server was hit at least twice
        assert!(counter.load(Ordering::SeqCst) >= 2);
    }
}
