// Additional higher-level tests for modules web_scan
#[cfg(test)]
mod tests {
    use crate::modules::web_scan::{run_dir_scan, run_fuzz_scan, run_subdomain_burst, ModuleScanConfig};
    use std::time::Duration;
    use warp::Filter;

    #[tokio::test]
    async fn dns_burst_filters_status() {
        let good = warp::path!(String).map(|_| warp::reply::with_status("ok", warp::http::StatusCode::OK));
        let bad = warp::path!("bad").map(|| warp::reply::with_status("no", warp::http::StatusCode::NOT_FOUND));
        let (addr, server) = warp::serve(good.or(bad)).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("{}", addr);

        let cfg = ModuleScanConfig { fetcher: crate::cores::web_en::FetcherConfig { timeout: Duration::from_secs(5), user_agent: None, max_retries: 0, accept_invalid_certs: false, per_host_concurrency: 2, default_headers: None, honor_retry_after: true, backoff_base_ms: 100, backoff_max_ms: 10_000 }, concurrency: 5, timeout_ms: Some(2000), max_retries: Some(0), status_min: Some(200), status_max: Some(299) };
        let words = vec!["bad", ""];
        let res = run_subdomain_burst(&base, &words, cfg).await.unwrap();
        // only the empty (root) should be considered healthy
        assert!(res.iter().all(|u| !u.contains("bad")));
    }
}