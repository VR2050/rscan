#[cfg(test)]
mod tests {
    use crate::modules::web_scan::ModuleScanResult;
    use crate::modules::web_scan::ModuleScanConfig;
    use crate::modules::web_scan::run_dir_scan_with_callback;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[tokio::test]
    async fn dir_scan_callback_invoked() {
        // simple server
        let route = warp::path::end().map(|| warp::reply::html("<a href=\"/a\">a</a>"));
        let (addr, server) = warp::serve(route).bind_ephemeral(([127,0,0,1],0));
        tokio::spawn(server);
        let base = format!("http://{}", addr);

        let called = Arc::new(AtomicUsize::new(0));
        let called2 = called.clone();
        let cb = move |_r: ModuleScanResult| { called2.fetch_add(1, Ordering::SeqCst); };

        let cfg = ModuleScanConfig::default();
        let handle = run_dir_scan_with_callback(&base, vec!["/a".to_string()], cfg, cb);
        let _ = handle.await; // wait for background task to finish

        assert!(called.load(Ordering::SeqCst) > 0);
    }
}