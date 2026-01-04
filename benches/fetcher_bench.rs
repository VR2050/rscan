use criterion::{criterion_group, criterion_main, Criterion};
use rscan::cores::web_en::fetcher::{Fetcher, FetcherConfig};
use std::time::Duration;
use warp::Filter;

fn bench_fetch(c: &mut Criterion) {
    // start a small warp server
    let route = warp::path::end().map(|| "ok");
    let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(server);
    });

    let url = format!("http://{}", addr);
    let cfg = FetcherConfig::default();
    let fetcher = Fetcher::new(cfg).unwrap();

    let bench_rt = tokio::runtime::Runtime::new().unwrap();
    let fetcher_clone = fetcher.clone();
    let url_clone = url.clone();
    c.bench_function("fetch_simple", |b| {
        b.iter(|| {
            let fetcher = fetcher_clone.clone();
            let url = url_clone.clone();
            bench_rt.block_on(async move {
                let _ = fetcher.fetch(&url).await.unwrap();
            })
        })
    });
}

criterion_group!(benches, bench_fetch);
criterion_main!(benches);
