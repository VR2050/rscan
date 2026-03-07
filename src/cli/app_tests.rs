use super::*;
use std::env;
use std::fs;
use tokio::net::{TcpListener, UdpSocket};

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[tokio::test]
async fn cli_host_tcp_writes_output_file() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let tmp = env::temp_dir().join(format!("rscan_cli_tcp_{}.out", port));
    let port_str = port.to_string();
    let tmp_str = tmp.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "host",
        "tcp",
        "--host",
        "127.0.0.1",
        "--ports",
        &port_str,
        "--output",
        "json",
        "--out",
        &tmp_str,
    ];
    run_from_args(args).await.unwrap();
    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("\"open_ports\""));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_host_udp_writes_output_file() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
            let _ = socket.send_to(&buf[..len], &addr).await;
        }
    });

    let tmp = env::temp_dir().join(format!("rscan_cli_udp_{}.out", port));
    let port_str = port.to_string();
    let tmp_str = tmp.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "host",
        "udp",
        "--host",
        "127.0.0.1",
        "--ports",
        &port_str,
        "--output",
        "json",
        "--out",
        &tmp_str,
    ];
    run_from_args(args).await.unwrap();
    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("\"open_ports\""));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_host_syn_writes_output_file() {
    if !is_root() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let tmp = env::temp_dir().join(format!("rscan_cli_syn_{}.out", port));
    let port_str = port.to_string();
    let tmp_str = tmp.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "host",
        "syn",
        "--host",
        "127.0.0.1",
        "--ports",
        &port_str,
        "--output",
        "json",
        "--out",
        &tmp_str,
    ];
    run_from_args(args).await.unwrap();
    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("\"open_ports\""));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_host_quick_returns_ok() {
    let tmp = env::temp_dir().join("rscan_cli_quick.out");
    let tmp_str = tmp.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "host",
        "quick",
        "--host",
        "127.0.0.1",
        "--output",
        "json",
        "--out",
        &tmp_str,
    ];
    run_from_args(args).await.unwrap();
    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("\"open_ports_count\""));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_concurrent_run_from_args_initialization_is_safe() {
    use std::ffi::OsString;
    // Spawn two concurrent invocations which both initialize tracing via try_init()
    let tmp1 = env::temp_dir().join("rscan_cli_concur1.out");
    let tmp2 = env::temp_dir().join("rscan_cli_concur2.out");
    let tmp1_os = tmp1.as_os_str().to_os_string();
    let tmp2_os = tmp2.as_os_str().to_os_string();
    let args1: Vec<OsString> = vec![
        "rscan".into(),
        "--log-level".into(),
        "info".into(),
        "host".into(),
        "quick".into(),
        "--host".into(),
        "127.0.0.1".into(),
        "--output".into(),
        "json".into(),
        "--out".into(),
        tmp1_os,
    ];
    let args2: Vec<OsString> = vec![
        "rscan".into(),
        "--log-level".into(),
        "info".into(),
        "host".into(),
        "quick".into(),
        "--host".into(),
        "127.0.0.1".into(),
        "--output".into(),
        "json".into(),
        "--out".into(),
        tmp2_os,
    ];
    let j1 = tokio::spawn(async move { run_from_args(args1).await });
    let j2 = tokio::spawn(async move { run_from_args(args2).await });
    let r1 = j1.await.unwrap();
    let r2 = j2.await.unwrap();
    assert!(r1.is_ok());
    assert!(r2.is_ok());
    let _ = fs::remove_file(tmp1);
    let _ = fs::remove_file(tmp2);
}

#[tokio::test]
async fn cli_service_detect_requires_probes_file() {
    let args = vec![
        "rscan",
        "host",
        "udp",
        "--host",
        "127.0.0.1",
        "--ports",
        "53",
        "--service-detect",
    ];
    let err = run_from_args(args).await.unwrap_err();
    assert!(format!("{err}").contains("--service-detect requires --probes-file"));
}

#[tokio::test]
async fn cli_host_ports_range_is_supported() {
    let tmp = env::temp_dir().join("rscan_cli_range.out");
    let tmp_str = tmp.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "host",
        "tcp",
        "--host",
        "127.0.0.1",
        "--ports",
        "1-2",
        "--output",
        "json",
        "--out",
        &tmp_str,
    ];
    run_from_args(args).await.unwrap();
    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("\"total_scanned\":2"));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_fuzz_summary_writes_cluster_lines() {
    let tmp = env::temp_dir().join("rscan_cli_fuzz_summary.out");
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(Ok(ModuleScanResult {
        url: "http://x/a".to_string(),
        status: 404,
        content_len: Some(100),
    }))
    .await
    .unwrap();
    tx.send(Ok(ModuleScanResult {
        url: "http://x/b".to_string(),
        status: 404,
        content_len: Some(100),
    }))
    .await
    .unwrap();
    tx.send(Ok(ModuleScanResult {
        url: "http://x/c".to_string(),
        status: 200,
        content_len: Some(20),
    }))
    .await
    .unwrap();
    drop(tx);

    consume_module_stream_with_summary(
        rx,
        Some(tmp.clone()),
        OutputFormat::Raw,
        None,
        Some(3),
        "web.fuzz",
        2,
    )
    .await
    .unwrap();

    let s = tokio::fs::read_to_string(&tmp).await.unwrap();
    assert!(s.contains("summary clusters=2 shown=2 errors=0"));
    assert!(s.contains("cluster status=404 content_len=100 count=2"));
    assert!(s.contains("cluster status=200 content_len=20 count=1"));
    let _ = fs::remove_file(&tmp);
}

#[tokio::test]
async fn cli_web_fuzz_preset_and_keywords_file_work() {
    use warp::Filter;

    let route = warp::path!(String)
        .map(|s: String| warp::reply::with_status(format!("ok:{s}"), warp::http::StatusCode::OK));
    let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
    tokio::spawn(server);
    let base = format!("http://{}", addr);

    let kw_file = env::temp_dir().join(format!("rscan_kw_{}.txt", addr.port()));
    let out_file = env::temp_dir().join(format!("rscan_cli_fuzz_{}.out", addr.port()));
    fs::write(&kw_file, "A B\n").unwrap();

    let base_url = format!("{}/FUZZ", base);
    let kw_path = kw_file.to_str().unwrap().to_string();
    let out_path = out_file.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "web",
        "fuzz",
        "--url",
        &base_url,
        "--keywords",
        "root",
        "--keywords-file",
        &kw_path,
        "--preset",
        "api",
        "--summary",
        "--summary-top",
        "3",
        "--stream-to",
        &out_path,
        "--output",
        "raw",
    ];
    run_from_args(args).await.unwrap();

    let s = tokio::fs::read_to_string(&out_file).await.unwrap();
    assert!(s.contains("/api/root"));
    assert!(s.contains("A%20B"));
    assert!(s.contains("summary clusters="));
    let _ = fs::remove_file(&kw_file);
    let _ = fs::remove_file(&out_file);
}

#[tokio::test]
async fn cli_web_dns_words_file_works() {
    use warp::Filter;

    let route = warp::any().map(|| warp::reply::with_status("ok", warp::http::StatusCode::OK));
    let (addr, server) = warp::serve(route).bind_ephemeral(([127, 0, 0, 1], 0));
    tokio::spawn(server);

    let domain = format!("127.0.0.1:{}", addr.port());
    let words_file = env::temp_dir().join(format!("rscan_dns_words_{}.txt", addr.port()));
    let out_file = env::temp_dir().join(format!("rscan_dns_out_{}.out", addr.port()));
    fs::write(&words_file, "a\nb\n").unwrap();

    let words_path = words_file.to_str().unwrap().to_string();
    let out_path = out_file.to_str().unwrap().to_string();
    let args = vec![
        "rscan",
        "web",
        "dns",
        "--domain",
        &domain,
        "--words",
        "a",
        "--words-file",
        &words_path,
        "--stream-to",
        &out_path,
        "--output",
        "raw",
    ];
    run_from_args(args).await.unwrap();

    let s = tokio::fs::read_to_string(&out_file).await.unwrap();
    assert!(s.contains("a.127.0.0.1"));
    assert!(s.contains("b.127.0.0.1"));
    let _ = fs::remove_file(&words_file);
    let _ = fs::remove_file(&out_file);
}

#[test]
fn fuzz_keyword_transforms_expand_and_dedupe() {
    let words = vec!["Admin".to_string(), "a b".to_string(), "Admin".to_string()];
    let out = build_fuzz_keywords(
        words,
        &[
            FuzzKeywordTransform::Raw,
            FuzzKeywordTransform::Lower,
            FuzzKeywordTransform::UrlEncode,
        ],
        Some("p-".to_string()),
        Some("-s".to_string()),
        Some(64),
    );
    assert!(out.iter().any(|x| x == "p-Admin-s"));
    assert!(out.iter().any(|x| x == "p-admin-s"));
    assert!(out.iter().any(|x| x == "p-a%20b-s"));
    assert!(out.len() >= 3);
}

#[test]
fn fuzz_keyword_max_len_filters_long_entries() {
    let out = build_fuzz_keywords(
        vec!["abc".to_string()],
        &[FuzzKeywordTransform::Raw],
        Some("prefix-".to_string()),
        Some("-suffix".to_string()),
        Some(8),
    );
    assert!(out.is_empty());
}

#[test]
fn fuzz_preset_expands_keywords() {
    let out = expand_keywords_with_preset(vec!["admin".to_string()], Some(FuzzPreset::Api));
    assert!(out.iter().any(|x| x == "admin"));
    assert!(out.iter().any(|x| x == "api/admin"));
    assert!(out.iter().any(|x| x == "admin.json"));
}

#[test]
fn fuzz_preset_defaults_are_not_empty() {
    let t = preset_default_transforms(FuzzPreset::Param);
    assert!(!t.is_empty());
}
