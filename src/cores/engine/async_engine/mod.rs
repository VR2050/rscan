use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, timeout};

use crate::cores::host::Protocol;
use crate::errors::RustpenError;
use crate::services::service_probe::{ProbeProtocol, ServiceProbeEngine};

use super::engine_trait::ScanEngine;
use super::scan_job::{ScanJob, ScanType};
use super::scan_result::{ScanResult, ScanStatus};

pub struct AsyncConnectEngine {
    tx: mpsc::Sender<ScanJob>,
    rx: Option<mpsc::Receiver<ScanResult>>,
    probe_engine: Option<Arc<ServiceProbeEngine>>,
}

impl AsyncConnectEngine {
    pub fn new(queue_size: usize, worker_count: usize) -> Self {
        Self::new_with_probe(queue_size, worker_count, None)
    }

    pub fn new_with_probe(
        queue_size: usize,
        worker_count: usize,
        probe_engine: Option<Arc<ServiceProbeEngine>>,
    ) -> Self {
        let (job_tx, job_rx) = mpsc::channel::<ScanJob>(queue_size.max(1));
        let (res_tx, res_rx) = mpsc::channel::<ScanResult>(queue_size.max(1));
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let workers = worker_count.max(1);

        for _ in 0..workers {
            let shared_rx = Arc::clone(&shared_rx);
            let res_tx = res_tx.clone();
            let probe_engine = probe_engine.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut guard = shared_rx.lock().await;
                        guard.recv().await
                    };

                    let Some(job) = job else {
                        break;
                    };
                    let mut result = execute_async_job(job, probe_engine.as_deref()).await;
                    if let Some(probe) = &probe_engine {
                        result = probe.enrich_scan_result(result);
                    }
                    if res_tx.send(result).await.is_err() {
                        break;
                    }
                }
            });
        }
        drop(res_tx);

        Self {
            tx: job_tx,
            rx: Some(res_rx),
            probe_engine,
        }
    }

    pub fn set_probe_engine(&mut self, probe_engine: Arc<ServiceProbeEngine>) {
        self.probe_engine = Some(probe_engine);
    }
}

impl Default for AsyncConnectEngine {
    fn default() -> Self {
        Self::new(1024, 64)
    }
}

impl ScanEngine for AsyncConnectEngine {
    fn name(&self) -> &str {
        "async-connect-engine"
    }

    fn submit(&self, job: ScanJob) -> Result<(), RustpenError> {
        self.tx
            .try_send(job)
            .map_err(|e| RustpenError::Generic(format!("submit failed: {e}")))
    }

    fn take_results(&mut self) -> Result<mpsc::Receiver<ScanResult>, RustpenError> {
        self.rx.take().ok_or(RustpenError::ResultsReceiverTaken)
    }
}

async fn execute_async_job(job: ScanJob, probe_engine: Option<&ServiceProbeEngine>) -> ScanResult {
    match job.scan_type {
        ScanType::Connect => scan_connect(job, probe_engine).await,
        ScanType::UdpProbe => scan_udp(job, false).await,
        ScanType::Dns => scan_udp(job, true).await,
        _ => ScanResult::new(job.target_ip, job.protocol, ScanStatus::Unknown)
            .with_port(job.port.unwrap_or_default())
            .with_meta("engine", "async")
            .with_meta("reason", "unsupported_scan_type"),
    }
}

fn select_tcp_probe_candidates(
    probe_engine: &ServiceProbeEngine,
    port: u16,
) -> Vec<(String, Vec<u8>)> {
    let mut picks = probe_engine
        .probes()
        .iter()
        .filter(|probe| probe.protocol == ProbeProtocol::Tcp && !probe.payload.is_empty())
        .filter_map(|probe| {
            let on_port = probe.ports.is_empty() || probe.ports.binary_search(&port).is_ok();
            on_port.then_some((
                probe.name.clone(),
                probe.rarity.unwrap_or(9),
                probe.payload.clone(),
            ))
        })
        .collect::<Vec<_>>();
    picks.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.len().cmp(&b.2.len())));
    picks
        .into_iter()
        .take(4)
        .map(|(name, _, payload)| (name, payload))
        .collect()
}

async fn active_probe_tcp_response(
    addr: SocketAddr,
    timeout_ms: u64,
    candidates: &[(String, Vec<u8>)],
) -> Option<(String, Vec<u8>)> {
    if candidates.is_empty() {
        return None;
    }
    let connect_budget = Duration::from_millis(timeout_ms.max(1));
    let write_budget = Duration::from_millis(220.min(timeout_ms.max(1)));
    let read_budget = Duration::from_millis(300.min(timeout_ms.max(1)));
    for (name, payload) in candidates {
        let Ok(Ok(mut stream)) = timeout(connect_budget, TcpStream::connect(addr)).await else {
            continue;
        };
        if timeout(write_budget, stream.write_all(payload))
            .await
            .is_err()
        {
            continue;
        }
        let mut buf = vec![0u8; 1024];
        if let Ok(Ok(n)) = timeout(read_budget, stream.read(&mut buf)).await
            && n > 0
        {
            buf.truncate(n);
            return Some((name.clone(), buf));
        }
    }
    None
}

async fn scan_connect(job: ScanJob, probe_engine: Option<&ServiceProbeEngine>) -> ScanResult {
    let Some(port) = job.port else {
        return ScanResult::new(job.target_ip, job.protocol, ScanStatus::Error)
            .with_meta("error", "missing_port");
    };

    let addr = SocketAddr::new(job.target_ip, port);
    const CONNECT_BANNER_READ_MS: u64 = 120;
    for attempt in 0..=job.retries {
        let start = Instant::now();
        let fut = TcpStream::connect(addr);
        match timeout(Duration::from_millis(job.timeout_ms), fut).await {
            Ok(Ok(mut stream)) => {
                let mut out = ScanResult::new(job.target_ip, Protocol::Tcp, ScanStatus::Open)
                    .with_port(port)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_meta("attempt", attempt.to_string())
                    .with_meta("engine", "async");
                let mut buf = vec![0u8; 512];
                if let Ok(Ok(n)) = timeout(
                    Duration::from_millis(CONNECT_BANNER_READ_MS.min(job.timeout_ms.max(1))),
                    stream.read(&mut buf),
                )
                .await
                    && n > 0
                {
                    buf.truncate(n);
                    out = out.with_response(buf);
                }
                // Release the initial connect socket before optional active probing to avoid
                // head-of-line blocking on single-threaded services.
                drop(stream);
                if out.response.is_none()
                    && let Some(engine) = probe_engine
                {
                    let candidates = select_tcp_probe_candidates(engine, port);
                    if let Some((probe_name, resp)) =
                        active_probe_tcp_response(addr, job.timeout_ms, &candidates).await
                    {
                        out = out.with_response(resp).with_meta("probe", probe_name);
                    }
                }
                return out;
            }
            Ok(Err(e)) => {
                if attempt == job.retries {
                    let status = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        ScanStatus::Closed
                    } else {
                        ScanStatus::Filtered
                    };
                    return ScanResult::new(job.target_ip, Protocol::Tcp, status)
                        .with_port(port)
                        .with_meta("attempt", attempt.to_string())
                        .with_meta("error", e.to_string())
                        .with_meta("engine", "async");
                }
            }
            Err(_) => {
                if attempt == job.retries {
                    return ScanResult::new(job.target_ip, Protocol::Tcp, ScanStatus::Filtered)
                        .with_port(port)
                        .with_meta("attempt", attempt.to_string())
                        .with_meta("error", "timeout")
                        .with_meta("engine", "async");
                }
            }
        }
        if attempt < job.retries
            && let Some(d) = job.retry_delay_ms
        {
            tokio::time::sleep(Duration::from_millis(d.max(1))).await;
        }
    }

    ScanResult::new(job.target_ip, Protocol::Tcp, ScanStatus::Error)
        .with_port(port)
        .with_meta("error", "unreachable")
}

async fn scan_udp(job: ScanJob, is_dns: bool) -> ScanResult {
    let Some(port) = job.port else {
        return ScanResult::new(
            job.target_ip,
            if is_dns { Protocol::Dns } else { job.protocol },
            ScanStatus::Error,
        )
        .with_meta("error", "missing_port");
    };

    let addr = SocketAddr::new(job.target_ip, port);
    let bind_addr = if job.target_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let payload = job.payload.clone().unwrap_or_else(|| vec![0x00]);

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            return ScanResult::new(
                job.target_ip,
                if is_dns { Protocol::Dns } else { Protocol::Udp },
                ScanStatus::Error,
            )
            .with_port(port)
            .with_meta("error", e.to_string())
            .with_meta("engine", "async");
        }
    };

    for attempt in 0..=job.retries {
        let start = Instant::now();
        match timeout(
            Duration::from_millis(job.timeout_ms),
            socket.send_to(&payload, addr),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                if attempt == job.retries {
                    return ScanResult::new(
                        job.target_ip,
                        if is_dns { Protocol::Dns } else { Protocol::Udp },
                        ScanStatus::Error,
                    )
                    .with_port(port)
                    .with_meta("attempt", attempt.to_string())
                    .with_meta("error", e.to_string())
                    .with_meta("engine", "async");
                }
                continue;
            }
            Err(_) => {
                if attempt == job.retries {
                    return ScanResult::new(
                        job.target_ip,
                        if is_dns { Protocol::Dns } else { Protocol::Udp },
                        ScanStatus::Filtered,
                    )
                    .with_port(port)
                    .with_meta("attempt", attempt.to_string())
                    .with_meta("error", "timeout_on_send")
                    .with_meta("engine", "async");
                }
                continue;
            }
        }

        let mut buf = vec![0u8; 1500];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(job.timeout_ms);
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                if attempt == job.retries {
                    return ScanResult::new(
                        job.target_ip,
                        if is_dns { Protocol::Dns } else { Protocol::Udp },
                        ScanStatus::Filtered,
                    )
                    .with_port(port)
                    .with_meta("attempt", attempt.to_string())
                    .with_meta("error", "timeout_on_recv")
                    .with_meta("engine", "async");
                }
                break;
            }

            let remaining = deadline.saturating_duration_since(now);
            match timeout(remaining, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    if from.ip() != addr.ip() || from.port() != addr.port() {
                        continue;
                    }
                    buf.truncate(n);
                    return ScanResult::new(
                        job.target_ip,
                        if is_dns { Protocol::Dns } else { Protocol::Udp },
                        ScanStatus::Open,
                    )
                    .with_port(port)
                    .with_latency_ms(start.elapsed().as_millis() as u64)
                    .with_response(buf)
                    .with_meta("attempt", attempt.to_string())
                    .with_meta("engine", "async");
                }
                Ok(Err(e)) => {
                    if attempt == job.retries {
                        return ScanResult::new(
                            job.target_ip,
                            if is_dns { Protocol::Dns } else { Protocol::Udp },
                            ScanStatus::Error,
                        )
                        .with_port(port)
                        .with_meta("attempt", attempt.to_string())
                        .with_meta("error", e.to_string())
                        .with_meta("engine", "async");
                    }
                    break;
                }
                Err(_) => {
                    if attempt == job.retries {
                        return ScanResult::new(
                            job.target_ip,
                            if is_dns { Protocol::Dns } else { Protocol::Udp },
                            ScanStatus::Filtered,
                        )
                        .with_port(port)
                        .with_meta("attempt", attempt.to_string())
                        .with_meta("error", "timeout_on_recv")
                        .with_meta("engine", "async");
                    }
                    break;
                }
            }
        }
        if attempt < job.retries
            && let Some(d) = job.retry_delay_ms
        {
            tokio::time::sleep(Duration::from_millis(d.max(1))).await;
        }
    }

    ScanResult::new(
        job.target_ip,
        if is_dns { Protocol::Dns } else { Protocol::Udp },
        ScanStatus::Error,
    )
    .with_port(port)
    .with_meta("error", "unreachable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::engine_trait::ScanEngine;
    use crate::services::service_probe::ServiceProbeEngine;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn async_engine_connect_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut engine = AsyncConnectEngine::new(16, 2);
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            Protocol::Tcp,
            ScanType::Connect,
        )
        .with_port(port)
        .with_timeout_ms(500);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert_eq!(res.status, ScanStatus::Open);
        assert_eq!(res.port, Some(port));
    }

    #[tokio::test]
    async fn async_engine_udp_open_port() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((n, addr)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(&buf[..n], addr).await;
            }
        });

        let mut engine = AsyncConnectEngine::new(16, 2);
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            Protocol::Udp,
            ScanType::UdpProbe,
        )
        .with_port(port)
        .with_payload(vec![0xAA, 0xBB])
        .with_timeout_ms(500);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert_eq!(res.status, ScanStatus::Open);
        assert_eq!(res.port, Some(port));
        assert_eq!(res.response, Some(vec![0xAA, 0xBB]));
    }

    #[tokio::test]
    async fn async_engine_probe_enriches_service_metadata() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok((_n, addr)) = server.recv_from(&mut buf).await {
                let _ = server.send_to(b"HTTP/1.1 200 OK\r\n\r\n", addr).await;
            }
        });

        let probe_text = r#"
match http m|^HTTP/1\.[01] \d\d\d|
"#;
        let probe = Arc::new(ServiceProbeEngine::from_nmap_text(probe_text).unwrap());
        let mut engine = AsyncConnectEngine::new_with_probe(16, 2, Some(probe));
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            Protocol::Udp,
            ScanType::UdpProbe,
        )
        .with_port(port)
        .with_payload(vec![0x01])
        .with_timeout_ms(700);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert!(
            res.metadata
                .iter()
                .any(|(k, v)| k == "service" && v == "http")
        );
    }

    #[tokio::test]
    async fn async_engine_connect_captures_banner_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"SSH-2.0-rscan\r\n").await;
            }
        });

        let mut engine = AsyncConnectEngine::new(16, 2);
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            Protocol::Tcp,
            ScanType::Connect,
        )
        .with_port(port)
        .with_timeout_ms(800);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert_eq!(res.status, ScanStatus::Open);
        assert_eq!(res.port, Some(port));
        assert!(
            res.response
                .as_ref()
                .is_some_and(|bytes| bytes.starts_with(b"SSH-2.0"))
        );
    }

    #[tokio::test]
    async fn async_engine_connect_active_probe_enriches_http_service() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf).await
                    && n > 0
                    && buf[..n].starts_with(b"GET / HTTP/1.0")
                {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                }
            }
        });

        let probe_text = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d\d\d|
"#;
        let probe = Arc::new(ServiceProbeEngine::from_nmap_text(probe_text).unwrap());
        let mut engine = AsyncConnectEngine::new_with_probe(16, 2, Some(probe));
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            Protocol::Tcp,
            ScanType::Connect,
        )
        .with_port(port)
        .with_timeout_ms(800);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert_eq!(res.status, ScanStatus::Open);
        assert!(
            res.metadata
                .iter()
                .any(|(k, v)| k == "service" && v == "http")
        );
    }
}
