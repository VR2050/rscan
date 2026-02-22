use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, Semaphore, mpsc};

use crate::errors::RustpenError;
use crate::services::service_probe::ServiceProbeEngine;

use super::engine_trait::ScanEngine;
use super::scan_job::{ScanJob, ScanType};
use super::scan_result::{ScanResult, ScanStatus};

mod backends;
mod core;
mod methods;
mod util;

use backends::hub::RawPacketHub;
use backends::icmp::IcmpBackend;
use backends::syn::SynBackend;
use backends::udp::UdpBackend;
use core::{FlowKey, FlowScanType, RawEngineState, spawn_cleanup_task};

#[derive(Debug, Clone)]
pub struct RawEnginePolicy {
    /// Maximum jobs per target during one engine run.
    pub max_jobs_per_target: Option<u64>,
    /// Maximum wall-clock time budget per target (milliseconds) during one engine run.
    pub max_target_runtime_ms: Option<u64>,
    /// Base inter-job delay per target in milliseconds.
    pub base_delay_ms: u64,
    /// Maximum adaptive delay per target in milliseconds.
    pub max_delay_ms: u64,
    /// Add this delay when timeout-like/failed outcomes are observed.
    pub failure_delay_step_ms: u64,
    /// Subtract this delay after successful outcomes.
    pub success_delay_step_ms: u64,
}

impl Default for RawEnginePolicy {
    fn default() -> Self {
        Self {
            max_jobs_per_target: None,
            max_target_runtime_ms: None,
            base_delay_ms: 0,
            max_delay_ms: 400,
            failure_delay_step_ms: 15,
            success_delay_step_ms: 5,
        }
    }
}

#[derive(Debug, Clone)]
struct TargetControl {
    started_at: Instant,
    jobs_started: u64,
    jobs_completed: u64,
    current_delay_ms: u64,
}

#[derive(Clone)]
struct AdaptiveControl {
    policy: RawEnginePolicy,
    targets: Arc<Mutex<HashMap<IpAddr, TargetControl>>>,
}

impl AdaptiveControl {
    fn new(policy: RawEnginePolicy) -> Self {
        Self {
            policy,
            targets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn preflight(&self, target: IpAddr) -> Result<u64, &'static str> {
        let mut guard = self.targets.lock().await;
        let entry = guard.entry(target).or_insert_with(|| TargetControl {
            started_at: Instant::now(),
            jobs_started: 0,
            jobs_completed: 0,
            current_delay_ms: self.policy.base_delay_ms,
        });

        if let Some(max_jobs) = self.policy.max_jobs_per_target
            && entry.jobs_started >= max_jobs
        {
            return Err("target_job_budget_exceeded");
        }
        if let Some(max_ms) = self.policy.max_target_runtime_ms
            && entry.started_at.elapsed().as_millis() as u64 >= max_ms
        {
            return Err("target_runtime_budget_exceeded");
        }

        entry.jobs_started += 1;
        Ok(entry.current_delay_ms)
    }

    async fn postflight(&self, target: IpAddr, status: ScanStatus) -> u64 {
        let mut guard = self.targets.lock().await;
        let entry = guard.entry(target).or_insert_with(|| TargetControl {
            started_at: Instant::now(),
            jobs_started: 0,
            jobs_completed: 0,
            current_delay_ms: self.policy.base_delay_ms,
        });
        entry.jobs_completed += 1;

        match status {
            ScanStatus::Open | ScanStatus::Closed => {
                entry.current_delay_ms = entry
                    .current_delay_ms
                    .saturating_sub(self.policy.success_delay_step_ms);
                if entry.current_delay_ms < self.policy.base_delay_ms {
                    entry.current_delay_ms = self.policy.base_delay_ms;
                }
            }
            ScanStatus::Filtered | ScanStatus::Error | ScanStatus::Unknown => {
                entry.current_delay_ms = (entry.current_delay_ms
                    + self.policy.failure_delay_step_ms)
                    .min(self.policy.max_delay_ms.max(self.policy.base_delay_ms));
            }
        }
        entry.current_delay_ms
    }

    async fn snapshot(&self, target: IpAddr) -> Option<TargetControl> {
        self.targets.lock().await.get(&target).cloned()
    }
}

pub struct RawPacketEngine {
    tx: mpsc::Sender<ScanJob>,
    rx: Option<mpsc::Receiver<ScanResult>>,
    state: Arc<RawEngineState>,
    probe_engine: Option<Arc<ServiceProbeEngine>>,
    has_syn_backend: bool,
    has_icmp_backend: bool,
    has_udp_backend: bool,
}

impl RawPacketEngine {
    pub fn new(queue_size: usize, worker_count: usize, max_in_flight: usize) -> Self {
        Self::new_with_probe_and_policy(
            queue_size,
            worker_count,
            max_in_flight,
            None,
            RawEnginePolicy::default(),
        )
    }

    pub fn new_with_probe(
        queue_size: usize,
        worker_count: usize,
        max_in_flight: usize,
        probe_engine: Option<Arc<ServiceProbeEngine>>,
    ) -> Self {
        Self::new_with_probe_and_policy(
            queue_size,
            worker_count,
            max_in_flight,
            probe_engine,
            RawEnginePolicy::default(),
        )
    }

    pub fn new_with_probe_and_policy(
        queue_size: usize,
        worker_count: usize,
        max_in_flight: usize,
        probe_engine: Option<Arc<ServiceProbeEngine>>,
        policy: RawEnginePolicy,
    ) -> Self {
        let q = queue_size.max(1);
        let (job_tx, job_rx) = mpsc::channel::<ScanJob>(q);
        let (res_tx, res_rx) = mpsc::channel::<ScanResult>(q);
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let workers = worker_count.max(1);
        let limiter = Arc::new(Semaphore::new(max_in_flight.max(1)));
        let state = Arc::new(RawEngineState::new());
        spawn_cleanup_task(Arc::clone(&state));
        let hub = RawPacketHub::new().ok().map(Arc::new);
        let syn_backend = hub
            .as_ref()
            .and_then(|h| SynBackend::new(Arc::clone(h)).ok().map(Arc::new));
        let icmp_backend = hub
            .as_ref()
            .and_then(|h| IcmpBackend::new(Arc::clone(h)).ok().map(Arc::new));
        let udp_backend = hub
            .as_ref()
            .and_then(|h| UdpBackend::new(Arc::clone(h)).ok().map(Arc::new));
        let has_syn_backend = syn_backend.is_some();
        let has_icmp_backend = icmp_backend.is_some();
        let has_udp_backend = udp_backend.is_some();
        let control = AdaptiveControl::new(policy);

        for _ in 0..workers {
            let shared_rx = Arc::clone(&shared_rx);
            let res_tx = res_tx.clone();
            let limiter = Arc::clone(&limiter);
            let state = Arc::clone(&state);
            let probe_engine = probe_engine.clone();
            let syn_backend = syn_backend.clone();
            let icmp_backend = icmp_backend.clone();
            let udp_backend = udp_backend.clone();
            let hub = hub.clone();
            let control = control.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut guard = shared_rx.lock().await;
                        guard.recv().await
                    };
                    let Some(job) = job else { break };

                    let delay_ms = match control.preflight(job.target_ip).await {
                        Ok(d) => d,
                        Err(reason) => {
                            let mut dropped =
                                ScanResult::new(job.target_ip, job.protocol, ScanStatus::Error)
                                    .with_port(job.port.unwrap_or_default())
                                    .with_meta("engine", "raw")
                                    .with_meta("reason", reason);
                            if let Some(s) = control.snapshot(job.target_ip).await {
                                dropped = dropped
                                    .with_meta("target_jobs_started", s.jobs_started.to_string())
                                    .with_meta(
                                        "target_jobs_completed",
                                        s.jobs_completed.to_string(),
                                    )
                                    .with_meta("target_delay_ms", s.current_delay_ms.to_string());
                            }
                            let _ = res_tx.send(dropped).await;
                            continue;
                        }
                    };
                    if delay_ms > 0 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    }

                    let flow_seq = state.next_seq();
                    let flow_key = FlowKey {
                        target: job.target_ip,
                        port: job.port,
                        scan_type: FlowScanType::from(&job.scan_type),
                        seq: flow_seq,
                    };
                    state
                        .insert_inflight(flow_key.clone(), job.timeout_ms)
                        .await;

                    let permit = match limiter.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    let res_tx = res_tx.clone();
                    let state = Arc::clone(&state);
                    let probe_engine = probe_engine.clone();
                    let syn_backend = syn_backend.clone();
                    let icmp_backend = icmp_backend.clone();
                    let udp_backend = udp_backend.clone();
                    let hub = hub.clone();
                    let control = control.clone();
                    tokio::spawn(async move {
                        let mut result =
                            execute_raw_job(job, syn_backend, icmp_backend, udp_backend).await;
                        if let Some(probe) = &probe_engine {
                            result = probe.enrich_scan_result(result);
                        }
                        if let Some(hub) = &hub {
                            let s = hub.stats();
                            result = result
                                .with_meta("hub_has_tcp", s.has_tcp.to_string())
                                .with_meta("hub_has_udp", s.has_udp.to_string())
                                .with_meta("hub_has_icmp", s.has_icmp.to_string())
                                .with_meta(
                                    "hub_dispatcher_inflight",
                                    s.dispatcher_inflight.to_string(),
                                );
                        }
                        let new_delay = control.postflight(result.target_ip, result.status).await;
                        result = result.with_meta("target_next_delay_ms", new_delay.to_string());
                        if let Some(s) = control.snapshot(result.target_ip).await {
                            result = result
                                .with_meta("target_jobs_started", s.jobs_started.to_string())
                                .with_meta("target_jobs_completed", s.jobs_completed.to_string())
                                .with_meta("target_delay_ms", s.current_delay_ms.to_string());
                        }

                        let entry = state.remove_inflight(&flow_key).await;
                        if let Some(entry) = entry {
                            result = result
                                .with_meta("flow_seq", flow_key.seq.to_string())
                                .with_meta(
                                    "flow_elapsed_ms",
                                    entry.started_at.elapsed().as_millis().to_string(),
                                )
                                .with_meta("flow_timeout_ms", entry.timeout_ms.to_string());
                        } else {
                            result = result.with_meta("flow_seq", flow_key.seq.to_string());
                        }

                        let _ = res_tx.send(result).await;
                        drop(permit);
                    });
                }
            });
        }
        drop(res_tx);

        Self {
            tx: job_tx,
            rx: Some(res_rx),
            state,
            probe_engine,
            has_syn_backend,
            has_icmp_backend,
            has_udp_backend,
        }
    }

    pub async fn inflight_len(&self) -> usize {
        self.state.inflight_len().await
    }

    pub fn set_probe_engine(&mut self, probe_engine: Arc<ServiceProbeEngine>) {
        self.probe_engine = Some(probe_engine);
    }

    pub fn has_syn_backend(&self) -> bool {
        self.has_syn_backend
    }

    pub fn has_icmp_backend(&self) -> bool {
        self.has_icmp_backend
    }

    pub fn has_udp_backend(&self) -> bool {
        self.has_udp_backend
    }
}

impl Default for RawPacketEngine {
    fn default() -> Self {
        Self::new(1024, 32, 512)
    }
}

impl ScanEngine for RawPacketEngine {
    fn name(&self) -> &str {
        "raw-packet-engine"
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

async fn execute_raw_job(
    job: ScanJob,
    syn_backend: Option<Arc<SynBackend>>,
    icmp_backend: Option<Arc<IcmpBackend>>,
    udp_backend: Option<Arc<UdpBackend>>,
) -> ScanResult {
    match job.scan_type {
        ScanType::Syn => methods::syn::scan_syn(job, syn_backend).await,
        ScanType::UdpProbe => methods::udp::scan_udp(job, false, udp_backend).await,
        ScanType::Dns => methods::udp::scan_udp(job, true, udp_backend).await,
        ScanType::IcmpEcho => methods::icmp::scan_icmp(job, icmp_backend).await,
        ScanType::Arp => methods::arp::scan_arp(job).await,
        ScanType::Connect => ScanResult::new(
            job.target_ip,
            crate::cores::host::Protocol::Tcp,
            ScanStatus::Unknown,
        )
        .with_meta("engine", "raw")
        .with_meta("reason", "connect_should_use_async_engine"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::engine_trait::ScanEngine;
    use crate::services::service_probe::ServiceProbeEngine;

    #[tokio::test]
    async fn raw_engine_syn_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut engine = RawPacketEngine::new(16, 2, 8);
        let expect_backend = engine.has_syn_backend();
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            crate::cores::host::Protocol::Tcp,
            ScanType::Syn,
        )
        .with_port(port)
        .with_timeout_ms(1500);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert_eq!(res.status, ScanStatus::Open);
        assert_eq!(res.port, Some(port));
        assert!(res.metadata.iter().any(|(k, _)| k == "flow_seq"));
        if expect_backend {
            assert!(
                res.metadata
                    .iter()
                    .any(|(k, v)| k == "scan_type" && v == "syn_backend")
            );
        }
    }

    #[tokio::test]
    async fn raw_engine_icmp_loopback() {
        let mut engine = RawPacketEngine::new(16, 2, 8);
        let expect_backend = engine.has_icmp_backend();
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            crate::cores::host::Protocol::Icmp,
            ScanType::IcmpEcho,
        )
        .with_timeout_ms(500)
        .with_retries(1);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert!(matches!(
            res.status,
            ScanStatus::Open | ScanStatus::Filtered | ScanStatus::Error
        ));
        assert!(res.metadata.iter().any(|(k, _)| k == "flow_seq"));
        if expect_backend {
            assert!(
                res.metadata
                    .iter()
                    .any(|(k, v)| k == "scan_type" && v == "icmp_backend")
            );
        }
    }

    #[tokio::test]
    async fn raw_engine_inflight_is_released() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut engine = RawPacketEngine::new(16, 2, 8);
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            crate::cores::host::Protocol::Tcp,
            ScanType::Syn,
        )
        .with_port(port)
        .with_timeout_ms(1000);
        engine.submit(job).unwrap();

        let _ = rx.recv().await.unwrap();
        assert_eq!(engine.inflight_len().await, 0);
    }

    #[tokio::test]
    async fn raw_engine_probe_enriches_service_metadata() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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
        let mut engine = RawPacketEngine::new_with_probe(16, 2, 8, Some(probe));
        let expect_backend = engine.has_udp_backend();
        let mut rx = engine.take_results().unwrap();
        let job = ScanJob::new(
            "127.0.0.1".parse().unwrap(),
            crate::cores::host::Protocol::Udp,
            ScanType::UdpProbe,
        )
        .with_port(port)
        .with_timeout_ms(1000)
        .with_payload(vec![0x01, 0x02]);
        engine.submit(job).unwrap();
        drop(engine);

        let res = rx.recv().await.unwrap();
        assert!(
            res.metadata
                .iter()
                .any(|(k, v)| k == "service" && v == "http")
        );
        if expect_backend {
            assert!(
                res.metadata
                    .iter()
                    .any(|(k, v)| k == "scan_type" && v == "udp_backend")
            );
        }
    }
}
