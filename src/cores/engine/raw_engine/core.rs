use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::Mutex;

use crate::cores::engine::scan_job::ScanType;

pub(crate) struct RawEngineState {
    seq: AtomicU64,
    inflight: Mutex<HashMap<FlowKey, InFlightEntry>>,
}

impl RawEngineState {
    pub(crate) fn new() -> Self {
        Self {
            seq: AtomicU64::new(1),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn insert_inflight(&self, key: FlowKey, timeout_ms: u64) {
        let mut map = self.inflight.lock().await;
        map.insert(
            key,
            InFlightEntry {
                started_at: Instant::now(),
                timeout_ms: timeout_ms.max(1),
            },
        );
    }

    pub(crate) async fn remove_inflight(&self, key: &FlowKey) -> Option<InFlightEntry> {
        let mut map = self.inflight.lock().await;
        map.remove(key)
    }

    pub(crate) async fn inflight_len(&self) -> usize {
        self.inflight.lock().await.len()
    }

    pub(crate) async fn cleanup_expired(&self) {
        let mut map = self.inflight.lock().await;
        map.retain(|_, entry| entry.started_at.elapsed().as_millis() < entry.timeout_ms as u128);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InFlightEntry {
    pub(crate) started_at: Instant,
    pub(crate) timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub(crate) target: std::net::IpAddr,
    pub(crate) port: Option<u16>,
    pub(crate) scan_type: FlowScanType,
    pub(crate) seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FlowScanType {
    Connect,
    Syn,
    UdpProbe,
    IcmpEcho,
    Arp,
    Dns,
}

impl From<&ScanType> for FlowScanType {
    fn from(value: &ScanType) -> Self {
        match value {
            ScanType::Connect => Self::Connect,
            ScanType::Syn => Self::Syn,
            ScanType::UdpProbe => Self::UdpProbe,
            ScanType::IcmpEcho => Self::IcmpEcho,
            ScanType::Arp => Self::Arp,
            ScanType::Dns => Self::Dns,
        }
    }
}

pub(crate) fn spawn_cleanup_task(state: Arc<RawEngineState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            state.cleanup_expired().await;
        }
    });
}
