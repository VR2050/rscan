use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::cores::engine::scan_result::ScanStatus;

#[derive(Debug, Clone)]
pub(crate) struct DispatchReply {
    pub(crate) status: ScanStatus,
    pub(crate) payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CorrKey {
    Tcp {
        remote_ip: IpAddr,
        remote_port: u16,
        local_port: u16,
    },
    Udp {
        remote_ip: IpAddr,
        remote_port: u16,
        local_port: u16,
    },
    IcmpEcho {
        remote_ip: IpAddr,
        ident: u16,
        seq: u16,
    },
}

#[derive(Clone, Default)]
pub(crate) struct Dispatcher {
    inflight: Arc<Mutex<HashMap<CorrKey, oneshot::Sender<DispatchReply>>>>,
}

impl Dispatcher {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, key: CorrKey) -> oneshot::Receiver<DispatchReply> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.inflight.lock().unwrap();
        map.insert(key, tx);
        rx
    }

    pub(crate) fn remove(&self, key: &CorrKey) {
        let mut map = self.inflight.lock().unwrap();
        map.remove(key);
    }

    pub(crate) fn fulfill(&self, key: &CorrKey, reply: DispatchReply) -> bool {
        let tx_opt = {
            let mut map = self.inflight.lock().unwrap();
            map.remove(key)
        };
        if let Some(tx) = tx_opt {
            let _ = tx.send(reply);
            true
        } else {
            false
        }
    }

    pub(crate) fn inflight_len(&self) -> usize {
        self.inflight.lock().unwrap().len()
    }
}
