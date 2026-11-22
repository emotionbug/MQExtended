use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// A completely idle TCP socket must not occupy a TLS or authenticated RPC slot.
const IDLE_LIMIT: usize = 1024;
const HANDSHAKE_LIMIT: usize = 128;
const SOURCE_LIMIT: usize = 16;
const RPC_LIMIT: usize = 512;

pub(crate) struct Admission {
    idle: Arc<Semaphore>,
    handshake: Mutex<Pending>,
    rpc: Arc<Semaphore>,
}

#[derive(Default)]
struct Pending {
    total: usize,
    sources: HashMap<IpAddr, usize>,
}

pub(crate) struct Handshake<'a> {
    pending: &'a Mutex<Pending>,
    source: IpAddr,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            idle: Arc::new(Semaphore::new(IDLE_LIMIT)),
            handshake: Mutex::default(),
            rpc: Arc::new(Semaphore::new(RPC_LIMIT)),
        }
    }
}

impl Admission {
    pub(crate) fn idle(&self) -> Option<OwnedSemaphorePermit> {
        self.idle.clone().try_acquire_owned().ok()
    }

    pub(crate) fn handshake(&self, source: IpAddr) -> Option<Handshake<'_>> {
        let mut pending = self.handshake.lock().unwrap();
        if pending.total >= HANDSHAKE_LIMIT
            || pending.sources.get(&source).copied().unwrap_or(0) >= SOURCE_LIMIT
        {
            return None;
        }
        pending.total += 1;
        *pending.sources.entry(source).or_default() += 1;
        Some(Handshake {
            pending: &self.handshake,
            source,
        })
    }

    pub(crate) fn rpc(&self) -> Option<OwnedSemaphorePermit> {
        self.rpc.clone().try_acquire_owned().ok()
    }
}

impl Drop for Handshake<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap();
        pending.total -= 1;
        let count = pending.sources.get_mut(&self.source).unwrap();
        *count -= 1;
        if *count == 0 {
            pending.sources.remove(&self.source);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_sockets_do_not_consume_handshake_or_rpc_capacity() {
        let admission = Admission::default();
        let idle: Vec<_> = (0..600).map(|_| admission.idle().unwrap()).collect();
        assert_eq!(idle.len(), 600);
        let source = "127.0.0.1".parse().unwrap();
        assert!(admission.handshake(source).is_some());
        assert!(admission.rpc().is_some());
    }

    #[test]
    fn pending_handshakes_are_limited_per_source_and_released_on_drop() {
        let admission = Admission::default();
        let source = "127.0.0.1".parse().unwrap();
        let mut pending: Vec<_> = (0..SOURCE_LIMIT)
            .map(|_| admission.handshake(source).unwrap())
            .collect();
        assert!(admission.handshake(source).is_none());
        assert!(admission.handshake("127.0.0.2".parse().unwrap()).is_some());
        pending.pop();
        assert!(admission.handshake(source).is_some());
    }
}
