//! Async owner of in-memory peer knowledge.
//!
//! `PeerRegistry` deliberately knows nothing about files, transport, or
//! identity handshakes. `PeerService` coordinates persistence around it.

use misaka_core::{PeerState, PeerStateTable};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct PeerRegistry {
    inner: Arc<RwLock<PeerStateTable>>,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerStateTable::new())),
        }
    }

    pub fn new_seeded(states: Vec<PeerState>) -> Self {
        let mut table = PeerStateTable::new();
        for state in states {
            table.upsert(state);
        }
        Self {
            inner: Arc::new(RwLock::new(table)),
        }
    }

    pub async fn upsert(&self, state: PeerState) {
        self.inner.write().await.upsert(state);
    }

    pub async fn get(&self, id: u64) -> Option<PeerState> {
        self.inner.read().await.get(id).cloned()
    }

    pub async fn addr_of(&self, id: u64) -> Option<SocketAddr> {
        self.get(id).await?.addr.parse().ok()
    }

    pub async fn all(&self) -> Vec<PeerState> {
        self.inner.read().await.all()
    }

    pub async fn contains(&self, id: u64) -> bool {
        self.inner.read().await.contains(id)
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    pub async fn prune_offline(&self, timeout: Duration) -> Vec<u64> {
        self.inner.write().await.prune_offline(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_core::NetworkId;

    fn state(id: u64, addr: &str) -> PeerState {
        PeerState {
            network_id: NetworkId::default(),
            id,
            nickname: format!("sister-{id}"),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![],
            stream_certificate: None,
            addr: addr.into(),
            cpu_usage: 5.0,
            memory_total: 10,
            memory_used: 2,
            running_jobs: 0,
            queued_jobs: 1,
            uptime_secs: 3,
            capabilities: vec!["shell".into()],
        }
    }

    #[tokio::test]
    async fn registry_wraps_table_operations() {
        let registry = PeerRegistry::new_seeded(vec![state(1, "127.0.0.1:31001")]);
        assert_eq!(registry.len().await, 1);
        assert!(registry.contains(1).await);
        assert_eq!(registry.addr_of(1).await.unwrap().port(), 31001);
        assert_eq!(registry.all().await[0].nickname, "sister-1");
        registry.upsert(state(2, "127.0.0.1:31002")).await;
        assert_eq!(registry.len().await, 2);
    }

    #[tokio::test]
    async fn registry_prunes_stale_entries() {
        let registry = PeerRegistry::new_seeded(vec![state(1, "127.0.0.1:31001")]);
        let removed = registry.prune_offline(Duration::ZERO).await;
        assert_eq!(removed, vec![1]);
        assert!(registry.is_empty().await);
    }
}
