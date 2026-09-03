//! Peer knowledge service.
//!
//! Coordinates the in-memory `PeerRegistry` and filesystem `PeerStore`.
//! Network transport remains owned by `SisterNode`, so this service is
//! deterministic and cannot accidentally turn persistence into networking.

use crate::peer_registry::PeerRegistry;
use crate::peer_store::PeerStore;
use misaka_core::introspection::PeerSnapshot;
use misaka_core::{PeerState, PeerStateTable, SisterIdentity};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub struct PeerService {
    registry: PeerRegistry,
    data_dir: PathBuf,
}

impl PeerService {
    pub fn new(registry: PeerRegistry, data_dir: PathBuf) -> Self {
        Self { registry, data_dir }
    }

    pub async fn all(&self) -> Vec<PeerState> {
        self.registry.all().await
    }

    pub async fn get(&self, id: u64) -> Option<PeerState> {
        self.registry.get(id).await
    }

    pub async fn addr_of(&self, id: u64) -> Option<std::net::SocketAddr> {
        self.registry.addr_of(id).await
    }

    pub async fn len(&self) -> usize {
        self.registry.len().await
    }

    pub async fn is_empty(&self) -> bool {
        self.registry.is_empty().await
    }

    pub async fn contains(&self, id: u64) -> bool {
        self.registry.contains(id).await
    }

    pub async fn upsert(&self, state: PeerState) {
        self.registry.upsert(state).await;
    }

    pub async fn prune_offline(&self, timeout: Duration) -> Vec<u64> {
        self.registry.prune_offline(timeout).await
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.all().await.iter().map(PeerSnapshot::from).collect()
    }

    /// Record the identity/advertised address received from a peer, then persist.
    pub async fn remember_peer(
        &self,
        identity: &SisterIdentity,
        listen_addr: &str,
        stream_addr: Option<&str>,
    ) {
        self.upsert(PeerState {
            id: identity.id.as_u64(),
            nickname: identity.nickname.as_str().to_string(),
            hostname: identity.hostname.clone(),
            platform: identity.platform.clone(),
            version: identity.version.clone(),
            stream_endpoints: stream_addr.into_iter().map(str::to_string).collect(),
            addr: listen_addr.to_string(),
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        })
        .await;
        self.persist().await;
    }

    pub async fn persist(&self) {
        let states = self.all().await;
        let mut table = PeerStateTable::new();
        for state in states {
            table.upsert(state);
        }
        let _ = PeerStore::save_to_dir(&table, &self.data_dir);
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile_like::TempDir;

    fn state(id: u64) -> PeerState {
        PeerState {
            id,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![],
            addr: "127.0.0.1:1".into(),
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        }
    }

    #[tokio::test]
    async fn service_exposes_registry_and_persists() {
        let dir = TempDir::new();
        let mut first = state(1);
        first.stream_endpoints = vec!["tcp://127.0.0.1:31701".into()];
        let registry = PeerRegistry::new_seeded(vec![first]);
        let service = PeerService::new(registry, dir.path().to_path_buf());
        assert_eq!(service.len().await, 1);
        service.upsert(state(2)).await;
        service.persist().await;
        assert!(dir.path().join("peers.json").exists());
        let saved = PeerStore::load_from_dir(dir.path());
        let first = saved.iter().find(|peer| peer.id == 1).unwrap();
        assert_eq!(first.stream_endpoints, vec!["tcp://127.0.0.1:31701"]);
    }
}

// Tiny test-only temporary directory helper avoids adding a runtime dependency.
#[cfg(test)]
mod tempfile_like {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("misaka-peer-service-{suffix}"));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
