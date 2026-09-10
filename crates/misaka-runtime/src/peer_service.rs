//! Peer knowledge service.
//!
//! Coordinates the in-memory `PeerRegistry` and filesystem `PeerStore`.
//! Network transport remains owned by `SisterNode`, so this service is
//! deterministic and cannot accidentally turn persistence into networking.

use crate::peer_registry::PeerRegistry;
use crate::peer_store::PeerStore;
use misaka_core::introspection::PeerSnapshot;
use misaka_core::{NetworkId, PeerRecord, PeerState, PeerStateTable, SisterIdentity};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct PeerService {
    registry: PeerRegistry,
    data_dir: PathBuf,
    network_id: NetworkId,
    records: Arc<RwLock<HashMap<u64, PeerRecord>>>,
}

impl PeerService {
    pub fn new(registry: PeerRegistry, data_dir: PathBuf) -> Self {
        Self::new_with_network_id(registry, data_dir, NetworkId::default())
    }

    pub fn new_with_network_id(
        registry: PeerRegistry,
        data_dir: PathBuf,
        network_id: NetworkId,
    ) -> Self {
        let records =
            crate::peer_record_store::PeerRecordStore::load_from_dir(&data_dir, network_id);
        Self {
            registry,
            data_dir,
            network_id,
            records: Arc::new(RwLock::new(records)),
        }
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

    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    pub async fn contains(&self, id: u64) -> bool {
        self.registry.contains(id).await
    }

    pub async fn upsert(&self, state: PeerState) {
        if state.network_id != self.network_id {
            tracing::debug!(
                peer_id = state.id,
                peer_network_id = %state.network_id,
                network_id = %self.network_id,
                "ignoring peer from another network"
            );
            return;
        }
        self.registry.upsert(state).await;
    }

    pub async fn peer_record(&self, id: u64) -> Option<PeerRecord> {
        self.records.read().await.get(&id).cloned()
    }

    pub async fn peer_records(&self) -> Vec<PeerRecord> {
        let mut records: Vec<_> = self.records.read().await.values().cloned().collect();
        records.sort_by_key(|record| record.sister_id.as_u64());
        records
    }

    /// Accept only a valid, same-network record and retain the newest
    /// transport sequence for a Sister.
    pub async fn upsert_peer_record(&self, record: PeerRecord) -> bool {
        if record.network_id != self.network_id || !record.verify() {
            return false;
        }
        let id = record.sister_id.as_u64();
        let mut records = self.records.write().await;
        if records
            .get(&id)
            .is_some_and(|current| current.sequence > record.sequence)
        {
            return false;
        }
        records.insert(id, record);
        // §19: peer knowledge is a non-critical cache — a failed write is not
        // fatal, but must be observable rather than silently dropped.
        if let Err(error) =
            crate::peer_record_store::PeerRecordStore::save_to_dir(&self.data_dir, &records)
        {
            tracing::debug!(
                sister_id = id,
                %error,
                "failed to persist the peer-record cache (non-fatal)"
            );
        }
        true
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
        network_id: NetworkId,
        listen_addr: &str,
        stream_addr: Option<&str>,
        stream_certificate: Option<Vec<u8>>,
    ) {
        if network_id != self.network_id {
            return;
        }
        self.upsert(PeerState {
            network_id,
            id: identity.id.as_u64(),
            nickname: identity.nickname.as_str().to_string(),
            hostname: identity.hostname.clone(),
            platform: identity.platform.clone(),
            version: identity.version.clone(),
            stream_endpoints: stream_addr.into_iter().map(str::to_string).collect(),
            stream_certificate,
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
        // §19: peer-knowledge persistence is best-effort cache; surface failure.
        if let Err(error) = PeerStore::save_to_dir(&table, &self.data_dir) {
            tracing::debug!(%error, "failed to persist the peer cache (non-fatal)");
        }
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
            network_id: NetworkId::default(),
            id,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![],
            stream_certificate: None,
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

    #[tokio::test]
    async fn service_rejects_peers_from_another_network() {
        let dir = TempDir::new();
        let network_id = NetworkId::generate();
        let service = PeerService::new_with_network_id(
            PeerRegistry::new(),
            dir.path().to_path_buf(),
            network_id,
        );
        let mut foreign = state(9);
        foreign.network_id = NetworkId::generate();
        service.upsert(foreign).await;
        assert!(service.is_empty().await);
        service.persist().await;
        assert!(PeerStore::load_from_dir(dir.path()).is_empty());
    }
}

// Tiny test-only temporary directory helper avoids adding a runtime dependency.
#[cfg(test)]
mod tempfile_like {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            // A unique suffix: nanosecond timestamps can collide across tests
            // that create their temp dir in the same clock tick under
            // parallel execution, which silently cross-contaminates them.
            let path =
                std::env::temp_dir().join(format!("misaka-peer-service-{}", uuid::Uuid::new_v4()));
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
