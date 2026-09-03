//! In-memory registry for active NetworkStream telemetry.

use misaka_core::introspection::{ActiveStreamSnapshot, NetworkStreamSummary};
use misaka_network::NetworkStream;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Default)]
pub(crate) struct StreamRegistry {
    next_id: Arc<AtomicU64>,
    entries: Arc<Mutex<HashMap<u64, ActiveStream>>>,
}

struct ActiveStream {
    path: misaka_network::PathInfo,
    path_provider: Option<misaka_network::PathInfoProvider>,
    stats: misaka_network::StreamStats,
    started_at: Instant,
    peer_addr: Option<SocketAddr>,
}

pub(crate) struct StreamRegistration {
    registry: StreamRegistry,
    id: u64,
}

impl StreamRegistry {
    pub(crate) fn register(
        &self,
        stream: &NetworkStream,
        peer_addr: Option<SocketAddr>,
    ) -> StreamRegistration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let active = ActiveStream {
            path: stream.path_info(),
            path_provider: stream.path_info_provider(),
            stats: stream.stats(),
            started_at: Instant::now(),
            peer_addr,
        };
        self.entries
            .lock()
            .expect("stream registry lock poisoned")
            .insert(id, active);
        StreamRegistration {
            registry: self.clone(),
            id,
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<ActiveStreamSnapshot> {
        let now = Instant::now();
        let mut streams = self
            .entries
            .lock()
            .expect("stream registry lock poisoned")
            .iter()
            .map(|(&stream_id, stream)| {
                let path = stream
                    .path_provider
                    .as_ref()
                    .map(|provider| provider())
                    .unwrap_or_else(|| stream.path.clone());
                ActiveStreamSnapshot {
                    stream_id,
                    backend: path.backend,
                    route: path.route,
                    rtt_ms: path.rtt_ms,
                    path_switches: path.path_switches,
                    local_endpoint: path.local_endpoint,
                    remote_endpoint: path
                        .remote_endpoint
                        .or_else(|| stream.peer_addr.map(|addr| addr.to_string())),
                    connected_for_ms: now.duration_since(stream.started_at).as_millis() as u64,
                    tx_bytes: stream.stats.tx_bytes(),
                    rx_bytes: stream.stats.rx_bytes(),
                }
            })
            .collect::<Vec<_>>();
        streams.sort_by_key(|stream| stream.stream_id);
        streams
    }

    pub(crate) fn summary(&self) -> NetworkStreamSummary {
        let entries = self.entries.lock().expect("stream registry lock poisoned");
        NetworkStreamSummary {
            streams: entries.len(),
            tx_bytes: entries.values().map(|stream| stream.stats.tx_bytes()).sum(),
            rx_bytes: entries.values().map(|stream| stream.stats.rx_bytes()).sum(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("stream registry lock poisoned")
            .len()
    }
}

impl Drop for StreamRegistration {
    fn drop(&mut self) {
        self.registry
            .entries
            .lock()
            .expect("stream registry lock poisoned")
            .remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::StreamRegistry;
    use misaka_network::{NetworkStream, PathInfo};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn active_stream_snapshot_tracks_counters_until_registration_drops() {
        let registry = StreamRegistry::default();
        let (left, mut right) = tokio::io::duplex(64);
        let mut stream = NetworkStream::from_stream(left);
        let registration = registry.register(&stream, None);

        stream.write_all(b"hello").await.unwrap();
        let mut received = [0u8; 5];
        right.read_exact(&mut received).await.unwrap();
        right.write_all(b"world").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].backend, "unknown");
        assert_eq!(snapshot[0].tx_bytes, 5);
        assert_eq!(snapshot[0].rx_bytes, 5);
        assert!(snapshot[0].connected_for_ms < 1_000);

        let summary = registry.summary();
        assert_eq!(summary.streams, 1);
        assert_eq!(summary.tx_bytes, 5);
        assert_eq!(summary.rx_bytes, 5);

        drop(registration);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn active_stream_snapshot_refreshes_dynamic_path_metadata() {
        let registry = StreamRegistry::default();
        let (left, _right) = tokio::io::duplex(64);
        let state = Arc::new(Mutex::new(PathInfo::new(
            "iroh",
            "relay",
            None,
            Some("peer".to_string()),
        )));
        let provider_state = Arc::clone(&state);
        let stream = NetworkStream::from_stream_with_path_provider(
            left,
            state.lock().unwrap().clone(),
            move || provider_state.lock().unwrap().clone(),
        );
        let _registration = registry.register(&stream, None);

        assert_eq!(registry.snapshot()[0].route, "relay");
        *state.lock().unwrap() =
            PathInfo::new("iroh", "direct", None, Some("peer".to_string())).with_path_switches(1);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot[0].route, "direct");
        assert_eq!(snapshot[0].path_switches, 1);
    }
}
