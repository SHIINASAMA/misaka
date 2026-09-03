//! In-memory registry for active NetworkStream telemetry.

use misaka_core::introspection::ActiveStreamSnapshot;
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
            .map(|(&stream_id, stream)| ActiveStreamSnapshot {
                stream_id,
                backend: stream.path.backend.clone(),
                route: stream.path.route.clone(),
                rtt_ms: stream.path.rtt_ms,
                local_endpoint: stream.path.local_endpoint.clone(),
                remote_endpoint: stream
                    .path
                    .remote_endpoint
                    .clone()
                    .or_else(|| stream.peer_addr.map(|addr| addr.to_string())),
                connected_for_ms: now.duration_since(stream.started_at).as_millis() as u64,
                tx_bytes: stream.stats.tx_bytes(),
                rx_bytes: stream.stats.rx_bytes(),
            })
            .collect::<Vec<_>>();
        streams.sort_by_key(|stream| stream.stream_id);
        streams
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
    use misaka_network::NetworkStream;
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

        drop(registration);
        assert_eq!(registry.len(), 0);
    }
}
