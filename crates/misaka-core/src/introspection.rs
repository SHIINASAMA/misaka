//! Read-only observation contracts shared between the runtime (producer)
//! and external harnesses (Testament as consumer).
//!
//! These are pure data types: the JSON shape a Sister's introspection
//! endpoint emits. They live in core so external harnesses can deserialize
//! them WITHOUT depending on misaka-runtime.

use serde::{Deserialize, Serialize};

use crate::peer::PeerState;
use crate::SisterIdentity;

#[cfg(test)]
mod tests {
    use super::NetworkStreamSummary;

    #[test]
    fn network_stream_summary_roundtrips_json() {
        let summary = NetworkStreamSummary {
            streams: 3,
            tx_bytes: 1024,
            rx_bytes: 2048,
        };
        let encoded = serde_json::to_string(&summary).unwrap();
        let decoded: NetworkStreamSummary = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, summary);
    }
}

/// 资源快照 (来自本地 sysinfo 观测)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceSnapshot {
    pub cpu_usage: f32,
    pub memory_total: u64,
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

/// Peer 快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub id: u64,
    pub nickname: String,
    pub addr: String,
    pub stream_endpoints: Vec<String>,
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub online: bool,
}

impl From<&PeerState> for PeerSnapshot {
    fn from(p: &PeerState) -> Self {
        Self {
            id: p.id,
            nickname: p.nickname.clone(),
            addr: p.addr.clone(),
            stream_endpoints: p.stream_endpoints.clone(),
            cpu_usage: p.cpu_usage,
            memory_used: p.memory_used,
            memory_total: p.memory_total,
            running_jobs: p.running_jobs,
            queued_jobs: p.queued_jobs,
            uptime_secs: p.uptime_secs,
            online: true,
        }
    }
}

/// Job 快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub id: String,
    pub command: String,
    pub status: String,
    pub creator: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

/// A currently active logical NetworkStream observed by the local Sister.
///
/// This is runtime telemetry, not a peer-protocol contract. A transport
/// endpoint may be known even when the stream has not been bound to a SisterId
/// by an application-level service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveStreamSnapshot {
    pub stream_id: u64,
    pub backend: String,
    pub route: String,
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    pub local_endpoint: Option<String>,
    pub remote_endpoint: Option<String>,
    pub connected_for_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Aggregate telemetry for the currently active logical NetworkStreams.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct NetworkStreamSummary {
    pub streams: usize,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// 完整 introspection snapshot —— Testament 的稳定观测面
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionSnapshot {
    pub identity: SisterIdentity,
    pub resources: ResourceSnapshot,
    pub peers: Vec<PeerSnapshot>,
    pub jobs: Vec<JobSnapshot>,
    pub queue_depth: usize,
    #[serde(default)]
    pub active_streams: Vec<ActiveStreamSnapshot>,
    #[serde(default)]
    pub stream_summary: NetworkStreamSummary,
}
