//! Read-only observation contracts shared between the runtime (producer)
//! and external harnesses (Testament as consumer).
//!
//! These are pure data types: the JSON shape a Sister's introspection
//! endpoint emits. They live in core so external harnesses can deserialize
//! them WITHOUT depending on misaka-runtime.

use serde::{Deserialize, Serialize};

use crate::peer::PeerState;
use crate::SisterIdentity;

/// 资源快照 (来自本地 sysinfo 观测)
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub online: bool,
}

impl From<&PeerState> for PeerSnapshot {
    fn from(p: &PeerState) -> Self {
        Self {
            id: p.id,
            nickname: p.nickname.clone(),
            addr: p.addr.clone(),
            cpu_usage: p.cpu_usage,
            memory_used: p.memory_used,
            memory_total: p.memory_total,
            running_jobs: p.running_jobs,
            queued_jobs: p.queued_jobs,
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

/// 完整 introspection snapshot —— Testament 的稳定观测面
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionSnapshot {
    pub identity: SisterIdentity,
    pub resources: ResourceSnapshot,
    pub peers: Vec<PeerSnapshot>,
    pub jobs: Vec<JobSnapshot>,
    pub queue_depth: usize,
}
