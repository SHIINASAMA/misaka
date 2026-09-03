//! Read-only introspection endpoint for debugging/testing.
//!
//! NOT part of the Misaka peer protocol. Binds loopback only, never
//! advertised via mDNS, never used by Sisters. Exposes a stable JSON
//! snapshot so external harnesses (Testament) can observe behavior.
//!
//! Hard rules (§13):
//! - disabled by default
//! - explicitly enabled via config
//! - binds to loopback only
//! - read-only
//! - not advertised through mDNS
//! - not used by Sisters

use misaka_core::{PeerState, SisterIdentity};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// 资源快照 (来自本地 sysinfo 观测)
#[derive(Debug, Clone, Serialize)]
pub struct ResourceSnapshot {
    pub cpu_usage: f32,
    pub memory_total: u64,
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

impl From<&crate::state::LocalState> for ResourceSnapshot {
    fn from(s: &crate::state::LocalState) -> Self {
        Self {
            cpu_usage: s.cpu_usage,
            memory_total: s.memory_total,
            memory_used: s.memory_used,
            running_jobs: s.running_jobs,
            queued_jobs: s.queued_jobs,
            uptime_secs: s.uptime_secs,
            capabilities: s.capabilities.clone(),
        }
    }
}

/// Peer 快照
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
pub struct JobSnapshot {
    pub id: String,
    pub command: String,
    pub status: String,
    pub creator: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

/// 完整 introspection snapshot —— Testament 的稳定观测面
#[derive(Debug, Clone, Serialize)]
pub struct IntrospectionSnapshot {
    pub identity: SisterIdentity,
    pub resources: ResourceSnapshot,
    pub peers: Vec<PeerSnapshot>,
    pub jobs: Vec<JobSnapshot>,
    pub queue_depth: usize,
}

/// 在 loopback 上起一个极简 TCP 服务器：每次连接读取一行，返回一行 JSON snapshot。
/// 返回实际绑定的地址。
pub async fn spawn_server(
    bind: SocketAddr,
    snapshot: impl Fn() -> BoxFuture<IntrospectionSnapshot> + Send + Sync + 'static,
) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let snapshot = std::sync::Arc::new(snapshot);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let snapshot = snapshot.clone();
            tokio::spawn(async move {
                let _ = handle(stream, snapshot).await;
            });
        }
    });
    Ok(addr)
}

async fn handle(
    mut stream: TcpStream,
    snapshot: std::sync::Arc<impl Fn() -> BoxFuture<IntrospectionSnapshot>>,
) -> std::io::Result<()> {
    let snap = snapshot().await;
    let json = serde_json::to_vec(&snap).map_err(|e| std::io::Error::other(e.to_string()))?;
    stream.write_all(&json).await?;
    stream.flush().await?;
    Ok(())
}
