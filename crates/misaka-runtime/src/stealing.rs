//! Idle-aware work-stealing service.

use crate::node::SisterNode;
use misaka_core::JobStatus;

/// Ask a peer with queued work for one job whenever this Sister is idle.
pub(crate) async fn run(node: &SisterNode, steal_when_lt: usize) -> crate::Result<()> {
    let mut interval = tokio::time::interval(node.config.steal_interval);
    loop {
        interval.tick().await;
        let is_busy = {
            let jobs = node.local_jobs.read().await;
            jobs.values()
                .any(|job| job.status == JobStatus::Running || job.status == JobStatus::Queued)
                || !node.job_queue.is_empty()
        };
        if is_busy || node.job_queue.len() >= steal_when_lt {
            continue;
        }

        let target = {
            let peers = node.peers.read().await;
            let list = peers.all();
            list.into_iter()
                .filter(|peer| peer.queued_jobs > 0)
                .min_by(|a, b| {
                    a.cpu_usage
                        .partial_cmp(&b.cpu_usage)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        };
        if let Some(peer) = target {
            tracing::info!(
                event = "work_requested",
                sister_id = node.identity.id.as_u64(),
                peer_id = peer.id,
                peer_queued_jobs = peer.queued_jobs,
                "requesting work from peer"
            );
            let _ = node.request_work_from(peer.id).await;
        }
    }
}
