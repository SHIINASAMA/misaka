//! Idle-aware work-stealing service.

use crate::node::SisterNode;

/// Ask a peer with queued work for one job whenever this Sister is idle.
pub(crate) async fn run(node: &SisterNode, steal_when_lt: usize) -> crate::Result<()> {
    let mut interval = tokio::time::interval(node.config.steal_interval);
    loop {
        tokio::select! {
            _ = node.shutdown.cancelled() => break,
            _ = interval.tick() => {}
        }

        if node.jobs.is_busy().await || node.jobs.queue_len() >= steal_when_lt {
            continue;
        }

        let target = {
            let list = node.peers.all().await;
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
    Ok(())
}
