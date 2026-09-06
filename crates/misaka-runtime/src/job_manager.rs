//! Job state owner.
//!
//! `JobManager` is the only runtime service that owns local job metadata,
//! queue membership, and pending remote result waiters. Protocol and worker
//! code interact through these methods instead of locking raw maps.

use crate::queue::JobQueue;
use crate::state::LocalJob;
use misaka_core::introspection::JobSnapshot;
use misaka_core::protocol::JobResultData;
use misaka_core::JobStatus;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, RwLock};

#[derive(Clone)]
pub struct JobManager {
    queue: JobQueue,
    jobs: Arc<RwLock<HashMap<String, LocalJob>>>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<JobResultData>>>>,
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            queue: JobQueue::new(),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert metadata and queue membership as one manager operation.
    pub async fn enqueue(&self, job: LocalJob) {
        let mut jobs = self.jobs.write().await;
        jobs.insert(job.id.clone(), job.clone());
        self.queue.push(job);
    }

    pub fn pop(&self) -> Option<LocalJob> {
        self.queue.pop()
    }

    /// Pop the next job this Sister may hand to `requester` under work stealing.
    ///
    /// §8/§9: a Human-authorized job runs only on its authorized target, so it is
    /// NOT stealable by an unrelated Sister. An un-authorized job is stealable
    /// only when `allow_unauthenticated` (explicit development/test mode). This
    /// deliberately avoids authorization delegation / chains / re-signing, which
    /// are separate future designs.
    pub fn pop_transferable(
        &self,
        requester: u64,
        allow_unauthenticated: bool,
    ) -> Option<LocalJob> {
        self.queue
            .pop_where(|job| job_transferable(job, requester, allow_unauthenticated))
    }

    pub fn push_back(&self, job: LocalJob) {
        self.queue.push(job);
    }

    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn queue_is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub async fn is_busy(&self) -> bool {
        let jobs = self.jobs.read().await;
        !self.queue.is_empty()
            || jobs
                .values()
                .any(|job| matches!(job.status, JobStatus::Queued | JobStatus::Running))
    }

    pub async fn mark_running(&self, job_id: &str, started_at: u64) {
        if let Some(job) = self.jobs.write().await.get_mut(job_id) {
            job.status = JobStatus::Running;
            job.started_at = Some(started_at);
        }
    }

    pub async fn mark_transferred(&self, job_id: &str) {
        if let Some(job) = self.jobs.write().await.get_mut(job_id) {
            job.status = JobStatus::Transferred;
        }
    }

    pub async fn mark_finished(&self, job_id: &str, result: &JobResultData) {
        if let Some(job) = self.jobs.write().await.get_mut(job_id) {
            job.status = if result.success {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };
            job.finished_at = Some(result.finished_at);
            job.result_output = Some(result.output.clone());
        }
    }

    pub fn reserve_pending(&self, job_id: &str) -> oneshot::Receiver<JobResultData> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(job_id.to_string(), tx);
        rx
    }

    pub fn resolve_pending(&self, job_id: &str) -> Option<oneshot::Sender<JobResultData>> {
        self.pending.lock().unwrap().remove(job_id)
    }

    pub fn cancel_pending(&self, job_id: &str) {
        self.pending.lock().unwrap().remove(job_id);
    }

    pub async fn count_queued(&self) -> usize {
        self.jobs
            .read()
            .await
            .values()
            .filter(|job| job.status == JobStatus::Queued)
            .count()
    }

    pub async fn count_running(&self) -> usize {
        self.jobs
            .read()
            .await
            .values()
            .filter(|job| job.status == JobStatus::Running)
            .count()
    }

    pub async fn job(&self, id: &str) -> Option<LocalJob> {
        self.jobs.read().await.get(id).cloned()
    }

    pub async fn all_jobs(&self) -> Vec<LocalJob> {
        self.jobs.read().await.values().cloned().collect()
    }

    pub async fn job_snapshots(&self) -> Vec<JobSnapshot> {
        self.all_jobs()
            .await
            .into_iter()
            .map(|job| JobSnapshot {
                id: job.id,
                command: job.command,
                status: job.status.to_string(),
                creator: job.creator,
                started_at: job.started_at,
                finished_at: job.finished_at,
            })
            .collect()
    }
}

/// Whether `requester` may take over `job` via work stealing.
///
/// - Authorization names the requester as its destination Sister → transferable.
/// - Authorization present but bound elsewhere (or `target == None`) → NOT
///   transferable to this requester.
/// - No authorization → transferable only in explicit insecure-development mode.
fn job_transferable(job: &LocalJob, requester: u64, allow_unauthenticated: bool) -> bool {
    match job.authorization.as_ref() {
        Some(authorization) => matches!(
            &authorization.target,
            Some(misaka_core::Principal::Sister(id)) if id.as_u64() == requester
        ),
        None => allow_unauthenticated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: &str) -> LocalJob {
        LocalJob::new(id.to_string(), format!("printf {id}"))
    }

    fn result(id: &str, success: bool) -> JobResultData {
        JobResultData {
            job_id: id.to_string(),
            creator: 1,
            executor: 2,
            output: "output".into(),
            exit_code: if success { 0 } else { 1 },
            success,
            started_at: 10,
            finished_at: 20,
        }
    }

    #[tokio::test]
    async fn enqueue_and_pop_preserve_metadata_and_fifo() {
        let manager = JobManager::new();
        manager.enqueue(job("one")).await;
        manager.enqueue(job("two")).await;
        assert_eq!(manager.queue_len(), 2);
        assert_eq!(manager.count_queued().await, 2);
        assert_eq!(manager.pop().unwrap().id, "one");
        assert!(manager.job("one").await.is_some());
        assert!(manager.is_busy().await);
    }

    #[tokio::test]
    async fn status_transitions_are_owned_by_manager() {
        let manager = JobManager::new();
        manager.enqueue(job("one")).await;
        manager.mark_running("one", 10).await;
        assert_eq!(manager.count_running().await, 1);
        manager.mark_transferred("one").await;
        assert_eq!(
            manager.job("one").await.unwrap().status,
            JobStatus::Transferred
        );
        manager.mark_finished("one", &result("one", true)).await;
        let finished = manager.job("one").await.unwrap();
        assert_eq!(finished.status, JobStatus::Completed);
        assert_eq!(finished.result_output.as_deref(), Some("output"));
    }

    #[tokio::test]
    async fn pending_result_can_resolve_or_cancel() {
        let manager = JobManager::new();
        let receiver = manager.reserve_pending("one");
        manager
            .resolve_pending("one")
            .unwrap()
            .send(result("one", true))
            .unwrap();
        assert_eq!(receiver.await.unwrap().job_id, "one");

        let receiver = manager.reserve_pending("two");
        manager.cancel_pending("two");
        assert!(receiver.await.is_err());
    }

    // JI07 / JI06: a pending waiter resolves at most once; a duplicate result or
    // a late result after cancel is ignored (no panic, no double-resolve).
    #[test]
    fn pending_resolves_once_ignores_duplicate_and_late() {
        let manager = JobManager::new();
        let _rx = manager.reserve_pending("job");
        // First result resolves it (removes the waiter).
        assert!(manager.resolve_pending("job").is_some());
        // Duplicate: nothing left to resolve.
        assert!(manager.resolve_pending("job").is_none());
        // Late after an explicit cancel: still no waiter, no panic.
        let _rx = manager.reserve_pending("late");
        manager.cancel_pending("late");
        assert!(manager.resolve_pending("late").is_none());
    }

    // §11: a submission that fails before delivery must not leak a waiter.
    #[test]
    fn cancel_removes_pending_waiter() {
        let manager = JobManager::new();
        let _rx = manager.reserve_pending("sub");
        manager.cancel_pending("sub");
        assert!(manager.resolve_pending("sub").is_none());
    }

    // JH05 / §8 / §9: work stealing must respect the authorization target.
    #[tokio::test]
    async fn pop_transferable_respects_authorization_target() {
        use misaka_core::{CommandAuthorization, NetworkId, Principal, SisterId};

        let manager = JobManager::new();

        // Job authorized for Sister B.
        let mut for_b = job("for-b");
        for_b.authorization = Some(CommandAuthorization {
            network_id: NetworkId::default(),
            issuer: for_b_dummy_issuer(),
            membership: for_b_dummy_membership(),
            role: misaka_core::Role::Operator,
            permission: misaka_core::Permission::JobSubmit,
            target: Some(Principal::Sister(SisterId(2))),
            constraints: vec![],
            issued_at: 0,
            expires_at: u64::MAX,
            nonce: [0u8; 16],
            signature: for_b_dummy_sig(),
        });
        // A job authorized for B must NOT be stolen by requester C (3), nor by an
        // unrelated peer, but IS transferable to B (2).
        manager.enqueue(for_b.clone()).await;
        assert!(
            manager.pop_transferable(3, false).is_none(),
            "C stole B's job"
        );
        assert_eq!(
            manager.queue_len(),
            1,
            "queue corrupted when refusing a peer"
        );
        let taken = manager
            .pop_transferable(2, false)
            .expect("B can take its job");
        assert_eq!(taken.id, "for-b");

        // No authorization → stealable only in explicit insecure-development mode.
        manager.enqueue(job("plain")).await;
        assert!(manager.pop_transferable(9, false).is_none());
        let stolen = manager
            .pop_transferable(9, true)
            .expect("plain job stealable in insecure mode");
        assert_eq!(stolen.id, "plain");
    }

    // Small helpers to build an authorization struct for the predicate test
    // (fields other than `target` are irrelevant to `job_transferable`).
    fn for_b_dummy_issuer() -> misaka_core::HumanIdentity {
        let key = misaka_core::HumanKeyPair::generate();
        misaka_core::HumanIdentity::new(
            misaka_core::HumanId::generate(),
            "op".into(),
            key.public_key(),
        )
    }
    fn for_b_dummy_membership() -> misaka_core::HumanMembershipCertificate {
        let issuer = for_b_dummy_issuer();
        misaka_core::HumanMembershipCertificate {
            network_id: misaka_core::NetworkId::default(),
            human: issuer,
            role: misaka_core::Role::Operator,
            issued_at: 0,
            expires_at: None,
            serial: 1,
            authority_signature: misaka_core::AuthoritySignature::from_bytes([0u8; 64]),
        }
    }
    fn for_b_dummy_sig() -> misaka_core::HumanSignature {
        misaka_core::HumanSignature::from_bytes([0u8; 64])
    }
}
