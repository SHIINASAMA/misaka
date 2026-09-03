//! Assertion primitives. Never use arbitrary sleeps as primary sync (§20):
//! every wait polls the introspection endpoint with an explicit timeout.
//! On timeout we gather last observed state for diagnostics.
//!
//! All failures are `ScenarioError::Assertion` — they describe behavior that
//! does not match expectation, not infrastructure problems.

use crate::observer;
use crate::types::ScenarioError;
use misaka_core::introspection::IntrospectionSnapshot;
use std::net::SocketAddr;
use std::time::Duration;

/// 轮询直到条件满足；超时返回 Err(诊断信息)
pub fn eventually(
    addr: SocketAddr,
    why: &str,
    timeout: Duration,
    predicate: impl FnMut(&IntrospectionSnapshot) -> bool,
) -> Result<(), ScenarioError> {
    observer::wait_until(addr, timeout, predicate)
        .map(|_| ())
        .ok_or_else(|| {
            let last = observer::fetch(addr, Duration::from_millis(500)).ok();
            ScenarioError::assertion(format!(
                "timeout after {:?}; condition: {}; last observed: {:?}",
                timeout,
                why,
                last.map(|s| format!(
                    "peers={} jobs={} queue={}",
                    s.peers.len(),
                    s.jobs.len(),
                    s.queue_depth
                ))
                .unwrap_or_else(|| "unreachable".into())
            ))
        })
}

pub fn assert_eq<T: PartialEq + std::fmt::Debug>(
    actual: T,
    expected: T,
    what: &str,
) -> Result<(), ScenarioError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ScenarioError::assertion(format!(
            "{}: expected {:?}, got {:?}",
            what, expected, actual
        )))
    }
}

pub fn assert_contains(actual: &str, expected: &str, what: &str) -> Result<(), ScenarioError> {
    if actual.contains(expected) {
        Ok(())
    } else {
        Err(ScenarioError::assertion(format!(
            "{}: expected output to contain {:?}, got {:?}",
            what, expected, actual
        )))
    }
}

pub fn assert_contains_peer(snap: &IntrospectionSnapshot, id: u64) -> Result<(), ScenarioError> {
    if snap.peers.iter().any(|p| p.id == id) {
        Ok(())
    } else {
        Err(ScenarioError::assertion(format!(
            "peer #{} not found; known peers: {:?}",
            id,
            snap.peers.iter().map(|p| p.id).collect::<Vec<_>>()
        )))
    }
}

pub fn assert_job_state(
    snap: &IntrospectionSnapshot,
    job_id: &str,
    wanted_status: &str,
) -> Result<(), ScenarioError> {
    match snap.jobs.iter().find(|j| j.id == job_id) {
        Some(j) if j.status == wanted_status => Ok(()),
        Some(j) => Err(ScenarioError::assertion(format!(
            "job {} status: expected {}, got {}",
            job_id, wanted_status, j.status
        ))),
        None => Err(ScenarioError::assertion(format!(
            "job {} not observed; known jobs: {:?}",
            job_id,
            snap.jobs.iter().map(|j| j.id.clone()).collect::<Vec<_>>()
        ))),
    }
}

pub fn assert_queue_empty(snap: &IntrospectionSnapshot) -> Result<(), ScenarioError> {
    if snap.queue_depth == 0 {
        Ok(())
    } else {
        Err(ScenarioError::assertion(format!(
            "queue not empty: {}",
            snap.queue_depth
        )))
    }
}
