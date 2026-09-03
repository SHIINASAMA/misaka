use crate::observer;
use crate::supervisor::pid_alive;
use crate::types::{Manifest, SisterEntry};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;

/// Live process state exposed by `testament ps`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SisterProcessStatus {
    Online,
    Unresponsive,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsEntry {
    pub alias: String,
    pub sister_id: Option<u64>,
    pub pid: Option<u32>,
    pub listen_addr: String,
    pub introspection_addr: Option<String>,
    pub process_alive: bool,
    pub introspection_reachable: bool,
    pub peers: Option<usize>,
    pub queue_depth: Option<usize>,
    pub running_jobs: Option<usize>,
    pub queued_jobs: Option<usize>,
    pub status: SisterProcessStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsReport {
    pub run_id: String,
    pub sisters: Vec<PsEntry>,
}

/// Build live entries from the persisted manifest. No log content is used for
/// state assertions.
pub fn collect(manifest: &Manifest) -> PsReport {
    let sisters = manifest.sisters.iter().map(collect_entry).collect();
    PsReport {
        run_id: manifest.run_id.clone(),
        sisters,
    }
}

fn collect_entry(entry: &SisterEntry) -> PsEntry {
    let process_alive = entry.pid.is_some_and(pid_alive);
    let snapshot = if process_alive {
        entry
            .introspection_addr
            .as_deref()
            .and_then(|addr| addr.parse::<SocketAddr>().ok())
            .and_then(|addr| observer::fetch(addr, Duration::from_millis(500)).ok())
            .filter(|snapshot| {
                entry
                    .id
                    .is_none_or(|id| id == snapshot.identity.id.as_u64())
            })
    } else {
        None
    };
    let introspection_reachable = snapshot.is_some();
    let status = if !process_alive {
        SisterProcessStatus::Dead
    } else if introspection_reachable {
        SisterProcessStatus::Online
    } else {
        SisterProcessStatus::Unresponsive
    };
    let (peers, queue_depth, running_jobs, queued_jobs) = snapshot
        .as_ref()
        .map(|snapshot| {
            (
                Some(snapshot.peers.len()),
                Some(snapshot.queue_depth),
                Some(snapshot.resources.running_jobs),
                Some(snapshot.resources.queued_jobs),
            )
        })
        .unwrap_or((None, None, None, None));
    PsEntry {
        alias: entry.alias.clone(),
        sister_id: entry.id,
        pid: entry.pid,
        listen_addr: entry.listen_addr.clone(),
        introspection_addr: entry.introspection_addr.clone(),
        process_alive,
        introspection_reachable,
        peers,
        queue_depth,
        running_jobs,
        queued_jobs,
        status,
    }
}

pub fn render_human(report: &PsReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("RUN {}\n", report.run_id));
    out.push_str("SISTER   ID                    PID     STATUS         LISTEN             PEERS  QUEUED  RUNNING\n");
    for entry in &report.sisters {
        out.push_str(&format!(
            "{:<8} {:<21} {:<7} {:<14} {:<18} {:>5}  {:>6}  {:>7}\n",
            entry.alias,
            entry
                .sister_id
                .map(|id| format!("#{id}"))
                .unwrap_or_else(|| "-".into()),
            entry
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".into()),
            status_label(entry.status),
            entry.listen_addr,
            display_num(entry.peers),
            display_num(entry.queued_jobs.or(entry.queue_depth)),
            display_num(entry.running_jobs),
        ));
    }
    let online = report
        .sisters
        .iter()
        .filter(|entry| entry.status == SisterProcessStatus::Online)
        .count();
    out.push_str(&format!(
        "\n{} online / {} known\n",
        online,
        report.sisters.len()
    ));
    out
}

fn status_label(status: SisterProcessStatus) -> &'static str {
    match status {
        SisterProcessStatus::Online => "online",
        SisterProcessStatus::Unresponsive => "unresponsive",
        SisterProcessStatus::Dead => "dead",
    }
}

fn display_num(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&SisterProcessStatus::Unresponsive).unwrap(),
            "\"unresponsive\""
        );
    }
}
