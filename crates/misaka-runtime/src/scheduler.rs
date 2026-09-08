use crate::state::LocalState;
use misaka_core::PeerState;

/// 调度器：根据 peer 状态选择一个目标 Sister 执行任务。
pub struct Scheduler {
    // 预留
}

impl Scheduler {
    pub fn new() -> Self {
        Self {}
    }

    /// 根据当前 local state + peer states 选取执行目标。
    /// 返回 Some(id) 表示派发给该 peer；None 表示本地执行。
    ///
    /// 规则:
    /// - 无 peer → 本地
    /// - 存在 CPU 明显更低 (低超过 15 个百分点) 的 peer → 派给 CPU 最低者
    /// - CPU 相同 → 选择 SisterId 较小者，不依赖 peer 的枚举顺序
    /// - 否则本地
    pub fn choose(&self, peers: &[PeerState], local: &LocalState) -> Option<u64> {
        if peers.is_empty() {
            return None;
        }

        // Reject invalid samples as well as peers at or above 85% load.
        let best = peers
            .iter()
            .filter(|p| (0.0..85.0).contains(&p.cpu_usage))
            .min_by(|a, b| {
                a.cpu_usage
                    .partial_cmp(&b.cpu_usage)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.id.cmp(&b.id))
            });

        match best {
            // peer 比本机明显更闲 → 派给它
            Some(p) if p.cpu_usage < local.cpu_usage - 15.0 => Some(p.id),
            // 本机排队任务积压且 peer 有空闲 → 派给它
            Some(p) if local.queued_jobs >= 2 && p.cpu_usage < 50.0 => Some(p.id),
            _ => None, // 否则本地
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_core::NetworkId;

    fn local(cpu_usage: f32, queued_jobs: usize) -> LocalState {
        LocalState {
            cpu_usage,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs,
            uptime_secs: 0,
            capabilities: vec![],
        }
    }

    fn peer(id: u64, cpu_usage: f32) -> PeerState {
        PeerState {
            network_id: NetworkId::default(),
            id,
            nickname: format!("sister-{id}"),
            hostname: "test".into(),
            platform: "test".into(),
            version: "test".into(),
            stream_endpoints: vec![],
            stream_certificate: None,
            addr: format!("127.0.0.1:{}", id),
            cpu_usage,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        }
    }

    #[test]
    fn no_peers_stays_local() {
        assert_eq!(Scheduler::new().choose(&[], &local(50.0, 0)), None);
    }

    #[test]
    fn selects_significantly_less_loaded_peer() {
        let peers = vec![peer(7, 20.0), peer(8, 40.0)];
        assert_eq!(Scheduler::new().choose(&peers, &local(50.0, 0)), Some(7));
    }

    #[test]
    fn does_not_select_high_load_peer() {
        let peers = vec![peer(7, 90.0)];
        assert_eq!(Scheduler::new().choose(&peers, &local(50.0, 0)), None);
    }

    #[test]
    fn queued_backlog_can_use_idle_peer() {
        let peers = vec![peer(7, 40.0)];
        assert_eq!(Scheduler::new().choose(&peers, &local(60.0, 2)), Some(7));
    }

    #[test]
    fn equal_load_selection_is_independent_of_peer_order() {
        for peers in [
            vec![peer(8, 20.0), peer(7, 20.0)],
            vec![peer(7, 20.0), peer(8, 20.0)],
        ] {
            assert_eq!(Scheduler::new().choose(&peers, &local(50.0, 0)), Some(7));
            assert_eq!(Scheduler::new().choose(&peers, &local(20.0, 2)), Some(7));
        }
    }

    #[test]
    fn invalid_cpu_samples_cannot_displace_a_valid_peer() {
        for invalid in [f32::NAN, f32::NEG_INFINITY, f32::INFINITY, -1.0, 101.0] {
            let peers = vec![peer(1, invalid), peer(7, 20.0)];
            assert_eq!(Scheduler::new().choose(&peers, &local(50.0, 0)), Some(7));
            assert_eq!(
                Scheduler::new().choose(&[peer(1, invalid)], &local(50.0, 2)),
                None
            );
        }
    }
}
