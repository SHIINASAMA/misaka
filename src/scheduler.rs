use crate::peer::PeerState;
use crate::state::LocalState;

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
    /// - 存在 CPU 明显更低 (至少低 15%) 的 peer → 派给 CPU 最低者
    /// - 否则本地
    pub fn choose(&self, peers: &[PeerState], local: &LocalState) -> Option<u64> {
        if peers.is_empty() {
            return None;
        }

        // 找 CPU 最低的 peer (排除高负载 > 85%)
        let best = peers
            .iter()
            .filter(|p| p.cpu_usage < 85.0)
            .min_by(|a, b| a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap_or(std::cmp::Ordering::Equal));

        match best {
            // peer 比本机明显更闲 → 派给它
            Some(p) if p.cpu_usage < local.cpu_usage - 15.0 => Some(p.id),
            // 本机排队任务积压且 peer 有空闲 → 派给它
            Some(p) if local.queued_jobs >= 2 && p.cpu_usage < 50.0 => Some(p.id),
            _ => None, // 否则本地
        }
    }
}
