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
    /// 规则 (Phase 5 初版):
    /// - 若本机排队任务多 (>= 3) 且存在 CPU 明显更低的 peer (< 40%)，选那个 peer。
    /// - 若本机也有空 (排队少)，优先本地执行 (None)。
    /// - 否则选 CPU 最低的 peer。
    /// 返回 None 表示本地执行。
    pub fn choose(&self, peers: &[PeerState], local: &LocalState) -> Option<u64> {
        // 没有 peer → 本地
        if peers.is_empty() {
            return None;
        }

        // 找到 CPU 最低的 peer
        let best = peers
            .iter()
            .filter(|p| p.cpu_usage < 80.0) // 排除已高负载的
            .min_by(|a, b| a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap_or(std::cmp::Ordering::Equal));

        match best {
            Some(p) if p.cpu_usage < 40.0 && local.cpu_usage > 60.0 => Some(p.id), // 本机忙，peer 闲
            Some(p) if p.cpu_usage < local.cpu_usage - 20.0 && local.queued_jobs >= 3 => Some(p.id), // 本机排队，peer 更闲
            _ => None, // 否则本地
        }
    }
}
