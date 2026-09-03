use serde::{Deserialize, Serialize};
use std::time::Instant;

/// 单个 peer 的状态表项 —— 我们“知道”的关于某个 Sister 的信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub id: u64,
    pub nickname: String,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub addr: String,

    // 本地的观测字段
    #[serde(skip)]
    pub cpu_usage: f32,
    #[serde(skip)]
    pub memory_total: u64,
    #[serde(skip)]
    pub memory_used: u64,
    #[serde(skip)]
    pub running_jobs: usize,
    #[serde(skip)]
    pub queued_jobs: usize,
    #[serde(skip)]
    pub uptime_secs: u64,
    #[serde(skip)]
    pub capabilities: Vec<String>,
}

/// 持久化用的最小化 peer 描述 (写入 peers.json，供独立进程解析)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerBlueprint {
    pub id: u64,
    pub addr: String,
    pub nickname: String,
    pub hostname: String,
    pub platform: String,
    pub version: String,
}

impl From<&PeerState> for PeerBlueprint {
    fn from(p: &PeerState) -> Self {
        Self {
            id: p.id,
            addr: p.addr.clone(),
            nickname: p.nickname.clone(),
            hostname: p.hostname.clone(),
            platform: p.platform.clone(),
            version: p.version.clone(),
        }
    }
}

/// Peer 表，维护当前节点已知的所有 neighbor 状态 (in-memory, deterministic).
///
/// 只负责内存知识；文件系统持久化由运行时层的 PeerStore 分离处理。
#[derive(Debug, Clone, Default)]
pub struct PeerStateTable {
    peers: std::collections::HashMap<u64, PeerState>,
    /// 记录每个 peer 最后一次收到消息的时间，用于 offline 检测
    last_seen: std::collections::HashMap<u64, Instant>,
}

impl PeerStateTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, state: PeerState) {
        self.last_seen.insert(state.id, Instant::now());
        // 保留观测字段
        if let Some(prev) = self.peers.get_mut(&state.id) {
            prev.cpu_usage = state.cpu_usage;
            prev.memory_total = state.memory_total;
            prev.memory_used = state.memory_used;
            prev.running_jobs = state.running_jobs;
            prev.queued_jobs = state.queued_jobs;
            prev.uptime_secs = state.uptime_secs;
            prev.capabilities = state.capabilities;
            // 保留较老的 hostname/addr 变化
            if !state.nickname.is_empty() {
                prev.nickname = state.nickname;
            }
        } else {
            self.peers.insert(state.id, state);
        }
    }

    pub fn contains(&self, id: u64) -> bool {
        self.peers.contains_key(&id)
    }

    pub fn get(&self, id: u64) -> Option<&PeerState> {
        self.peers.get(&id)
    }

    pub fn all(&self) -> Vec<PeerState> {
        self.peers.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// 移除超过 timeout 未通信的 peers，返回被移除的 id 列表
    pub fn prune_offline(&mut self, timeout: std::time::Duration) -> Vec<u64> {
        let now = Instant::now();
        let mut removed = Vec::new();
        self.peers.retain(|id, _| {
            let alive = self
                .last_seen
                .get(id)
                .is_some_and(|t| now.duration_since(*t) <= timeout);
            if !alive {
                removed.push(*id);
            }
            alive
        });
        // 清理 last_seen
        for id in &removed {
            self.last_seen.remove(id);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(id: u64, addr: &str) -> PeerState {
        PeerState {
            id,
            nickname: format!("misaka-{}", id),
            hostname: "h".into(),
            platform: "p".into(),
            version: "v".into(),
            addr: addr.into(),
            cpu_usage: 10.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        }
    }

    #[test]
    fn insert_update_remove() {
        let mut t = PeerStateTable::new();
        t.upsert(state(1, "127.0.0.1:1"));
        assert!(t.contains(1));
        assert_eq!(t.len(), 1);

        // 更新同名 peer，不重复插入。addr 保持第一次的值 (延续旧语义)。
        t.upsert(state(1, "127.0.0.1:2"));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(1).unwrap().addr, "127.0.0.1:1");

        // 移除离线
        let removed = t.prune_offline(std::time::Duration::from_secs(0));
        assert_eq!(removed, vec![1]);
        assert!(t.is_empty());
    }
}
