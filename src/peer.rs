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

/// Peer 表，维护当前节点已知的所有 neighbor 状态
#[derive(Debug, Clone)]
pub struct PeerStateTable {
    peers: std::collections::HashMap<u64, PeerState>,
    /// 记录每个 peer 最后一次收到消息的时间，用于 offline 检测
    last_seen: std::collections::HashMap<u64, Instant>,
}

impl PeerStateTable {
    pub fn new() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            last_seen: std::collections::HashMap::new(),
        }
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

    /// 把所有已知 peers 序列化持久化到磁盘 (供独立进程解析地址)
    pub fn save_to_file(&self) -> std::io::Result<()> {
        let dir = crate::identity::SisterIdentity::config_dir()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("peers.json");
        let blues: Vec<PeerBlueprint> = self.peers.values().map(PeerBlueprint::from).collect();
        let json = serde_json::to_string_pretty(&blues)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    /// 从磁盘加载已知 peers 的地址映射 (供独立进程使用)
    pub fn load_from_file() -> Vec<PeerBlueprint> {
        let dir = if let Ok(d) = crate::identity::SisterIdentity::config_dir() {
            d
        } else {
            return vec![];
        };
        let path = dir.join("peers.json");
        if !path.exists() {
            return vec![];
        }
        let json = match std::fs::read_to_string(&path) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        serde_json::from_str(&json).unwrap_or_default()
    }
}

impl Default for PeerStateTable {
    fn default() -> Self {
        Self::new()
    }
}
