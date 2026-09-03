use crate::resources::detect_capabilities;
use misaka_core::{JobStatus, ResourceSnapshot};
use serde::{Deserialize, Serialize};

/// 本地资源状态，由资源 provider 提供系统指标。
#[derive(Debug, Clone)]
pub struct LocalState {
    pub cpu_usage: f32,
    pub memory_total: u64, // bytes
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

impl LocalState {
    pub fn new() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: detect_capabilities(),
        }
    }

    /// 应用资源 provider 的最新快照。
    pub fn apply_snapshot(&mut self, snapshot: ResourceSnapshot) {
        self.cpu_usage = snapshot.cpu_usage;
        self.memory_total = snapshot.memory_total;
        self.memory_used = snapshot.memory_used;
        self.running_jobs = snapshot.running_jobs;
        self.queued_jobs = snapshot.queued_jobs;
        self.uptime_secs = snapshot.uptime_secs;
        self.capabilities = snapshot.capabilities;
    }
}

impl Default for LocalState {
    fn default() -> Self {
        Self::new()
    }
}

/// 记录本地任务的运行状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalJob {
    pub id: String,
    pub command: String,
    pub status: JobStatus,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub result_output: Option<String>,
    /// 任务的发起方 (本机 id 表示本地创建)
    pub creator: u64,
    /// 执行完成后把结果回送的地址 (远端委派时使用)
    pub creator_addr: Option<String>,
}

impl LocalJob {
    pub fn new(id: String, command: String) -> Self {
        Self {
            id,
            command,
            status: JobStatus::Queued,
            started_at: None,
            finished_at: None,
            result_output: None,
            creator: 0, // 默认本地 (caller 显式设置)
            creator_addr: None,
        }
    }
}
