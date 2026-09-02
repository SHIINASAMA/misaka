use serde::{Deserialize, Serialize};

pub const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// 本地资源状态,由 sysinfo 定期刷新
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

    /// 刷新系统指标
    pub fn refresh(&mut self, system: &mut sysinfo::System) {
        // sysinfo 0.30 API:
        // - refresh_cpu() 刷新 CPU 使用率
        // - global_cpu_info() 返回 &Cpu，其 cpu_usage() 返回 f32
        // - total_memory() / used_memory() 单位是字节
        // - uptime 使用 System::uptime()
        system.refresh_cpu();
        system.refresh_memory();
        self.cpu_usage = system.global_cpu_info().cpu_usage();
        self.memory_total = system.total_memory();
        self.memory_used = system.used_memory();
        self.uptime_secs = sysinfo::System::uptime();
    }
}

fn detect_capabilities() -> Vec<String> {
    let mut caps = Vec::new();
    if std::env::consts::OS == "macos" || std::env::consts::OS == "linux" {
        caps.push("posix-shell".into());
    }
    caps.push("unknown".into());
    caps
}

/// 记录本地任务的运行状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalJob {
    pub id: String,
    pub command: String,
    pub status: String, // queued | running | completed | failed
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
            status: "queued".into(),
            started_at: None,
            finished_at: None,
            result_output: None,
            creator: 0, // 默认本地 (caller 显式设置)
            creator_addr: None,
        }
    }
}
