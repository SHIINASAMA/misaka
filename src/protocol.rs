use serde::{Deserialize, Serialize};

/// 消息类型枚举 (对等网络，无主从之分)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Hello = 0x01,       // 握手：交换身份
    Heartbeat = 0x02,   // 心跳
    State = 0x03,       // 状态上报
    Job = 0x04,         // 下发任务
    JobRequest = 0x05,  // 请求任务 (Work Stealing)
    JobResponse = 0x06, // 任务结果返回
    Ack = 0x07,         // 通用确认
}

/// 网络层封装的消息 (对等)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub msg_type: MessageType,
    pub from: u64,   // 发送方 Sister ID
    pub to: u64,     // 接收方 Sister ID (0 = 广播)
    pub data: Vec<u8>, // bincode 序列化后的具体 payload
}

impl Envelope {
    pub fn new(msg_type: MessageType, from: u64, to: u64, data: Vec<u8>) -> Self {
        Self {
            msg_type,
            from,
            to,
            data,
        }
    }
}

/// 握手 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloData {
    pub identity: super::identity::SisterIdentity,
    /// 发送方自己声明的监听地址，用于建 peer 表 (不要用 TCP 源地址)
    pub listen_addr: String,
}

/// 状态 payload —— Sister 上报自身局部状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateData {
    pub identity: super::identity::SisterIdentity,
    /// 发送方自己声明的监听地址，用于建 peer 表 (不要用 TCP 源地址)
    pub listen_addr: String,
    pub cpu_usage: f32,
    pub memory_total: u64,
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

/// 任务 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobData {
    pub id: String,
    pub creator: u64,
    /// 预期执行者 (0 = 由接收方自行决定)
    pub executor: u64,
    pub creator_addr: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub created_at: u64,
}

impl JobData {
    pub fn full_command(&self) -> String {
        if self.arguments.is_empty() {
            self.command.clone()
        } else {
            format!("{} {}", self.command, self.arguments.join(" "))
        }
    }
}

/// 任务结果 payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResultData {
    pub job_id: String,
    pub creator: u64,
    pub executor: u64,
    pub output: String,
    pub exit_code: i32,
    pub success: bool,
    pub started_at: u64,
    pub finished_at: u64,
}
