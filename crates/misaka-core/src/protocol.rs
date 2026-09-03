use serde::{Deserialize, Serialize};

/// Current version of the encrypted wire envelope.
pub const PROTOCOL_VERSION: u16 = 2;

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
    Ping = 0x08,        // 无副作用的 reachability probe
    Pong = 0x09,        // Ping response
}

/// 网络层封装的消息 (对等)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol_version: u16,
    pub msg_type: MessageType,
    pub from: u64,     // 发送方 Sister ID
    pub to: u64,       // 接收方 Sister ID (0 = 广播)
    pub data: Vec<u8>, // bincode 序列化后的具体 payload
}

impl Envelope {
    pub fn new(msg_type: MessageType, from: u64, to: u64, data: Vec<u8>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
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
    /// Optional candidate address for the long-lived stream listener.
    #[serde(default)]
    pub stream_addr: Option<String>,
    /// Optional DER certificate used to pin the secure stream peer.
    #[serde(default)]
    pub stream_certificate: Option<Vec<u8>>,
}

/// 状态 payload —— Sister 上报自身局部状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateData {
    pub identity: super::identity::SisterIdentity,
    /// 发送方自己声明的监听地址，用于建 peer 表 (不要用 TCP 源地址)
    pub listen_addr: String,
    /// Optional candidate address for the long-lived stream listener.
    #[serde(default)]
    pub stream_addr: Option<String>,
    /// Optional DER certificate used to pin the secure stream peer.
    #[serde(default)]
    pub stream_certificate: Option<Vec<u8>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrips_bincode() {
        let env = Envelope::new(MessageType::State, 10032, 0, vec![1, 2, 3]);
        let bytes = bincode::serialize(&env).unwrap();
        let back: Envelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.protocol_version, PROTOCOL_VERSION);
        assert_eq!(back.msg_type, MessageType::State);
        assert_eq!(back.from, 10032);
        assert_eq!(back.data, vec![1, 2, 3]);
    }

    #[test]
    fn job_data_full_command() {
        let j = JobData {
            id: "j1".into(),
            creator: 1,
            executor: 0,
            creator_addr: "127.0.0.1:1".into(),
            command: "echo".into(),
            arguments: vec!["a".into(), "b".into()],
            created_at: 0,
        };
        assert_eq!(j.full_command(), "echo a b");
    }
}
