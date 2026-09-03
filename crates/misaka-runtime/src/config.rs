use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// 发现模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    /// 通过 mDNS 自动发现 (默认，局域网)
    Mdns,
    /// 只使用 --peer 手工指定地址
    Manual,
    /// 关闭发现
    Off,
}

/// Sister 运行配置。
///
/// 所有定时器/端口/目录集中在此，避免散落在运行时循环里。
/// Testament (外部 harness) 可提供短而确定性的间隔，无需等待真实超时。
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// 监听端口
    pub listen_port: u16,
    /// 告知 peer 的对外地址 (None = 用 listen_port 在回环/本机)
    pub advertise_host: Option<IpAddr>,
    /// 数据目录 (persistent identity/peers)
    pub data_dir: PathBuf,

    /// 心跳/状态广播间隔
    pub heartbeat_interval: Duration,
    /// 判定 peer 离线的时间
    pub peer_timeout: Duration,
    /// 工作窃取检查间隔
    pub steal_interval: Duration,
    /// 离线清理检查间隔
    pub cleanup_interval: Duration,
    /// 任务队列空闲轮询间隔
    pub executor_poll_interval: Duration,
    /// 远端任务等待结果的最大时长
    pub job_timeout: Duration,

    /// 发现模式
    pub discovery: DiscoveryMode,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            listen_port: 31700,
            advertise_host: None,
            // 数据目录在 CLI 层通过 MISAKA_CONFIG_DIR 决定；这里放默认值
            data_dir: PathBuf::from("."),
            heartbeat_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(60),
            steal_interval: Duration::from_secs(4),
            cleanup_interval: Duration::from_secs(15),
            executor_poll_interval: Duration::from_millis(200),
            job_timeout: Duration::from_secs(60),
            discovery: DiscoveryMode::Mdns,
        }
    }
}
