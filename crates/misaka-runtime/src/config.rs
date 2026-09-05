use misaka_core::{NetworkId, PeerRecord};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::authenticated_session::AuthenticatedSessionConfig;
use crate::enrollment::EnrollmentServer;

#[derive(Debug, Clone)]
pub enum StreamSecurity {
    /// The development-only raw stream, restricted to loopback.
    InsecureLoopback,
    /// TLS 1.3/mTLS with an explicitly provisioned peer trust set.
    MutualTls {
        identity: misaka_network::tls::TlsIdentity,
        trusted_peer_certificates: Vec<Vec<u8>>,
    },
}

/// Transport backend used by the optional long-lived stream listener.
///
/// The `RuntimeConfig::default()` here is DirectTcp purely for internal/test
/// construction convenience — it is NOT the user-facing default. The `misaka
/// start` CLI defaults to Iroh (see the CLI `--stream-backend` arg); DirectTcp
/// is retained as a compatibility / debug path. Iroh owns its own endpoint
/// identity, encryption, and path selection.
#[derive(Clone, Debug, Default)]
pub enum StreamBackend {
    #[default]
    DirectTcp,
    Iroh(misaka_network::IrohBackend),
}

impl StreamSecurity {
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::MutualTls { .. })
    }
}

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
    /// Namespace of the independent Misaka Network this Sister belongs to.
    pub network_id: NetworkId,
    /// 监听端口
    pub listen_port: u16,
    /// 实验性 Network Stream 监听端口 (None = 禁用)
    pub stream_port: Option<u16>,
    /// Backend for the optional Network Stream listener.
    pub stream_backend: StreamBackend,
    /// Stream security mode. Raw streams remain loopback-only by default.
    pub stream_security: StreamSecurity,
    /// Keep the stream listener limited to raw probes; reject transfer/tunnel preambles.
    pub probe_only: bool,
    /// Optional authenticated Iroh session material. When present, Iroh
    /// streams must complete ClientHello/ServerHello before services run.
    pub authenticated_session: Option<AuthenticatedSessionConfig>,
    /// Optional enrollment service. When present, a Sister that holds the
    /// Network Authority private key answers the enrollment ALPN by redeeming
    /// timed invites into ordinary memberships. Never set without the authority
    /// private key, and never served by a Gateway.
    pub enrollment: Option<EnrollmentServer>,
    /// Explicit compatibility switch for local development scenarios that do
    /// not provision Human identity material. Production defaults to fail
    /// closed for every side-effecting remote operation.
    pub allow_unauthenticated_operations: bool,
    /// The local signed locator shared during Network Knowledge exchange.
    pub peer_record: Option<PeerRecord>,
    /// Gateway base URLs this Sister announces to and discovers through. Empty
    /// means Gateway discovery is off. Multiple entries are announced to and
    /// fetched from independently (no cross-Gateway replication).
    pub gateways: Vec<String>,
    /// How often to announce + fetch peers from each Gateway.
    pub gateway_interval: Duration,
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

    /// 运行时优雅停止的最大等待时间
    pub shutdown_timeout: Duration,

    /// 发现模式
    pub discovery: DiscoveryMode,

    /// 只读 introspection 监听地址 (None = 禁用，默认)
    pub introspection_addr: Option<SocketAddr>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            network_id: NetworkId::default(),
            listen_port: 31700,
            stream_port: None,
            stream_backend: StreamBackend::DirectTcp,
            stream_security: StreamSecurity::InsecureLoopback,
            probe_only: false,
            authenticated_session: None,
            enrollment: None,
            allow_unauthenticated_operations: false,
            peer_record: None,
            gateways: Vec::new(),
            gateway_interval: Duration::from_secs(120),
            advertise_host: None,
            // 数据目录在 CLI 层通过 MISAKA_CONFIG_DIR 决定；这里放默认值
            data_dir: PathBuf::from("."),
            heartbeat_interval: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(60),
            steal_interval: Duration::from_secs(4),
            cleanup_interval: Duration::from_secs(15),
            executor_poll_interval: Duration::from_millis(200),
            job_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(3),
            discovery: DiscoveryMode::Mdns,
            introspection_addr: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeConfig, StreamBackend};
    use misaka_core::NetworkId;

    #[test]
    fn stream_listener_is_opt_in() {
        assert_eq!(RuntimeConfig::default().stream_port, None);
    }

    #[test]
    fn stream_backend_defaults_to_direct_tcp() {
        assert!(matches!(
            RuntimeConfig::default().stream_backend,
            StreamBackend::DirectTcp
        ));
    }

    #[test]
    fn runtime_config_defaults_to_the_compatibility_network_namespace() {
        assert_eq!(RuntimeConfig::default().network_id, NetworkId::default());
    }
}
