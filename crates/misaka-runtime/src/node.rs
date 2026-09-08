use crate::config::{RuntimeConfig, StreamBackend};
use crate::crypto::Crypto;
use crate::gateway_client::GatewayClient;
use crate::job_manager::JobManager;
use crate::network::PeerTransport;
use crate::peer_registry::PeerRegistry;
use crate::peer_service::PeerService;
use crate::peer_store::PeerStore;
use crate::resources::{ResourceProvider, SysinfoResourceProvider};
use crate::scheduler::Scheduler;
use crate::shutdown::ShutdownToken;
use crate::state::{LocalJob, LocalState};
use crate::stream_registry::StreamRegistry;
use misaka_core::introspection::{IntrospectionSnapshot, ResourceSnapshot};
use misaka_core::protocol::*;
use misaka_core::{
    CommandAuthorization, IrohEndpointId, NetworkId, PeerRecord, PeerState, Principal,
    SisterIdentity,
};
use misaka_network::NetworkEndpoint;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

/// 一个完整的对等节点 —— 既是 server 也是 client。
/// 没有任何主从身份：每个 Sister 都能独立工作、发现彼此、共享状态、收发任务。
#[derive(Clone)]
pub struct SisterNode {
    pub identity: Arc<SisterIdentity>,
    encryption_key: [u8; 32],
    /// 运行配置 (集中定时器/端口)
    pub config: RuntimeConfig,

    pub bind_addr: SocketAddr,

    /// 本节点对外可访问的地址 (用于告诉 peer 往哪儿连)
    pub listen_addr: SocketAddr,

    /// 已知的所有 peer 状态 (Network Knowledge)，由 PeerService 独占。
    pub peers: PeerService,

    /// JobManager 独占本地 job metadata、queue 与 pending results。
    pub jobs: JobManager,

    /// 本机资源状态 (定期刷新)
    pub local_state: Arc<tokio::sync::RwLock<LocalState>>,

    /// 调度器
    pub scheduler: Arc<Scheduler>,

    /// 网络收发原语。
    pub(crate) transport: PeerTransport,

    /// 运行时统一取消 token。
    pub(crate) shutdown: ShutdownToken,

    /// In-memory active stream telemetry; never persisted or advertised.
    pub(crate) stream_registry: StreamRegistry,

    /// Serializes durable authorization nonce updates within this Sister.
    pub(crate) authorization_nonce_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SisterNode {
    pub fn new(identity: SisterIdentity, encryption_key: [u8; 32], config: RuntimeConfig) -> Self {
        let data_dir = config.data_dir.clone();
        let port = config.listen_port;
        // §17: the legacy fixed-key Direct-TCP control plane fails closed to
        // loopback by default. It only binds all interfaces when the operator
        // explicitly asked for a non-loopback advertisement (LAN/debug intent)
        // or runs probe-only. Iroh is the normal transport; this is the
        // compatibility path and should not accidentally expose the fixed-key
        // protocol on a public interface.
        let bind_host = if config.probe_only || config.advertise_host.is_none() {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        };
        let bind_addr: SocketAddr = format!("{bind_host}:{port}").parse().unwrap();
        // 告知 peer 的连接地址: 单机测试用 127.0.0.1; 局域网环境可换成机器 IP。
        let listen_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // 启动时立刻刷新一次本机状态
        let mut local_state = LocalState::new();
        let mut resource_provider = SysinfoResourceProvider::new();
        local_state.apply_snapshot(resource_provider.snapshot());

        // 从磁盘 seed 已知 peers (供 run 独立进程复用地址)
        let seeded = PeerStore::load_from_dir(&data_dir)
            .into_iter()
            .filter(|bp| bp.network_id == config.network_id)
            .map(|bp| PeerState {
                network_id: bp.network_id,
                id: bp.id,
                nickname: bp.nickname,
                hostname: bp.hostname,
                platform: bp.platform,
                version: bp.version,
                stream_endpoints: bp.stream_endpoints,
                stream_certificate: bp.stream_certificate,
                addr: bp.addr,
                cpu_usage: 0.0,
                memory_total: 0,
                memory_used: 0,
                running_jobs: 0,
                queued_jobs: 0,
                uptime_secs: 0,
                capabilities: vec![],
            })
            .collect();
        let peers = PeerService::new_with_network_id(
            PeerRegistry::new_seeded(seeded),
            data_dir,
            config.network_id,
        );

        Self {
            identity: Arc::new(identity),
            encryption_key,
            config,
            bind_addr,
            listen_addr,
            peers,
            jobs: JobManager::new(),
            local_state: Arc::new(tokio::sync::RwLock::new(local_state)),
            scheduler: Arc::new(Scheduler::new()),
            transport: PeerTransport::new(Crypto::new(&encryption_key).unwrap()),
            shutdown: ShutdownToken::never(),
            stream_registry: StreamRegistry::default(),
            authorization_nonce_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// 将 runtime 创建的统一取消 token 注入 node。
    pub fn set_shutdown_token(&mut self, token: ShutdownToken) {
        self.shutdown = token;
    }

    /// 让本节点能感知局域网中其他 Sister，需要本机真实 IP (非 127.0.0.1)。
    /// 单机测试时保持 127.0.0.1 即可；跨机部署时暴露本机局域网 IP。
    pub fn set_advertise_host(&mut self, host: &str) {
        let bind_host = if self.config.probe_only {
            "127.0.0.1"
        } else {
            "0.0.0.0"
        };
        self.bind_addr = format!("{bind_host}:{}", self.config.listen_port)
            .parse()
            .unwrap();
        self.listen_addr = format!("{}:{}", host, self.config.listen_port)
            .parse()
            .unwrap();
    }

    /// Current stream endpoint candidate, kept separate from the control address.
    pub fn stream_addr(&self) -> Option<SocketAddr> {
        if matches!(&self.config.stream_backend, StreamBackend::Iroh(_)) {
            return None;
        }
        let candidate = self
            .config
            .stream_port
            .map(|port| SocketAddr::new(self.listen_addr.ip(), port));
        candidate.filter(|addr| addr.ip().is_loopback() || self.config.stream_security.is_secure())
    }

    pub fn stream_endpoint(&self) -> Option<String> {
        match &self.config.stream_backend {
            StreamBackend::DirectTcp => self.stream_addr().map(|addr| format!("tcp://{addr}")),
            StreamBackend::Iroh(backend) => {
                Some(NetworkEndpoint::Iroh(backend.endpoint_addr()).to_string())
            }
        }
    }

    pub fn stream_certificate(&self) -> Option<Vec<u8>> {
        match &self.config.stream_security {
            crate::config::StreamSecurity::InsecureLoopback => None,
            crate::config::StreamSecurity::MutualTls { identity, .. } => {
                Some(identity.certificate_der().to_vec())
            }
        }
    }

    pub fn get_crypto(&self) -> Crypto {
        Crypto::new(&self.encryption_key).unwrap()
    }

    // ---------- introspection (只读观测面) ----------

    /// 组装当前只读 snapshot (供 Testament 等外部 harness 观测)
    pub async fn introspection_snapshot(&self) -> IntrospectionSnapshot {
        let resources = {
            let s = self.local_state.read().await;
            ResourceSnapshot {
                cpu_usage: s.cpu_usage,
                memory_total: s.memory_total,
                memory_used: s.memory_used,
                running_jobs: s.running_jobs,
                queued_jobs: s.queued_jobs,
                uptime_secs: s.uptime_secs,
                capabilities: s.capabilities.clone(),
            }
        };
        let peers = self.peers.peer_snapshots().await;
        let jobs = self.jobs.job_snapshots().await;
        let queue_depth = self.jobs.queue_len();
        let active_streams = self.stream_registry.snapshot();
        let stream_summary = self.stream_registry.summary();
        IntrospectionSnapshot {
            network_id: self.config.network_id,
            identity: self.identity.as_ref().clone(),
            resources,
            peers,
            jobs,
            queue_depth,
            active_streams,
            stream_summary,
        }
    }

    /// 在给定地址上启动只读 introspection 服务器 (loopback)。返回实际绑定地址。
    pub async fn spawn_introspection_server(&self, bind: SocketAddr) -> crate::Result<SocketAddr> {
        let me = self.clone();
        let addr = crate::introspection::spawn_server(
            bind,
            move || {
                let me = me.clone();
                Box::pin(async move { me.introspection_snapshot().await })
            },
            self.shutdown.clone(),
        )
        .await?;
        Ok(addr)
    }

    // ---------- 网络层原语 ----------

    /// 打开一条短连接发送 envelope，等待一条响应
    pub async fn send_to(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<Envelope> {
        self.transport.send_to(addr, env).await
    }

    /// Bootstrap the Iroh control plane from one explicit endpoint. The peer
    /// identity is learned from the authenticated Hello response; no legacy
    /// TCP control listener is required.
    pub async fn add_known_iroh_peer(&self, endpoint: NetworkEndpoint) -> crate::Result<()> {
        self.connect_iroh(endpoint, None, None).await
    }

    /// Connect to an Iroh endpoint and run the authenticated Hello. When
    /// `expected_sister_id` / `expected_sister_public_key` are set, the handshake
    /// is pinned to that identity, so a peer presenting a different (or unsigned)
    /// identity — or the right id under a different key — is rejected.
    async fn connect_iroh(
        &self,
        endpoint: NetworkEndpoint,
        expected_sister_id: Option<u64>,
        expected_sister_public_key: Option<misaka_core::SisterPublicKey>,
    ) -> crate::Result<()> {
        let NetworkEndpoint::Iroh(endpoint) = endpoint else {
            return Err(crate::Error::Other(
                "Iroh bootstrap requires an iroh:// endpoint".to_string(),
            ));
        };
        let StreamBackend::Iroh(backend) = &self.config.stream_backend else {
            return Err(crate::Error::Other(
                "Iroh bootstrap requires the Iroh stream backend".to_string(),
            ));
        };
        let reply = crate::control_channel::send(
            backend,
            NetworkEndpoint::Iroh(endpoint),
            self.config.network_id,
            self.config.authenticated_session.as_ref(),
            &self.hello_envelope_to(expected_sister_id.unwrap_or(0))?,
            true,
            expected_sister_public_key,
        )
        .await
        .map_err(|error| crate::Error::Network(error.to_string()))?
        .ok_or_else(|| crate::Error::Network("Iroh Hello returned no response".to_string()))?;
        self.record_hello_reply(reply).await
    }

    /// Bootstrap the authenticated Iroh control plane from a signed `PeerRecord`
    /// obtained from a Gateway. This is the v0 discovery path and the reason the
    /// Gateway exists — a Sister never touches a raw `iroh://` string itself.
    ///
    /// The record is never trusted on faith: it is re-verified, its advertised
    /// endpoint is cross-checked against its own signed `TransportBinding`, the
    /// Hello is pinned to the record's Sister id, and only then is it stored. A
    /// compromised Gateway therefore cannot point us at — or have us accept — a
    /// Sister other than the one the record cryptographically names.
    /// Cheap, dial-free validation of a Gateway-supplied `PeerRecord`: correct
    /// Network, self-verifying signature, and an endpoint that matches its own
    /// signed `TransportBinding`. Used to keep an invalid candidate from winning
    /// the multi-Gateway sequence merge (§8). `bootstrap_peer_record` re-checks
    /// all of this before dialing; this only filters what is worth merging.
    pub(crate) fn peer_record_usable(&self, record: &PeerRecord) -> bool {
        if record.network_id != self.config.network_id || !record.verify() {
            return false;
        }
        match record.endpoint_addr.parse::<NetworkEndpoint>() {
            Ok(NetworkEndpoint::Iroh(addr)) => {
                IrohEndpointId::from_bytes(*addr.id.as_bytes())
                    == record.transport_binding.iroh_endpoint_id
            }
            _ => false,
        }
    }

    pub async fn bootstrap_peer_record(&self, record: PeerRecord) -> crate::Result<()> {
        if record.network_id != self.config.network_id || !record.verify() {
            return Err(crate::Error::Other(
                "rejecting invalid or foreign PeerRecord".to_string(),
            ));
        }
        let endpoint: NetworkEndpoint = record.endpoint_addr.parse().map_err(|error| {
            crate::Error::Other(format!("invalid PeerRecord endpoint: {error}"))
        })?;
        // The dial target must be the endpoint the record itself signed, so a
        // tampered locator cannot redirect the connection.
        let endpoint_matches = match &endpoint {
            NetworkEndpoint::Iroh(addr) => {
                IrohEndpointId::from_bytes(*addr.id.as_bytes())
                    == record.transport_binding.iroh_endpoint_id
            }
            NetworkEndpoint::Tcp(_) => false,
        };
        if !endpoint_matches {
            return Err(crate::Error::Other(
                "PeerRecord endpoint disagrees with its TransportBinding".to_string(),
            ));
        }
        // The dial is pinned to the record's Sister id *and* its signed public
        // key: a peer that authenticates as this id under a different key is an
        // equivocation and is rejected (§2).
        self.connect_iroh(
            endpoint,
            Some(record.sister_id.as_u64()),
            Some(record.sister_public_key),
        )
        .await?;
        self.remember_peer_record(record).await;
        Ok(())
    }

    /// Periodic Gateway discovery: announce the local locator, then fetch and
    /// bootstrap peers from every configured Gateway.
    ///
    /// Announce and fetch hit ALL gateways independently (they never talk to
    /// each other, replicate, or reconcile); the results are merged per Sister
    /// taking the highest `PeerRecord::sequence`. Every Gateway error is logged
    /// as a warning and never aborts the runtime, so Gateway outage cannot take
    /// an already-formed Network down.
    pub async fn gateway_loop(&self) -> crate::Result<()> {
        if self.config.gateways.is_empty() {
            self.shutdown.cancelled().await;
            return Ok(());
        }
        let Some(session) = self.config.authenticated_session.clone() else {
            tracing::warn!(
                "gateway discovery configured but no authenticated session is present; skipping"
            );
            self.shutdown.cancelled().await;
            return Ok(());
        };
        let mut interval = tokio::time::interval(self.config.gateway_interval);
        let mut known: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let mut merged: std::collections::HashMap<u64, PeerRecord> =
                std::collections::HashMap::new();
            for base in &self.config.gateways {
                let client = match GatewayClient::new(
                    base,
                    session.network_id,
                    session.sister_id,
                    session.sister_key.clone(),
                    session.membership_certificate.clone(),
                ) {
                    Ok(client) => client,
                    Err(error) => {
                        tracing::warn!(%base, %error, "gateway client init failed");
                        continue;
                    }
                };
                match client.info().await {
                    Ok(info) if info.network_id != session.network_id => {
                        tracing::warn!(
                            %base,
                            expected = %session.network_id,
                            observed = %info.network_id,
                            "gateway serves a different Network; skipping"
                        );
                        continue;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%base, %error, "gateway info failed");
                        continue;
                    }
                }
                if let Some(local) = self.config.peer_record.as_ref() {
                    if let Err(error) = client.announce(local).await {
                        tracing::warn!(%base, %error, "gateway announce failed");
                    }
                }
                match client.peers().await {
                    Ok(records) => {
                        for record in records {
                            // §8: only a basic-valid candidate may compete for the
                            // highest sequence. A malformed/foreign record from one
                            // Gateway must not suppress a valid record for the same
                            // Sister from another. This is availability hardening,
                            // not Byzantine consensus.
                            if !self.peer_record_usable(&record) {
                                tracing::debug!(
                                    sister_id = record.sister_id.as_u64(),
                                    "discarding an invalid Gateway PeerRecord before merge"
                                );
                                continue;
                            }
                            merge_gateway_candidate(&mut merged, record);
                        }
                    }
                    Err(error) => tracing::warn!(%base, %error, "gateway peer fetch failed"),
                }
            }
            for (id, record) in merged {
                if id == session.sister_id {
                    continue; // never bootstrap ourselves
                }
                let sequence = record.sequence;
                // §9: skip a same-or-older sequence only while the peer is
                // currently known. If it was pruned/went offline and returns with
                // the same sequence, that must still be a recovery path — a
                // "seen once" marker must not permanently suppress re-bootstrap.
                let live = self.peers.get(id).await.is_some();
                if !should_rebootstrap(known.get(&id).copied(), sequence, live) {
                    continue;
                }
                // Only remember the attempt on success; a transient failure must
                // stay retryable on the next cycle (same sequence).
                if let Err(error) = self.bootstrap_peer_record(record).await {
                    tracing::warn!(sister_id = id, %error, "gateway bootstrap failed");
                } else {
                    known.insert(id, sequence);
                }
            }
        }
        Ok(())
    }

    /// 单向发送 (不等待响应)
    pub async fn send_fire(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<()> {
        self.transport.send_fire(addr, env).await
    }

    /// Send a control-plane envelope to a known Sister. Iroh candidates are
    /// preferred when this node is running the Iroh backend; TCP remains the
    /// compatibility fallback while the control-plane migration is staged.
    pub async fn send_to_peer(&self, peer_id: u64, env: &Envelope) -> crate::Result<Envelope> {
        if let Some((backend, endpoint)) = self.iroh_peer_endpoint(peer_id).await {
            let response = crate::control_channel::send(
                backend,
                endpoint,
                self.config.network_id,
                self.config.authenticated_session.as_ref(),
                env,
                true,
                None,
            )
            .await
            .map_err(|error| crate::Error::Network(error.to_string()))?;
            return response.ok_or_else(|| {
                crate::Error::Network("Iroh control channel returned no response".to_string())
            });
        }
        let addr =
            self.peers.addr_of(peer_id).await.ok_or_else(|| {
                crate::Error::Other(format!("no address for executor #{peer_id}"))
            })?;
        self.send_to(addr, env).await
    }

    pub async fn send_fire_to_peer(&self, peer_id: u64, env: &Envelope) -> crate::Result<()> {
        if let Some((backend, endpoint)) = self.iroh_peer_endpoint(peer_id).await {
            crate::control_channel::send(
                backend,
                endpoint,
                self.config.network_id,
                self.config.authenticated_session.as_ref(),
                env,
                false,
                None,
            )
            .await
            .map_err(|error| crate::Error::Network(error.to_string()))?;
            return Ok(());
        }
        let addr = self
            .peers
            .addr_of(peer_id)
            .await
            .ok_or_else(|| crate::Error::Other(format!("no address for Sister #{peer_id}")))?;
        self.send_fire(addr, env).await
    }

    async fn iroh_peer_endpoint(
        &self,
        peer_id: u64,
    ) -> Option<(&misaka_network::IrohBackend, NetworkEndpoint)> {
        let StreamBackend::Iroh(backend) = &self.config.stream_backend else {
            return None;
        };
        if let Some(peer) = self.peers.get(peer_id).await {
            if let Some(endpoint) = peer
                .stream_endpoints
                .into_iter()
                .filter_map(|endpoint| endpoint.parse::<NetworkEndpoint>().ok())
                .find_map(|endpoint| match endpoint {
                    NetworkEndpoint::Iroh(_) => Some(endpoint),
                    NetworkEndpoint::Tcp(_) => None,
                })
            {
                return Some((backend, endpoint));
            }
        }
        self.peers
            .peer_record(peer_id)
            .await
            .and_then(|record| record.endpoint_addr.parse().ok())
            .and_then(|endpoint| match endpoint {
                NetworkEndpoint::Iroh(endpoint) => Some((backend, NetworkEndpoint::Iroh(endpoint))),
                NetworkEndpoint::Tcp(_) => None,
            })
    }

    /// 从 peer 表取一个 peer 的对外地址
    pub async fn peer_addr(&self, id: u64) -> Option<SocketAddr> {
        self.peers.addr_of(id).await
    }

    // ---------- 入站处理 ----------

    pub async fn handle_inbound(
        &self,
        mut stream: TcpStream,
        _addr: SocketAddr,
    ) -> crate::Result<()> {
        let env = self.transport.receive(&mut stream).await?;
        crate::handler::dispatch(self, env, &mut stream).await
    }

    /// 把 hello 里的身份信息存进 peer service。
    pub(crate) async fn remember_peer(
        &self,
        identity: &SisterIdentity,
        network_id: NetworkId,
        listen_addr: &str,
        stream_addr: Option<&str>,
        stream_certificate: Option<Vec<u8>>,
    ) {
        self.peers
            .remember_peer(
                identity,
                network_id,
                listen_addr,
                stream_addr,
                stream_certificate,
            )
            .await;
    }

    /// 手工插入一个 peer (Phase 1 没有 mDNS 时用 --peer 指定)
    pub async fn add_known_peer(&self, addr: SocketAddr) -> crate::Result<()> {
        let env = self.hello_envelope()?;
        let reply = self.send_to(addr, &env).await?;
        self.record_hello_reply(reply).await
    }

    /// Bootstrap a peer discovered through metadata. Iroh discovery must not
    /// fall back to the legacy TCP control address: the endpoint candidate is
    /// the bootstrap transport and the authenticated control channel is the
    /// only protocol path.
    pub async fn add_known_discovered_peer(
        &self,
        peer: &crate::discovery::DiscoveredPeer,
    ) -> crate::Result<()> {
        let env = self.hello_envelope()?;
        let reply = match (&self.config.stream_backend, peer.stream_endpoint.clone()) {
            (StreamBackend::Iroh(backend), Some(NetworkEndpoint::Iroh(endpoint))) => {
                crate::control_channel::send(
                    backend,
                    NetworkEndpoint::Iroh(endpoint),
                    self.config.network_id,
                    self.config.authenticated_session.as_ref(),
                    &env,
                    true,
                    None,
                )
                .await
                .map_err(|error| crate::Error::Network(error.to_string()))?
                .ok_or_else(|| {
                    crate::Error::Network(
                        "Iroh Hello control channel returned no response".to_string(),
                    )
                })?
            }
            _ => self.send_to(peer.control_addr, &env).await?,
        };
        self.record_hello_reply(reply).await
    }

    fn hello_envelope(&self) -> crate::Result<Envelope> {
        self.hello_envelope_to(0)
    }

    fn hello_envelope_to(&self, to: u64) -> crate::Result<Envelope> {
        Ok(Envelope::new(
            self.config.network_id,
            MessageType::Hello,
            self.identity.id.as_u64(),
            to,
            bincode::serialize(&HelloData {
                network_id: self.config.network_id,
                identity: self.identity.as_ref().clone(),
                listen_addr: self.listen_addr.to_string(),
                stream_addr: self.stream_endpoint(),
                stream_certificate: self.stream_certificate(),
            })?,
        ))
    }

    async fn record_hello_reply(&self, reply: Envelope) -> crate::Result<()> {
        if reply.msg_type != MessageType::Hello {
            return Err(crate::Error::Protocol(format!(
                "expected Hello response, got {:?}",
                reply.msg_type
            )));
        }
        let hello: HelloData = bincode::deserialize(&reply.data)?;
        if hello.network_id != self.config.network_id {
            return Err(crate::Error::Protocol(format!(
                "peer belongs to network {} instead of {}",
                hello.network_id, self.config.network_id
            )));
        }
        self.remember_peer(
            &hello.identity,
            hello.network_id,
            &hello.listen_addr,
            hello.stream_addr.as_deref(),
            hello.stream_certificate,
        )
        .await;
        tracing::info!(
            event = "peer_connected",
            sister_id = self.identity.id.as_u64(),
            peer_id = hello.identity.id.as_u64(),
            peer_nickname = %hello.identity.nickname.as_str(),
            peer_addr = %hello.listen_addr,
            "peer handshake completed"
        );
        Ok(())
    }

    pub(crate) async fn remember_peer_record(&self, record: PeerRecord) {
        if record.network_id != self.config.network_id || !record.verify() {
            tracing::debug!(
                peer_id = record.sister_id.as_u64(),
                "ignoring invalid or foreign PeerRecord"
            );
            return;
        }
        let valid_endpoint = record
            .endpoint_addr
            .parse::<NetworkEndpoint>()
            .ok()
            .is_some_and(|endpoint| match endpoint {
                NetworkEndpoint::Iroh(endpoint) => {
                    IrohEndpointId::from_bytes(*endpoint.id.as_bytes())
                        == record.transport_binding.iroh_endpoint_id
                }
                NetworkEndpoint::Tcp(_) => false,
            });
        if !valid_endpoint {
            tracing::debug!(
                peer_id = record.sister_id.as_u64(),
                "ignoring PeerRecord whose endpoint disagrees with its TransportBinding"
            );
            return;
        }
        self.peers.upsert_peer_record(record).await;
    }

    pub(crate) async fn send_peer_records(&self, peer_id: u64) -> crate::Result<()> {
        let mut records = self.peers.peer_records().await;
        if let Some(local) = self.config.peer_record.clone() {
            records.retain(|record| record.sister_id != local.sister_id);
            records.push(local);
        }
        if records.is_empty() {
            return Ok(());
        }
        let envelope = Envelope::new(
            self.config.network_id,
            MessageType::PeerRecords,
            self.identity.id.as_u64(),
            peer_id,
            bincode::serialize(&PeerRecordsData {
                network_id: self.config.network_id,
                records,
            })?,
        );
        self.send_fire_to_peer(peer_id, &envelope).await
    }

    // ---------- 任务提交 (Phase 5 核心) ----------

    /// 提交一个任务。目标由调度器决定；若调度器选 None 则本地执行。
    /// 返回执行结果。
    pub async fn submit_job(&self, command: &str) -> crate::Result<JobResultData> {
        self.submit_job_authorized(command, None).await
    }

    /// Run the scheduler and return the concrete executor for a network job
    /// (self id if it chooses local). Exposed so a Human Authorization can be
    /// bound to the chosen Sister *before* submission (§5).
    pub async fn choose_executor(&self) -> u64 {
        let peer_data = self.peers.all().await;
        let local = { self.local_state.read().await.clone() };
        let target = self.scheduler.choose(&peer_data, &local);
        let creator = self.identity.id.as_u64();
        match target {
            Some(id) if id != creator => id,
            _ => creator,
        }
    }

    /// Build a target-bound JobSubmit Human Authorization from the local
    /// operator material (human identity/key/membership + Network authority) in
    /// this Sister's data dir, mirroring the CLI. Returns `None` when no human
    /// material is present (compatibility / local execution). The authorization
    /// is always bound to `target` — never `target = None` (§14).
    pub fn build_job_submit_authorization(
        &self,
        target: u64,
        command: &str,
    ) -> crate::Result<Option<CommandAuthorization>> {
        use crate::human_identity_store::HumanIdentityStore;
        use crate::revocation_store::RevocationStore;
        let dir = &self.config.data_dir;
        let network_id = self.config.network_id;
        let human = HumanIdentityStore::load(dir)
            .map_err(|error| crate::Error::Other(error.to_string()))?;
        let human_key = HumanIdentityStore::load_key(dir)
            .map_err(|error| crate::Error::Other(error.to_string()))?;
        let membership = HumanIdentityStore::load_membership(dir)
            .map_err(|error| crate::Error::Other(error.to_string()))?;
        if human.is_none() && human_key.is_none() && membership.is_none() {
            return Ok(None);
        }
        let (Some(human), Some(human_key), Some(membership)) = (human, human_key, membership)
        else {
            return Err(crate::Error::Protocol(
                "human authorization requires human-identity.json, human-identity-key, and human-membership.bin"
                    .to_string(),
            ));
        };
        let authority = crate::network_authority_store::NetworkAuthorityStore::load(dir)
            .map_err(|error| crate::Error::Other(error.to_string()))?
            .ok_or_else(|| {
                crate::Error::Protocol("human authorization requires network.json".to_string())
            })?;
        let now = now_secs();
        if authority.network_id != network_id
            || membership.human != human
            || !membership.verify(&authority, now)
            || human_key.public_key() != human.public_key
        {
            return Err(crate::Error::Protocol(
                "local human identity or membership is invalid".to_string(),
            ));
        }
        if RevocationStore::is_revoked(
            dir,
            &authority,
            network_id,
            misaka_core::MembershipKind::Human,
            membership.serial,
        )
        .map_err(|error| crate::Error::Other(error.to_string()))?
        {
            return Err(crate::Error::Protocol(
                "local Human membership has been revoked".to_string(),
            ));
        }
        Ok(Some(CommandAuthorization::issue(
            network_id,
            human,
            membership.clone(),
            membership.role,
            misaka_core::Permission::JobSubmit,
            Some(Principal::Sister(misaka_core::SisterId(target))),
            vec![format!("command={command}")],
            now,
            now.saturating_add(300),
            rand::random(),
            &human_key,
        )))
    }

    /// Resolve the executor (directed or scheduler-chosen), issue a target-bound
    /// authorization, and submit — the single entry point the loopback API uses
    /// so a running Sister submits over authenticated Iroh (§3/§5).
    pub async fn submit_job_remote(
        &self,
        command: &str,
        sister: Option<u64>,
    ) -> crate::Result<JobResultData> {
        let creator = self.identity.id.as_u64();
        let executor = match sister {
            Some(sid) => sid,
            None => self.choose_executor().await,
        };
        if executor == creator {
            // Scheduler chose local (or directed at self): run here, no auth.
            return Ok(self.execute_and_record(&new_job_id(), command).await);
        }
        let authorization = self.build_job_submit_authorization(executor, command)?;
        self.submit_to_sister_authorized(executor, command, authorization)
            .await
    }

    pub async fn submit_job_authorized(
        &self,
        command: &str,
        authorization: Option<CommandAuthorization>,
    ) -> crate::Result<JobResultData> {
        let creator = self.identity.id.as_u64();
        let executor = self.choose_executor().await;

        if executor != creator {
            tracing::info!(
                event = "job_submitted",
                sister_id = self.identity.id.as_u64(),
                executor,
                "job submitted to peer"
            );
        }
        self.submit_to_sister_authorized(executor, command, authorization)
            .await
    }

    /// 请求一个空闲 peer 拿走我们排队中的任务 (Work Stealing)。
    pub async fn request_work_from(&self, peer_id: u64) -> crate::Result<()> {
        let env = Envelope::new(
            self.config.network_id,
            MessageType::JobRequest,
            self.identity.id.as_u64(),
            peer_id,
            vec![],
        );
        let _ = self.send_fire_to_peer(peer_id, &env).await;
        Ok(())
    }

    /// 提交一个任务（就地执行；不返回 JobResultData，执行逻辑由 executor loop 处理）。
    /// run -l 子命令专用：把任务塞进本地队列即可。
    pub async fn submit_local(&self, command: &str) -> crate::Result<()> {
        let job_id = new_job_id();
        let mut job = LocalJob::new(job_id.clone(), command.to_string());
        job.creator = self.identity.id.as_u64();
        self.jobs.enqueue(job).await;
        tracing::info!(
            event = "job_created",
            sister_id = self.identity.id.as_u64(),
            job_id = %job_id,
            "local job queued"
        );
        Ok(())
    }

    /// 提交一个任务到指定 Sister (run --sister)。若目标就是本机则本地执行。
    /// 远端部分会临时开一个响应端口，等结果回来。
    pub async fn submit_to_sister(
        &self,
        executor: u64,
        command: &str,
    ) -> crate::Result<JobResultData> {
        self.submit_to_sister_authorized(executor, command, None)
            .await
    }

    /// Submit a job while preserving a human authorization through remote
    /// forwarding and work stealing.
    pub async fn submit_to_sister_authorized(
        &self,
        executor: u64,
        command: &str,
        authorization: Option<CommandAuthorization>,
    ) -> crate::Result<JobResultData> {
        let my_listen = if executor == self.identity.id.as_u64() {
            self.listen_addr
        } else if matches!(&self.config.stream_backend, StreamBackend::Iroh(_)) {
            // Iroh JobResponse returns through the authenticated control
            // channel; do not create a legacy TCP callback listener.
            self.listen_addr
        } else {
            // Direct TCP compatibility still uses a temporary callback port.
            self.spawn_response_listener().await?
        };

        let job_id = new_job_id();
        let creator = self.identity.id.as_u64();
        let creator_addr = my_listen.to_string();
        let job_data = JobData {
            id: job_id.clone(),
            creator,
            executor,
            creator_addr,
            command: command.to_string(),
            arguments: vec![],
            created_at: now_secs(),
            authorization,
        };

        if executor == creator {
            // 本地
            return Ok(self.execute_and_record(&job_id, command).await);
        }

        let rx = self.jobs.reserve_pending(&job_id);

        let exec_addr = if matches!(&self.config.stream_backend, StreamBackend::Iroh(_)) {
            None
        } else {
            Some(self.peers.addr_of(executor).await.ok_or_else(|| {
                self.jobs.cancel_pending(&job_id);
                crate::Error::Other(format!("no address for executor #{}", executor))
            })?)
        };

        let env = Envelope::new(
            self.config.network_id,
            MessageType::Job,
            creator,
            executor,
            bincode::serialize(&job_data)?,
        );
        let delivery = if matches!(&self.config.stream_backend, StreamBackend::Iroh(_)) {
            self.send_fire_to_peer(executor, &env).await
        } else {
            self.send_fire(exec_addr.expect("Direct TCP executor address"), &env)
                .await
        };
        if let Err(error) = delivery {
            self.jobs.cancel_pending(&job_id);
            return Err(error);
        }

        match tokio::time::timeout(self.config.job_timeout, rx).await {
            Ok(result) => {
                result.map_err(|_| crate::Error::Other(format!("job {} canceled", job_id)))
            }
            Err(_) => {
                self.jobs.cancel_pending(&job_id);
                Err(crate::Error::Other(format!("job {} timed out", job_id)))
            }
        }
    }

    /// 同步在本地执行任务并返回结果 (供 `run` 独立进程使用)。
    pub async fn run_local_sync(&self, command: &str) -> JobResultData {
        let job_id = new_job_id();
        self.execute_and_record_public(&job_id, command).await
    }

    /// 在本地执行并记录任务状态，返回结果 (公开封装)
    pub async fn execute_and_record_public(&self, job_id: &str, command: &str) -> JobResultData {
        self.execute_and_record(job_id, command).await
    }

    /// 在本地执行并记录任务状态，返回结果
    async fn execute_and_record(&self, job_id: &str, command: &str) -> JobResultData {
        let started = now_secs();
        let mut job = LocalJob::new(job_id.to_string(), command.to_string());
        job.creator = self.identity.id.as_u64();
        self.jobs.start_inline(job, started).await;
        tracing::info!(
            event = "job_started",
            sister_id = self.identity.id.as_u64(),
            job_id = %job_id,
            "job execution started"
        );
        let result = crate::executor::execute_blocking(command.to_string()).await;
        let finished = now_secs();

        let job_result = JobResultData {
            job_id: job_id.to_string(),
            creator: self.identity.id.as_u64(),
            executor: self.identity.id.as_u64(),
            output: result.full_output(),
            exit_code: result.exit_code,
            success: result.success(),
            started_at: started,
            finished_at: finished,
        };

        self.jobs.mark_finished(job_id, &job_result).await;
        if result.success() {
            tracing::info!(
                event = "job_completed",
                sister_id = self.identity.id.as_u64(),
                job_id = %job_id,
                success = true,
                exit_code = result.exit_code,
                output_bytes = job_result.output.len(),
                "local job finished"
            );
        } else {
            tracing::warn!(
                event = "job_failed",
                sister_id = self.identity.id.as_u64(),
                job_id = %job_id,
                success = false,
                exit_code = result.exit_code,
                output_bytes = job_result.output.len(),
                "local job failed"
            );
        }
        job_result
    }

    /// mDNS 广播 + 发现循环。注册本 Sister 服务，并持续把发现的 peer 收进 peer 表。
    pub async fn mdns_loop(&self) -> crate::Result<()> {
        let (advertise_guard, mut rx) = {
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let s = match crate::discovery::advertise(
                self.identity.nickname.as_str(),
                self.identity.id.as_u64(),
                self.config.network_id,
                &self.identity.hostname,
                &self.identity.platform,
                self.listen_addr,
                self.stream_addr().map(|addr| addr.port()),
                self.stream_endpoint(),
                tx,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        event = "discovery_advertise_failed",
                        error = ?e,
                        "mDNS advertisement failed"
                    );
                    return Ok(());
                }
            };
            (s, rx)
        };

        tracing::info!(
            event = "discovery_started",
            sister_id = self.identity.id.as_u64(),
            nickname = %self.identity.nickname.as_str(),
            listen_addr = %self.listen_addr,
            "mDNS advertisement started"
        );

        loop {
            let instance = tokio::select! {
                _ = self.shutdown.cancelled() => None,
                instance = rx.recv() => instance,
            };
            let Some(instance) = instance else { break };
            // 忽略自己 (instance 名等于本机 nickname; 同时 id 相同则跳过)
            if let Some(peer) = crate::discovery::instance_to_peer(&instance) {
                let peer_id = peer.id;
                let addr = peer.control_addr;
                if peer_id == self.identity.id.as_u64() {
                    continue;
                }
                if peer.network_id != self.config.network_id {
                    continue;
                }
                // 已有记录且地址没变，跳过
                let discovered_endpoint = peer.stream_endpoint.clone();
                let endpoint_known = self.peers.get(peer_id).await.is_some_and(|known| {
                    known.stream_endpoints
                        == discovered_endpoint
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                });
                if self.peers.addr_of(peer_id).await == Some(addr) && endpoint_known {
                    continue;
                }
                // 新 peer：握手建立连接，写进 peer 表
                if let Some(nick) = instance.attributes.get(crate::discovery::TXT_NICK) {
                    let nick = nick
                        .clone()
                        .unwrap_or_else(|| format!("misaka-{}", peer_id));
                    let host = instance
                        .attributes
                        .get(crate::discovery::TXT_HOST)
                        .cloned()
                        .flatten()
                        .unwrap_or_default();
                    let platform = instance
                        .attributes
                        .get(crate::discovery::TXT_PLATFORM)
                        .cloned()
                        .flatten()
                        .unwrap_or_default();
                    tracing::info!(
                        event = "peer_discovered",
                        sister_id = self.identity.id.as_u64(),
                        peer_id,
                        nickname = %nick,
                        peer_addr = %addr,
                        "mDNS peer discovered"
                    );
                    // 握手。Iroh 节点完全走 Iroh control channel；Direct
                    // TCP 节点继续使用旧的 control address。
                    if let Err(error) = self.add_known_discovered_peer(&peer).await {
                        tracing::warn!(
                            event = "peer_handshake_failed",
                            sister_id = self.identity.id.as_u64(),
                            peer_id,
                            error = %error,
                            "discovered peer handshake failed"
                        );
                        continue;
                    }
                    // 记录 host/platform (handshake 会更新 version 等，这里补齐 host/platform)
                    self.peers
                        .upsert(PeerState {
                            network_id: peer.network_id,
                            id: peer_id,
                            nickname: nick,
                            hostname: host,
                            platform,
                            version: String::new(),
                            stream_endpoints: peer
                                .stream_endpoint
                                .into_iter()
                                .map(|endpoint| endpoint.to_string())
                                .collect(),
                            stream_certificate: None,
                            addr: addr.to_string(),
                            cpu_usage: 0.0,
                            memory_total: 0,
                            memory_used: 0,
                            running_jobs: 0,
                            queued_jobs: 0,
                            uptime_secs: 0,
                            capabilities: vec![],
                        })
                        .await;
                }
            }
        }

        // keep guard alive (unreachable normally)
        let _ = advertise_guard;
        Ok(())
    }

    // ---------- 后台循环 ----------

    /// 启动监听，返回 listener
    pub async fn start_listener(&self) -> crate::Result<TcpListener> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        tracing::info!(
            event = "sister_started",
            sister_id = self.identity.id.as_u64(),
            listen_addr = %self.bind_addr,
            "Sister listener started"
        );
        Ok(listener)
    }

    /// 绑一个临时端口并派生于入站处理循环，用于独立 `run` 进程接收远端结果。
    /// 返回临时端口地址 (作为 creator_addr 告知对方)。
    pub async fn spawn_response_listener(&self) -> crate::Result<SocketAddr> {
        let listener = TcpListener::bind("0.0.0.0:0").await?;
        let addr = listener.local_addr()?;
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = me.shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, a)) = accepted else { break };
                        let me = me.clone();
                        tokio::spawn(async move {
                            let _ = me.handle_inbound(stream, a).await;
                        });
                    }
                }
            }
        });
        Ok(addr)
    }

    /// 周期刷新本机状态并广播给已知 peers
    pub async fn state_broadcast_loop(&self) -> crate::Result<()> {
        let mut interval = tokio::time::interval(self.config.heartbeat_interval);
        let mut resource_provider = SysinfoResourceProvider::new();
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let queued = self.jobs.count_queued().await;
            let running = self.jobs.count_running().await;
            {
                let mut state = self.local_state.write().await;
                state.apply_snapshot(resource_provider.snapshot());
                // 从任务管理器统计排队/运行数，比 queue.len() 更准确。
                state.queued_jobs = queued;
                state.running_jobs = running;
            }
            let peers: Vec<u64> = self.peers.all().await.into_iter().map(|p| p.id).collect();
            if peers.is_empty() {
                continue;
            }
            let state_data = {
                let ls = self.local_state.read().await;
                StateData {
                    network_id: self.config.network_id,
                    identity: self.identity.as_ref().clone(),
                    listen_addr: self.listen_addr.to_string(),
                    stream_addr: self.stream_endpoint(),
                    stream_certificate: self.stream_certificate(),
                    cpu_usage: ls.cpu_usage,
                    memory_total: ls.memory_total,
                    memory_used: ls.memory_used,
                    running_jobs: ls.running_jobs,
                    queued_jobs: ls.queued_jobs,
                    uptime_secs: ls.uptime_secs,
                    capabilities: ls.capabilities.clone(),
                }
            };
            let data = bincode::serialize(&state_data)?;
            for peer_id in peers {
                let env = Envelope::new(
                    self.config.network_id,
                    MessageType::State,
                    self.identity.id.as_u64(),
                    0,
                    data.clone(),
                );
                let _ = self.send_fire_to_peer(peer_id, &env).await;
            }
        }
        Ok(())
    }

    /// 离线清理循环
    pub async fn cleanup_loop(&self) -> crate::Result<()> {
        let mut interval = tokio::time::interval(self.config.cleanup_interval);
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let removed = self.peers.prune_offline(self.config.peer_timeout).await;
            if !removed.is_empty() {
                tracing::info!(
                    event = "peer_offline",
                    sister_id = self.identity.id.as_u64(),
                    peer_ids = ?removed,
                    "peer timeout cleanup removed offline peers"
                );
            }
        }
        Ok(())
    }

    /// 工作窃取循环由独立 stealing service 承担。
    pub async fn work_stealing_loop(&self, steal_when_lt: usize) -> crate::Result<()> {
        crate::stealing::run(self, steal_when_lt).await
    }

    /// 本地执行队列循环由独立 executor service 承担。
    pub async fn local_executor_loop(&self) -> crate::Result<()> {
        crate::executor::run(self).await
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A globally unique, unguessable job id (a random 128-bit UUID). Job results
/// are correlated by this id across a single protocol generation, so it must not
/// be guessable: a 4-digit suffix let a rogue Sister guess an in-flight pending
/// job and inject a fake result.
fn new_job_id() -> String {
    format!("job-{}", uuid::Uuid::new_v4())
}

/// Whether a Gateway-sourced PeerRecord for a Sister should (re)bootstrap.
///
/// `known` is the sequence we last successfully bootstrapped. A strictly newer
/// sequence always proceeds. A same-or-older sequence proceeds ONLY when the
/// peer is not currently known — so a Sister that was pruned/went offline and
/// returns with its original sequence is reconnectable, instead of a "seen once"
/// marker suppressing it forever (§9).
fn should_rebootstrap(known: Option<u64>, sequence: u64, live: bool) -> bool {
    match known {
        None => true,
        Some(last) => sequence > last || !live,
    }
}

/// Keep the highest-sequence `PeerRecord` per Sister during multi-Gateway
/// merge. Only records that already passed [`SisterNode::peer_record_usable`]
/// reach here, so an invalid high-sequence record cannot displace a valid lower
/// one (§8).
fn merge_gateway_candidate(
    merged: &mut std::collections::HashMap<u64, PeerRecord>,
    record: PeerRecord,
) {
    merged
        .entry(record.sister_id.as_u64())
        .and_modify(|current| {
            if record.sequence > current.sequence {
                *current = record.clone();
            }
        })
        .or_insert(record);
}

#[cfg(test)]
mod local_job_tests {
    use super::SisterNode;
    use crate::config::{DiscoveryMode, RuntimeConfig};
    use misaka_core::{JobStatus, SisterIdentity};

    #[tokio::test]
    async fn inline_entry_points_record_results_without_queueing_duplicate_work() {
        let config = RuntimeConfig {
            data_dir: std::env::temp_dir().join(format!("misaka-inline-{}", uuid::Uuid::new_v4())),
            discovery: DiscoveryMode::Off,
            ..Default::default()
        };
        let identity = SisterIdentity::new(
            42,
            "local".into(),
            "host".into(),
            "test".into(),
            "0.1".into(),
            0,
        );
        let node = SisterNode::new(identity, [0u8; 32], config);
        // Keep scheduler selection deterministic without sampling host load.
        node.local_state.write().await.cpu_usage = 0.0;

        let local = node.run_local_sync("echo inline-result").await;
        let scheduled = node
            .submit_job_remote("echo inline-result", None)
            .await
            .unwrap();
        let directed = node.submit_job_remote("exit 7", Some(42)).await.unwrap();

        assert_eq!(local.output.trim(), "inline-result");
        assert_eq!(scheduled.output.trim(), "inline-result");
        assert_eq!(directed.exit_code, 7);

        for (result, expected_status) in [
            (local, JobStatus::Completed),
            (scheduled, JobStatus::Completed),
            (directed, JobStatus::Failed),
        ] {
            let recorded = node.jobs.job(&result.job_id).await.unwrap();
            assert_eq!(recorded.creator, 42);
            assert_eq!(recorded.status, expected_status);
            assert_eq!(recorded.started_at, Some(result.started_at));
            assert_eq!(recorded.finished_at, Some(result.finished_at));
            assert_eq!(
                recorded.result_output.as_deref(),
                Some(result.output.as_str())
            );
        }
        assert_eq!(node.jobs.job_snapshots().await.len(), 3);
        assert_eq!(node.jobs.count_running().await, 0);
        assert_eq!(node.jobs.count_queued().await, 0);
        assert!(node.jobs.pop().is_none());
        assert!(!node.jobs.is_busy().await);
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::SisterNode;
    use crate::config::RuntimeConfig;
    use misaka_core::{
        IrohEndpointId, NetworkId, PeerRecord, SisterIdentity, SisterKeyPair, TransportBinding,
    };

    fn node() -> SisterNode {
        let dir = std::env::temp_dir().join(format!("misaka-gw-node-{}", std::process::id()));
        let config = RuntimeConfig {
            network_id: NetworkId::default(),
            data_dir: dir,
            discovery: crate::config::DiscoveryMode::Off,
            ..Default::default()
        };
        let identity = SisterIdentity::new(
            1,
            "tester".to_string(),
            "host".to_string(),
            "platform".to_string(),
            "0.0.0".to_string(),
            31700,
        );
        SisterNode::new(identity, [0u8; 32], config)
    }

    fn valid_record(network_id: NetworkId, endpoint: &str) -> PeerRecord {
        let key = SisterKeyPair::from_bytes([5u8; 32]);
        let binding = TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([9u8; 32]),
            1,
            &key,
        );
        PeerRecord::issue(network_id, 42, endpoint.to_string(), binding, 1, &key)
    }

    /// A record for Sister 42 on `network_id` with a chosen sequence and a
    /// self-consistent Iroh endpoint that matches its own TransportBinding.
    fn record_with_seq(
        network_id: NetworkId,
        sequence: u64,
        endpoint: &str,
        endpoint_id: IrohEndpointId,
    ) -> PeerRecord {
        let key = SisterKeyPair::from_bytes([5u8; 32]);
        let binding = TransportBinding::sign(network_id, 42, endpoint_id, sequence, &key);
        PeerRecord::issue(
            network_id,
            42,
            endpoint.to_string(),
            binding,
            sequence,
            &key,
        )
    }

    // S09: an invalid high-sequence record from one Gateway must not suppress a
    // valid lower-sequence record from another. Validation precedes the merge.
    #[test]
    fn merge_discards_invalid_high_sequence_before_valid_lower() {
        let node = node();
        let network_id = node.config.network_id;
        // A real, parseable Iroh endpoint whose id matches the binding.
        let secret = iroh::SecretKey::generate();
        let endpoint_id = IrohEndpointId::from_bytes(*secret.public().as_bytes());
        let endpoint =
            misaka_network::NetworkEndpoint::Iroh(iroh::EndpointAddr::new(secret.public()))
                .to_string();

        let valid = record_with_seq(network_id, 10, &endpoint, endpoint_id);
        // Same Sister + endpoint, higher sequence, but foreign Network → invalid.
        let invalid = record_with_seq(NetworkId::generate(), 999, &endpoint, endpoint_id);
        assert!(
            node.peer_record_usable(&valid),
            "valid record must be usable"
        );
        assert!(
            !node.peer_record_usable(&invalid),
            "foreign high-seq record must be unusable"
        );

        // Order-independent: whichever arrives, only the valid one is merged.
        for order in [
            [valid.clone(), invalid.clone()],
            [invalid.clone(), valid.clone()],
        ] {
            let mut merged = std::collections::HashMap::new();
            for record in order {
                if node.peer_record_usable(&record) {
                    super::merge_gateway_candidate(&mut merged, record);
                }
            }
            let kept = merged.get(&42).expect("a valid record must survive");
            assert_eq!(
                kept.sequence, 10,
                "valid seq 10 must win over an invalid seq 999"
            );
        }
    }

    /// S10: a peer that was pruned/offline and returns with the same PeerRecord
    /// sequence must be reconnectable — the "seen" marker only suppresses while
    /// the peer is live.
    #[test]
    fn same_sequence_peer_reconnects_after_it_is_no_longer_live() {
        // Never bootstrapped → proceed.
        assert!(super::should_rebootstrap(None, 5, true));
        // Newer sequence → proceed regardless of liveness.
        assert!(super::should_rebootstrap(Some(5), 6, true));
        // Same sequence, still live → skip (no churn).
        assert!(!super::should_rebootstrap(Some(5), 5, true));
        // Same sequence, no longer live → re-bootstrap (the recovery path).
        assert!(super::should_rebootstrap(Some(5), 5, false));
        // Older sequence, not live → still re-bootstrap to recover.
        assert!(super::should_rebootstrap(Some(9), 5, false));
    }

    /// G06: a Sister never trusts a Gateway-supplied locator without
    /// re-verifying it. Each reject happens before any Iroh dial.
    #[tokio::test]
    async fn bootstrap_rejects_untrusted_records() {
        let node = node();

        // (a) Foreign network.
        let foreign = valid_record(NetworkId::generate(), "iroh://x");
        assert!(
            node.bootstrap_peer_record(foreign).await.is_err(),
            "foreign-network record must be rejected"
        );

        // (b) Tampered signature.
        let mut forged = valid_record(node.config.network_id, "iroh://x");
        forged.sister_signature = misaka_core::SisterSignature::from_bytes([0u8; 64]);
        assert!(
            node.bootstrap_peer_record(forged).await.is_err(),
            "record failing self-verification must be rejected"
        );

        // (c) Endpoint does not match the record's own TransportBinding (a
        //     Gateway redirect cannot point us at a different key).
        let redirected = valid_record(node.config.network_id, "tcp://127.0.0.1:1");
        assert!(
            node.bootstrap_peer_record(redirected).await.is_err(),
            "endpoint/TransportBinding disagreement must be rejected"
        );
    }
}
