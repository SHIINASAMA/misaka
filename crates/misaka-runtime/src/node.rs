use crate::config::RuntimeConfig;
use crate::crypto::Crypto;
use crate::network::PeerTransport;
use crate::peer_store::PeerStore;
use crate::queue::JobQueue;
use crate::resources::{ResourceProvider, SysinfoResourceProvider};
use crate::scheduler::Scheduler;
use crate::state::{LocalJob, LocalState};
use misaka_core::introspection::{
    IntrospectionSnapshot, JobSnapshot, PeerSnapshot, ResourceSnapshot,
};
use misaka_core::protocol::*;
use misaka_core::JobStatus;
use misaka_core::SisterIdentity;
use misaka_core::{PeerState, PeerStateTable};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, RwLock};

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

    /// 已知的所有 peer 状态 (Network Knowledge)
    pub peers: Arc<RwLock<PeerStateTable>>,

    /// 本地任务队列 (排队待执行)
    pub job_queue: JobQueue,

    /// 本机资源状态 (定期刷新)
    pub local_state: Arc<RwLock<LocalState>>,

    /// 本机所有已知任务 (含排队/运行/完成) 的元数据
    pub local_jobs: Arc<RwLock<HashMap<String, LocalJob>>>,

    /// 我发起、正在等待远端结果的任务: job_id -> oneshot
    pub pending_jobs: Arc<Mutex<HashMap<String, oneshot::Sender<JobResultData>>>>,

    /// 调度器
    pub scheduler: Arc<Scheduler>,

    /// 网络收发原语。
    pub(crate) transport: PeerTransport,
}

impl SisterNode {
    pub fn new(identity: SisterIdentity, encryption_key: [u8; 32], config: RuntimeConfig) -> Self {
        let data_dir = config.data_dir.clone();
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", identity.listen_port).parse().unwrap();
        // 告知 peer 的连接地址: 单机测试用 127.0.0.1; 局域网环境可换成机器 IP。
        let listen_addr: SocketAddr = format!("127.0.0.1:{}", identity.listen_port)
            .parse()
            .unwrap();
        // 启动时立刻刷新一次本机状态
        let mut local_state = LocalState::new();
        let mut resource_provider = SysinfoResourceProvider::new();
        local_state.apply_snapshot(resource_provider.snapshot());

        // 从磁盘 seed 已知 peers (供 run 独立进程复用地址)
        let mut peers = PeerStateTable::new();
        for bp in PeerStore::load_from_dir(&data_dir) {
            peers.upsert(PeerState {
                id: bp.id,
                nickname: bp.nickname,
                hostname: bp.hostname,
                platform: bp.platform,
                version: bp.version,
                addr: bp.addr,
                cpu_usage: 0.0,
                memory_total: 0,
                memory_used: 0,
                running_jobs: 0,
                queued_jobs: 0,
                uptime_secs: 0,
                capabilities: vec![],
            });
        }

        Self {
            identity: Arc::new(identity),
            encryption_key,
            config,
            bind_addr,
            listen_addr,
            peers: Arc::new(RwLock::new(peers)),
            job_queue: JobQueue::new(),
            local_state: Arc::new(RwLock::new(local_state)),
            local_jobs: Arc::new(RwLock::new(HashMap::new())),
            pending_jobs: Arc::new(Mutex::new(HashMap::new())),
            scheduler: Arc::new(Scheduler::new()),
            transport: PeerTransport::new(Crypto::new(&encryption_key).unwrap()),
        }
    }

    /// 让本节点能感知局域网中其他 Sister，需要本机真实 IP (非 127.0.0.1)。
    /// 单机测试时保持 127.0.0.1 即可；跨机部署时暴露本机局域网 IP。
    pub fn set_advertise_host(&mut self, host: &str) {
        self.bind_addr = format!("0.0.0.0:{}", self.identity.listen_port)
            .parse()
            .unwrap();
        self.listen_addr = format!("{}:{}", host, self.identity.listen_port)
            .parse()
            .unwrap();
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
        let peers = {
            let p = self.peers.read().await;
            p.all().iter().map(PeerSnapshot::from).collect()
        };
        let jobs = {
            let j = self.local_jobs.read().await;
            j.values()
                .map(|lj| JobSnapshot {
                    id: lj.id.clone(),
                    command: lj.command.clone(),
                    status: lj.status.to_string(),
                    creator: lj.creator,
                    started_at: lj.started_at,
                    finished_at: lj.finished_at,
                })
                .collect()
        };
        let queue_depth = self.job_queue.len();
        IntrospectionSnapshot {
            identity: self.identity.as_ref().clone(),
            resources,
            peers,
            jobs,
            queue_depth,
        }
    }

    /// 在给定地址上启动只读 introspection 服务器 (loopback)。返回实际绑定地址。
    pub async fn spawn_introspection_server(&self, bind: SocketAddr) -> crate::Result<SocketAddr> {
        let me = self.clone();
        let addr = crate::introspection::spawn_server(bind, move || {
            let me = me.clone();
            Box::pin(async move { me.introspection_snapshot().await })
        })
        .await?;
        Ok(addr)
    }

    // ---------- 网络层原语 ----------

    /// 打开一条短连接发送 envelope，等待一条响应
    pub async fn send_to(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<Envelope> {
        self.transport.send_to(addr, env).await
    }

    /// 单向发送 (不等待响应)
    pub async fn send_fire(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<()> {
        self.transport.send_fire(addr, env).await
    }

    /// 从 peer 表取一个 peer 的对外地址
    pub async fn peer_addr(&self, id: u64) -> Option<SocketAddr> {
        let peers = self.peers.read().await;
        peers.get(id).and_then(|p| p.addr.parse().ok())
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

    /// 把当前 peer 表持久化到磁盘 (供独立 run 进程解析地址)
    async fn save_peers(&self) {
        let peers = self.peers.read().await;
        let _ = PeerStore::save_to_dir(&peers, &self.config.data_dir);
    }

    /// 把 hello 里的身份信息存进 peer 表
    pub(crate) async fn remember_peer(&self, identity: &SisterIdentity, listen_addr: &str) {
        let mut peers = self.peers.write().await;
        peers.upsert(PeerState {
            id: identity.id.as_u64(),
            nickname: identity.nickname.as_str().to_string(),
            hostname: identity.hostname.clone(),
            platform: identity.platform.clone(),
            version: identity.version.clone(),
            addr: listen_addr.to_string(),
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        });
        drop(peers);
        self.save_peers().await;
    }

    /// 手工插入一个 peer (Phase 1 没有 mDNS 时用 --peer 指定)
    pub async fn add_known_peer(&self, addr: SocketAddr) -> crate::Result<()> {
        let env = Envelope::new(
            MessageType::Hello,
            self.identity.id.as_u64(),
            0,
            bincode::serialize(&HelloData {
                identity: self.identity.as_ref().clone(),
                listen_addr: self.listen_addr.to_string(),
            })?,
        );
        let reply = self.send_to(addr, &env).await?;
        let hello: HelloData = bincode::deserialize(&reply.data)?;
        self.remember_peer(&hello.identity, &hello.listen_addr)
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

    // ---------- 任务提交 (Phase 5 核心) ----------

    /// 提交一个任务。目标由调度器决定；若调度器选 None 则本地执行。
    /// 返回执行结果。
    pub async fn submit_job(&self, command: &str) -> crate::Result<JobResultData> {
        // 选目标
        let peer_data = {
            let p = self.peers.read().await;
            p.all()
        };
        let local = { self.local_state.read().await.clone() };
        let target = self.scheduler.choose(&peer_data, &local);
        let creator = self.identity.id.as_u64();
        let executor = match target {
            Some(id) if id != creator => id,
            _ => creator,
        };

        if executor != creator {
            tracing::info!(
                event = "job_submitted",
                sister_id = self.identity.id.as_u64(),
                executor,
                command = %command,
                "job submitted to peer"
            );
        }
        self.submit_to_sister(executor, command).await
    }

    /// 请求一个空闲 peer 拿走我们排队中的任务 (Work Stealing)。
    pub async fn request_work_from(&self, peer_id: u64) -> crate::Result<()> {
        if let Some(addr) = self.peer_addr(peer_id).await {
            let env = Envelope::new(
                MessageType::JobRequest,
                self.identity.id.as_u64(),
                peer_id,
                vec![],
            );
            let _ = self.send_fire(addr, &env).await;
        }
        Ok(())
    }

    /// 提交一个任务（就地执行；不返回 JobResultData，执行逻辑由 executor loop 处理）。
    /// run -l 子命令专用：把任务塞进本地队列即可。
    pub async fn submit_local(&self, command: &str) -> crate::Result<()> {
        let job_id = format!("job-{}-{}", now_secs(), rand_int() % 10000);
        let mut job = LocalJob::new(job_id, command.to_string());
        job.creator = self.identity.id.as_u64();
        let mut jobs = self.local_jobs.write().await;
        jobs.insert(job.id.clone(), job.clone());
        drop(jobs);
        self.job_queue.push(job);
        tracing::info!(
            event = "job_created",
            sister_id = self.identity.id.as_u64(),
            command = %command,
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
        let my_listen = if executor == self.identity.id.as_u64() {
            self.listen_addr
        } else {
            // 开一个临时端口收返回结果
            self.spawn_response_listener().await?
        };

        let job_id = format!("job-{}-{}", now_secs(), rand_int() % 10000);
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
        };

        if executor == creator {
            // 本地
            return Ok(self.execute_and_record(&job_id, command).await);
        }

        let (tx, rx) = oneshot::channel::<JobResultData>();
        self.pending_jobs.lock().unwrap().insert(job_id.clone(), tx);

        let exec_addr = self
            .peer_addr(executor)
            .await
            .ok_or_else(|| crate::Error::Other(format!("no address for executor #{}", executor)))?;
        let env = Envelope::new(
            MessageType::Job,
            creator,
            executor,
            bincode::serialize(&job_data)?,
        );
        self.send_fire(exec_addr, &env).await?;

        tokio::time::timeout(self.config.job_timeout, rx)
            .await
            .map_err(|_| crate::Error::Other(format!("job {} timed out", job_id)))?
            .map_err(|_| crate::Error::Other(format!("job {} canceled", job_id)))
    }

    /// 同步在本地执行任务并返回结果 (供 `run` 独立进程使用)。
    pub async fn run_local_sync(&self, command: &str) -> JobResultData {
        let job_id = format!("job-{}-{}", now_secs(), rand_int() % 10000);
        self.execute_and_record_public(&job_id, command).await
    }

    /// 在本地执行并记录任务状态，返回结果 (公开封装)
    pub async fn execute_and_record_public(&self, job_id: &str, command: &str) -> JobResultData {
        self.execute_and_record(job_id, command).await
    }

    /// 在本地执行并记录任务状态，返回结果
    async fn execute_and_record(&self, job_id: &str, command: &str) -> JobResultData {
        let started = now_secs();
        {
            let mut jobs = self.local_jobs.write().await;
            if let Some(lj) = jobs.get_mut(job_id) {
                lj.status = JobStatus::Running;
                lj.started_at = Some(started);
            }
        }
        tracing::info!(
            event = "job_started",
            sister_id = self.identity.id.as_u64(),
            command = %command,
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

        {
            let mut jobs = self.local_jobs.write().await;
            if let Some(lj) = jobs.get_mut(job_id) {
                lj.status = if result.success() {
                    JobStatus::Completed
                } else {
                    JobStatus::Failed
                };
                lj.finished_at = Some(finished);
                lj.result_output = Some(result.full_output());
            }
        }
        if result.success() {
            tracing::info!(
                event = "job_completed",
                sister_id = self.identity.id.as_u64(),
                job_id = %job_id,
                success = true,
                exit_code = result.exit_code,
                output = %result.full_output(),
                "local job finished"
            );
        } else {
            tracing::warn!(
                event = "job_failed",
                sister_id = self.identity.id.as_u64(),
                job_id = %job_id,
                success = false,
                exit_code = result.exit_code,
                output = %result.full_output(),
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
                &self.identity.hostname,
                &self.identity.platform,
                self.listen_addr,
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

        while let Some(instance) = rx.recv().await {
            // 忽略自己 (instance 名等于本机 nickname; 同时 id 相同则跳过)
            if let Some((peer_id, _nick, addr)) = crate::discovery::instance_to_peer(&instance) {
                if peer_id == self.identity.id.as_u64() {
                    continue;
                }
                // 已有记录且地址没变，跳过
                {
                    let peers = self.peers.read().await;
                    if let Some(p) = peers.get(peer_id) {
                        if p.addr == addr.to_string() {
                            continue;
                        }
                    }
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
                    // 握手
                    let _ = self.add_known_peer(addr).await;
                    // 记录 host/platform (handshake 会更新 version 等，这里补齐 host/platform)
                    let mut peers = self.peers.write().await;
                    peers.upsert(misaka_core::PeerState {
                        id: peer_id,
                        nickname: nick,
                        hostname: host,
                        platform,
                        version: String::new(),
                        addr: addr.to_string(),
                        cpu_usage: 0.0,
                        memory_total: 0,
                        memory_used: 0,
                        running_jobs: 0,
                        queued_jobs: 0,
                        uptime_secs: 0,
                        capabilities: vec![],
                    });
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
            while let Ok((stream, a)) = listener.accept().await {
                let me = me.clone();
                tokio::spawn(async move {
                    let _ = me.handle_inbound(stream, a).await;
                });
            }
        });
        Ok(addr)
    }

    /// 周期刷新本机状态并广播给已知 peers
    pub async fn state_broadcast_loop(&self) -> crate::Result<()> {
        let mut interval = tokio::time::interval(self.config.heartbeat_interval);
        let mut resource_provider = SysinfoResourceProvider::new();
        loop {
            interval.tick().await;
            {
                let mut state = self.local_state.write().await;
                state.apply_snapshot(resource_provider.snapshot());
                // 从任务表统计排队/运行数，比 job_queue.len() 更准确
                // (排队任务被 pop 后标记 running，若前面有长任务，queue.len() 会掉到 0 但仍有积压)
                let jobs = self.local_jobs.read().await;
                let queued = jobs
                    .values()
                    .filter(|j| j.status == JobStatus::Queued)
                    .count();
                let running = jobs
                    .values()
                    .filter(|j| j.status == JobStatus::Running)
                    .count();
                state.queued_jobs = queued;
                state.running_jobs = running;
            }
            let addrs: Vec<SocketAddr> = {
                let peers = self.peers.read().await;
                peers
                    .all()
                    .iter()
                    .filter_map(|p| p.addr.parse().ok())
                    .collect()
            };
            if addrs.is_empty() {
                continue;
            }
            let state_data = {
                let ls = self.local_state.read().await;
                StateData {
                    identity: self.identity.as_ref().clone(),
                    listen_addr: self.listen_addr.to_string(),
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
            for addr in addrs {
                let env = Envelope::new(
                    MessageType::State,
                    self.identity.id.as_u64(),
                    0,
                    data.clone(),
                );
                let _ = self.send_fire(addr, &env).await;
            }
        }
    }

    /// 离线清理循环
    pub async fn cleanup_loop(&self) -> crate::Result<()> {
        let mut interval = tokio::time::interval(self.config.cleanup_interval);
        loop {
            interval.tick().await;
            let mut peers = self.peers.write().await;
            let removed = peers.prune_offline(self.config.peer_timeout);
            if !removed.is_empty() {
                tracing::info!(
                    event = "peer_offline",
                    sister_id = self.identity.id.as_u64(),
                    peer_ids = ?removed,
                    "peer timeout cleanup removed offline peers"
                );
            }
        }
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

fn rand_int() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen::<u64>()
}
