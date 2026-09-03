use crate::crypto::Crypto;
use crate::peer_store::PeerStore;
use crate::queue::JobQueue;
use crate::scheduler::Scheduler;
use crate::state::{LocalJob, LocalState, HEARTBEAT_INTERVAL, PEER_TIMEOUT};
use misaka_core::protocol::*;
use misaka_core::JobStatus;
use misaka_core::SisterIdentity;
use misaka_core::{PeerState, PeerStateTable};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, RwLock};

/// 一个完整的对等节点 —— 既是 server 也是 client。
/// 没有任何主从身份：每个 Sister 都能独立工作、发现彼此、共享状态、收发任务。
#[derive(Clone)]
pub struct SisterNode {
    pub identity: Arc<SisterIdentity>,
    encryption_key: [u8; 32],

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
}

impl SisterNode {
    pub fn new(identity: SisterIdentity, encryption_key: [u8; 32]) -> Self {
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", identity.listen_port).parse().unwrap();
        // 告知 peer 的连接地址: 单机测试用 127.0.0.1; 局域网环境可换成机器 IP。
        let listen_addr: SocketAddr = format!("127.0.0.1:{}", identity.listen_port)
            .parse()
            .unwrap();
        // 启动时立刻刷新一次本机状态
        let mut local_state = LocalState::new();
        local_state.refresh(&mut sysinfo::System::new());

        // 从磁盘 seed 已知 peers (供 run 独立进程复用地址)
        let mut peers = PeerStateTable::new();
        for bp in PeerStore::load_from_file() {
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
            bind_addr,
            listen_addr,
            peers: Arc::new(RwLock::new(peers)),
            job_queue: JobQueue::new(),
            local_state: Arc::new(RwLock::new(local_state)),
            local_jobs: Arc::new(RwLock::new(HashMap::new())),
            pending_jobs: Arc::new(Mutex::new(HashMap::new())),
            scheduler: Arc::new(Scheduler::new()),
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

    // ---------- 网络层原语 ----------

    /// 打开一条短连接发送 envelope，等待一条响应
    pub async fn send_to(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<Envelope> {
        let mut stream = TcpStream::connect(addr).await?;
        write_envelope(&mut stream, &self.get_crypto(), env).await?;
        let resp = read_envelope(&mut stream, &self.get_crypto()).await?;
        Ok(resp)
    }

    /// 单向发送 (不等待响应)
    pub async fn send_fire(&self, addr: SocketAddr, env: &Envelope) -> crate::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        write_envelope(&mut stream, &self.get_crypto(), env).await?;
        Ok(())
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
        let env = read_envelope(&mut stream, &self.get_crypto()).await?;
        self.dispatch(env, &mut stream).await
    }

    async fn dispatch(&self, env: Envelope, stream: &mut TcpStream) -> crate::Result<()> {
        match env.msg_type {
            MessageType::Hello => {
                let hello: HelloData = bincode::deserialize(&env.data)?;
                self.remember_peer(&hello.identity, &hello.listen_addr)
                    .await;
                let reply = Envelope::new(
                    MessageType::Hello,
                    self.identity.id.as_u64(),
                    env.from,
                    bincode::serialize(&HelloData {
                        identity: self.identity.as_ref().clone(),
                        listen_addr: self.listen_addr.to_string(),
                    })?,
                );
                write_envelope(stream, &self.get_crypto(), &reply).await?;
            }

            MessageType::State => {
                let state: StateData = bincode::deserialize(&env.data)?;
                println!(
                    "[Misaka] {} <- state from #{} ({}): cpu={:.1}% mem={}/{}, jobs {}/{}",
                    self.identity.nickname.as_str(),
                    env.from,
                    state.identity.nickname.as_str(),
                    state.cpu_usage,
                    state.memory_used,
                    state.memory_total,
                    state.running_jobs,
                    state.queued_jobs,
                );
                let mut peers = self.peers.write().await;
                peers.upsert(PeerState {
                    id: state.identity.id.as_u64(),
                    nickname: state.identity.nickname.as_str().to_string(),
                    hostname: state.identity.hostname,
                    platform: state.identity.platform,
                    version: state.identity.version,
                    addr: state.listen_addr,
                    cpu_usage: state.cpu_usage,
                    memory_total: state.memory_total,
                    memory_used: state.memory_used,
                    running_jobs: state.running_jobs,
                    queued_jobs: state.queued_jobs,
                    uptime_secs: state.uptime_secs,
                    capabilities: state.capabilities,
                });
            }

            MessageType::Job => {
                let job: JobData = bincode::deserialize(&env.data)?;
                // 若指定了 executor 且不是本机 → 转发
                if job.executor != 0 && job.executor != self.identity.id.as_u64() {
                    if let Some(addr) = self.peer_addr(job.executor).await {
                        println!(
                            "[Misaka] {} forwarding job {} to #{}",
                            self.identity.nickname.as_str(),
                            job.id,
                            job.executor
                        );
                        self.send_fire(
                            addr,
                            &Envelope::new(
                                MessageType::Job,
                                env.from,
                                job.executor,
                                env.data.clone(),
                            ),
                        )
                        .await?;
                        return Ok(());
                    }
                }
                // 本机执行
                let job_id = job.id.clone();
                let full_cmd = job.full_command();
                let mut local_job = LocalJob::new(job_id.clone(), full_cmd.clone());
                local_job.creator = job.creator;
                local_job.creator_addr = Some(job.creator_addr.clone());
                let mut jobs = self.local_jobs.write().await;
                jobs.insert(job_id.clone(), local_job.clone());
                self.job_queue.push(local_job);
                println!(
                    "[Misaka] {} queued job {} from #{}: {}",
                    self.identity.nickname.as_str(),
                    job_id,
                    env.from,
                    full_cmd
                );
            }

            MessageType::JobResponse => {
                let result: JobResultData = bincode::deserialize(&env.data)?;
                println!(
                    "[Misaka] {} got result for job {} (executor #{}, exit_code={})",
                    self.identity.nickname.as_str(),
                    result.job_id,
                    result.executor,
                    result.exit_code
                );
                // 唤醒等结果的提交方
                if let Some(tx) = self.pending_jobs.lock().unwrap().remove(&result.job_id) {
                    let _ = tx.send(result);
                }
            }

            MessageType::JobRequest => {
                // Work Stealing: 有人来要活。给一个本地排队中的任务。
                let requester = env.from;
                let peer_addr = self.peer_addr(requester).await;
                if let Some(job) = self.job_queue.pop() {
                    let job_data = JobData {
                        id: job.id.clone(),
                        creator: job.creator,
                        executor: requester,
                        creator_addr: job
                            .creator_addr
                            .clone()
                            .unwrap_or_else(|| self.listen_addr.to_string()),
                        command: job.command.clone(),
                        arguments: vec![],
                        created_at: now_secs(),
                    };
                    if let Some(addr) = peer_addr {
                        println!(
                            "[Misaka] {} stealing job {} out to #{}",
                            self.identity.nickname.as_str(),
                            job.id,
                            requester
                        );
                        let env = Envelope::new(
                            MessageType::Job,
                            self.identity.id.as_u64(),
                            requester,
                            bincode::serialize(&job_data)?,
                        );
                        let _ = self.send_fire(addr, &env).await;
                    }
                } else if let Some(addr) = peer_addr {
                    // 没有 → 回 Ack 表示无活
                    let _ = self
                        .send_fire(
                            addr,
                            &Envelope::new(
                                MessageType::Ack,
                                self.identity.id.as_u64(),
                                requester,
                                vec![],
                            ),
                        )
                        .await;
                }
            }

            _ => {}
        }
        Ok(())
    }

    /// 把当前 peer 表持久化到磁盘 (供独立 run 进程解析地址)
    async fn save_peers(&self) {
        let peers = self.peers.read().await;
        let _ = PeerStore::save_to_file(&peers);
    }

    /// 把 hello 里的身份信息存进 peer 表
    async fn remember_peer(&self, identity: &SisterIdentity, listen_addr: &str) {
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
        println!(
            "[Misaka] Handshake with {} @ {}",
            hello.identity.display_name(),
            hello.listen_addr
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
            println!(
                "[Misaka] {} submits to #{}",
                self.identity.nickname.as_str(),
                executor
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
        println!("[Misaka] enqueued {}", command);
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

        tokio::time::timeout(std::time::Duration::from_secs(60), rx)
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
        println!("[Misaka] executing locally: {}", command);
        let result = crate::commands::CommandExecutor::execute(command).unwrap_or_else(|e| {
            crate::commands::CommandResult {
                stdout: format!("Error: {}", e),
                stderr: String::new(),
                exit_code: -1,
            }
        });
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
        println!(
            "[Misaka] job {} done -> {:?}\n{}",
            job_id,
            if result.success() {
                "completed"
            } else {
                "failed"
            },
            result.full_output()
        );
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
                self.identity.listen_port,
                tx,
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[Misaka] mDNS advertise failed: {:?}", e);
                    return Ok(());
                }
            };
            (s, rx)
        };

        println!(
            "[Misaka] mDNS advertising as {} (port {})",
            self.identity.nickname.as_str(),
            self.identity.listen_port
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
                    println!(
                        "[Misaka] mDNS discovered #{} \"{}\" @ {}",
                        peer_id, nick, addr
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
        println!(
            "[Misaka] {} listening on {}",
            self.identity.display_name(),
            self.bind_addr
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
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            interval.tick().await;
            {
                let mut state = self.local_state.write().await;
                state.refresh(&mut sysinfo::System::new());
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
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            let mut peers = self.peers.write().await;
            let removed = peers.prune_offline(PEER_TIMEOUT);
            if !removed.is_empty() {
                println!(
                    "[Misaka] {} sister(s) went offline: {:?}",
                    removed.len(),
                    removed
                );
            }
        }
    }

    /// 工作窃取循环: 本机真正空闲 (无运行 + 无排队) 时，
    /// 主动向已知 peer 要活。
    pub async fn work_stealing_loop(&self, steal_when_lt: usize) -> crate::Result<()> {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(4));
        loop {
            interval.tick().await;
            // 只在本地真的没活干时才去偷
            let is_busy = {
                let jobs = self.local_jobs.read().await;
                jobs.values()
                    .any(|j| j.status == JobStatus::Running || j.status == JobStatus::Queued)
                    || !self.job_queue.is_empty()
            };
            if is_busy || self.job_queue.len() >= steal_when_lt {
                continue;
            }
            // 从已知 peer 里挑一个，请求它给我们一个排队任务
            let target = {
                let peers = self.peers.read().await;
                let list = peers.all();
                list.into_iter()
                    .filter(|p| p.queued_jobs > 0) // 只向确实有积压任务的 peer 要
                    .min_by(|a, b| {
                        a.cpu_usage
                            .partial_cmp(&b.cpu_usage)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            };
            if let Some(p) = target {
                println!(
                    "[Misaka] {} wants work from #{} (peer has {} queued)",
                    self.identity.nickname.as_str(),
                    p.id,
                    p.queued_jobs
                );
                let _ = self.request_work_from(p.id).await;
            }
        }
    }

    /// 本地执行队列循环：从 job_queue 弹出任务并执行。
    /// 若任务来自远端 (creator != 本机)，执行完要回送 JobResponse 给创建者。
    pub async fn local_executor_loop(&self) -> crate::Result<()> {
        loop {
            if let Some(job) = self.job_queue.pop() {
                let mut jobs = self.local_jobs.write().await;
                if let Some(lj) = jobs.get_mut(&job.id) {
                    lj.status = JobStatus::Running;
                    lj.started_at = Some(now_secs());
                }
                drop(jobs);

                println!("[Misaka] executing locally: {}", job.command);
                let result = crate::commands::CommandExecutor::execute(&job.command)
                    .unwrap_or_else(|e| crate::commands::CommandResult {
                        stdout: format!("Error: {}", e),
                        stderr: String::new(),
                        exit_code: -1,
                    });

                let finished = now_secs();
                let job_result = JobResultData {
                    job_id: job.id.clone(),
                    creator: job.creator,
                    executor: self.identity.id.as_u64(),
                    output: result.full_output(),
                    exit_code: result.exit_code,
                    success: result.success(),
                    started_at: job.started_at.unwrap_or(finished),
                    finished_at: finished,
                };

                let mut jobs = self.local_jobs.write().await;
                if let Some(lj) = jobs.get_mut(&job.id) {
                    lj.status = if result.success() {
                        JobStatus::Completed
                    } else {
                        JobStatus::Failed
                    };
                    lj.finished_at = Some(finished);
                    lj.result_output = Some(result.full_output());
                    println!(
                        "[Misaka] job {} -> {:?}\n{}",
                        job.id,
                        lj.status,
                        result.full_output()
                    );
                }
                drop(jobs);

                // 远端委派来的任务：回送结果给 creator
                if job.creator != self.identity.id.as_u64() {
                    if let Some(creator_addr) = job.creator_addr {
                        if let Ok(addr) = creator_addr.parse::<SocketAddr>() {
                            let env = Envelope::new(
                                MessageType::JobResponse,
                                self.identity.id.as_u64(),
                                job.creator,
                                bincode::serialize(&job_result)?,
                            );
                            let _ = self.send_fire(addr, &env).await;
                        }
                    }
                }
            } else {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn rand_int() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen::<u64>()
}

/// 序列化 + 加密 + 写入 stream
pub async fn write_envelope(
    stream: &mut TcpStream,
    crypto: &Crypto,
    env: &Envelope,
) -> crate::Result<()> {
    let plaintext = bincode::serialize(env)?;
    let encrypted = crypto.encrypt(&plaintext)?;
    stream
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&encrypted).await?;
    Ok(())
}

/// 从 stream 读取 + 解密 + 反序列化
pub async fn read_envelope(stream: &mut TcpStream, crypto: &Crypto) -> crate::Result<Envelope> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let decrypted = crypto.decrypt(&buf)?;
    let env: Envelope = bincode::deserialize(&decrypted)?;
    Ok(env)
}
