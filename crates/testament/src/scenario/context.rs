use super::*;
use crate::scenario::helpers::{allocate_ports, provision_iroh_membership, provision_tls_identity};

pub struct Context {
    pub run_id: String,
    pub layout: RunLayout,
    pub binary: PathBuf,
    pub heartbeat: u64,
    pub peer_timeout: u64,
    pub discovery: String,

    pub sisters: HashMap<String, SisterProcess>,
    pub entries: HashMap<String, SisterEntry>,
    pub manifest: Manifest,
    /// Authority material used only to provision isolated Iroh test peers.
    /// Testament never sends the private key to a running Sister.
    iroh_authority: Option<(NetworkAuthority, misaka_core::AuthorityKeyPair)>,
}
impl Context {
    pub fn new(run_id: String, layout: RunLayout) -> Self {
        let manifest = Manifest {
            run_id: run_id.clone(),
            sisters: vec![],
        };
        Self {
            run_id,
            layout,
            binary: misaka_binary(),
            heartbeat: 2,
            peer_timeout: 8,
            discovery: "manual".to_string(),
            sisters: HashMap::new(),
            entries: HashMap::new(),
            manifest,
            iroh_authority: None,
        }
    }

    /// 启动一个 Sister (分配 listen + introspect 端口)。
    pub fn start_sister(
        &mut self,
        alias: &str,
        nickname: &str,
        peers: &[SocketAddr],
    ) -> Result<(), ScenarioError> {
        let listen_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let introspect_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let stream_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;

        let (entry, cmd, restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            stream_port,
            introspect_port,
            binary: &self.binary,
            peers,
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        self.do_spawn(alias, entry, cmd, restart)
    }

    /// Start a production-mode Sister without the explicit local compatibility
    /// authorization bypass. Used only by adversarial security scenarios.
    pub fn start_sister_secure(
        &mut self,
        alias: &str,
        nickname: &str,
        peers: &[SocketAddr],
    ) -> Result<(), ScenarioError> {
        let listen_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc listen port: {e}")))?;
        let introspect_port = alloc_port()
            .map_err(|e| ScenarioError::infra(format!("alloc introspection port: {e}")))?;
        let stream_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc stream port: {e}")))?;
        let (entry, command, restart) = build_spawn_secure(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            stream_port,
            introspect_port,
            binary: &self.binary,
            peers,
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        self.do_spawn(alias, entry, command, restart)
    }

    /// Start a Sister and an independent native Iroh relay in the same process.
    pub fn start_sister_with_relay(
        &mut self,
        alias: &str,
        nickname: &str,
        peers: &[SocketAddr],
        relay_bind: SocketAddr,
    ) -> Result<(), ScenarioError> {
        let listen_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let introspect_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let stream_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;

        let (entry, mut cmd, mut restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            stream_port,
            introspect_port,
            binary: &self.binary,
            peers,
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        cmd.arg("--relay")
            .arg("--relay-bind")
            .arg(relay_bind.to_string());
        restart.append_args(["--relay", "--relay-bind", &relay_bind.to_string()]);
        self.do_spawn(alias, entry, cmd, restart)
    }

    /// 用指定 config dir + peer 拓扑启动一个 Sister (身份持久化测试用)。
    pub fn start_sister_with_config(
        &mut self,
        alias: &str,
        nickname: &str,
        config_dir: PathBuf,
        peers: &[SocketAddr],
    ) -> Result<(), ScenarioError> {
        let listen_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let introspect_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let stream_port =
            alloc_port().map_err(|e| ScenarioError::infra(format!("alloc_port: {}", e)))?;
        let _ = std::fs::create_dir_all(&config_dir);

        let (mut entry, mut cmd, restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            stream_port,
            introspect_port,
            binary: &self.binary,
            peers,
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        cmd.env("MISAKA_CONFIG_DIR", &config_dir);
        entry.config_dir = config_dir.to_string_lossy().to_string();
        self.do_spawn(alias, entry, cmd, restart)
    }

    fn do_spawn(
        &mut self,
        alias: &str,
        entry: SisterEntry,
        cmd: std::process::Command,
        restart: crate::supervisor::RestartSpec,
    ) -> Result<(), ScenarioError> {
        self.spawn_only(alias, entry, cmd, restart)?;
        self.wait_until_ready(alias)
    }

    fn spawn_only(
        &mut self,
        alias: &str,
        entry: SisterEntry,
        cmd: std::process::Command,
        restart: crate::supervisor::RestartSpec,
    ) -> Result<(), ScenarioError> {
        let mut proc = SisterProcess::with_restart(entry.clone(), restart);
        proc.spawn(cmd, &entry.stdout_log, &entry.stderr_log)
            .map_err(|e| ScenarioError::infra(format!("spawn {alias}: {}", e)))?;
        let mut entry = entry;
        entry.pid = proc.pid();
        self.entries.insert(alias.to_string(), entry.clone());
        self.sisters.insert(alias.to_string(), proc);
        self.manifest.sisters.push(entry);
        Ok(())
    }

    fn remove_failed_process(&mut self, alias: &str) {
        if let Some(mut process) = self.sisters.remove(alias) {
            process.terminate();
            let _ = process.wait();
        }
        self.entries.remove(alias);
        self.manifest.sisters.retain(|entry| entry.alias != alias);
    }

    fn wait_until_ready(&mut self, alias: &str) -> Result<(), ScenarioError> {
        let entry = self
            .entries
            .get(alias)
            .cloned()
            .ok_or_else(|| ScenarioError::infra(format!("no entry for {alias}")))?;
        let ia: SocketAddr = entry
            .introspection_addr
            .as_ref()
            .ok_or_else(|| ScenarioError::infra(format!("{alias} has no introspection address")))?
            .parse()
            .map_err(|e| ScenarioError::infra(format!("{alias} introspection address: {e}")))?;
        if observer::wait_until(ia, Duration::from_secs(15), |_| true).is_none() {
            self.remove_failed_process(alias);
            return Err(ScenarioError::infra(format!(
                "{alias} never became ready (introspect {}); stderr tail: {}",
                ia,
                std::fs::read_to_string(&entry.stderr_log).unwrap_or_default()
            )));
        }

        let snap = match observer::fetch(ia, Duration::from_millis(500)) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                self.remove_failed_process(alias);
                return Err(ScenarioError::infra(format!("introspect {alias}: {}", e)));
            }
        };
        let id = snap.identity.id.as_u64();
        if let Some(entry) = self.entries.get_mut(alias) {
            entry.id = Some(id);
            entry.pid = self.sisters.get(alias).and_then(SisterProcess::pid);
        }
        if let Some(entry) = self
            .manifest
            .sisters
            .iter_mut()
            .find(|entry| entry.alias == alias)
        {
            entry.id = Some(id);
            entry.pid = self.sisters.get(alias).and_then(SisterProcess::pid);
        }
        if let Some(process) = self.sisters.get_mut(alias) {
            process.entry.id = Some(id);
        }
        Ok(())
    }

    /// Prepare every endpoint and launch all Sisters with a deterministic
    /// full-mesh topology. Existing scenario `start_sister` remains the
    /// one-node-at-a-time API used by the Foundation scenarios.
    pub fn start_full_mesh(&mut self, count: u32) -> Result<(), ScenarioError> {
        if count == 0 {
            return Err(ScenarioError::infra("number of sisters must be at least 1"));
        }
        let mut ports = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let listen = alloc_port()
                .map_err(|e| ScenarioError::infra(format!("alloc listen port: {e}")))?;
            let introspect = alloc_port()
                .map_err(|e| ScenarioError::infra(format!("alloc introspection port: {e}")))?;
            let stream = alloc_port()
                .map_err(|e| ScenarioError::infra(format!("alloc stream port: {e}")))?;
            ports.push((listen, stream, introspect));
        }
        let addresses: Vec<SocketAddr> = ports
            .iter()
            .map(|(listen, _, _)| format!("127.0.0.1:{listen}").parse().unwrap())
            .collect();

        let mut prepared = Vec::with_capacity(count as usize);
        for (i, (listen_port, stream_port, introspect_port)) in ports.iter().copied().enumerate() {
            let alias = format!("s{}", i + 1);
            let peers: Vec<SocketAddr> = addresses
                .iter()
                .enumerate()
                .filter_map(|(j, addr)| (i != j).then_some(*addr))
                .collect();
            let (entry, command, restart) = build_spawn(SpawnConfig {
                layout: &self.layout,
                alias: &alias,
                nickname: &alias,
                listen_port,
                stream_port,
                introspect_port,
                binary: &self.binary,
                peers: &peers,
                discovery: "manual",
                heartbeat: self.heartbeat,
                peer_timeout: self.peer_timeout,
            });
            prepared.push((alias, entry, command, restart));
        }

        for (alias, entry, command, restart) in prepared {
            if let Err(error) = self.spawn_only(&alias, entry, command, restart) {
                self.teardown();
                return Err(error);
            }
        }
        let aliases: Vec<String> = self.entries.keys().cloned().collect();
        for alias in &aliases {
            if let Err(error) = self.wait_until_ready(alias) {
                self.teardown();
                return Err(error);
            }
        }

        // Readiness only proves the local endpoints are up. Confirm the
        // network itself converged before reporting `up` success.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            let complete = aliases.iter().all(|alias| {
                self.entries
                    .get(alias)
                    .and_then(|entry| entry.introspection_addr.as_deref())
                    .and_then(|addr| addr.parse().ok())
                    .and_then(|addr| observer::fetch(addr, Duration::from_millis(300)).ok())
                    .is_some_and(|snapshot| snapshot.peers.len() == count as usize - 1)
            });
            if complete {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(ScenarioError::infra(format!(
                    "full mesh did not converge: expected {} peers per Sister",
                    count - 1
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Start two real Sisters with pre-provisioned mutually trusted TLS
    /// identities. The harness only provisions files and launches processes;
    /// the TLS handshake and stream exchange are performed by `misaka`.
    pub fn start_secure_pair(&mut self) -> Result<(), ScenarioError> {
        let a_ports = allocate_ports()?;
        let b_ports = allocate_ports()?;
        let a_addr: SocketAddr = format!("127.0.0.1:{}", a_ports.0).parse().unwrap();
        let b_addr: SocketAddr = format!("127.0.0.1:{}", b_ports.0).parse().unwrap();

        let (a_entry, mut a_command, a_restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias: "a",
            nickname: "alpha",
            listen_port: a_ports.0,
            stream_port: a_ports.1,
            introspect_port: a_ports.2,
            binary: &self.binary,
            peers: &[b_addr],
            discovery: "manual",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        let (b_entry, mut b_command, b_restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias: "b",
            nickname: "beta",
            listen_port: b_ports.0,
            stream_port: b_ports.1,
            introspect_port: b_ports.2,
            binary: &self.binary,
            peers: &[a_addr],
            discovery: "manual",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });

        let a_cert = provision_tls_identity(&a_entry.config_dir, 10001, "alpha", a_ports.0)?;
        let b_cert = provision_tls_identity(&b_entry.config_dir, 10002, "beta", b_ports.0)?;
        a_command
            .arg("--stream-secure")
            .arg("--stream-trust-cert")
            .arg(&b_cert);
        b_command
            .arg("--stream-secure")
            .arg("--stream-trust-cert")
            .arg(&a_cert);

        self.spawn_only("a", a_entry, a_command, a_restart)?;
        self.spawn_only("b", b_entry, b_command, b_restart)?;
        for alias in ["a", "b"] {
            if let Err(error) = self.wait_until_ready(alias) {
                self.teardown();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Start two real Sisters whose stream transport is the opt-in Iroh
    /// backend. Control-plane discovery remains the same manual black-box
    /// mechanism; only the advertised stream endpoint changes.
    pub fn start_iroh_pair(&mut self) -> Result<(), ScenarioError> {
        self.start_iroh_pair_mode(true)
    }

    pub fn start_iroh_pair_secure(&mut self) -> Result<(), ScenarioError> {
        self.start_iroh_pair_mode(false)
    }

    fn start_iroh_pair_mode(&mut self, insecure_development: bool) -> Result<(), ScenarioError> {
        let a_ports = allocate_ports()?;
        let b_ports = allocate_ports()?;

        let spawn = |config: SpawnConfig<'_>| {
            if insecure_development {
                build_spawn(config)
            } else {
                build_spawn_secure(config)
            }
        };
        let (mut a_entry, mut a_command, mut a_restart) = spawn(SpawnConfig {
            layout: &self.layout,
            alias: "a",
            nickname: "alpha",
            listen_port: a_ports.0,
            stream_port: a_ports.1,
            introspect_port: a_ports.2,
            binary: &self.binary,
            peers: &[],
            discovery: "manual",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        let (mut b_entry, mut b_command, mut b_restart) = spawn(SpawnConfig {
            layout: &self.layout,
            alias: "b",
            nickname: "beta",
            listen_port: b_ports.0,
            stream_port: b_ports.1,
            introspect_port: b_ports.2,
            binary: &self.binary,
            peers: &[],
            discovery: "manual",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        a_entry.stream_backend = "iroh".to_string();
        b_entry.stream_backend = "iroh".to_string();
        let (authority, authority_key) = self.ensure_iroh_authority();
        provision_iroh_membership(
            &a_entry.config_dir,
            10001,
            "alpha",
            a_ports.0,
            &authority,
            &authority_key,
        )?;
        provision_iroh_membership(
            &b_entry.config_dir,
            10002,
            "beta",
            b_ports.0,
            &authority,
            &authority_key,
        )?;
        a_command.arg("--stream-backend").arg("iroh");
        b_command.arg("--stream-backend").arg("iroh");
        a_restart.append_args(["--stream-backend", "iroh"]);
        b_restart.append_args(["--stream-backend", "iroh"]);

        self.spawn_only("a", a_entry, a_command, a_restart)?;
        if let Err(error) = self.wait_until_ready("a") {
            self.teardown();
            return Err(error);
        }
        let endpoint = self
            .run_cli("a", &["endpoint", "--json"])?
            .parse::<serde_json::Value>()
            .map_err(|error| ScenarioError::assertion(format!("decode Iroh endpoint: {error}")))?
            .get("endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ScenarioError::assertion("Iroh endpoint export has no endpoint"))?
            .to_string();
        b_command.arg("--iroh-peer").arg(&endpoint);
        b_restart.append_arg("--iroh-peer");
        b_restart.append_arg(endpoint);
        self.spawn_only("b", b_entry, b_command, b_restart)?;
        if let Err(error) = self.wait_until_ready("b") {
            self.teardown();
            return Err(error);
        }
        Ok(())
    }

    /// Start an Iroh probe-only Sister with no control-plane peers or
    /// discovery. The endpoint is exchanged through the public CLI only.
    pub fn start_iroh_probe_only(&mut self, alias: &str) -> Result<(), ScenarioError> {
        let ports = allocate_ports()?;
        let (mut entry, mut command, mut restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname: alias,
            listen_port: ports.0,
            stream_port: ports.1,
            introspect_port: ports.2,
            binary: &self.binary,
            peers: &[],
            discovery: "off",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        let (authority, authority_key) = self.ensure_iroh_authority();
        let (id, nickname) = match alias {
            "a" => (10001, "a"),
            "b" => (10002, "b"),
            _ => (10000 + self.entries.len() as u64, alias),
        };
        provision_iroh_membership(
            &entry.config_dir,
            id,
            nickname,
            ports.0,
            &authority,
            &authority_key,
        )?;
        entry.stream_backend = "iroh".to_string();
        command
            .arg("--stream-backend")
            .arg("iroh")
            .arg("--probe-only");
        restart.append_args(["--stream-backend", "iroh", "--probe-only"]);
        self.spawn_only(alias, entry, command, restart)?;
        self.wait_until_ready(alias)
    }

    pub(crate) fn ensure_iroh_authority(
        &mut self,
    ) -> (NetworkAuthority, misaka_core::AuthorityKeyPair) {
        if let Some((authority, key)) = &self.iroh_authority {
            return (*authority, key.clone());
        }
        let network_id = NetworkId::parse("00000000-0000-0000-0000-000000000001")
            .expect("Testament network id is a valid UUID");
        let (authority, key) = NetworkAuthority::generate(network_id);
        self.iroh_authority = Some((authority, key.clone()));
        (authority, key)
    }

    pub fn introspect(&self, alias: &str) -> Result<IntrospectionSnapshot, ScenarioError> {
        let addr = self
            .entries
            .get(alias)
            .and_then(|e| e.introspection_addr.as_ref())
            .ok_or_else(|| ScenarioError::infra(format!("no introspection for {alias}")))?;
        observer::fetch(addr.parse().unwrap(), Duration::from_millis(500))
            .map_err(|e| ScenarioError::infra(format!("introspect {alias}: {}", e)))
    }

    pub fn peer_addr(&self, alias: &str) -> Result<SocketAddr, ScenarioError> {
        self.entries
            .get(alias)
            .map(|e| e.listen_addr.parse().unwrap())
            .ok_or_else(|| ScenarioError::infra(format!("no entry for {alias}")))
    }

    pub fn stream_addr(&self, alias: &str) -> Result<SocketAddr, ScenarioError> {
        self.entries
            .get(alias)
            .map(|e| e.stream_addr.parse().unwrap())
            .ok_or_else(|| ScenarioError::infra(format!("no stream entry for {alias}")))
    }

    /// 强杀一个 Sister (模拟崩溃)，不移除条目，供 peer-offline 观察。
    pub fn kill_sister(&mut self, alias: &str) -> Result<std::process::ExitStatus, ScenarioError> {
        let process = self
            .sisters
            .get_mut(alias)
            .ok_or_else(|| ScenarioError::infra(format!("no running sister {alias}")))?;
        process
            .kill_status()
            .map_err(|e| ScenarioError::infra(format!("kill {alias}: {e}")))
    }

    /// 温和停止一个 Sister，并返回 OS 的真实退出状态。
    pub fn terminate_sister(
        &mut self,
        alias: &str,
    ) -> Result<std::process::ExitStatus, ScenarioError> {
        let process = self
            .sisters
            .get_mut(alias)
            .ok_or_else(|| ScenarioError::infra(format!("no running sister {alias}")))?;
        process
            .terminate_status()
            .map_err(|e| ScenarioError::infra(format!("terminate {alias}: {e}")))
    }
    /// 从场景状态移除一个已结束的 Sister (停止+清理条目)。
    pub fn stop_and_forget(&mut self, alias: &str) -> Result<(), ScenarioError> {
        self.stop_sister(alias)
    }

    /// 用同一 config 重启一个 Sister (同名、同端口、同数据目录)。
    /// 通过 supervisor 的 `restart` 复用完全相同的启动参数，SisterId 与监听端口都不变。
    pub fn restart_sister(&mut self, alias: &str) -> Result<(), ScenarioError> {
        let process = self
            .sisters
            .get_mut(alias)
            .ok_or_else(|| ScenarioError::infra(format!("no running sister {alias}")))?;
        let stdout_log = process.entry.stdout_log.clone();
        let stderr_log = process.entry.stderr_log.clone();
        process
            .restart(&stdout_log, &stderr_log)
            .map_err(|e| ScenarioError::infra(format!("restart {alias}: {e}")))?;

        // 等待重新就绪并刷新条目中的 pid。
        let ia: SocketAddr = process
            .entry
            .introspection_addr
            .as_ref()
            .ok_or_else(|| ScenarioError::infra(format!("{alias} has no introspection address")))?
            .parse()
            .map_err(|e| ScenarioError::infra(format!("{alias} introspection address: {e}")))?;
        if observer::wait_until(ia, Duration::from_secs(15), |_| true).is_none() {
            return Err(ScenarioError::infra(format!(
                "{alias} did not become ready after restart; stderr: {}",
                std::fs::read_to_string(&stderr_log).unwrap_or_default()
            )));
        }
        process.entry.pid = process.pid();
        if let Some(entry) = self.entries.get_mut(alias) {
            entry.pid = process.pid();
        }
        Ok(())
    }

    /// 运行一条独立 `misaka` CLI 命令 (非 Node 进程)，拿到结果。
    pub fn run_cli(&self, alias: &str, args: &[&str]) -> Result<String, ScenarioError> {
        let entry = self
            .entries
            .get(alias)
            .ok_or_else(|| ScenarioError::infra(format!("no entry for {alias}")))?;
        let out = std::process::Command::new(&self.binary)
            .args(args)
            .env("MISAKA_CONFIG_DIR", &entry.config_dir)
            .output()
            .map_err(|e| ScenarioError::infra(format!("run cli: {}", e)))?;
        if !out.status.success() {
            return Err(ScenarioError::assertion(format!(
                "run cli exited with {}; stderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// 启动一条独立 `misaka` CLI 命令，供并发场景编排。
    pub fn spawn_cli(&self, alias: &str, args: &[&str]) -> Result<CliProcess, ScenarioError> {
        let entry = self
            .entries
            .get(alias)
            .ok_or_else(|| ScenarioError::infra(format!("no entry for {alias}")))?;
        self.spawn_cli_with_config(Path::new(&entry.config_dir), args)
    }

    /// 使用已有的隔离 config 目录启动 CLI，不需要运行中的 Sister。
    pub fn spawn_cli_with_config(
        &self,
        config_dir: &Path,
        args: &[&str],
    ) -> Result<CliProcess, ScenarioError> {
        let mut command = std::process::Command::new(&self.binary);
        command.args(args).env("MISAKA_CONFIG_DIR", config_dir);
        CliProcess::spawn(command).map_err(|e| ScenarioError::infra(format!("spawn cli: {e}")))
    }
    /// 停止一个 Sister，并从当前场景移除它。
    pub fn stop_sister(&mut self, alias: &str) -> Result<(), ScenarioError> {
        let Some(mut process) = self.sisters.remove(alias) else {
            return Err(ScenarioError::infra(format!("no running sister {alias}")));
        };
        process.terminate();
        process
            .wait()
            .map_err(|e| ScenarioError::infra(format!("wait {alias}: {e}")))?;
        self.collect_entry_events(&process.entry);
        self.entries.remove(alias);
        self.manifest.sisters.retain(|entry| entry.alias != alias);
        Ok(())
    }

    fn collect_entry_events(&self, entry: &SisterEntry) {
        let Ok(mut events) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.layout.events_path)
        else {
            return;
        };
        for path in [&entry.stdout_log, &entry.stderr_log] {
            if let Ok(contents) = std::fs::read_to_string(path) {
                for line in contents.lines().filter(|line| !line.is_empty()) {
                    let _ = writeln!(events, "{}", line);
                }
            }
        }
    }

    fn collect_events(&self) {
        for entry in self.entries.values() {
            self.collect_entry_events(entry);
        }
    }

    /// 全部停止并清理。
    pub fn teardown(&mut self) {
        for (_, mut p) in self.sisters.drain() {
            p.terminate();
            let _ = p.wait();
        }
        self.collect_events();
        // 已结束的场景不应让 down 误杀未来复用这些 PID 的进程。
        for entry in &mut self.manifest.sisters {
            entry.pid = None;
        }
    }

    pub fn artifacts(&self) -> Artifacts {
        Artifacts {
            manifest: self.layout.manifest_path.to_string_lossy().to_string(),
            events: self.layout.events_path.to_string_lossy().to_string(),
            sister_logs: self
                .entries
                .iter()
                .map(|(a, e)| (a.clone(), e.stderr_log.clone()))
                .collect(),
        }
    }

    pub fn report(&self, scenario: &str, result: Result<(), ScenarioError>) -> Report {
        match result {
            Ok(()) => crate::reporter::passed_report(scenario, &self.run_id, self.artifacts()),
            Err(err) => {
                crate::reporter::report_from_error(scenario, &self.run_id, self.artifacts(), &err)
            }
        }
    }
}

// ---------- 场景定义 ----------
impl Context {
    /// Start two Iroh Sisters that discover each other ONLY through a Gateway:
    /// each is given `--gateway <url>` and a short announce/fetch interval, and
    /// crucially NO `--iroh-peer`. This is the v0 normal-discovery UX.
    pub fn start_iroh_pair_via_gateway(
        &mut self,
        gateway_urls: &[String],
    ) -> Result<(), ScenarioError> {
        let a_ports = allocate_ports()?;
        let b_ports = allocate_ports()?;
        let (mut a_entry, mut a_command, mut a_restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias: "a",
            nickname: "alpha",
            listen_port: a_ports.0,
            stream_port: a_ports.1,
            introspect_port: a_ports.2,
            binary: &self.binary,
            peers: &[],
            discovery: "off",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        let (mut b_entry, mut b_command, mut b_restart) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias: "b",
            nickname: "beta",
            listen_port: b_ports.0,
            stream_port: b_ports.1,
            introspect_port: b_ports.2,
            binary: &self.binary,
            peers: &[],
            discovery: "off",
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        let (authority, authority_key) = self.ensure_iroh_authority();
        provision_iroh_membership(
            &a_entry.config_dir,
            10001,
            "alpha",
            a_ports.0,
            &authority,
            &authority_key,
        )?;
        provision_iroh_membership(
            &b_entry.config_dir,
            10002,
            "beta",
            b_ports.0,
            &authority,
            &authority_key,
        )?;
        for (entry, command, restart) in [
            (&mut a_entry, &mut a_command, &mut a_restart),
            (&mut b_entry, &mut b_command, &mut b_restart),
        ] {
            entry.stream_backend = "iroh".to_string();
            command
                .arg("--stream-backend")
                .arg("iroh")
                .arg("--gateway-interval")
                .arg("1");
            for url in gateway_urls {
                command.arg("--gateway").arg(url);
            }
            restart.append_args(["--stream-backend", "iroh", "--gateway-interval", "1"]);
            for url in gateway_urls {
                restart.append_arg("--gateway");
                restart.append_arg(url.clone());
            }
        }
        self.spawn_only("a", a_entry, a_command, a_restart)?;
        self.wait_until_ready("a")?;
        self.spawn_only("b", b_entry, b_command, b_restart)?;
        self.wait_until_ready("b")?;
        Ok(())
    }
}
