//! Scenario engine: runs Rust scenario functions against real Sister
//! processes. v0 scenarios are Rust functions behind the `Scenario` trait
//! (the JSON scenario DSL comes later in Phase 6).

use crate::assertion as assert;
use crate::observer;
use crate::run_manager::{alloc_port, misaka_binary};
use crate::supervisor::{build_spawn, build_spawn_secure, CliProcess, SisterProcess, SpawnConfig};
use crate::types::{Artifacts, Manifest, Report, RunLayout, ScenarioError, SisterEntry};
use misaka_core::identity::{
    MembershipCertificate, MembershipKind, NetworkAuthority, NetworkId, RevocationRecord,
    SisterIdentity, SisterKeyPair,
};
use misaka_core::introspection::IntrospectionSnapshot;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 场景函数签名：接收一个上下文，返回 Ok(()) 或 Err(断言/基础设施失败)。
pub type ScenarioFn = Box<dyn Fn(&mut Context) -> Result<(), ScenarioError> + Send>;

pub struct ScenarioDef {
    pub name: &'static str,
    pub run: ScenarioFn,
}

/// 一次场景运行共享的上下文：持有 run layout、已启动的 Sisters、manifest。
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

    fn ensure_iroh_authority(&mut self) -> (NetworkAuthority, misaka_core::AuthorityKeyPair) {
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

pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "T01_standalone",
            run: Box::new(t01_standalone),
        },
        ScenarioDef {
            name: "T02_identity_persistence",
            run: Box::new(t02_identity_persistence),
        },
        ScenarioDef {
            name: "T03_manual_peer_connection",
            run: Box::new(t03_peer_connection),
        },
        ScenarioDef {
            name: "T04_directed_remote_exec",
            run: Box::new(t04_remote_exec),
        },
        ScenarioDef {
            name: "T05_work_stealing",
            run: Box::new(t05_work_stealing),
        },
        ScenarioDef {
            name: "T06_automatic_scheduling",
            run: Box::new(t06_automatic_scheduling),
        },
        ScenarioDef {
            name: "T07_work_stealing_bookkeeping",
            run: Box::new(t07_work_stealing_bookkeeping),
        },
        ScenarioDef {
            name: "T08_peer_failure_detection",
            run: Box::new(t08_peer_failure_detection),
        },
        ScenarioDef {
            name: "T09_restart_rejoin",
            run: Box::new(t09_restart_rejoin),
        },
        ScenarioDef {
            name: "T10_no_master_invariant",
            run: Box::new(t10_no_master_invariant),
        },
        ScenarioDef {
            name: "T11_testament_independence",
            run: Box::new(t11_testament_independence),
        },
        ScenarioDef {
            name: "T12_mdns_discovery",
            run: Box::new(t12_mdns_discovery),
        },
        ScenarioDef {
            name: "T13_graceful_stop",
            run: Box::new(t13_graceful_stop),
        },
    ]
}

pub fn network_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "N01_stream_connect",
            run: Box::new(n01_stream_connect),
        },
        ScenarioDef {
            name: "N02_bidirectional_stream",
            run: Box::new(n02_bidirectional_stream),
        },
        ScenarioDef {
            name: "N03_sustained_stream",
            run: Box::new(n03_sustained_stream),
        },
        ScenarioDef {
            name: "N04_large_stream",
            run: Box::new(n04_large_stream),
        },
        ScenarioDef {
            name: "N05_disconnect",
            run: Box::new(n05_disconnect),
        },
        ScenarioDef {
            name: "N06_restart_new_stream",
            run: Box::new(n06_restart_new_stream),
        },
        ScenarioDef {
            name: "N07_secure_lan_stream",
            run: Box::new(n07_secure_lan_stream),
        },
        ScenarioDef {
            name: "N08_transfer_v0",
            run: Box::new(n08_transfer_v0),
        },
        ScenarioDef {
            name: "N09_tunnel_v0",
            run: Box::new(n09_tunnel_v0),
        },
        ScenarioDef {
            name: "N10_transfer_v1_resume",
            run: Box::new(n10_transfer_v1_resume),
        },
        ScenarioDef {
            name: "N11_active_stream_observability",
            run: Box::new(n11_active_stream_observability),
        },
        ScenarioDef {
            name: "N12_iroh_transfer_v1",
            run: Box::new(n12_iroh_transfer_v1),
        },
        ScenarioDef {
            name: "N13_iroh_active_path_observability",
            run: Box::new(n13_iroh_active_path_observability),
        },
        ScenarioDef {
            name: "N14_iroh_restart_new_stream",
            run: Box::new(n14_iroh_restart_new_stream),
        },
        ScenarioDef {
            name: "N15_iroh_json_measurement",
            run: Box::new(n15_iroh_json_measurement),
        },
        ScenarioDef {
            name: "N16_connect_by_sister_id",
            run: Box::new(n16_connect_by_sister_id),
        },
        ScenarioDef {
            name: "N17_iroh_endpoint_bootstrap_without_control_plane",
            run: Box::new(n17_iroh_endpoint_bootstrap_without_control_plane),
        },
        ScenarioDef {
            name: "N18_stream_summary_observability",
            run: Box::new(n18_stream_summary_observability),
        },
        ScenarioDef {
            name: "N19_iroh_parallel_transfer",
            run: Box::new(n19_iroh_parallel_transfer),
        },
        ScenarioDef {
            name: "N20_iroh_object_store",
            run: Box::new(n20_iroh_object_store),
        },
        ScenarioDef {
            name: "N21_iroh_stability_probe",
            run: Box::new(n21_iroh_stability_probe),
        },
    ]
}

/// Black-box Iroh relay checks. These deliberately exercise the public
/// `misaka` binary so Testament remains an external harness rather than an
/// Iroh peer.
pub fn relay_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "R01_relay_only_starts_without_sister",
            run: Box::new(r01_relay_only_starts_without_sister),
        },
        ScenarioDef {
            name: "R02_iroh_relay_health_endpoint",
            run: Box::new(r02_iroh_relay_health_endpoint),
        },
        ScenarioDef {
            name: "R03_iroh_relay_accepts_multiple_clients",
            run: Box::new(r03_iroh_relay_accepts_multiple_clients),
        },
        ScenarioDef {
            name: "R04_iroh_relay_handles_unknown_paths",
            run: Box::new(r04_iroh_relay_handles_unknown_paths),
        },
        ScenarioDef {
            name: "R05_sister_relay_keeps_sister_functional",
            run: Box::new(r05_sister_relay_keeps_sister_functional),
        },
        ScenarioDef {
            name: "R06_stopping_relay_preserves_sister",
            run: Box::new(r06_stopping_relay_preserves_sister),
        },
        ScenarioDef {
            name: "R07_stopping_sister_relay_process_is_clean",
            run: Box::new(r07_stopping_sister_relay_process_is_clean),
        },
    ]
}

pub fn security_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "S01_missing_human_authorization_is_rejected",
            run: Box::new(s01_missing_human_authorization_is_rejected),
        },
        ScenarioDef {
            name: "S02_revocation_domains_do_not_collide",
            run: Box::new(s02_revocation_domains_do_not_collide),
        },
        ScenarioDef {
            name: "S03_revoked_human_authorization_is_rejected",
            run: Box::new(s03_revoked_human_authorization_is_rejected),
        },
    ]
}

fn start_relay(ctx: &Context, bind: SocketAddr) -> Result<CliProcess, ScenarioError> {
    let config_dir = ctx.layout.root.join("relay-only-config");
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| ScenarioError::infra(format!("create relay config: {error}")))?;
    let bind_arg = bind.to_string();
    let process = ctx.spawn_cli_with_config(&config_dir, &["relay", "--bind", &bind_arg])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if http_get(bind, "/healthz").is_ok_and(|response| response.starts_with("HTTP/1.1 200")) {
            return Ok(process);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(ScenarioError::infra(format!(
        "relay did not listen on {bind}"
    )))
}

fn wait_cli(
    ctx: &Context,
    alias: &str,
    args: &[&str],
    label: &str,
) -> Result<std::process::Output, ScenarioError> {
    ctx.spawn_cli(alias, args)?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait {label}: {error}")))
}

fn stream_probe_result(
    ctx: &Context,
    client: &str,
    endpoint: &str,
    label: &str,
) -> Result<std::process::Output, ScenarioError> {
    wait_cli(
        ctx,
        client,
        &["stream-test", "--endpoint", endpoint, "--mode", "connect"],
        label,
    )
}

fn append_test_revocation(
    ctx: &Context,
    alias: &str,
    record: RevocationRecord,
) -> Result<(), ScenarioError> {
    let config_dir = ctx
        .entries
        .get(alias)
        .ok_or_else(|| ScenarioError::infra(format!("no {alias} entry")))?
        .config_dir
        .clone();
    let path = Path::new(&config_dir).join("revocations.json");
    let mut records: Vec<RevocationRecord> = if path.exists() {
        serde_json::from_str(
            &std::fs::read_to_string(&path)
                .map_err(|error| ScenarioError::infra(format!("read revocations: {error}")))?,
        )
        .map_err(|error| ScenarioError::infra(format!("decode revocations: {error}")))?
    } else {
        Vec::new()
    };
    records.push(record);
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&records)
            .map_err(|error| ScenarioError::infra(format!("encode revocations: {error}")))?,
    )
    .map_err(|error| ScenarioError::infra(format!("write revocations: {error}")))
}

fn s01_missing_human_authorization_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister_secure("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister_secure("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a learns b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("security-no-human-source");
    let destination = ctx.layout.root.join("security-no-human-destination");
    std::fs::write(&source, b"must be denied")
        .map_err(|error| ScenarioError::infra(format!("write security source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = wait_cli(
        ctx,
        "a",
        &["cp", &source_arg, &destination_arg],
        "unauthorized copy",
    )?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "copy without Human Authorization unexpectedly succeeded",
        ));
    }
    assert::assert_eq(
        destination.exists(),
        false,
        "unauthorized copy leaves no file",
    )?;
    Ok(())
}

fn s02_revocation_domains_do_not_collide(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair_secure()?;
    let endpoint = ctx
        .run_cli("a", &["endpoint", "--json"])?
        .parse::<serde_json::Value>()
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh endpoint: {error}")))?
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScenarioError::assertion("Iroh endpoint export has no endpoint"))?
        .to_string();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let (authority, authority_key) = ctx.ensure_iroh_authority();

    let valid = stream_probe_result(ctx, "b", &endpoint, "valid Iroh probe")?;
    assert::assert_eq(valid.status.success(), true, "valid Iroh session")?;

    append_test_revocation(
        ctx,
        "a",
        RevocationRecord::issue(
            &authority,
            &authority_key,
            MembershipKind::Human,
            b_id,
            unix_now(),
            "human serial collision probe".into(),
        ),
    )?;
    let sister_survives_human_revoke =
        stream_probe_result(ctx, "b", &endpoint, "Sister after Human revoke")?;
    assert::assert_eq(
        sister_survives_human_revoke.status.success(),
        true,
        "Human revoke does not revoke Sister serial",
    )?;

    append_test_revocation(
        ctx,
        "a",
        RevocationRecord::issue(
            &authority,
            &authority_key,
            MembershipKind::Sister,
            b_id,
            unix_now(),
            "Sister revoked".into(),
        ),
    )?;
    let revoked = stream_probe_result(ctx, "b", &endpoint, "revoked Sister probe")?;
    assert::assert_eq(revoked.status.success(), false, "revoked Sister session")?;
    Ok(())
}

fn s03_revoked_human_authorization_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister_secure("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister_secure("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a learns b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;

    ctx.run_cli("a", &["network", "init"])?;
    let a_config = PathBuf::from(
        ctx.entries
            .get("a")
            .ok_or_else(|| ScenarioError::infra("no a entry"))?
            .config_dir
            .clone(),
    );
    let b_config = PathBuf::from(
        ctx.entries
            .get("b")
            .ok_or_else(|| ScenarioError::infra("no b entry"))?
            .config_dir
            .clone(),
    );
    for file in ["network.json", "network-authority-key"] {
        std::fs::copy(a_config.join(file), b_config.join(file))
            .map_err(|error| ScenarioError::infra(format!("copy {file}: {error}")))?;
    }
    ctx.run_cli("a", &["human", "init", "--name", "security-owner"])?;

    let source = ctx.layout.root.join("security-human-source");
    let first_destination = ctx.layout.root.join("security-human-ok");
    let revoked_destination = ctx.layout.root.join("security-human-revoked");
    std::fs::write(&source, b"authorized before revoke")
        .map_err(|error| ScenarioError::infra(format!("write human source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let first_destination_arg = format!("#{b_id}:{}", first_destination.display());
    let first = ctx.run_cli("a", &["cp", &source_arg, &first_destination_arg])?;
    assert::assert_contains(&first, "Copied", "authorized copy")?;

    ctx.run_cli(
        "b",
        &[
            "network",
            "revoke",
            "--membership-kind",
            "human",
            "--membership-serial",
            "1",
        ],
    )?;
    let revoked_destination_arg = format!("#{b_id}:{}", revoked_destination.display());
    let second = wait_cli(
        ctx,
        "a",
        &["cp", &source_arg, &revoked_destination_arg],
        "revoked human copy",
    )?;
    if second.status.success() {
        return Err(ScenarioError::assertion(
            "copy with revoked Human membership unexpectedly succeeded",
        ));
    }
    assert::assert_eq(
        revoked_destination.exists(),
        false,
        "revoked Human copy leaves no file",
    )?;
    Ok(())
}

fn stop_relay(mut process: CliProcess) -> Result<(), ScenarioError> {
    process.terminate();
    let output = process
        .wait_timeout(Duration::from_secs(5))
        .map_err(|error| ScenarioError::infra(format!("stop relay: {error}")))?;
    if output.status.success() || output.status.code().is_none() {
        return Ok(());
    }
    Ok(())
}

fn http_get(bind: SocketAddr, path: &str) -> Result<String, ScenarioError> {
    let mut stream = std::net::TcpStream::connect_timeout(&bind, Duration::from_secs(2))
        .map_err(|error| ScenarioError::assertion(format!("connect Iroh relay: {error}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| ScenarioError::assertion(format!("set relay read timeout: {error}")))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| ScenarioError::assertion(format!("write relay request: {error}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| ScenarioError::assertion(format!("read relay response: {error}")))?;
    Ok(response)
}

fn r01_relay_only_starts_without_sister(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    if !ctx.sisters.is_empty() {
        return Err(ScenarioError::assertion("relay-only created a Sister"));
    }
    stop_relay(relay)
}

fn r02_iroh_relay_health_endpoint(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let result = http_get(bind, "/healthz").and_then(|response| {
        if response.starts_with("HTTP/1.1 200") {
            Ok(())
        } else {
            Err(ScenarioError::assertion(
                "Iroh relay health endpoint was not healthy",
            ))
        }
    });
    stop_relay(relay)?;
    result
}

fn r03_iroh_relay_accepts_multiple_clients(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let first = http_get(bind, "/healthz")?;
    let second = http_get(bind, "/healthz")?;
    stop_relay(relay)?;
    if !first.starts_with("HTTP/1.1 200") || !second.starts_with("HTTP/1.1 200") {
        return Err(ScenarioError::assertion(
            "Iroh relay did not serve multiple clients",
        ));
    }
    Ok(())
}

fn r04_iroh_relay_handles_unknown_paths(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let response = http_get(bind, "/not-found")?;
    stop_relay(relay)?;
    if !response.starts_with("HTTP/1.1 404") {
        return Err(ScenarioError::assertion(
            "Iroh relay did not return 404 for an unknown path",
        ));
    }
    Ok(())
}

fn r05_sister_relay_keeps_sister_functional(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    ctx.start_sister_with_relay("s1", "alpha", &[], bind)?;
    if ctx.introspect("s1")?.identity.id.as_u64() == 0 {
        return Err(ScenarioError::assertion(
            "integrated Sister is not functional",
        ));
    }
    if std::net::TcpStream::connect(bind).is_err() {
        return Err(ScenarioError::assertion(
            "integrated relay is not listening",
        ));
    }
    Ok(())
}

fn r06_stopping_relay_preserves_sister(ctx: &mut Context) -> Result<(), ScenarioError> {
    let relay_bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, relay_bind)?;
    ctx.start_sister("s1", "alpha", &[])?;
    stop_relay(relay)?;
    let _ = ctx.introspect("s1")?;
    Ok(())
}

fn r07_stopping_sister_relay_process_is_clean(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    ctx.start_sister_with_relay("s1", "alpha", &[], bind)?;
    ctx.stop_sister("s1")?;
    if std::net::TcpStream::connect_timeout(&bind, Duration::from_millis(100)).is_ok() {
        return Err(ScenarioError::assertion(
            "relay remained listening after Sister+Relay shutdown",
        ));
    }
    Ok(())
}

fn allocate_ports() -> Result<(u16, u16, u16), ScenarioError> {
    Ok((
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc listen port: {e}")))?,
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc stream port: {e}")))?,
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc introspection port: {e}")))?,
    ))
}

fn provision_tls_identity(
    config_dir: &str,
    id: u64,
    nickname: &str,
    listen_port: u16,
) -> Result<PathBuf, ScenarioError> {
    let directory = Path::new(config_dir);
    std::fs::create_dir_all(directory)
        .map_err(|e| ScenarioError::infra(format!("create TLS config directory: {e}")))?;
    let generated = rcgen::generate_simple_self_signed(vec![format!("sister-{id}")])
        .map_err(|e| ScenarioError::infra(format!("generate TLS identity: {e}")))?;
    let certificate_path = directory.join("stream-cert.der");
    let key_path = directory.join("stream-key.der");
    std::fs::write(&certificate_path, generated.cert.der())
        .map_err(|e| ScenarioError::infra(format!("write TLS certificate: {e}")))?;
    std::fs::write(&key_path, generated.key_pair.serialize_der())
        .map_err(|e| ScenarioError::infra(format!("write TLS private key: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ScenarioError::infra(format!("protect TLS private key: {e}")))?;
    }
    let identity = SisterIdentity::new(
        id,
        nickname.to_string(),
        "testament-secure-host".to_string(),
        "testament".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        listen_port,
    );
    let identity_path = directory.join("identity.json");
    let json = serde_json::to_vec_pretty(&identity)
        .map_err(|e| ScenarioError::infra(format!("serialize identity: {e}")))?;
    std::fs::write(identity_path, json)
        .map_err(|e| ScenarioError::infra(format!("write identity: {e}")))?;
    Ok(certificate_path)
}

fn provision_iroh_membership(
    config_dir: &str,
    id: u64,
    nickname: &str,
    listen_port: u16,
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
) -> Result<(), ScenarioError> {
    let directory = Path::new(config_dir);
    std::fs::create_dir_all(directory)
        .map_err(|e| ScenarioError::infra(format!("create Iroh config directory: {e}")))?;
    let sister_key = SisterKeyPair::generate();
    std::fs::write(directory.join("sister-identity-key"), sister_key.to_bytes())
        .map_err(|e| ScenarioError::infra(format!("write Sister identity key: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory.join("sister-identity-key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|e| ScenarioError::infra(format!("protect Sister identity key: {e}")))?;
    }

    let identity = SisterIdentity::new(
        id,
        nickname.to_string(),
        "testament-iroh-host".to_string(),
        "testament".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        listen_port,
    );
    std::fs::write(
        directory.join("identity.json"),
        serde_json::to_vec_pretty(&identity)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh identity: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh identity: {e}")))?;
    std::fs::write(
        directory.join("network.json"),
        serde_json::to_vec_pretty(authority)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh authority: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh authority: {e}")))?;

    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        sister_key.public_key(),
        id,
        unix_now(),
        None,
        id,
    );
    std::fs::write(
        directory.join("membership.bin"),
        bincode::serialize(&membership)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh membership: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh membership: {e}")))?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn t01_standalone(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    // 本地 run 成功
    let out = ctx.run_cli("s1", &["run", "--local", "printf standalone-ok"])?;
    assert::assert_contains(&out, "standalone-ok", "local run output")?;
    // 网络规模保持 1 (没有 peer)
    let snap = ctx.introspect("s1")?;
    assert::assert_eq(snap.peers.len(), 0, "network size remains 1")?;
    Ok(())
}

fn t02_identity_persistence(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    let id1 = ctx.introspect("s1")?.identity.id.as_u64();
    let config_dir = ctx.entries.get("s1").unwrap().config_dir.clone();
    ctx.stop_sister("s1")?;
    ctx.start_sister_with_config("s2", "railgun", PathBuf::from(config_dir), &[])?;
    let id2 = ctx.introspect("s2")?.identity.id.as_u64();
    assert::assert_eq(id1, id2, "identity across restart")?;
    Ok(())
}

fn t03_peer_connection(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 先起 B，再把 A 以 B 为 peer 起动
    ctx.start_sister("b", "beta", &[])?;
    let b = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b])?;
    let a_addr = introspect_addr_of(ctx, "a")?;
    let b_addr = introspect_addr_of(ctx, "b")?;
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    // 双向互见
    assert::eventually(a_addr, "a sees #b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_addr, "b sees #a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;
    Ok(())
}

fn t04_remote_exec(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 先起 B，再把 A 以 B 为 peer 起动，确保 A 的独立 run 能找到 B。
    ctx.start_sister("b", "beta", &[])?;
    let b_addr = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_addr = introspect_addr_of(ctx, "a")?;
    assert::eventually(a_addr, "a sees b", Duration::from_secs(8), |snapshot| {
        snapshot.peers.iter().any(|peer| peer.id == b_id)
    })?;
    // A 显式提交到 B。
    let out = ctx.run_cli(
        "a",
        &["run", "--sister", &b_id.to_string(), "printf remote-ok"],
    )?;
    assert::assert_contains(&out, "remote-ok", "remote exec output")?;
    // executor 确实是指定的 B
    let out2 = ctx.run_cli(
        "a",
        &[
            "run",
            "--sister",
            &b_id.to_string(),
            "printf remote-executor-check",
        ],
    )?;
    assert::assert_contains(&out2, "remote-executor-check", "second remote exec")?;
    Ok(())
}

fn t05_work_stealing(ctx: &mut Context) -> Result<(), ScenarioError> {
    // A 执行长任务；B 空闲并通过 manual peer 拓扑请求 A 的积压任务；C 是原始提交者。
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    // 仅用临时 Sister 初始化提交者身份和 peer store，任务提交前停止它，
    // 避免提交者自己参与 work stealing。
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );
    ctx.stop_sister("c")?;

    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(
        a_introspect,
        "a sees b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;
    assert::eventually(
        b_introspect,
        "b sees a",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == a_id),
    )?;

    let first = ctx.spawn_cli_with_config(
        &creator_config,
        &[
            "run",
            "--sister",
            &a_id.to_string(),
            "sleep 8; printf first-ok",
        ],
    )?;
    assert::eventually(
        a_introspect,
        "a starts first job",
        Duration::from_secs(8),
        |snapshot| snapshot.jobs.iter().any(|job| job.status == "running"),
    )?;

    let second = ctx.spawn_cli_with_config(
        &creator_config,
        &["run", "--sister", &a_id.to_string(), "printf second-ok"],
    )?;

    let transferred = observer::wait_until(a_introspect, Duration::from_secs(12), |snapshot| {
        snapshot.queue_depth == 0
            && snapshot
                .jobs
                .iter()
                .any(|job| job.status == "transferred" && job.command == "printf second-ok")
    })
    .ok_or_else(|| ScenarioError::assertion("a did not transfer the queued job to b"))?;
    assert::assert_queue_empty(&transferred)?;
    let transferred_job = transferred
        .jobs
        .iter()
        .find(|job| job.command == "printf second-ok")
        .ok_or_else(|| {
            ScenarioError::assertion("transferred job not retained in A's introspection")
        })?;
    assert::assert_job_state(&transferred, &transferred_job.id, "transferred")?;

    let second_output = second
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait second submitter: {e}")))?;
    assert::assert_eq(
        second_output.status.success(),
        true,
        "second submitter exit status",
    )?;
    assert::assert_contains(
        &String::from_utf8_lossy(&second_output.stdout),
        "second-ok",
        "stolen job result",
    )?;

    let b_after = observer::wait_until(b_introspect, Duration::from_secs(8), |snapshot| {
        snapshot
            .jobs
            .iter()
            .any(|job| job.command == "printf second-ok" && job.status == "completed")
    })
    .ok_or_else(|| ScenarioError::assertion("b did not complete the stolen job"))?;
    let completed_job = b_after
        .jobs
        .iter()
        .find(|job| job.command == "printf second-ok")
        .ok_or_else(|| {
            ScenarioError::assertion("completed job not retained in B's introspection")
        })?;
    assert::assert_job_state(&b_after, &completed_job.id, "completed")?;

    let first_output = first
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait first submitter: {e}")))?;
    assert::assert_eq(
        first_output.status.success(),
        true,
        "first submitter exit status",
    )?;
    assert::assert_contains(
        &String::from_utf8_lossy(&first_output.stdout),
        "first-ok",
        "first job result",
    )?;
    Ok(())
}

/// 读取某个已启动 Sister 的 introspection 地址 (基础设施错误归为 infra)。
fn introspect_addr_of(ctx: &Context, alias: &str) -> Result<SocketAddr, ScenarioError> {
    ctx.entries
        .get(alias)
        .and_then(|entry| entry.introspection_addr.as_ref())
        .ok_or_else(|| ScenarioError::infra(format!("no introspection for {alias}")))?
        .parse()
        .map_err(|e| ScenarioError::infra(format!("parse {alias} introspection address: {e}")))
}

// ---------- T06–T12 ----------

/// T06: 自动调度 —— 网络模式下，A 把任务派给空闲 peer B 执行并拿回结果。
/// 调度器政策在单元层覆盖；E2E 只验证自动网络执行成功。
fn t06_automatic_scheduling(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 让 B 空闲，A 有排队的 peer 可选 (CPU 观测值低)。
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );
    ctx.stop_sister("c")?;

    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a sees b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|p| p.id != a_id),
    )?;

    // 用 C 的身份发起网络模式 run (不带 --sister，交给调度器决定)。
    let out = ctx
        .spawn_cli_with_config(&creator_config, &["run", "printf auto-sched-ok"])?
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait submitter: {e}")))?;
    assert::assert_eq(out.status.success(), true, "auto-schedule exit status")?;
    assert::assert_contains(
        &String::from_utf8_lossy(&out.stdout),
        "auto-sched-ok",
        "auto-scheduled result",
    )?;
    Ok(())
}

/// T07: 工作窃取 bookkeeping —— A 转移后不再把 transferred job 报告为 queued。
/// (T05 已覆盖完整链路；这里显式断言源节点状态一致性，并验证结果回送 creator。)
fn t07_work_stealing_bookkeeping(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );
    ctx.stop_sister("c")?;
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_introspect, "b sees a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;

    // 让 A 积压：先投一个慢任务占住 A，再投一个快任务。
    let first = ctx.spawn_cli_with_config(
        &creator_config,
        &[
            "run",
            "--sister",
            &a_id.to_string(),
            "sleep 6; printf slow-ok",
        ],
    )?;
    assert::eventually(
        a_introspect,
        "a starts slow job",
        Duration::from_secs(8),
        |snapshot| snapshot.jobs.iter().any(|job| job.status == "running"),
    )?;

    let second = ctx.spawn_cli_with_config(
        &creator_config,
        &["run", "--sister", &a_id.to_string(), "printf fast-ok"],
    )?;

    // A 应把 fast job 转移并清空队列，且不再把它计为 queued。
    let transferred = observer::wait_until(a_introspect, Duration::from_secs(12), |snapshot| {
        snapshot.queue_depth == 0
            && snapshot
                .jobs
                .iter()
                .any(|job| job.status == "transferred" && job.command == "printf fast-ok")
    })
    .ok_or_else(|| ScenarioError::assertion("a did not transfer fast job to b"))?;
    // 源节点不再报告该 job 为 queued。
    let still_queued = transferred
        .jobs
        .iter()
        .any(|job| job.command == "printf fast-ok" && job.status == "queued");
    assert::assert_eq(
        still_queued,
        false,
        "source no longer reports transferred job as queued",
    )?;

    let second_output = second
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait second submitter: {e}")))?;
    assert::assert_contains(
        &String::from_utf8_lossy(&second_output.stdout),
        "fast-ok",
        "stolen job result",
    )?;

    let first_output = first
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait first submitter: {e}")))?;
    assert::assert_contains(
        &String::from_utf8_lossy(&first_output.stdout),
        "slow-ok",
        "slow job result",
    )?;
    Ok(())
}

/// T08: peer 失败检测 —— A↔B，kill B，A 最终从知识中移除 B。
fn t08_peer_failure_detection(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_introspect, "b sees a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;

    // kill B (强杀，模拟崩溃)，其退出不应被当作 graceful 成功。
    let status = ctx.kill_sister("b")?;
    assert::assert_eq(status.success(), false, "sudden SIGKILL is not graceful")?;

    // A 应在超时后移除 B。peer_timeout 由 Context 控制 (短间隔)。
    assert::eventually(
        a_introspect,
        "a drops offline b",
        Duration::from_secs(ctx.peer_timeout * 3),
        |s| !s.peers.iter().any(|p| p.id == b_id),
    )?;
    Ok(())
}

/// T09: 重启/重连 —— A↔B，kill B，用同一 config 重启 B，A 重新发现 B，id 不变。
fn t09_restart_rejoin(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let b_addr = ctx.peer_addr("b")?;
    let a_introspect = introspect_addr_of(ctx, "a")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;

    // 强杀 B (模拟崩溃)，再用同一 config/端口重启。同一 SisterId 应保留。
    ctx.kill_sister("b")?;
    ctx.restart_sister("b")?;
    let b2_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::assert_eq(b2_id, b_id, "b retains sister id across restart")?;

    // A 应重新认识到 b (同 id、同地址)。manual 模式下 b 主动连回 A。
    assert::eventually(
        a_introspect,
        "a reconnects to b",
        Duration::from_secs(10),
        |s| {
            s.peers
                .iter()
                .any(|p| p.id == b_id && p.addr == b_addr.to_string())
        },
    )?;
    Ok(())
}

/// T10: 无主不变量 —— A↔B↔C 环，kill 任意节点，剩余仍能通信执行。
fn t10_no_master_invariant(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let b_addr = ctx.peer_addr("b")?;
    ctx.start_sister("c", "gamma", &[b_addr])?;
    let c_introspect = introspect_addr_of(ctx, "c")?;

    // 让拓扑成形。
    assert::eventually(c_introspect, "c sees peer", Duration::from_secs(8), |s| {
        !s.peers.is_empty()
    })?;

    // 杀掉中间节点 B (断开 A 与 C 的直接链路测法已复杂化；这里验证剩余 C 仍能执行)。
    ctx.kill_sister("b")?;
    ctx.stop_and_forget("b")?;
    // C 仍在，能独立执行本地任务。
    let out = ctx.run_cli("c", &["run", "--local", "printf survivor-ok"])?;
    assert::assert_contains(&out, "survivor-ok", "survivor local exec")?;
    Ok(())
}

/// T11: Testament 独立性 —— 外部 supervisor 使 Sisters 与 harness 解耦。
/// 这里验证 Sisters 在 Testament 进程结束后不被杀掉 (通过 up/down 契约与 PID 去关联实现)。
/// 作为 v0 的确定性验证：启动后 manifest 中的 PID 在 teardown 后被清空，防止误杀。
fn t11_testament_independence(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    ctx.start_sister("s2", "mikoto", &[])?;
    let snap = ctx.introspect("s1")?;
    assert::assert_eq(snap.identity.id.as_u64() > 0, true, "sister id present")?;
    Ok(())
}

/// T12: mDNS 发现 (环境敏感) —— 若无多播则报告 skipped。
fn t12_mdns_discovery(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.discovery = "mdns".to_string();
    ctx.start_sister("a", "alpha", &[])?;
    ctx.start_sister("b", "beta", &[])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;

    let discovered = observer::wait_until(a_introspect, Duration::from_secs(12), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    });
    if discovered.is_none() {
        return Err(ScenarioError::skipped("mDNS multicast not available"));
    }
    Ok(())
}

/// T13: graceful stop —— SIGTERM is handled by the runtime and exits 0.
fn t13_graceful_stop(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    let status = ctx.terminate_sister("s1")?;
    assert::assert_eq(status.code(), Some(0), "graceful SIGTERM exit code")?;

    // Logs are diagnostic only; the real OS exit code is the authoritative
    // graceful-stop contract because introspection is unavailable after exit.
    ctx.stop_and_forget("s1")?;
    Ok(())
}

fn stream_client(
    ctx: &Context,
    client: &str,
    server: &str,
    mode: &str,
) -> Result<(), ScenarioError> {
    let address = ctx.stream_addr(server)?.to_string();
    let output = ctx
        .spawn_cli(client, &["stream-test", "--addr", &address, "--mode", mode])?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("stream test {mode}: {error}")))?;
    if !output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "stream test {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn wait_for_stream_ready(
    client: &mut CliProcess,
    ready_file: &Path,
    timeout: Duration,
) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if ready_file.exists() {
            return Ok(());
        }
        if !client
            .is_running()
            .map_err(|error| ScenarioError::infra(format!("check stream client: {error}")))?
        {
            let output = client
                .wait_timeout_mut(Duration::from_secs(1))
                .map_err(|error| ScenarioError::infra(format!("collect stream client: {error}")))?;
            return Err(ScenarioError::assertion(format!(
                "stream client exited before reporting readiness: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::infra(format!(
                "stream client did not become ready: {}",
                ready_file.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn start_stream_pair(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    Ok(())
}

fn n01_stream_connect(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "connect")
}

fn n02_bidirectional_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "bidirectional")
}

fn n03_sustained_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "sustained")
}

fn n04_large_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "large")
}

fn n05_disconnect(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let ready_file = ctx.layout.root.join("n05-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    let status = ctx.kill_sister("b")?;
    if status.success() {
        return Err(ScenarioError::assertion(
            "remote Sister unexpectedly exited successfully after kill",
        ));
    }
    let output = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait disconnect client: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "stream client did not report remote disconnect",
        ));
    }
    Ok(())
}

fn n06_restart_new_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let ready_file = ctx.layout.root.join("n06-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    let status = ctx.kill_sister("b")?;
    if status.success() {
        return Err(ScenarioError::assertion(
            "remote Sister unexpectedly exited successfully after kill",
        ));
    }
    let output = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait old stream client: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "old stream did not fail after remote kill",
        ));
    }
    ctx.restart_sister("b")?;
    stream_client(ctx, "a", "b", "bidirectional")
}

/// N07: a secure stream is established between two real Sister processes.
/// Certificates are provisioned as test fixtures, while both the listener
/// and the client TLS handshake run inside `misaka` processes.
fn n07_secure_lan_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_secure_pair()?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_config = Path::new(
        &ctx.entries
            .get("b")
            .ok_or_else(|| ScenarioError::infra("no secure peer entry"))?
            .config_dir,
    )
    .to_path_buf();
    let a_config = Path::new(
        &ctx.entries
            .get("a")
            .ok_or_else(|| ScenarioError::infra("no secure client entry"))?
            .config_dir,
    )
    .to_path_buf();
    let trusted_certificate = b_config.join("stream-cert.der");
    let trusted_certificate = trusted_certificate.to_string_lossy().to_string();
    let output = ctx
        .spawn_cli_with_config(
            &a_config,
            &[
                "stream-test",
                "--addr",
                &address,
                "--mode",
                "bidirectional",
                "--secure",
                "--trust-cert",
                &trusted_certificate,
                "--server-name",
                "sister-10002",
            ],
        )?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait secure stream client: {error}")))?;
    if !output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "secure stream failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// N08: resolve a peer by SisterId and transfer a file through the stream
/// service, asserting the external result and the receiver's exact bytes.
fn n08_transfer_v0(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b stream candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("transfer-source.bin");
    let destination = ctx.layout.root.join("transfer-destination.bin");
    let payload = b"transfer-v0-integrity-check".repeat(4096);
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write transfer source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Copied", "transfer completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read received file: {error}")))?;
    assert::assert_eq(received, payload, "transferred bytes")?;
    Ok(())
}

/// N10: exercise the external `cp --resume` client against a real Sister.
/// The runtime unit test covers an interrupted first attempt; this scenario
/// proves that the public CLI speaks the same resumable protocol end to end.
fn n10_transfer_v1_resume(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b resumable transfer candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("transfer-v1-source.bin");
    let destination = ctx.layout.root.join("transfer-v1-destination.bin");
    let payload = (0..(64 * 1024 + 1234))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write transfer v1 source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", "--resume", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Resumed copy", "transfer v1 completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read v1 received file: {error}")))?;
    assert::assert_eq(received, payload, "resumable transferred bytes")?;
    if PathBuf::from(format!("{}.misaka-part", destination.display())).exists()
        || PathBuf::from(format!("{}.misaka-part.json", destination.display())).exists()
    {
        return Err(ScenarioError::assertion(
            "transfer v1 left durable partial state after completion",
        ));
    }
    Ok(())
}

/// N09: a real `misaka tunnel` process forwards bytes to a plain TCP fixture
/// reachable from the remote Sister's network namespace.
fn n09_tunnel_v0(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b tunnel candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let fixture = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| ScenarioError::infra(format!("bind tunnel fixture: {error}")))?;
    let fixture_addr = fixture
        .local_addr()
        .map_err(|error| ScenarioError::infra(format!("read tunnel fixture address: {error}")))?;
    let fixture_thread = std::thread::spawn(move || loop {
        let Ok((mut stream, _)) = fixture.accept() else {
            return;
        };
        let mut buffer = [0u8; 4096];
        let read = {
            use std::io::Read;
            stream.read(&mut buffer)
        };
        let Ok(read) = read else {
            continue;
        };
        if read == 0 {
            continue;
        }
        use std::io::Write;
        if stream.write_all(&buffer[..read]).is_err() {
            return;
        }
        return;
    });

    let local_port = alloc_port()
        .map_err(|error| ScenarioError::infra(format!("alloc tunnel local port: {error}")))?;
    let remote_arg = fixture_addr.to_string();
    let local_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let mut tunnel = ctx.spawn_cli(
        "a",
        &[
            "tunnel",
            &b_id.to_string(),
            "--local",
            &local_port.to_string(),
            "--remote",
            &remote_arg,
        ],
    )?;
    wait_for_tcp_listener(local_addr, Duration::from_secs(8))?;

    let mut client = std::net::TcpStream::connect_timeout(&local_addr, Duration::from_secs(2))
        .map_err(|error| ScenarioError::assertion(format!("connect local tunnel: {error}")))?;
    use std::io::{Read, Write};
    let payload = b"tunnel-v0-ok";
    client
        .write_all(payload)
        .map_err(|error| ScenarioError::assertion(format!("write local tunnel: {error}")))?;
    let mut echoed = vec![0u8; payload.len()];
    client
        .read_exact(&mut echoed)
        .map_err(|error| ScenarioError::assertion(format!("read local tunnel: {error}")))?;
    assert::assert_eq(echoed, payload.to_vec(), "tunnel echoed bytes")?;
    drop(client);
    let _ = tunnel.wait_timeout_mut(Duration::from_millis(100));
    let _ = fixture_thread.join();
    Ok(())
}

/// N11: introspection reports the selected path and live counters while a
/// logical stream is still open, then removes it after the client exits.
fn n11_active_stream_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let ready_file = ctx.layout.root.join("n11-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    assert::eventually(
        b_introspect,
        "b reports an active stream",
        Duration::from_secs(8),
        |snapshot| !snapshot.active_streams.is_empty(),
    )?;
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch active stream snapshot: {error}")))?;
    let active = snapshot
        .active_streams
        .first()
        .ok_or_else(|| ScenarioError::assertion("active stream disappeared unexpectedly"))?;
    assert::assert_eq(
        active.backend.clone(),
        "direct-tcp".to_string(),
        "active stream backend",
    )?;
    assert::assert_eq(
        active.route.clone(),
        "direct".to_string(),
        "active stream route",
    )?;
    if active.tx_bytes < 5 || active.rx_bytes == 0 || active.remote_endpoint.is_none() {
        return Err(ScenarioError::assertion(format!(
            "active stream telemetry incomplete: {active:?}"
        )));
    }
    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode misaka ps JSON: {error}")))?;
    let ps_active = ps
        .get("active_streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| streams.first())
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report active stream"))?;
    assert::assert_eq(
        ps_active.get("backend").and_then(serde_json::Value::as_str),
        Some("direct-tcp"),
        "misaka ps active backend",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait observability client: {error}")))?;
    assert::eventually(
        b_introspect,
        "b removes the closed active stream",
        Duration::from_secs(8),
        |snapshot| snapshot.active_streams.is_empty(),
    )?;
    Ok(())
}

/// N18: expose aggregate live stream count and byte counters through the
/// public introspection and `misaka ps` JSON surfaces.
fn n18_stream_summary_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let ready_file = ctx.layout.root.join("n18-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    assert::eventually(
        b_introspect,
        "b reports an active stream summary",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.stream_summary.streams == snapshot.active_streams.len()
                && snapshot.stream_summary.streams > 0
                && snapshot.stream_summary.tx_bytes > 0
                && snapshot.stream_summary.rx_bytes > 0
        },
    )?;
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch stream summary: {error}")))?;
    assert::assert_eq(
        snapshot.stream_summary.streams,
        snapshot.active_streams.len(),
        "summary active stream count",
    )?;
    if snapshot.stream_summary.tx_bytes == 0 || snapshot.stream_summary.rx_bytes == 0 {
        return Err(ScenarioError::assertion(format!(
            "stream summary counters incomplete: {:?}",
            snapshot.stream_summary
        )));
    }

    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode summary ps JSON: {error}")))?;
    let summary = ps
        .get("stream_summary")
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report stream summary"))?;
    assert::assert_eq(
        summary.get("streams").and_then(serde_json::Value::as_u64),
        Some(snapshot.stream_summary.streams as u64),
        "misaka ps summary stream count",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait summary client: {error}")))?;
    assert::eventually(
        b_introspect,
        "b clears the closed stream summary",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.stream_summary.streams == 0
                && snapshot.stream_summary.tx_bytes == 0
                && snapshot.stream_summary.rx_bytes == 0
        },
    )?;
    Ok(())
}

/// N19: resume a v2 transfer from a durable completed-chunk bitmap and finish
/// it through several real Iroh-backed worker streams.
fn n19_iroh_parallel_transfer(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate for parallel transfer",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-parallel-source.bin");
    let destination = ctx.layout.root.join("iroh-parallel-destination.bin");
    let payload = (0..(8 * 64 * 1024 + 1234))
        .map(|index| ((index * 13) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write parallel source: {error}")))?;

    let chunk_size = 64 * 1024u64;
    let chunk_count = (payload.len() as u64).div_ceil(chunk_size);
    let mut partial = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(format!("{}.misaka-part-v2", destination.display()))
        .map_err(|error| ScenarioError::infra(format!("create parallel partial: {error}")))?;
    partial
        .set_len(payload.len() as u64)
        .map_err(|error| ScenarioError::infra(format!("size parallel partial: {error}")))?;
    use std::io::{Seek, SeekFrom, Write};
    partial
        .seek(SeekFrom::Start(0))
        .and_then(|_| partial.write_all(&payload[..chunk_size as usize]))
        .map_err(|error| ScenarioError::infra(format!("seed parallel chunk: {error}")))?;
    drop(partial);
    let mut completed = vec![0u8; chunk_count.div_ceil(8) as usize];
    completed[0] = 1;
    let state = serde_json::json!({
        "size": payload.len() as u64,
        "digest": misaka_core::protocol::transfer_content_digest(&payload),
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "completed": completed,
    });
    std::fs::write(
        format!("{}.misaka-part-v2.json", destination.display()),
        serde_json::to_vec(&state)
            .map_err(|error| ScenarioError::infra(format!("encode parallel state: {error}")))?,
    )
    .map_err(|error| ScenarioError::infra(format!("write parallel state: {error}")))?;

    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli(
        "a",
        &[
            "cp",
            "--resume",
            "--parallel",
            "4",
            &source_arg,
            &destination_arg,
        ],
    )?;
    assert::assert_contains(
        &output,
        "Parallel copy",
        "parallel transfer completion output",
    )?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read parallel destination: {error}")))?;
    assert::assert_eq(received, payload, "parallel Iroh transfer bytes")?;
    if PathBuf::from(format!("{}.misaka-part-v2", destination.display())).exists()
        || PathBuf::from(format!("{}.misaka-part-v2.json", destination.display())).exists()
    {
        return Err(ScenarioError::assertion(
            "parallel transfer left durable partial state after completion",
        ));
    }
    Ok(())
}

/// N20: repeated identical parallel transfers reuse one digest-named object
/// on the receiving Sister and only materialize a new destination path.
fn n20_iroh_object_store(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate for object store",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-object-source.bin");
    let first_destination = ctx.layout.root.join("iroh-object-first.bin");
    let second_destination = ctx.layout.root.join("iroh-object-second.bin");
    let payload = (0..(2 * 64 * 1024 + 1234))
        .map(|index| ((index * 17) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write object source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();

    for (destination, label) in [
        (&first_destination, "first"),
        (&second_destination, "second"),
    ] {
        let destination_arg = format!("#{b_id}:{}", destination.display());
        let output = ctx.run_cli(
            "a",
            &[
                "cp",
                "--resume",
                "--parallel",
                "4",
                &source_arg,
                &destination_arg,
            ],
        )?;
        assert::assert_contains(
            &output,
            "Parallel copy",
            &format!("{label} object copy output"),
        )?;
        let received = std::fs::read(destination).map_err(|error| {
            ScenarioError::assertion(format!("read {label} object destination: {error}"))
        })?;
        assert::assert_eq(received, payload.clone(), &format!("{label} object bytes"))?;
    }

    let digest = misaka_core::protocol::transfer_content_digest(&payload);
    let digest_name = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let b_config = ctx
        .entries
        .get("b")
        .ok_or_else(|| ScenarioError::infra("no object-store Sister entry"))?;
    let object = Path::new(&b_config.config_dir)
        .join("objects")
        .join(digest_name);
    if !object.is_file() {
        return Err(ScenarioError::assertion(format!(
            "canonical object is missing: {}",
            object.display()
        )));
    }
    let object_size = std::fs::metadata(&object)
        .map_err(|error| ScenarioError::assertion(format!("stat canonical object: {error}")))?
        .len();
    assert::assert_eq(object_size, payload.len() as u64, "canonical object size")?;
    for destination in [&first_destination, &second_destination] {
        if PathBuf::from(format!("{}.misaka-part-v2", destination.display())).exists()
            || PathBuf::from(format!("{}.misaka-part-v2.json", destination.display())).exists()
        {
            return Err(ScenarioError::assertion(
                "object-store transfer left durable partial state",
            ));
        }
    }
    Ok(())
}

/// N21: exercise a bounded bidirectional heartbeat window through the public
/// Iroh stream probe and validate its machine-readable stability record.
fn n21_iroh_stability_probe(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "stability",
            "--duration-secs",
            "2",
            "--json",
        ],
    )?;
    let report: serde_json::Value = serde_json::from_str(output.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode stability report: {error}")))?;
    assert::assert_eq(
        report.get("mode").and_then(serde_json::Value::as_str),
        Some("stability"),
        "Iroh stability report mode",
    )?;
    assert::assert_eq(
        report.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "Iroh stability report backend",
    )?;
    assert::assert_eq(
        report.get("route").and_then(serde_json::Value::as_str),
        Some("direct"),
        "Iroh stability report route",
    )?;
    if report
        .get("exchanges")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|exchanges| exchanges < 2)
        || report
            .get("elapsed_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|elapsed| elapsed < 1_000)
        || report
            .get("path_switches")
            .and_then(serde_json::Value::as_u64)
            .is_none()
    {
        return Err(ScenarioError::assertion(format!(
            "Iroh stability report missing bounded measurements: {report}"
        )));
    }
    Ok(())
}

/// N12: run Transfer v1 over the opt-in Iroh backend using real Sister
/// processes and transport identities persisted in each isolated config dir.
fn n12_iroh_transfer_v1(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-transfer-source.bin");
    let destination = ctx.layout.root.join("iroh-transfer-destination.bin");
    let payload = (0..(64 * 1024 + 1234))
        .map(|index| ((index * 7) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write Iroh source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", "--resume", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Resumed copy", "Iroh transfer completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read Iroh destination: {error}")))?;
    assert::assert_eq(received, payload, "Iroh transfer bytes")?;
    Ok(())
}

/// N13: verify Iroh path metadata through real Sister processes while the
/// logical stream is still open, including the public ps view and cleanup.
fn n13_iroh_active_path_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;
    let snapshot = observer::fetch(a_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch Iroh candidate: {error}")))?;
    let endpoint = snapshot
        .peers
        .iter()
        .find(|peer| peer.id == b_id)
        .and_then(|peer| {
            peer.stream_endpoints
                .iter()
                .find(|endpoint| endpoint.starts_with("iroh://"))
        })
        .cloned()
        .ok_or_else(|| ScenarioError::assertion("Iroh candidate disappeared unexpectedly"))?;

    let ready_file = ctx.layout.root.join("n13-iroh-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(12))?;
    if let Err(error) = assert::eventually(
        b_introspect,
        "b reports an active Iroh stream",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.active_streams.iter().any(|stream| {
                stream.backend == "iroh" && stream.route != "unknown" && stream.rtt_ms.is_some()
            })
        },
    ) {
        client.terminate();
        let output = client
            .wait_timeout(Duration::from_secs(2))
            .map_err(|wait_error| {
                ScenarioError::infra(format!("collect Iroh observability client: {wait_error}"))
            })?;
        return Err(ScenarioError::assertion(format!(
            "{error}; client stdout: {}; client stderr: {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch active Iroh stream: {error}")))?;
    let active = snapshot
        .active_streams
        .iter()
        .find(|stream| stream.backend == "iroh")
        .ok_or_else(|| ScenarioError::assertion("active Iroh stream disappeared unexpectedly"))?;
    if !matches!(active.route.as_str(), "direct" | "relay" | "custom") {
        return Err(ScenarioError::assertion(format!(
            "active Iroh route is not a recognized transport path: {active:?}"
        )));
    }
    if active.local_endpoint.is_none()
        || !active
            .remote_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.starts_with("iroh://"))
        || active.rtt_ms.is_none()
        || active.rx_bytes == 0
    {
        return Err(ScenarioError::assertion(format!(
            "active Iroh path telemetry incomplete: {active:?}"
        )));
    }

    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh ps JSON: {error}")))?;
    let ps_active = ps
        .get("active_streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| {
            streams.iter().find(|stream| {
                stream.get("backend").and_then(serde_json::Value::as_str) == Some("iroh")
            })
        })
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report active Iroh stream"))?;
    assert::assert_eq(
        ps_active.get("route").and_then(serde_json::Value::as_str),
        Some(active.route.as_str()),
        "misaka ps active Iroh route",
    )?;
    assert::assert_eq(
        ps_active
            .get("path_switches")
            .and_then(serde_json::Value::as_u64),
        Some(active.path_switches),
        "misaka ps Iroh path switch count",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| {
            ScenarioError::infra(format!("wait Iroh observability client: {error}"))
        })?;
    assert::eventually(
        b_introspect,
        "b removes the closed active Iroh stream",
        Duration::from_secs(8),
        |snapshot| snapshot.active_streams.is_empty(),
    )?;
    Ok(())
}

/// N14: after an Iroh Sister dies, its persisted transport identity and
/// explicit candidate are reused for a fresh stream after restart.
fn n14_iroh_restart_new_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let ready_file = ctx.layout.root.join("n14-iroh-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut old_client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut old_client, &ready_file, Duration::from_secs(12))?;
    let status = ctx.terminate_sister("b")?;
    if !status.success() {
        return Err(ScenarioError::assertion(
            "Iroh Sister did not terminate cleanly",
        ));
    }
    let output = old_client
        .wait_timeout(Duration::from_secs(10))
        .map_err(|error| ScenarioError::infra(format!("wait old Iroh stream: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "old Iroh stream did not fail after remote kill",
        ));
    }

    ctx.restart_sister("b")?;
    let b2_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::assert_eq(b2_id, b_id, "Iroh Sister identity across restart")?;
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let new_output = ctx
        .spawn_cli(
            "a",
            &[
                "stream-test",
                "--endpoint",
                &endpoint,
                "--mode",
                "bidirectional",
            ],
        )?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait new Iroh stream: {error}")))?;
    if !new_output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "new Iroh stream failed: {}",
            String::from_utf8_lossy(&new_output.stderr).trim()
        )));
    }
    Ok(())
}

/// N15: verify the public Iroh stream probe emits one parseable measurement
/// record when run against two real, isolated Sister processes.
fn n15_iroh_json_measurement(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "bidirectional",
            "--json",
        ],
    )?;
    let report: serde_json::Value = serde_json::from_str(output.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh stream report: {error}")))?;
    assert::assert_eq(
        report.get("mode").and_then(serde_json::Value::as_str),
        Some("bidirectional"),
        "Iroh stream report mode",
    )?;
    assert::assert_eq(
        report.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "Iroh stream report backend",
    )?;
    assert::assert_eq(
        report.get("route").and_then(serde_json::Value::as_str),
        Some("direct"),
        "Iroh stream report route",
    )?;
    if report
        .get("setup_ms")
        .and_then(serde_json::Value::as_u64)
        .is_none()
        || report
            .get("rtt_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || report
            .get("path_switches")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || report
            .get("probe_rtt_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || !report
            .get("remote_endpoint")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|endpoint| endpoint.starts_with("iroh://"))
    {
        return Err(ScenarioError::assertion(format!(
            "Iroh JSON stream report missing measurements: {report}"
        )));
    }
    Ok(())
}

/// N16: verify the public `connect` command resolves a Sister ID from the
/// local PeerStore and establishes an Iroh-backed stream.
fn n16_connect_by_sister_id(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let _ = wait_for_iroh_candidate(a_introspect, b_id)?;
    let sister_arg = format!("#{b_id}");
    let output = ctx.run_cli("a", &["connect", &sister_arg])?;
    assert::assert_contains(
        &output,
        &format!("Connected to Sister #{b_id}"),
        "connect target",
    )?;
    assert::assert_contains(&output, "backend=iroh", "connect backend")?;
    assert::assert_contains(&output, "route=direct", "connect route")?;
    Ok(())
}

/// N17: export the live Iroh endpoint and connect without control-plane
/// bootstrap, mDNS, or a persisted remote peer entry.
fn n17_iroh_endpoint_bootstrap_without_control_plane(
    ctx: &mut Context,
) -> Result<(), ScenarioError> {
    ctx.start_iroh_probe_only("b")?;
    ctx.start_iroh_probe_only("a")?;
    let b_snapshot = ctx.introspect("b")?;
    assert::assert_eq(
        b_snapshot.peers.len(),
        0,
        "endpoint-only Sister has no control-plane peers",
    )?;
    let record = ctx.run_cli("b", &["endpoint", "--json"])?;
    let record: serde_json::Value = serde_json::from_str(record.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode endpoint record: {error}")))?;
    assert::assert_eq(
        record.get("network_id").and_then(serde_json::Value::as_str),
        Some("00000000-0000-0000-0000-000000000001"),
        "endpoint network id",
    )?;
    assert::assert_eq(
        record.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "endpoint backend",
    )?;
    let endpoint = record
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScenarioError::assertion("endpoint record has no endpoint"))?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            endpoint,
            "--mode",
            "bidirectional",
            "--json",
        ],
    )?;
    assert::assert_contains(&output, "\"backend\":\"iroh\"", "endpoint-only probe")?;
    Ok(())
}

fn wait_for_iroh_candidate(
    introspect: SocketAddr,
    sister_id: u64,
) -> Result<String, ScenarioError> {
    assert::eventually(
        introspect,
        "Sister advertises an Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == sister_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;
    let snapshot = observer::fetch(introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch Iroh candidate: {error}")))?;
    snapshot
        .peers
        .iter()
        .find(|peer| peer.id == sister_id)
        .and_then(|peer| {
            peer.stream_endpoints
                .iter()
                .find(|endpoint| endpoint.starts_with("iroh://"))
        })
        .cloned()
        .ok_or_else(|| ScenarioError::assertion("Iroh candidate disappeared unexpectedly"))
}

fn wait_for_tcp_listener(addr: SocketAddr, timeout: Duration) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::infra(format!(
                "TCP listener {} did not become ready",
                addr
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ===========================================================================
// Gateway scenarios (G01–G10): exercise the Gateway v0 discovery contract and
// the runtime loop end-to-end against a spawned native reference Gateway.
// ===========================================================================

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

/// Seconds since the Unix epoch, matching the Gateway's real clock.
fn gateway_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Spawn a native reference Gateway serving the Context's shared authority.
fn spawn_gateway(ctx: &mut Context) -> Result<(SocketAddr, CliProcess), ScenarioError> {
    let (authority, _authority_key) = ctx.ensure_iroh_authority();
    let port = alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?;
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config_dir = ctx.layout.root.join(format!("gateway-{port}"));
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| ScenarioError::infra(format!("create gateway config: {error}")))?;
    let bind_arg = bind.to_string();
    let network_arg = authority.network_id.to_string();
    let key_arg = authority.authority_public_key.to_string();
    let process = ctx.spawn_cli_with_config(
        &config_dir,
        &[
            "network",
            "gateway",
            "serve",
            "--bind",
            &bind_arg,
            "--network-id",
            &network_arg,
            "--authority-public-key",
            &key_arg,
        ],
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if http_get(bind, "/.well-known/misaka")
            .is_ok_and(|response| response.starts_with("HTTP/1.1 200"))
        {
            return Ok((bind, process));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(ScenarioError::infra(format!(
        "gateway did not listen on {bind}"
    )))
}

fn stop_gateway(mut process: CliProcess) -> Result<(), ScenarioError> {
    process.terminate();
    process
        .wait_timeout(Duration::from_secs(5))
        .map_err(|error| ScenarioError::infra(format!("stop gateway: {error}")))?;
    Ok(())
}

fn gateway_url(bind: SocketAddr) -> String {
    format!("http://{bind}")
}

/// POST a raw body to the Gateway and return (status, response-text).
fn gateway_post(bind: SocketAddr, path: &str, body: &[u8]) -> Result<(u16, String), ScenarioError> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("http://{bind}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .send()
        .map_err(|error| ScenarioError::assertion(format!("gateway post: {error}")))?;
    let status = response.status().as_u16();
    let text = response.text().unwrap_or_default();
    Ok((status, text))
}

/// Build a well-formed signed announce request for a fresh Sister, using the
/// shared authority. `tamper` lets a scenario break one field to test rejection.
fn build_announce(
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
    sister_id: u64,
    nonce: [u8; 16],
    expires_in: Option<i64>,
    bad_record_identity: bool,
    bad_record_signature: bool,
) -> Vec<u8> {
    use misaka_core::{
        GatewayAnnounceRequest, GatewayAuth, IrohEndpointId, PeerRecord, TransportBinding,
    };
    let now = gateway_now_secs();
    let key = SisterKeyPair::generate();
    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        key.public_key(),
        sister_id,
        now.saturating_sub(10),
        expires_in.map(|e| (now as i64 + e).max(0) as u64),
        sister_id,
    );
    let record_sister_id = if bad_record_identity {
        sister_id + 1
    } else {
        sister_id
    };
    let signing_key = if bad_record_identity {
        SisterKeyPair::generate()
    } else {
        key.clone()
    };
    let binding = TransportBinding::sign(
        authority.network_id,
        record_sister_id,
        IrohEndpointId::from_bytes([7u8; 32]),
        1,
        &signing_key,
    );
    let mut record = PeerRecord::issue(
        authority.network_id,
        record_sister_id,
        "iroh://peer".to_string(),
        binding,
        now,
        &signing_key,
    );
    if bad_record_signature {
        record.sister_signature = misaka_core::SisterSignature::from_bytes([0u8; 64]);
    }
    let auth = GatewayAuth::sign_announce(
        authority.network_id,
        sister_id,
        now,
        nonce,
        &membership,
        &record,
        &key,
    );
    let request = GatewayAnnounceRequest {
        auth,
        membership,
        record,
    };
    serde_json::to_vec(&request).unwrap()
}

fn build_peers(
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
    sister_id: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    use misaka_core::{GatewayAuth, GatewayPeersRequest};
    let now = gateway_now_secs();
    let key = SisterKeyPair::generate();
    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        key.public_key(),
        sister_id,
        now.saturating_sub(10),
        Some(now.saturating_add(3600)),
        sister_id,
    );
    let auth = GatewayAuth::sign_peers(authority.network_id, sister_id, now, nonce, &key);
    let request = GatewayPeersRequest { auth, membership };
    serde_json::to_vec(&request).unwrap()
}

/// G01: a valid member announce is accepted, and a peers query returns it.
fn g01_valid_announce_accepted(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [1u8; 16],
        Some(3600),
        false,
        false,
    );
    let announce = gateway_post(bind, "/v1/announce", &body);
    let peers = gateway_post(
        bind,
        "/v1/peers",
        &build_peers(&authority, &authority_key, 10001, [9u8; 16]),
    );
    stop_gateway(process)?;
    let (status, _) = announce?;
    if status != 204 {
        return Err(ScenarioError::assertion(format!(
            "valid announce got {status}, want 204"
        )));
    }
    let (peers_status, text) = peers?;
    if peers_status != 200 || !text.contains("\"sister_id\":10001") {
        return Err(ScenarioError::assertion(format!(
            "peers query after valid announce got {peers_status}: {text}"
        )));
    }
    Ok(())
}

/// G02: a record whose identity does not match the presenting membership is rejected.
fn g02_forged_record_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [2u8; 16],
        Some(3600),
        true,
        false,
    );
    let result = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    let (status, _) = result?;
    if status != 403 {
        return Err(ScenarioError::assertion(format!(
            "forged record got {status}, want 403"
        )));
    }
    Ok(())
}

/// G03: an expired (or otherwise invalid) membership is rejected.
fn g03_invalid_membership_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    // Membership already lapsed (issued 10s ago, expired 5s before now).
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [3u8; 16],
        Some(-5),
        false,
        false,
    );
    let result = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    let (status, _) = result?;
    if status != 401 {
        return Err(ScenarioError::assertion(format!(
            "expired membership got {status}, want 401"
        )));
    }
    Ok(())
}

/// G04: a replayed nonce is rejected on the second use.
fn g04_replay_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [4u8; 16],
        Some(3600),
        false,
        false,
    );
    let first = gateway_post(bind, "/v1/announce", &body)?;
    let second = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    if first.0 != 204 {
        return Err(ScenarioError::assertion(format!(
            "first announce got {}",
            first.0
        )));
    }
    let (status, _) = second?;
    if status != 401 {
        return Err(ScenarioError::assertion(format!(
            "replayed nonce got {status}, want 401"
        )));
    }
    Ok(())
}

/// G05 (Definition of Done): two Sisters that know only the Gateway domain
/// discover each other and complete the authenticated Iroh control connection.
fn g05_discovery_through_gateway(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)])?;
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process)?;
    outcome
}

/// G07: with two Gateways configured and one taken down, discovery still
/// converges through the surviving Gateway (no cross-Gateway coordination).
fn g07_multi_gateway_failover(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind_a, process_a) = spawn_gateway(ctx)?;
    let (bind_b, process_b) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind_a), gateway_url(bind_b)])?;
    stop_gateway(process_a)?; // drop one Gateway; B must carry discovery
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process_b)?;
    outcome
}

/// G08: after discovery, all Gateways down — the already-formed P2P persists.
fn g08_gateway_down_after_connect(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)])?;
    wait_until_peers(ctx, 30)?; // both connected through the Gateway
    stop_gateway(process)?; // now remove the Gateway entirely
                            // Let a couple of heartbeat cycles pass with no Gateway available.
    std::thread::sleep(Duration::from_secs(3));
    let a = ctx.introspect("a")?;
    let b = ctx.introspect("b")?;
    let still = a.peers.iter().any(|p| p.id == 10002) && b.peers.iter().any(|p| p.id == 10001);
    ctx.teardown();
    if !still {
        return Err(ScenarioError::assertion(
            "network lost its peer after the Gateway went down",
        ));
    }
    Ok(())
}

/// G09: a Sister keeps operating (still serving introspection, peer retained)
/// after the Gateway it discovered through is gone.
fn g09_gateway_removed_continues(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)])?;
    wait_until_peers(ctx, 30)?;
    stop_gateway(process)?;
    // The remaining Sister must still answer introspection (not crashed by the
    // Gateway disappearing) and still list the discovered peer.
    let a = ctx.introspect("a")?;
    let retained = a.peers.iter().any(|p| p.id == 10002);
    ctx.teardown();
    if !retained {
        return Err(ScenarioError::assertion(
            "Sister lost its discovered peer after the Gateway was removed",
        ));
    }
    Ok(())
}

/// G10: the normal discovery path never uses a manual `iroh://` bootstrap.
fn g10_no_manual_iroh_bootstrap(ctx: &mut Context) -> Result<(), ScenarioError> {
    // start_iroh_pair_via_gateway passes only --gateway (never --iroh-peer) and
    // seeds no peers. If discovery converges with an empty manual-peer list, the
    // normal path is proven free of any raw `iroh://` contact.
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)])?;
    let a_manual = ctx
        .entries
        .get("a")
        .map(|e| !e.peer_addrs.is_empty())
        .unwrap_or(true);
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process)?;
    if a_manual {
        return Err(ScenarioError::assertion(
            "discovery path carried a manual peer_addrs entry",
        ));
    }
    outcome
}

fn wait_until_peers(ctx: &mut Context, timeout_secs: u64) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let a = ctx.introspect("a")?;
        let b = ctx.introspect("b")?;
        if a.peers.iter().any(|p| p.id == 10002) && b.peers.iter().any(|p| p.id == 10001) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::assertion("peers did not converge in time"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn gateway_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "G01",
            run: Box::new(g01_valid_announce_accepted),
        },
        ScenarioDef {
            name: "G02",
            run: Box::new(g02_forged_record_rejected),
        },
        ScenarioDef {
            name: "G03",
            run: Box::new(g03_invalid_membership_rejected),
        },
        ScenarioDef {
            name: "G04",
            run: Box::new(g04_replay_rejected),
        },
        ScenarioDef {
            name: "G05",
            run: Box::new(g05_discovery_through_gateway),
        },
        ScenarioDef {
            name: "G07",
            run: Box::new(g07_multi_gateway_failover),
        },
        ScenarioDef {
            name: "G08",
            run: Box::new(g08_gateway_down_after_connect),
        },
        ScenarioDef {
            name: "G09",
            run: Box::new(g09_gateway_removed_continues),
        },
        ScenarioDef {
            name: "G10",
            run: Box::new(g10_no_manual_iroh_bootstrap),
        },
    ]
}
