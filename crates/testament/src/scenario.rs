//! Scenario engine: runs Rust scenario functions against real Sister
//! processes. v0 scenarios are Rust functions behind the `Scenario` trait
//! (the JSON scenario DSL comes later in Phase 6).

use crate::assertion as assert;
use crate::observer;
use crate::run_manager::{alloc_port, misaka_binary};
use crate::supervisor::{build_spawn, CliProcess, SisterProcess, SpawnConfig};
use crate::types::{Artifacts, Manifest, Report, RunLayout, SisterEntry};
use misaka_core::introspection::IntrospectionSnapshot;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// 场景函数签名：接收一个上下文，返回 Ok(()) 或 Err(断言/基础设施失败)。
pub type ScenarioFn = Box<dyn Fn(&mut Context) -> Result<(), String> + Send>;

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
        }
    }

    /// 启动一个 Sister (分配 listen + introspect 端口)。
    pub fn start_sister(
        &mut self,
        alias: &str,
        nickname: &str,
        peers: &[SocketAddr],
    ) -> Result<(), String> {
        let listen_port = alloc_port().map_err(|e| format!("alloc_port: {}", e))?;
        let introspect_port = alloc_port().map_err(|e| format!("alloc_port: {}", e))?;

        let (entry, cmd) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            introspect_port,
            binary: &self.binary,
            peers,
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        self.do_spawn(alias, entry, cmd)
    }

    /// 用指定 config dir 启动一个 Sister (身份持久化测试用)。
    pub fn start_sister_with_config(
        &mut self,
        alias: &str,
        nickname: &str,
        config_dir: PathBuf,
    ) -> Result<(), String> {
        let listen_port = alloc_port().map_err(|e| format!("alloc_port: {}", e))?;
        let introspect_port = alloc_port().map_err(|e| format!("alloc_port: {}", e))?;
        let _ = std::fs::create_dir_all(&config_dir);

        let (mut entry, mut cmd) = build_spawn(SpawnConfig {
            layout: &self.layout,
            alias,
            nickname,
            listen_port,
            introspect_port,
            binary: &self.binary,
            peers: &[],
            discovery: &self.discovery,
            heartbeat: self.heartbeat,
            peer_timeout: self.peer_timeout,
        });
        cmd.env("MISAKA_CONFIG_DIR", &config_dir);
        entry.config_dir = config_dir.to_string_lossy().to_string();
        self.do_spawn(alias, entry, cmd)
    }

    fn do_spawn(
        &mut self,
        alias: &str,
        entry: SisterEntry,
        cmd: std::process::Command,
    ) -> Result<(), String> {
        let mut proc = SisterProcess {
            entry: entry.clone(),
            child: None,
        };
        proc.spawn(cmd, &entry.stdout_log, &entry.stderr_log)
            .map_err(|e| format!("spawn {alias}: {}", e))?;

        // 等待 introspection 就绪 (wait_ready)
        let ia: SocketAddr = entry.introspection_addr.as_ref().unwrap().parse().unwrap();
        if observer::wait_until(ia, Duration::from_secs(15), |_| true).is_none() {
            proc.terminate();
            return Err(format!(
                "{alias} never became ready (introspect {}); stderr tail: {}",
                ia,
                std::fs::read_to_string(&entry.stderr_log).unwrap_or_default()
            ));
        }

        // 读取真实 SisterId
        let snap = match observer::fetch(ia, Duration::from_millis(500)) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                proc.terminate();
                let _ = proc.wait();
                return Err(format!("introspect {alias}: {}", e));
            }
        };
        let mut entry = entry;
        entry.id = Some(snap.identity.id.as_u64());
        entry.pid = proc.pid();

        self.entries.insert(alias.to_string(), entry.clone());
        self.sisters.insert(alias.to_string(), proc);
        self.manifest.sisters.push(entry);
        Ok(())
    }

    pub fn introspect(&self, alias: &str) -> Result<IntrospectionSnapshot, String> {
        let addr = self
            .entries
            .get(alias)
            .and_then(|e| e.introspection_addr.as_ref())
            .ok_or_else(|| format!("no introspection for {alias}"))?;
        observer::fetch(addr.parse().unwrap(), Duration::from_millis(500))
            .map_err(|e| format!("introspect {alias}: {}", e))
    }

    pub fn peer_addr(&self, alias: &str) -> Result<SocketAddr, String> {
        self.entries
            .get(alias)
            .map(|e| e.listen_addr.parse().unwrap())
            .ok_or_else(|| format!("no entry for {alias}"))
    }

    /// 运行一条独立 `misaka` CLI 命令 (非 Node 进程)，拿到结果。
    pub fn run_cli(&self, alias: &str, args: &[&str]) -> Result<String, String> {
        let entry = self
            .entries
            .get(alias)
            .ok_or_else(|| format!("no entry for {alias}"))?;
        let out = std::process::Command::new(&self.binary)
            .args(args)
            .env("MISAKA_CONFIG_DIR", &entry.config_dir)
            .output()
            .map_err(|e| format!("run cli: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "run cli exited with {}; stderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// 启动一条独立 `misaka` CLI 命令，供并发场景编排。
    pub fn spawn_cli(&self, alias: &str, args: &[&str]) -> Result<CliProcess, String> {
        let entry = self
            .entries
            .get(alias)
            .ok_or_else(|| format!("no entry for {alias}"))?;
        self.spawn_cli_with_config(Path::new(&entry.config_dir), args)
    }

    /// 使用已有的隔离 config 目录启动 CLI，不需要运行中的 Sister。
    pub fn spawn_cli_with_config(
        &self,
        config_dir: &Path,
        args: &[&str],
    ) -> Result<CliProcess, String> {
        let mut command = std::process::Command::new(&self.binary);
        command.args(args).env("MISAKA_CONFIG_DIR", config_dir);
        CliProcess::spawn(command).map_err(|e| format!("spawn cli: {e}"))
    }
    /// 停止一个 Sister，并从当前场景移除它。
    pub fn stop_sister(&mut self, alias: &str) -> Result<(), String> {
        let Some(mut process) = self.sisters.remove(alias) else {
            return Err(format!("no running sister {alias}"));
        };
        process.terminate();
        process.wait().map_err(|e| format!("wait {alias}: {e}"))?;
        self.entries.remove(alias);
        self.manifest.sisters.retain(|entry| entry.alias != alias);
        Ok(())
    }

    /// 全部停止并清理。
    pub fn teardown(&mut self) {
        for (_, mut p) in self.sisters.drain() {
            p.terminate();
            let _ = p.wait();
        }
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

    pub fn report(&self, scenario: &str, result: Result<(), String>) -> Report {
        match result {
            Ok(()) => crate::reporter::passed_report(scenario, &self.run_id, self.artifacts()),
            Err(msg) => crate::reporter::failed_report(
                scenario,
                None,
                Some(msg),
                None,
                None,
                &self.run_id,
                self.artifacts(),
            ),
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
    ]
}

fn t01_standalone(ctx: &mut Context) -> Result<(), String> {
    ctx.start_sister("s1", "railgun", &[])?;
    // 本地 run 成功
    let out = ctx.run_cli("s1", &["run", "--local", "printf standalone-ok"])?;
    assert::assert_contains(&out, "standalone-ok", "local run output")?;
    Ok(())
}

fn t02_identity_persistence(ctx: &mut Context) -> Result<(), String> {
    ctx.start_sister("s1", "railgun", &[])?;
    let id1 = ctx.introspect("s1")?.identity.id.as_u64();
    let config_dir = ctx.entries.get("s1").unwrap().config_dir.clone();
    ctx.stop_sister("s1")?;
    ctx.start_sister_with_config("s2", "railgun", PathBuf::from(config_dir))?;
    let id2 = ctx.introspect("s2")?.identity.id.as_u64();
    assert::assert_eq(id1, id2, "identity across restart")?;
    Ok(())
}

fn t03_peer_connection(ctx: &mut Context) -> Result<(), String> {
    // 先起 B，再把 A 以 B 为 peer 起动
    ctx.start_sister("b", "beta", &[])?;
    let b = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b])?;
    // 等 A 看到 B
    let als_a = ctx
        .entries
        .get("a")
        .unwrap()
        .introspection_addr
        .clone()
        .unwrap();
    let addr: SocketAddr = als_a.parse().unwrap();
    assert::eventually(addr, "a sees #b", Duration::from_secs(8), |s| {
        !s.peers.is_empty()
    })?;
    Ok(())
}

fn t04_remote_exec(ctx: &mut Context) -> Result<(), String> {
    // 先起 B，再把 A 以 B 为 peer 起动，确保 A 的独立 run 能找到 B。
    ctx.start_sister("b", "beta", &[])?;
    let b_addr = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_addr: SocketAddr = ctx
        .entries
        .get("a")
        .and_then(|entry| entry.introspection_addr.as_ref())
        .ok_or_else(|| "no introspection for a".to_string())?
        .parse()
        .map_err(|e| format!("parse a introspection address: {e}"))?;
    assert::eventually(a_addr, "a sees b", Duration::from_secs(8), |snapshot| {
        snapshot.peers.iter().any(|peer| peer.id == b_id)
    })?;
    // A 显式提交到 B。
    let out = ctx.run_cli(
        "a",
        &["run", "--sister", &b_id.to_string(), "printf remote-ok"],
    )?;
    assert::assert_contains(&out, "remote-ok", "remote exec output")?;
    Ok(())
}

fn t05_work_stealing(ctx: &mut Context) -> Result<(), String> {
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
            .ok_or_else(|| "no creator entry".to_string())?
            .config_dir
            .clone(),
    );
    ctx.stop_sister("c")?;

    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = ctx
        .entries
        .get("a")
        .and_then(|entry| entry.introspection_addr.as_ref())
        .ok_or_else(|| "no introspection for a".to_string())?
        .parse::<SocketAddr>()
        .map_err(|e| format!("parse a introspection address: {e}"))?;
    let b_introspect = ctx
        .entries
        .get("b")
        .and_then(|entry| entry.introspection_addr.as_ref())
        .ok_or_else(|| "no introspection for b".to_string())?
        .parse::<SocketAddr>()
        .map_err(|e| format!("parse b introspection address: {e}"))?;

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
    .ok_or_else(|| "a did not transfer the queued job to b".to_string())?;
    assert::assert_queue_empty(&transferred)?;
    let transferred_job = transferred
        .jobs
        .iter()
        .find(|job| job.command == "printf second-ok")
        .ok_or_else(|| "transferred job not retained in A's introspection".to_string())?;
    assert::assert_job_state(&transferred, &transferred_job.id, "transferred")?;

    let second_output = second
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| format!("wait second submitter: {e}"))?;
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
    .ok_or_else(|| "b did not complete the stolen job".to_string())?;
    let completed_job = b_after
        .jobs
        .iter()
        .find(|job| job.command == "printf second-ok")
        .ok_or_else(|| "completed job not retained in B's introspection".to_string())?;
    assert::assert_job_state(&b_after, &completed_job.id, "completed")?;

    let first_output = first
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| format!("wait first submitter: {e}"))?;
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
