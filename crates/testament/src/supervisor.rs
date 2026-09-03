//! Process supervisor: spawn real `misaka` OS processes for each Sister.
//!
//! Hard invariants (§14): Testament never runs Misaka jobs in-process, never participates
//! in discovery, never acts as a peer, Sisters never know Testament exists,
//! killing Testament must not break the network. So we only ever `exec` the
//! binary and drain its I/O — we never import misaka-runtime.
//!
//! Required ops: spawn / wait_ready / terminate / kill / restart / cleanup.
//! We continuously drain stdout/stderr (never leave pipes unread).

use crate::run_manager::sister_config_dir;
use crate::types::{RunLayout, SisterEntry};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// 一个被监督的 Sister OS 进程。
pub struct SisterProcess {
    pub entry: SisterEntry,
    pub child: Option<Child>,
}

/// Parameters for constructing one isolated Sister process.
pub struct SpawnConfig<'a> {
    pub layout: &'a RunLayout,
    pub alias: &'a str,
    pub nickname: &'a str,
    pub listen_port: u16,
    pub introspect_port: u16,
    pub binary: &'a Path,
    pub peers: &'a [SocketAddr],
    pub discovery: &'a str,
    pub heartbeat: u64,
    pub peer_timeout: u64,
}

/// 一个由 Testament 启动、用于提交测试任务的外部 CLI 进程。
///
/// 任务仍由 `misaka` 执行；Testament 只负责编排、观察和收集结果。
pub struct CliProcess {
    child: Option<Child>,
}

impl CliProcess {
    pub fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        Ok(Self {
            child: Some(command.spawn()?),
        })
    }

    /// 等待外部 CLI 在限定时间内结束，并收集 stdout/stderr。
    pub fn wait_timeout(mut self, timeout: Duration) -> std::io::Result<Output> {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .child
                .as_mut()
                .expect("CLI process already consumed")
                .try_wait()?
                .is_some()
            {
                return self
                    .child
                    .take()
                    .expect("CLI process already consumed")
                    .wait_with_output();
            }
            if Instant::now() >= deadline {
                self.terminate();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "CLI process timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn terminate(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
        }
    }
}

impl Drop for CliProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
/// 分配端口 + 组装启动参数，但**不**实际 spawn (便于测试启动命令)。
pub fn build_spawn(config: SpawnConfig<'_>) -> (SisterEntry, Command) {
    let SpawnConfig {
        layout,
        alias,
        nickname,
        listen_port,
        introspect_port,
        binary,
        peers,
        discovery,
        heartbeat,
        peer_timeout,
    } = config;
    let config_dir = sister_config_dir(layout, alias);
    let _ = std::fs::create_dir_all(&config_dir);
    let sdir = layout.sisters_dir.join(alias);
    let _ = std::fs::create_dir_all(&sdir);
    let stdout_log = sdir.join("stdout.log");
    let stderr_log = sdir.join("stderr.log");

    let mut cmd = Command::new(binary);
    cmd.arg("start")
        .arg("--port")
        .arg(listen_port.to_string())
        .arg("--nickname")
        .arg(nickname)
        .arg("--log-format")
        .arg("json")
        .arg("--discovery")
        .arg(discovery)
        .arg("--heartbeat")
        .arg(heartbeat.to_string())
        .arg("--peer-timeout")
        .arg(peer_timeout.to_string())
        .arg("--introspect")
        .arg(introspect_port.to_string())
        .env("MISAKA_CONFIG_DIR", &config_dir);
    if !peers.is_empty() {
        for p in peers {
            cmd.arg("--peer").arg(p.to_string());
        }
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let entry = SisterEntry {
        alias: alias.to_string(),
        id: None,
        pid: None,
        listen_addr: format!("127.0.0.1:{}", listen_port),
        introspection_addr: Some(format!("127.0.0.1:{}", introspect_port)),
        config_dir: config_dir.to_string_lossy().to_string(),
        stdout_log: stdout_log.to_string_lossy().to_string(),
        stderr_log: stderr_log.to_string_lossy().to_string(),
    };
    (entry, cmd)
}

impl SisterProcess {
    /// 启动进程并接管 stdout/stderr 管道 (持续 drain)。
    pub fn spawn(
        &mut self,
        mut cmd: Command,
        stdout_path: &str,
        stderr_path: &str,
    ) -> std::io::Result<()> {
        let stdout = std::fs::File::create(stdout_path)?;
        let stderr = std::fs::File::create(stderr_path)?;
        cmd.stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr));

        let child = cmd.spawn()?;
        self.entry.pid = Some(child.id());
        self.child = Some(child);
        Ok(())
    }

    pub fn pid(&self) -> Option<u32> {
        self.entry.pid
    }

    /// 等待进程退出
    pub fn wait(&mut self) -> std::io::Result<()> {
        if let Some(mut c) = self.child.take() {
            c.wait()?;
        }
        Ok(())
    }

    /// SIGTERM / kill
    pub fn terminate(&mut self) {
        if let Some(ref mut c) = self.child {
            let _ = c.kill();
        }
    }
}

/// 读取某 Sister 的 stdout.log 尾部 (供 logs 命令)。
pub fn read_stdout(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
