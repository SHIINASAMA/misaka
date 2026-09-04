//! Process supervisor: spawn real `misaka` OS processes for each Sister.
//!
//! Hard invariants (§14): Testament never runs Misaka jobs in-process, never participates
//! in discovery, never acts as a peer, Sisters never know Testament exists,
//! killing Testament must not break the network. So we only ever `exec` the
//! binary and drain its I/O — we never import misaka-runtime.
//!
//! Required ops: spawn / wait_ready / terminate / kill / restart / cleanup.

use crate::run_manager::sister_config_dir;
use crate::types::{RunLayout, SisterEntry};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// All Sisters in one Testament run share this deterministic namespace.
/// Each run still uses isolated config directories, so this is test topology,
/// not a developer's production NetworkId.
const TEST_NETWORK_ID: &str = "00000000-0000-0000-0000-000000000001";

/// 一个被监督的 Sister OS 进程。
pub struct SisterProcess {
    pub entry: SisterEntry,
    pub child: Option<Child>,
    /// 重新启动所需的最小信息 (binary + args + config_dir)。
    pub restart: Option<RestartSpec>,
}

#[derive(Clone)]
pub struct RestartSpec {
    program: PathBuf,
    args: Vec<String>,
    config_dir: PathBuf,
}

impl RestartSpec {
    /// Append launch arguments for scenario-specific backend flags.
    pub fn append_args<const N: usize>(&mut self, args: [&str; N]) {
        self.args.extend(args.into_iter().map(str::to_string));
    }
}

/// Parameters for constructing one isolated Sister process.
pub struct SpawnConfig<'a> {
    pub layout: &'a RunLayout,
    pub alias: &'a str,
    pub nickname: &'a str,
    pub listen_port: u16,
    pub stream_port: u16,
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
    /// 输出管道由后台线程持续 drain，避免大量输出阻塞子进程。
    pub fn wait_timeout(mut self, timeout: Duration) -> std::io::Result<Output> {
        self.wait_timeout_mut(timeout)
    }

    /// Wait for a CLI while retaining mutable ownership for readiness polling.
    pub fn wait_timeout_mut(&mut self, timeout: Duration) -> std::io::Result<Output> {
        let Some(mut child) = self.child.take() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "CLI process already consumed",
            ));
        };

        let stdout_handle = child.stdout.take().map(spawn_pump);
        let stderr_handle = child.stderr.take().map(spawn_pump);

        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "CLI process timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(25));
        };

        let stdout = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        let stderr = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_default();
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// Check whether the CLI is still running without consuming its output.
    pub fn is_running(&mut self) -> std::io::Result<bool> {
        let Some(child) = &mut self.child else {
            return Ok(false);
        };
        Ok(child.try_wait()?.is_none())
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

/// 起一个后台线程把子进程输出读进内存并在结束时返回。
fn spawn_pump(mut stream: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stream, &mut buf);
        buf
    })
}

/// 分配端口 + 组装启动参数，但**不**实际 spawn (便于测试启动命令)。
/// 一并返回重建 command 所需的 RestartSpec。
pub fn build_spawn(config: SpawnConfig<'_>) -> (SisterEntry, Command, RestartSpec) {
    let SpawnConfig {
        layout,
        alias,
        nickname,
        listen_port,
        stream_port,
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

    let mut args: Vec<String> = vec![
        "start".into(),
        "--network-id".into(),
        TEST_NETWORK_ID.into(),
        "--port".into(),
        listen_port.to_string(),
        "--stream-port".into(),
        stream_port.to_string(),
        "--nickname".into(),
        nickname.to_string(),
        "--log-format".into(),
        "json".into(),
        "--discovery".into(),
        discovery.to_string(),
        "--heartbeat".into(),
        heartbeat.to_string(),
        "--peer-timeout".into(),
        peer_timeout.to_string(),
        "--introspect".into(),
        introspect_port.to_string(),
    ];
    if !peers.is_empty() {
        for p in peers {
            args.push("--peer".into());
            args.push(p.to_string());
        }
    }

    let mut cmd = Command::new(binary);
    cmd.args(&args).env("MISAKA_CONFIG_DIR", &config_dir);

    let entry = SisterEntry {
        alias: alias.to_string(),
        id: None,
        pid: None,
        listen_addr: format!("127.0.0.1:{}", listen_port),
        stream_addr: format!("127.0.0.1:{}", stream_port),
        stream_backend: String::new(),
        introspection_addr: Some(format!("127.0.0.1:{}", introspect_port)),
        config_dir: config_dir.to_string_lossy().to_string(),
        stdout_log: stdout_log.to_string_lossy().to_string(),
        stderr_log: stderr_log.to_string_lossy().to_string(),
        nickname: nickname.to_string(),
        discovery: discovery.to_string(),
        peer_addrs: peers.iter().map(ToString::to_string).collect(),
        heartbeat,
        peer_timeout,
        binary: binary.to_string_lossy().to_string(),
    };
    let spec = RestartSpec {
        program: binary.to_path_buf(),
        args,
        config_dir,
    };
    (entry, cmd, spec)
}

/// Rebuild the exact command recorded in a manifest entry.
///
/// This is deliberately a pure process-construction helper: Testament does
/// not link against `misaka-runtime` and never turns the manifest into a
/// network control plane.
pub fn command_for_entry(entry: &SisterEntry, fallback_binary: &Path) -> std::io::Result<Command> {
    let binary = if !entry.binary.is_empty() {
        let configured = PathBuf::from(&entry.binary);
        if configured.exists() {
            configured
        } else {
            fallback_binary.to_path_buf()
        }
    } else {
        fallback_binary.to_path_buf()
    };
    let listen_port = entry
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .port();
    let introspect_port = entry
        .introspection_addr
        .as_deref()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing introspection address",
            )
        })?
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .port();
    let nickname = if entry.nickname.is_empty() {
        entry.alias.as_str()
    } else {
        entry.nickname.as_str()
    };
    let discovery = if entry.discovery.is_empty() {
        "manual"
    } else {
        entry.discovery.as_str()
    };
    let heartbeat = if entry.heartbeat == 0 {
        2
    } else {
        entry.heartbeat
    };
    let peer_timeout = if entry.peer_timeout == 0 {
        8
    } else {
        entry.peer_timeout
    };
    let mut args = vec![
        "start".to_string(),
        "--port".to_string(),
        listen_port.to_string(),
        "--nickname".to_string(),
        nickname.to_string(),
        "--log-format".to_string(),
        "json".to_string(),
        "--discovery".to_string(),
        discovery.to_string(),
        "--heartbeat".to_string(),
        heartbeat.to_string(),
        "--peer-timeout".to_string(),
        peer_timeout.to_string(),
        "--introspect".to_string(),
        introspect_port.to_string(),
    ];
    if let Some(stream_port) = stream_port_from_entry(entry)? {
        args.splice(3..3, ["--stream-port".to_string(), stream_port.to_string()]);
    }
    if !entry.stream_backend.is_empty() {
        args.push("--stream-backend".to_string());
        args.push(entry.stream_backend.clone());
    }
    for peer in &entry.peer_addrs {
        args.push("--peer".to_string());
        args.push(peer.clone());
    }
    let mut command = Command::new(&binary);
    command
        .args(&args)
        .env("MISAKA_CONFIG_DIR", &entry.config_dir);
    Ok(command)
}

/// Construct a process whose launch specification comes entirely from a
/// persisted manifest entry.
pub fn spawn_from_entry(
    entry: SisterEntry,
    fallback_binary: &Path,
) -> std::io::Result<SisterProcess> {
    let command = command_for_entry(&entry, fallback_binary)?;
    let binary = if !entry.binary.is_empty() && Path::new(&entry.binary).exists() {
        PathBuf::from(&entry.binary)
    } else {
        fallback_binary.to_path_buf()
    };
    let args = command_args_for_entry(&entry)?;
    let restart = RestartSpec {
        program: binary,
        args,
        config_dir: PathBuf::from(&entry.config_dir),
    };
    let mut process = SisterProcess::with_restart(entry.clone(), restart);
    process.spawn(command, &entry.stdout_log, &entry.stderr_log)?;
    Ok(process)
}

fn command_args_for_entry(entry: &SisterEntry) -> std::io::Result<Vec<String>> {
    let listen_port = entry
        .listen_addr
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .port();
    let introspect_port = entry
        .introspection_addr
        .as_deref()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing introspection address",
            )
        })?
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .port();
    let nickname = if entry.nickname.is_empty() {
        entry.alias.as_str()
    } else {
        entry.nickname.as_str()
    };
    let discovery = if entry.discovery.is_empty() {
        "manual"
    } else {
        entry.discovery.as_str()
    };
    let heartbeat = if entry.heartbeat == 0 {
        2
    } else {
        entry.heartbeat
    };
    let peer_timeout = if entry.peer_timeout == 0 {
        8
    } else {
        entry.peer_timeout
    };
    let mut args = vec![
        "start".into(),
        "--port".into(),
        listen_port.to_string(),
        "--nickname".into(),
        nickname.into(),
        "--log-format".into(),
        "json".into(),
        "--discovery".into(),
        discovery.into(),
        "--heartbeat".into(),
        heartbeat.to_string(),
        "--peer-timeout".into(),
        peer_timeout.to_string(),
        "--introspect".into(),
        introspect_port.to_string(),
    ];
    if let Some(stream_port) = stream_port_from_entry(entry)? {
        args.splice(3..3, ["--stream-port".into(), stream_port.to_string()]);
    }
    if !entry.stream_backend.is_empty() {
        args.push("--stream-backend".into());
        args.push(entry.stream_backend.clone());
    }
    for peer in &entry.peer_addrs {
        args.push("--peer".into());
        args.push(peer.clone());
    }
    Ok(args)
}

fn stream_port_from_entry(entry: &SisterEntry) -> std::io::Result<Option<u16>> {
    if entry.stream_addr.is_empty() {
        return Ok(None);
    }
    let addr = entry
        .stream_addr
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    Ok(Some(addr.port()))
}

impl SisterProcess {
    /// 用外部传入的 restart spec 构造 (供 build_spawn + spawn 组合使用)。
    pub fn with_restart(entry: SisterEntry, restart: RestartSpec) -> Self {
        Self {
            entry,
            child: None,
            restart: Some(restart),
        }
    }

    /// 启动进程并把 stdout/stderr 重定向到文件 (不占据管道)。
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

    /// 温和停止 (Unix SIGTERM)；若等待窗口内未退出则升级为 SIGKILL。
    /// 返回真实退出状态，供 graceful-stop 场景断言。
    pub fn terminate_status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no child"))?;
        request_stop(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        return child.wait();
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// 温和停止；调用者不需要关心退出状态时使用。
    pub fn terminate(&mut self) {
        let _ = self.terminate_status();
    }

    /// 强杀 (SIGKILL)，等待并返回真实退出状态。
    pub fn kill_status(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no child"))?;
        child.kill()?;
        child.wait()
    }

    /// 强杀 (SIGKILL)。不等待优雅退出。
    pub fn kill(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
        }
    }

    /// 暂停进程 (Unix SIGSTOP)。
    pub fn pause(&self) -> std::io::Result<()> {
        let pid = self
            .child
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no child"))?
            .id();
        signal_pid(pid, "STOP")
    }

    /// 恢复进程 (Unix SIGCONT)。
    pub fn resume(&self) -> std::io::Result<()> {
        let pid = self
            .child
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no child"))?
            .id();
        signal_pid(pid, "CONT")
    }

    /// 用同一 config 重启 (先终止再重新 spawn，保留 entry 字段)。
    pub fn restart(&mut self, stdout_path: &str, stderr_path: &str) -> std::io::Result<()> {
        let RestartSpec {
            program,
            args,
            config_dir,
        } = self.restart.clone().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Unsupported, "no restart spec")
        })?;
        if self.child.is_some() {
            self.terminate();
            self.wait()?;
        }
        self.entry.pid = None;
        let mut cmd = Command::new(&program);
        cmd.args(&args).env("MISAKA_CONFIG_DIR", config_dir);
        self.spawn(cmd, stdout_path, stderr_path)
    }
}

#[cfg(unix)]
fn signal_pid(pid: u32, sig: &str) -> std::io::Result<()> {
    let status = std::process::Command::new("kill")
        .args([format!("-{}", sig), pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "kill -{} {} exited with {}",
            sig, pid, status
        )))
    }
}

/// Test whether a PID currently exists without owning or reaping its child.
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Send a signal to a process started by a previous Testament invocation.
pub fn signal_process(pid: u32, signal: &str) -> std::io::Result<()> {
    signal_pid(pid, signal)
}

/// Wait until an externally-owned process disappears. Returns whether it did.
pub fn wait_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while pid_alive(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    true
}

#[cfg(not(unix))]
fn signal_pid(pid: u32, sig: &str) -> std::io::Result<()> {
    let _ = (pid, sig);
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "signals are unsupported on this platform",
    ))
}

/// 请求子进程优雅停止。Unix 用 SIGTERM；其它平台回退到 kill。
#[cfg(unix)]
fn request_stop(child: &mut Child) {
    let _ = signal_pid(child.id(), "TERM");
}

#[cfg(not(unix))]
fn request_stop(child: &mut Child) {
    let _ = child.kill();
}

/// 读取某 Sister 的 stdout.log 尾部 (供 logs 命令)。
pub fn read_stdout(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{build_spawn, command_for_entry, SpawnConfig};
    use crate::types::RunLayout;
    use std::path::PathBuf;

    #[test]
    fn spawn_metadata_and_restart_command_keep_stream_port() {
        let root = PathBuf::from("target/testament-stream-metadata");
        let layout = RunLayout {
            root: root.clone(),
            manifest_path: root.join("manifest.json"),
            report_path: root.join("report.json"),
            events_path: root.join("events.jsonl"),
            sisters_dir: root.join("sisters"),
        };
        let (mut entry, _, _) = build_spawn(SpawnConfig {
            layout: &layout,
            alias: "s1",
            nickname: "test",
            listen_port: 31700,
            stream_port: 31701,
            introspect_port: 31702,
            binary: PathBuf::from("/bin/echo").as_path(),
            peers: &[],
            discovery: "manual",
            heartbeat: 2,
            peer_timeout: 8,
        });

        assert_eq!(entry.stream_addr, "127.0.0.1:31701");
        let command = command_for_entry(&entry, PathBuf::from("/bin/echo").as_path()).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--stream-port", "31701"]));

        entry.stream_backend = "iroh".to_string();
        let iroh_command = command_for_entry(&entry, PathBuf::from("/bin/echo").as_path()).unwrap();
        let iroh_args: Vec<_> = iroh_command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(iroh_args
            .windows(2)
            .any(|pair| pair == ["--stream-backend", "iroh"]));
    }
}
