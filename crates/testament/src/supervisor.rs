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
    /// 输出管道由后台线程持续 drain，避免大量输出阻塞子进程。
    pub fn wait_timeout(mut self, timeout: Duration) -> std::io::Result<Output> {
        let Some(mut child) = self.child.take() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "CLI process already consumed",
            ));
        };
        self.child = None;

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
        "--port".into(),
        listen_port.to_string(),
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
        introspection_addr: Some(format!("127.0.0.1:{}", introspect_port)),
        config_dir: config_dir.to_string_lossy().to_string(),
        stdout_log: stdout_log.to_string_lossy().to_string(),
        stderr_log: stderr_log.to_string_lossy().to_string(),
    };
    let spec = RestartSpec {
        program: binary.to_path_buf(),
        args,
        config_dir,
    };
    (entry, cmd, spec)
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
    /// 等待进程真正退出后返回。
    pub fn terminate(&mut self) {
        let Some(child) = &mut self.child else { return };
        request_stop(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
                Err(_) => {
                    let _ = child.kill();
                    return;
                }
            }
        }
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
        self.terminate();
        self.wait()?;
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

#[cfg(not(unix))]
fn signal_pid(_pid: u32, _sig: &str) -> std::io::Result<()> {
    Ok(())
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
