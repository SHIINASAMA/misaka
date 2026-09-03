use crate::types::{Manifest, RunLayout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn runs_dir() -> PathBuf {
    PathBuf::from(crate::types::TESTAMENT_ROOT).join("runs")
}

/// Pointer to the run selected by the last successful interactive `up`.
pub fn current_path() -> PathBuf {
    PathBuf::from(crate::types::TESTAMENT_ROOT).join("current")
}

/// Read the active run pointer without falling back to a historical run.
pub fn load_current_run() -> std::io::Result<String> {
    let run_id = std::fs::read_to_string(current_path())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "no current run"))?;
    let run_id = run_id.trim();
    if run_id.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no current run",
        ));
    }
    Ok(run_id.to_string())
}

/// Select a run for commands that operate on a live network.
/// An explicit id always wins over the persisted current pointer.
pub fn resolve_run_id(explicit: Option<&str>) -> std::io::Result<String> {
    if let Some(run_id) = explicit {
        if run_id.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "run id cannot be empty",
            ));
        }
        return Ok(run_id.to_string());
    }

    load_current_run()
}

/// Point future live-operator commands at `run_id`.
pub fn set_current_run(run_id: &str) -> std::io::Result<()> {
    let path = current_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}\n", run_id))?;
    std::fs::rename(tmp, path)
}

/// Remove the current pointer only when it still refers to `run_id`.
pub fn clear_current_run(run_id: &str) -> std::io::Result<()> {
    let path = current_path();
    let current = match std::fs::read_to_string(&path) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if current.trim() != run_id {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// 直接定位某 run 的根目录 (供 CLI status/logs/down) —— 不强制存在。
///
/// The layout is reconstructed without creating any files.
pub fn layout_for_run(run_id: &str) -> RunLayout {
    let root = run_root(run_id);
    RunLayout {
        root: root.clone(),
        manifest_path: root.join("manifest.json"),
        report_path: root.join("report.json"),
        events_path: root.join("events.jsonl"),
        sisters_dir: root.join("sisters"),
    }
}

pub fn run_root(run_id: &str) -> PathBuf {
    runs_dir().join(run_id)
}

/// 从 OS 申请一个空闲端口 (绑 loopback 0 端口后释放，再交给子进程绑定)。
pub fn alloc_port() -> std::io::Result<u16> {
    let l = std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

/// 每次 invocation 生成一个隔离的 run 目录。
pub fn create_run() -> std::io::Result<(String, RunLayout)> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let run_id = format!("r-{}", millis);
    let root = runs_dir().join(&run_id);

    let layout = RunLayout {
        root: root.clone(),
        manifest_path: root.join("manifest.json"),
        report_path: root.join("report.json"),
        events_path: root.join("events.jsonl"),
        sisters_dir: root.join("sisters"),
    };
    std::fs::create_dir_all(&layout.sisters_dir)?;
    std::fs::File::create(&layout.events_path)?;
    Ok((run_id, layout))
}

pub fn write_manifest(layout: &RunLayout, manifest: &Manifest) -> std::io::Result<()> {
    let json =
        serde_json::to_string_pretty(manifest).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(&layout.manifest_path, json)
}

pub fn load_manifest(layout: &RunLayout) -> std::io::Result<Manifest> {
    let json = std::fs::read_to_string(&layout.manifest_path)?;
    serde_json::from_str(&json).map_err(|e| std::io::Error::other(e.to_string()))
}

/// 定位运行中的 misaka 二进制。优先环境变量 MISAKA_BIN，否则用开发构建产物。
pub fn misaka_binary() -> PathBuf {
    if let Ok(b) = std::env::var("MISAKA_BIN") {
        let p = PathBuf::from(b);
        if p.exists() {
            return p;
        }
    }
    // 相对当前工作目录: target/debug/misaka (workspace root)
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let candidate = cwd.join("target").join("debug").join("misaka");
    if candidate.exists() {
        return candidate;
    }
    // 兜底: 直接在 PATH 里找
    PathBuf::from("misaka")
}

/// 生成本场景的孤立 data 目录 (每个 Sister 独立 config dir)。
pub fn sister_config_dir(layout: &RunLayout, alias: &str) -> PathBuf {
    layout.sisters_dir.join(alias).join("config")
}
