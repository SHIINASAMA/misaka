use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Testament 场景运行结果契约 (§21)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub scenario: String,
    pub result: String, // "passed" | "failed"
    pub failed_step: Option<usize>,
    pub assertion: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub run_id: String,
    pub artifacts: Artifacts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifacts {
    pub manifest: String,
    pub events: String,
    pub sister_logs: Vec<(String, String)>,
}

/// manifest.json —— run 顶层元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub run_id: String,
    pub sisters: Vec<SisterEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SisterEntry {
    pub alias: String,   // s1, s2 ...
    pub id: Option<u64>, // 启动后经 introspection 查询得到
    pub pid: Option<u32>,
    pub listen_addr: String,
    pub introspection_addr: Option<String>,
    pub config_dir: String,
    pub stdout_log: String,
    pub stderr_log: String,
}

/// 一个 run 在磁盘上的位置
#[derive(Debug, Clone)]
pub struct RunLayout {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub report_path: PathBuf,
    pub events_path: PathBuf,
    pub sisters_dir: PathBuf,
}

pub const TESTAMENT_ROOT: &str = ".testament";

pub fn runs_dir() -> PathBuf {
    PathBuf::from(TESTAMENT_ROOT).join("runs")
}
