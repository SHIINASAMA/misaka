use misaka_core::NetworkId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 完整 verify 运行的结果 (所有场景聚合)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteReport {
    pub run_id: String,
    pub scenarios: Vec<Report>,
    pub passed: usize,
    pub failed: usize,
    pub infra_failed: usize,
    pub skipped: usize,
    pub exit_code: i32,
}

impl SuiteReport {
    pub fn count(&mut self, report: &Report) {
        match report.result.as_str() {
            "passed" => self.passed += 1,
            "failed" => self.failed += 1,
            "infra_failed" => self.infra_failed += 1,
            "skipped" => self.skipped += 1,
            _ => {}
        }
    }
}

/// 场景运行结果契约 (§21)。`result` 用 "passed" | "failed" | "infra_failed" | "skipped"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub scenario: String,
    pub result: String,
    pub failed_step: Option<usize>,
    pub assertion: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub run_id: String,
    pub artifacts: Artifacts,
}

/// 场景失败的分类，决定最终 exit code。
#[derive(Debug, Clone)]
pub enum ScenarioError {
    /// 断言不满足：被测行为与预期不符 (exit 1)
    Assertion(String),
    /// 基础设施/启动失败：进程无法启动或未就绪，无法判定行为 (exit 3)
    Infra(String),
    /// 环境不可用，跳过 (exit 0) —— 例如 CI 上无多播 mDNS
    Skipped(String),
}

impl ScenarioError {
    pub fn assertion(msg: impl Into<String>) -> Self {
        Self::Assertion(msg.into())
    }
    pub fn infra(msg: impl Into<String>) -> Self {
        Self::Infra(msg.into())
    }
    pub fn skipped(msg: impl Into<String>) -> Self {
        Self::Skipped(msg.into())
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Assertion(m) | Self::Infra(m) | Self::Skipped(m) => m,
        }
    }

    /// 对应的报告 result 字符串。
    pub fn result_label(&self) -> &'static str {
        match self {
            Self::Assertion(_) => "failed",
            Self::Infra(_) => "infra_failed",
            Self::Skipped(_) => "skipped",
        }
    }
}

impl std::fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for ScenarioError {}

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
    #[serde(default)]
    pub stream_addr: String,
    /// Optional stream backend flag needed to rebuild an Iroh Sister.
    #[serde(default)]
    pub stream_backend: String,
    pub introspection_addr: Option<String>,
    pub config_dir: String,
    pub stdout_log: String,
    pub stderr_log: String,
    /// The launch identity and topology are persisted so another Testament
    /// invocation can rebuild the exact same process.
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub discovery: String,
    #[serde(default)]
    pub peer_addrs: Vec<String>,
    #[serde(default)]
    pub heartbeat: u64,
    #[serde(default)]
    pub peer_timeout: u64,
    #[serde(default)]
    pub binary: String,
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

/// Stable NetworkId for the **live** Gateway smoke (`gateway-live-verify`).
///
/// The live Cloudflare Gateway must be deployed with this exact `NETWORK_ID`
/// (the value it is bound to is public configuration, never secret). Testament
/// mints two test Sisters' memberships against a locally-held operator authority
/// and points them at the Gateway; the Gateway's authority PUBLIC key must be
/// that same operator authority. Keeping the id fixed makes that binding
/// reproducible. It is unrelated to real production networks.
pub const LIVE_TEST_NETWORK: &str = "00000000-0000-0000-0000-0000000000ff";

pub fn live_test_network_id() -> NetworkId {
    NetworkId::parse(LIVE_TEST_NETWORK).expect("live test network id is a valid UUID")
}
