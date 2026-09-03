//! Reporter: write report.json (§21 contract) and map results to exit codes.
//!
//! 0 = scenario passed
//! 1 = scenario assertion failed
//! 2 = Testament/configuration error
//! 3 = Sister startup/runtime infrastructure failure

use crate::types::{Artifacts, Report};

pub fn write_report(path: &std::path::Path, report: &Report) -> std::io::Result<()> {
    let json =
        serde_json::to_string_pretty(report).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(path, json)
}

pub fn exit_code_for(report: &Report) -> i32 {
    match report.result.as_str() {
        "passed" => 0,
        "failed" => 1,
        _ => 2,
    }
}

/// 构造一个失败的 report (场景断言失败时)
pub fn failed_report(
    scenario: &str,
    failed_step: Option<usize>,
    assertion: Option<String>,
    expected: Option<String>,
    actual: Option<String>,
    run_id: &str,
    artifacts: Artifacts,
) -> Report {
    Report {
        scenario: scenario.to_string(),
        result: "failed".to_string(),
        failed_step,
        assertion,
        expected,
        actual,
        run_id: run_id.to_string(),
        artifacts,
    }
}

pub fn passed_report(scenario: &str, run_id: &str, artifacts: Artifacts) -> Report {
    Report {
        scenario: scenario.to_string(),
        result: "passed".to_string(),
        failed_step: None,
        assertion: None,
        expected: None,
        actual: None,
        run_id: run_id.to_string(),
        artifacts,
    }
}
