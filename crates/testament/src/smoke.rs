//! Black-box operator smoke suite.
//!
//! Each check crosses a real Testament process boundary. The suite uses
//! Testament to launch and inspect Sisters; it never starts a Sister itself.

use crate::operator::{PsReport, SisterProcessStatus};
use crate::run_manager::misaka_binary;
use crate::types::{Manifest, SisterEntry};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run() -> Result<Vec<&'static str>, String> {
    let testament = std::env::current_exe().map_err(|error| error.to_string())?;
    let testament = testament
        .canonicalize()
        .map_err(|error| format!("canonicalize testament: {error}"))?;
    let misaka = misaka_binary()
        .canonicalize()
        .map_err(|error| format!("canonicalize misaka: {error}"))?;
    let root = smoke_root();
    std::fs::create_dir_all(&root).map_err(|error| format!("create smoke root: {error}"))?;

    let result = run_suite(&root, &testament, &misaka);
    // If a check fails before the final default `down`, let Testament clean
    // the manifest-backed children before removing the temporary workspace.
    let _ = invoke(&root, &testament, &misaka, &["clean"]);
    let _ = std::fs::remove_dir_all(&root);
    result
}

fn run_suite(root: &Path, testament: &Path, misaka: &Path) -> Result<Vec<&'static str>, String> {
    let mut passed = Vec::new();
    let up = invoke(root, testament, misaka, &["up", "-n", "3", "--json"])?;
    let manifest: Manifest = decode_json(&up, "O01 up manifest")?;
    check(
        manifest.sisters.len() == 3
            && manifest
                .sisters
                .iter()
                .all(|entry| entry.peer_addrs.len() == 2),
        "O01 interactive_up_forms_network",
    )?;
    passed.push("O01 interactive_up_forms_network");
    let run_id = manifest.run_id.clone();

    let online_ps = ps(root, testament, misaka, &[])?;
    check(
        online_ps.sisters.len() == 3
            && online_ps
                .sisters
                .iter()
                .all(|entry| entry.status == SisterProcessStatus::Online && entry.peers == Some(2)),
        "O02 testament_ps_online",
    )?;
    passed.push("O02 testament_ps_online");

    invoke(root, testament, misaka, &["kill", "s3"])?;
    let dead_ps = ps(root, testament, misaka, &[])?;
    let dead = dead_ps
        .sisters
        .iter()
        .find(|entry| entry.alias == "s3")
        .ok_or_else(|| "O03 missing s3 after kill".to_string())?;
    check(
        dead.status == SisterProcessStatus::Dead && !dead.process_alive,
        "O03 testament_ps_dead",
    )?;
    passed.push("O03 testament_ps_dead");

    let before = manifest_entry(&manifest, "s3")?;
    invoke(root, testament, misaka, &["restart", "s3"])?;
    let restart_ps = ps(root, testament, misaka, &[])?;
    let restarted = restart_ps
        .sisters
        .iter()
        .find(|entry| entry.alias == "s3")
        .ok_or_else(|| "O04 missing s3 after restart".to_string())?;
    check(
        restarted.status == SisterProcessStatus::Online
            && restarted.sister_id == before.id
            && restarted.listen_addr == before.listen_addr
            && restarted.introspection_addr == before.introspection_addr,
        "O04 testament_restart",
    )?;
    passed.push("O04 testament_restart");

    invoke(root, testament, misaka, &["stop", "s2"])?;
    let stopped_ps = ps(root, testament, misaka, &[])?;
    let stopped = stopped_ps
        .sisters
        .iter()
        .find(|entry| entry.alias == "s2")
        .ok_or_else(|| "O05 missing s2 after stop".to_string())?;
    check(
        stopped.status == SisterProcessStatus::Dead && !stopped.process_alive,
        "O05 graceful_stop",
    )?;
    passed.push("O05 graceful_stop");

    let current_ps = ps(root, testament, misaka, &[])?;
    check(
        current_ps.run_id == run_id && current_ps.sisters.len() == 3,
        "O06 current_run",
    )?;
    passed.push("O06 current_run");

    let config_dir = manifest_entry(&manifest, "s1")?.config_dir.clone();
    let network_ps = Command::new(misaka)
        .current_dir(root)
        .env("MISAKA_CONFIG_DIR", &config_dir)
        .args(["ps", "--json"])
        .output()
        .map_err(|error| format!("O07 spawn misaka ps: {error}"))?;
    if !network_ps.status.success() {
        return Err(format!(
            "O07 misaka ps failed: {}",
            String::from_utf8_lossy(&network_ps.stderr).trim()
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&network_ps.stdout)
        .map_err(|error| format!("O07 decode misaka ps: {error}"))?;
    check(
        value["self"].is_u64()
            && value["sisters"]
                .as_array()
                .is_some_and(|rows| rows.len() >= 2),
        "O07 misaka_ps",
    )?;
    passed.push("O07 misaka_ps");

    // Default current-run down is the final cleanup assertion.
    invoke(root, testament, misaka, &["down"])?;
    if root.join(".testament").join("current").exists() {
        return Err("O06 current pointer survived default down".into());
    }
    Ok(passed)
}

fn ps(root: &Path, testament: &Path, misaka: &Path, args: &[&str]) -> Result<PsReport, String> {
    let mut full = vec!["ps", "--json"];
    full.extend_from_slice(args);
    let output = invoke(root, testament, misaka, &full)?;
    decode_json(&output, "testament ps")
}

fn invoke(root: &Path, testament: &Path, misaka: &Path, args: &[&str]) -> Result<Output, String> {
    let output = Command::new(testament)
        .current_dir(root)
        .env("MISAKA_BIN", misaka)
        .args(args)
        .output()
        .map_err(|error| format!("spawn testament {:?}: {error}", args))?;
    if !output.status.success() {
        return Err(format!(
            "testament {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn decode_json<T: serde::de::DeserializeOwned>(output: &Output, label: &str) -> Result<T, String> {
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "{label}: {error}; stdout: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        )
    })
}

fn manifest_entry<'a>(manifest: &'a Manifest, alias: &str) -> Result<&'a SisterEntry, String> {
    manifest
        .sisters
        .iter()
        .find(|entry| entry.alias == alias)
        .ok_or_else(|| format!("missing manifest entry {alias}"))
}

fn check(condition: bool, label: &str) -> Result<(), String> {
    condition
        .then_some(())
        .ok_or_else(|| format!("{label} failed"))
}

fn smoke_root() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("testament-operator-{millis}"))
}
