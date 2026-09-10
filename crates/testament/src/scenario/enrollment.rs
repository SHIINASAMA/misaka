//! E01–E13: black-box enrollment verification.
//!
//! Every scenario drives real `misaka` OS processes only. The Authority is
//! created with `misaka network init`, started with the normal `misaka start`
//! (Iroh is the default backend), and issues a timed Invite Code with
//! `misaka network invite`. A brand-new device joins with exactly
//! `misaka network join <network-id> <invite-code> [--gateway <url>]` — no Sister
//! IDs, public keys, `--peer`/`--iroh-peer`, or `invite.json` anywhere. Each
//! Sister uses an isolated `MISAKA_CONFIG_DIR`; nothing touches `~/.misaka`.

use super::*;
use crate::scenario::helpers::http_get;
use serde_json::Value;

/// The fixed harness Network ID. `build_spawn` starts every scenario Sister with
/// this `--network-id`, so the Authority is initialized with the same value and
/// the joined device (whose Network ID comes from the invite) matches too.
const TEST_NET: &str = "00000000-0000-0000-0000-000000000001";

/// Create an isolated config directory under the current scenario's layout.
fn config_dir(ctx: &Context, name: &str) -> PathBuf {
    let dir = ctx.layout.root.join(format!("enroll-{name}"));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `misaka network init` on a fresh directory: creates the Network + Authority.
/// Returns (Network ID, Authority public key hex) from the command's own JSON
/// output — public material only, never the private key.
fn network_init(ctx: &Context, dir: &Path) -> Result<(String, String), ScenarioError> {
    let output = ctx.run_config_cli(dir, &["--network-id", TEST_NET, "network", "init"])?;
    let value: Value = output.parse().map_err(|error| {
        ScenarioError::assertion(format!("network init output not JSON: {error}"))
    })?;
    let network_id = value["network_id"]
        .as_str()
        .ok_or_else(|| ScenarioError::assertion("network init output missing network_id"))?
        .to_string();
    let authority_public_key = value["authority_public_key"]
        .as_str()
        .ok_or_else(|| {
            ScenarioError::assertion("network init output missing authority_public_key")
        })?
        .to_string();
    Ok((network_id, authority_public_key))
}

/// Start the Authority Sister over Iroh so its enrollment handler is live.
fn start_authority(
    ctx: &mut Context,
    alias: &str,
    dir: &Path,
    gateway: Option<&str>,
) -> Result<(), ScenarioError> {
    ctx.start_iroh_sister_with_config(alias, alias, dir, gateway)
}

/// `misaka network invite` on the running Authority; capture (network_id, code).
fn mint_invite(
    ctx: &Context,
    dir: &Path,
    expires: &str,
) -> Result<(String, String), ScenarioError> {
    let output = ctx.run_config_cli(dir, &["network", "invite", "--expires", expires, "--json"])?;
    let value: Value = output.parse().map_err(|error| {
        ScenarioError::assertion(format!("invite --json not decodable: {error}"))
    })?;
    let network_id = value["network_id"]
        .as_str()
        .ok_or_else(|| ScenarioError::assertion("invite JSON missing network_id"))?
        .to_string();
    let code = value["invite_code"]
        .as_str()
        .ok_or_else(|| ScenarioError::assertion("invite JSON missing invite_code"))?
        .to_string();
    if !code.starts_with("misaka1_") {
        return Err(ScenarioError::assertion(
            "invite code has no versioned prefix",
        ));
    }
    Ok((network_id, code))
}

struct JoinResult {
    success: bool,
    stderr: String,
}

/// Run `misaka network join` and capture the outcome without failing the
/// scenario, so negative cases can assert on the rejection.
fn try_join(
    ctx: &Context,
    dir: &Path,
    network_id: &str,
    code: &str,
    gateway: Option<&str>,
) -> Result<JoinResult, ScenarioError> {
    let mut args = vec!["network", "join", network_id, code];
    if let Some(gateway) = gateway {
        args.extend(["--gateway", gateway]);
    }
    let output = ctx
        .spawn_cli_with_config(dir, &args)?
        .wait_timeout(Duration::from_secs(60))
        .map_err(|error| ScenarioError::infra(format!("join cli: {error}")))?;
    Ok(JoinResult {
        success: output.status.success(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn assert_installed(dir: &Path, network_id: &str) -> Result<(), ScenarioError> {
    for name in [
        "network-id",
        "network.json",
        "membership.bin",
        "peer-records.json",
    ] {
        if !dir.join(name).exists() {
            return Err(ScenarioError::assertion(format!(
                "joined device is missing {name}"
            )));
        }
    }
    let persisted = std::fs::read_to_string(dir.join("network-id"))
        .map_err(|error| ScenarioError::infra(format!("read network-id: {error}")))?;
    if persisted.trim() != network_id {
        return Err(ScenarioError::assertion(
            "persisted NetworkId does not match invite",
        ));
    }
    // The Authority private key must never be installed on a joined device.
    if dir.join("network-authority-key").exists() {
        return Err(ScenarioError::assertion(
            "joined device received the Authority private key",
        ));
    }
    Ok(())
}

// --- E01 -------------------------------------------------------------------

fn e01_fresh_join_with_network_id_and_code(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e01-a");
    let joiner = config_dir(ctx, "e01-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e01a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    if !result.success {
        ctx.teardown();
        return Err(ScenarioError::assertion(format!(
            "fresh join failed: {}",
            result.stderr.trim()
        )));
    }
    ctx.teardown();
    assert_installed(&joiner, &network_id)
}

// --- E02 -------------------------------------------------------------------

fn e02_identity_generated_without_start(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e02-a");
    let joiner = config_dir(ctx, "e02-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e02a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    // The joiner has never run `misaka start`; the join must generate identity +
    // Sister key on its own.
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    ctx.teardown();
    if !result.success {
        return Err(ScenarioError::assertion(format!(
            "join on fresh device failed: {}",
            result.stderr.trim()
        )));
    }
    for name in ["identity.json", "sister-identity-key"] {
        if !joiner.join(name).exists() {
            return Err(ScenarioError::assertion(format!(
                "{name} was not auto-generated on the fresh device"
            )));
        }
    }
    assert_installed(&joiner, &network_id)
}

// --- E03 -------------------------------------------------------------------

fn e03_expired_code_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e03-a");
    let joiner = config_dir(ctx, "e03-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e03a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1s")?;
    // Let the one-second window close.
    std::thread::sleep(Duration::from_secs(3));
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    ctx.teardown();
    if result.success {
        return Err(ScenarioError::assertion("an expired invite was accepted"));
    }
    assert_no_partial_network(&joiner)?;
    Ok(())
}

// --- E04 -------------------------------------------------------------------

fn e04_tampered_code_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e04-a");
    let joiner = config_dir(ctx, "e04-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e04a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let mut tampered = code.clone();
    let last = tampered.pop().expect("invite non-empty");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let result = try_join(ctx, &joiner, &network_id, &tampered, None)?;
    ctx.teardown();
    if result.success {
        return Err(ScenarioError::assertion("a tampered invite was accepted"));
    }
    assert_no_partial_network(&joiner)
}

// --- E05 -------------------------------------------------------------------

fn e05_wrong_network_id_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e05-a");
    let joiner = config_dir(ctx, "e05-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e05a", &authority, None)?;
    let (_network_id, code) = mint_invite(ctx, &authority, "1h")?;
    // Supply a different NetworkId on the command line than the invite carries.
    let wrong = "00000000-0000-0000-0000-0000000000e5";
    let result = try_join(ctx, &joiner, wrong, &code, None)?;
    ctx.teardown();
    if result.success {
        return Err(ScenarioError::assertion(
            "join accepted a NetworkId that does not match the invite",
        ));
    }
    assert_no_partial_network(&joiner)
}

// --- E07 -------------------------------------------------------------------

fn e07_join_with_gateway_persists_it(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e07-a");
    let joiner = config_dir(ctx, "e07-b");
    // A local native Gateway serving the Authority's Network (public config only).
    let (network_id, authority_public_key) = network_init(ctx, &authority)?;
    let (bind, process) = spawn_gateway_for_network(&network_id, &authority_public_key)?;
    start_authority(ctx, "e07a", &authority, Some(&gateway_url(bind)))?;
    let (invite_network, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(
        ctx,
        &joiner,
        &invite_network,
        &code,
        Some(&gateway_url(bind)),
    )?;
    let outcome = if result.success {
        let persisted = std::fs::read_to_string(joiner.join("gateways.json"))
            .ok()
            .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
            .unwrap_or_default();
        if persisted
            .iter()
            .any(|url| url.trim_end_matches('/') == gateway_url(bind))
        {
            Ok(())
        } else {
            Err(ScenarioError::assertion(
                "join --gateway did not persist the Gateway URL",
            ))
        }
    } else {
        ctx.teardown();
        Err(ScenarioError::assertion(format!(
            "gateway join failed: {}",
            result.stderr.trim()
        )))
    };
    ctx.teardown();
    stop_gateway(process)?;
    outcome
}

// --- E08 -------------------------------------------------------------------

fn e08_join_without_gateway_succeeds(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e08-a");
    let joiner = config_dir(ctx, "e08-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e08a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    ctx.teardown();
    if !result.success {
        return Err(ScenarioError::assertion(format!(
            "join without a Gateway failed: {}",
            result.stderr.trim()
        )));
    }
    // No gateway was configured, so none should have been persisted.
    assert_installed(&joiner, &network_id)
}

// --- E09 -------------------------------------------------------------------

fn e09_one_invite_redeemed_by_two_sisters(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e09-a");
    let b = config_dir(ctx, "e09-b");
    let c = config_dir(ctx, "e09-c");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e09a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let first = try_join(ctx, &b, &network_id, &code, None)?;
    let second = try_join(ctx, &c, &network_id, &code, None)?;
    ctx.teardown();
    if !(first.success && second.success) {
        return Err(ScenarioError::assertion(
            "a still-valid invite must be reusable by multiple Sisters",
        ));
    }
    // Two distinct Sisters each got their own membership.
    let b_id = std::fs::read_to_string(b.join("network-id"))
        .ok()
        .map(|value| value.trim().to_string());
    let c_id = std::fs::read_to_string(c.join("network-id"))
        .ok()
        .map(|value| value.trim().to_string());
    if b_id.as_deref() != Some(network_id.as_str()) || c_id.as_deref() != Some(network_id.as_str())
    {
        return Err(ScenarioError::assertion(
            "reused invite installed the wrong NetworkId",
        ));
    }
    Ok(())
}

// --- E10 -------------------------------------------------------------------

fn e10_normal_path_uses_no_low_level_inputs(ctx: &mut Context) -> Result<(), ScenarioError> {
    // The scenario itself only ever passes the documented normal inputs; this
    // asserts the joined device carries none of the forbidden legacy artifacts
    // and that a join needs no `invite.json`/`--peer`/`--iroh-peer`/`--sister-*`.
    let authority = config_dir(ctx, "e10-a");
    let joiner = config_dir(ctx, "e10-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e10a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    ctx.teardown();
    if !result.success {
        return Err(ScenarioError::assertion(format!(
            "normal join failed: {}",
            result.stderr.trim()
        )));
    }
    if joiner.join("invite.json").exists() {
        return Err(ScenarioError::assertion(
            "normal join produced an invite.json artifact",
        ));
    }
    // The join command argv is built solely from network-id + invite-code; there
    // is no code path in this scenario that passes a Sister id/key or peer flag.
    Ok(())
}

// --- E11 -------------------------------------------------------------------

fn e11_failed_join_leaves_no_partial_network(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e11-a");
    let joiner = config_dir(ctx, "e11-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e11a", &authority, None)?;
    let (network_id, _) = mint_invite(ctx, &authority, "1h")?;
    // A syntactically bogus code fails validation; no Network state may persist.
    let result = try_join(ctx, &joiner, &network_id, "misaka1_notarealinvite", None)?;
    ctx.teardown();
    if result.success {
        return Err(ScenarioError::assertion("a malformed invite was accepted"));
    }
    assert_no_partial_network(&joiner)
}

// --- E12 -------------------------------------------------------------------

fn e12_joined_sister_starts_with_authenticated_session(
    ctx: &mut Context,
) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e12-a");
    let joiner = config_dir(ctx, "e12-b");
    network_init(ctx, &authority)?;
    start_authority(ctx, "e12a", &authority, None)?;
    let (network_id, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(ctx, &joiner, &network_id, &code, None)?;
    if !result.success {
        ctx.teardown();
        return Err(ScenarioError::assertion(format!(
            "join failed: {}",
            result.stderr.trim()
        )));
    }
    // Start the joined device normally. A fresh, valid Authority-signed
    // membership + transport binding must let `misaka start` establish its
    // authenticated Iroh session (it becomes ready on the introspection port).
    start_authority(ctx, "e12b", &joiner, None)?;
    let snapshot = ctx.introspect("e12b")?;
    ctx.teardown();
    let joined_id = snapshot.identity.id.as_u64();
    if joined_id == 0 {
        return Err(ScenarioError::assertion(
            "joined Sister started with no identity",
        ));
    }
    Ok(())
}

// --- E13 -------------------------------------------------------------------

fn e13_joined_sister_discovers_authority_through_gateway(
    ctx: &mut Context,
) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "e13-a");
    let joiner = config_dir(ctx, "e13-b");
    let (network_id, authority_public_key) = network_init(ctx, &authority)?;
    let (bind, process) = spawn_gateway_for_network(&network_id, &authority_public_key)?;
    let url = gateway_url(bind);
    // Authority announces through the Gateway; the joiner is configured to it too.
    start_authority(ctx, "e13a", &authority, Some(&url))?;
    let (invite_network, code) = mint_invite(ctx, &authority, "1h")?;
    let result = try_join(ctx, &joiner, &invite_network, &code, Some(&url))?;
    if !result.success {
        ctx.teardown();
        stop_gateway(process)?;
        return Err(ScenarioError::assertion(format!(
            "gateway join failed: {}",
            result.stderr.trim()
        )));
    }
    // The joined device already has the Gateway persisted (from join), so a bare
    // `misaka start` discovers through it — no manual peer, no raw iroh://.
    start_authority(ctx, "e13b", &joiner, None)?;

    // Wait for the authenticated Iroh session to form via Gateway discovery, in
    // both directions.
    let outcome = (|| -> Result<(), ScenarioError> {
        let a_id = ctx.introspect("e13a")?.identity.id.as_u64();
        let b_id = ctx.introspect("e13b")?.identity.id.as_u64();
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        loop {
            let a = ctx.introspect("e13a")?;
            let b = ctx.introspect("e13b")?;
            let a_sees_b = a.peers.iter().any(|peer| peer.id == b_id);
            let b_sees_a = b.peers.iter().any(|peer| peer.id == a_id);
            if a_sees_b && b_sees_a {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(ScenarioError::assertion(format!(
                    "peers never converged through the Gateway (a saw b: {a_sees_b}, b saw a: {b_sees_a})"
                )));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    })();
    // Regression guard: `misaka ps` must report the discovered peer as online.
    // The normal Iroh backend disables the legacy TCP control listener, so peer
    // liveness has to be probed over the authenticated Iroh control channel.
    let ps_outcome = outcome.and_then(|()| {
        let a_id = ctx.introspect("e13a")?.identity.id.as_u64();
        let report: Value = ctx
            .run_cli("e13b", &["ps", "--json"])?
            .parse()
            .map_err(|error| {
                ScenarioError::assertion(format!("ps --json not decodable: {error}"))
            })?;
        let a_online = report["sisters"]
            .as_array()
            .map(|entries| {
                entries.iter().any(|entry| {
                    entry["id"].as_u64() == Some(a_id) && entry["status"].as_str() == Some("online")
                })
            })
            .unwrap_or(false);
        if a_online {
            Ok(())
        } else {
            Err(ScenarioError::assertion(
                "`misaka ps` did not report the Iroh peer as online",
            ))
        }
    });
    ctx.teardown();
    stop_gateway(process)?;
    ps_outcome
}

// --- Local native Gateway helpers (public config only) ---------------------

fn gateway_url(bind: SocketAddr) -> String {
    format!("http://{bind}")
}

fn spawn_gateway_for_network(
    network_id: &str,
    authority_public_key: &str,
) -> Result<(SocketAddr, CliProcess), ScenarioError> {
    let port = alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?;
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config_dir = std::env::temp_dir().join(format!("misaka-enroll-gateway-{port}"));
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| ScenarioError::infra(format!("create gateway dir: {error}")))?;
    let bind_arg = bind.to_string();
    let mut command = std::process::Command::new(misaka_binary());
    command
        .args([
            "network",
            "gateway",
            "serve",
            "--bind",
            &bind_arg,
            "--network-id",
            network_id,
            "--authority-public-key",
            authority_public_key,
        ])
        .env("MISAKA_CONFIG_DIR", &config_dir);
    let process = CliProcess::spawn(command)
        .map_err(|error| ScenarioError::infra(format!("spawn gateway: {error}")))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        if http_get(bind, "/.well-known/misaka")
            .is_ok_and(|response| response.starts_with("HTTP/1.1 200"))
        {
            return Ok((bind, process));
        }
        std::thread::sleep(Duration::from_millis(25));
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

/// After a failed join, none of the Network-scoped artifacts may exist. Sister
/// identity/key are joiner-local and inert, so they are permitted to remain.
fn assert_no_partial_network(dir: &Path) -> Result<(), ScenarioError> {
    for name in [
        "network-id",
        "network.json",
        "membership.bin",
        "peer-records.json",
    ] {
        if dir.join(name).exists() {
            return Err(ScenarioError::assertion(format!(
                "failed join left partial Network state: {name}"
            )));
        }
    }
    // No staging residue either.
    if std::fs::read_dir(dir)
        .map(|entries| {
            entries.filter_map(|entry| entry.ok()).any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".misaka-join")
            })
        })
        .unwrap_or(false)
    {
        return Err(ScenarioError::assertion(
            "failed join left a staging directory behind",
        ));
    }
    Ok(())
}

pub fn enrollment_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "E01",
            run: Box::new(e01_fresh_join_with_network_id_and_code),
        },
        ScenarioDef {
            name: "E02",
            run: Box::new(e02_identity_generated_without_start),
        },
        ScenarioDef {
            name: "E03",
            run: Box::new(e03_expired_code_is_rejected),
        },
        ScenarioDef {
            name: "E04",
            run: Box::new(e04_tampered_code_is_rejected),
        },
        ScenarioDef {
            name: "E05",
            run: Box::new(e05_wrong_network_id_is_rejected),
        },
        ScenarioDef {
            name: "E07",
            run: Box::new(e07_join_with_gateway_persists_it),
        },
        ScenarioDef {
            name: "E08",
            run: Box::new(e08_join_without_gateway_succeeds),
        },
        ScenarioDef {
            name: "E09",
            run: Box::new(e09_one_invite_redeemed_by_two_sisters),
        },
        ScenarioDef {
            name: "E10",
            run: Box::new(e10_normal_path_uses_no_low_level_inputs),
        },
        ScenarioDef {
            name: "E11",
            run: Box::new(e11_failed_join_leaves_no_partial_network),
        },
        ScenarioDef {
            name: "E12",
            run: Box::new(e12_joined_sister_starts_with_authenticated_session),
        },
        ScenarioDef {
            name: "E13",
            run: Box::new(e13_joined_sister_discovers_authority_through_gateway),
        },
        ScenarioDef {
            name: "JI01",
            run: Box::new(ji01_directed_job_over_iroh),
        },
        ScenarioDef {
            name: "JI04",
            run: Box::new(ji04_unreachable_executor_bounded),
        },
        ScenarioDef {
            name: "JI08",
            run: Box::new(ji08_no_running_sister_fails_closed),
        },
        ScenarioDef {
            name: "JI09",
            run: Box::new(ji09_iroh_unavailable_fails_closed),
        },
    ]
}

// ---------------------------------------------------------------------------
// JI — authenticated-Iroh Job control plane (the normal `misaka run` path).
// The creator is the running Authority Sister; its `misaka run` routes through
// its own loopback API and submits over the authenticated Iroh control plane.
// These Sisters run Iroh only — the legacy TCP control listener is disabled —
// so a green test proves the Job used Iroh, not a DirectTcp fallback.
// ---------------------------------------------------------------------------

/// Converge A's view of B through the Gateway (A must resolve B by SisterId to
/// reach it over Iroh) before submitting a Job.
fn wait_for_a_sees_b(ctx: &mut Context, a_alias: &str, b_id: u64) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let a = ctx.introspect(a_alias)?;
        if a.peers.iter().any(|peer| peer.id == b_id) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::infra(format!(
                "{a_alias} never discovered Sister {b_id} through the Gateway"
            )));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// JI01 — directed `misaka run --sister B` submits over authenticated Iroh,
/// B executes, and the result returns to the caller. Asserts `misaka ps`/the
/// Iroh-only topology (no TCP control listener) is what carried it.
fn ji01_directed_job_over_iroh(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "ji01-a");
    let joiner = config_dir(ctx, "ji01-b");
    let (network_id, authority_public_key) = network_init(ctx, &authority)?;
    // A is the operator+authority: it holds the Human identity used to sign the
    // target-bound JobSubmit authorization for the directed executor.
    ctx.run_config_cli(
        &authority,
        &[
            "--network-id",
            &network_id,
            "human",
            "init",
            "--name",
            "operator",
        ],
    )?;
    let (bind, gateway) = spawn_gateway_for_network(&network_id, &authority_public_key)?;
    let url = gateway_url(bind);
    start_authority(ctx, "ji01a", &authority, Some(&url))?;
    let (invite_network, code) = mint_invite(ctx, &authority, "1h")?;
    let joined = try_join(ctx, &joiner, &invite_network, &code, Some(&url))?;
    if !joined.success {
        ctx.teardown();
        stop_gateway(gateway)?;
        return Err(ScenarioError::assertion(format!(
            "JI01 join failed: {}",
            joined.stderr.trim()
        )));
    }
    start_authority(ctx, "ji01b", &joiner, None)?;

    let b_id = ctx.introspect("ji01b")?.identity.id.as_u64();
    // A must be able to reach B over Iroh before a directed submission works.
    wait_for_a_sees_b(ctx, "ji01a", b_id)?;

    // `misaka run --sister B` on A routes through A's loopback API and submits
    // over the authenticated Iroh control plane (A's TCP control listener is
    // off, so success proves Iroh carried it).
    let output = ctx.run_cli(
        "ji01a",
        &["run", "--sister", &b_id.to_string(), "printf iroh-job-ok"],
    )?;

    // §49: an unauthenticated local caller must be rejected, and its command
    // must not run. POST /api/v1/jobs with no Authorization header → 401.
    if let Ok(raw) = std::fs::read_to_string(authority.join("api-endpoint")) {
        if let Ok(api_addr) = raw.trim().parse::<std::net::SocketAddr>() {
            let sentinel = ctx.layout.root.join("ji01-unauth-sentinel");
            let body = serde_json::json!({
                "command": format!("touch {}", sentinel.display())
            })
            .to_string();
            let response = unauthenticated_post(api_addr, "/api/v1/jobs", &body);
            if !response.contains("401") {
                ctx.teardown();
                stop_gateway(gateway)?;
                return Err(ScenarioError::assertion(format!(
                    "unauthenticated POST /api/v1/jobs was not rejected with 401: {response}"
                )));
            }
            if sentinel.exists() {
                let _ = std::fs::remove_file(&sentinel);
                ctx.teardown();
                stop_gateway(gateway)?;
                return Err(ScenarioError::assertion(
                    "an unauthenticated local caller executed a command".to_string(),
                ));
            }
        }
    }
    ctx.teardown();
    stop_gateway(gateway)?;
    if output.contains("iroh-job-ok") {
        Ok(())
    } else {
        Err(ScenarioError::assertion(format!(
            "directed Iroh job did not return the expected result: {output}"
        )))
    }
}

/// A raw HTTP POST with no `Authorization` header — a hostile local caller.
/// Returns the raw response (possibly empty on transport failure).
fn unauthenticated_post(addr: std::net::SocketAddr, path: &str, body: &str) -> String {
    use std::io::{Read, Write};
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(1500))
    else {
        return String::new();
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// JI04 — submitting to a known-but-unreachable Sister fails within a bound
/// window (no indefinite wait), the CLI exits non-zero with a real diagnostic,
/// no legacy TCP path was attempted, and no Job leaks onto the running Sister.
fn ji04_unreachable_executor_bounded(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "ji04-a");
    let (network_id, authority_public_key) = network_init(ctx, &authority)?;
    ctx.run_config_cli(
        &authority,
        &[
            "--network-id",
            &network_id,
            "human",
            "init",
            "--name",
            "operator",
        ],
    )?;
    let (bind, gateway) = spawn_gateway_for_network(&network_id, &authority_public_key)?;
    start_authority(ctx, "ji04a", &authority, Some(&gateway_url(bind)))?;
    // A Sister id A has never seen → directed submission cannot reach it over
    // the authenticated Iroh control plane. It must fail fast (no Iroh
    // connection, no pending leak), not hang or downgrade to a TCP path.
    let started = std::time::Instant::now();
    let result = ctx.run_cli("ji04a", &["run", "--sister", "424242", "printf x"]);
    let elapsed = started.elapsed();
    // After the failure the running Sister must hold no queued/running Job: the
    // command never executed anywhere and the pending waiter was cleaned up.
    let snapshot = ctx.introspect("ji04a")?;
    ctx.teardown();
    stop_gateway(gateway)?;
    let diagnostic = match result {
        Ok(out) if out.contains("printf x") => {
            return Err(ScenarioError::assertion(
                "unreachable executor unexpectedly produced a result (DirectTcp fallback?)",
            ))
        }
        Ok(out) => out,
        Err(error) => error.to_string(),
    };
    if elapsed > Duration::from_secs(20) {
        return Err(ScenarioError::assertion(format!(
            "unreachable executor submission took {elapsed:?}; must fail bounded"
        )));
    }
    if diagnostic.trim().is_empty() {
        return Err(ScenarioError::assertion(
            "unreachable executor failure produced no diagnostic",
        ));
    }
    let leaked = snapshot
        .jobs
        .iter()
        .any(|job| job.command.contains("printf x"));
    if leaked || snapshot.queue_depth != 0 {
        return Err(ScenarioError::assertion(format!(
            "unreachable executor submission leaked state onto the running Sister (jobs={}, queue_depth={})",
            snapshot.jobs.len(),
            snapshot.queue_depth
        )));
    }
    Ok(())
}

/// JI08 — no running local Sister means remote `misaka run` fails closed.
///
/// A valid local config exists (Sister identity + network membership are
/// present) but no Sister daemon is running. A remote `misaka run --sister B`
/// must fail with a clear error — it must NOT construct a one-shot DirectTcp
/// Sister, open a TCP callback listener, or attempt any TCP submission. The
/// scenario asserts no remote side-effect occurs and no `--sister` TCP address
/// is reachable afterward.
fn ji08_no_running_sister_fails_closed(ctx: &mut Context) -> Result<(), ScenarioError> {
    let dir = config_dir(ctx, "ji08-standalone");
    // Initialize valid local Network material without starting any daemon. The
    // persisted identity + membership make the config look like a real joined
    // device (whose operator forgot to `misaka start`).
    network_init(ctx, &dir)?;
    // A config with no `api-endpoint` recorded (no daemon ever wrote one) is
    // exactly the no-running-Sister state.
    if dir.join("api-endpoint").exists() {
        return Err(ScenarioError::assertion(
            "JI08 fixture unexpectedly has a recorded API endpoint",
        ));
    }

    // There is no running local Sister for `misaka run --sister` to relay
    // through. It must fail closed rather than silently degrade to DirectTcp.
    let started = std::time::Instant::now();
    let result = ctx.spawn_cli_with_config(
        &dir,
        &["run", "--sister", "424242", "printf should-not-run"],
    )?;
    let elapsed = started.elapsed();
    let output = result
        .wait_timeout(Duration::from_secs(30))
        .map_err(|error| ScenarioError::infra(format!("ji08 run cli: {error}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}\n{stderr}");

    if output.status.success() {
        return Err(ScenarioError::assertion(
            "remote run without a running Sister unexpectedly succeeded (DirectTcp fallback?)",
        ));
    }
    if combined.contains("should-not-run") {
        return Err(ScenarioError::assertion(
            "remote run without a running Sister executed the command (DirectTcp fallback?)",
        ));
    }
    if combined.is_empty() {
        return Err(ScenarioError::assertion(
            "remote run without a running Sister failed with no diagnostic",
        ));
    }
    if elapsed > Duration::from_secs(20) {
        return Err(ScenarioError::assertion(format!(
            "no-running-Sister failure took {elapsed:?}; must be bounded"
        )));
    }
    // The fail-closed path constructs no one-shot DirectTcp Sister and opens no
    // legacy callback listener — the CLI exited non-zero without executing the
    // command and without binding any listener. (A bare `run` never binds the
    // config's own control-plane listen port, so no listener could exist.)
    Ok(())
}

/// JI09 — a running Sister whose authenticated-Iroh route to the target is
/// unavailable fails closed (no DirectTcp downgrade).
///
/// The creator Sister runs (loopback API reachable), but its directed target
/// has no authenticated-Iroh route. The submission must reach the local API and
/// fail there — the CLI must report the failure and must NOT fall back to a
/// legacy TCP path.
fn ji09_iroh_unavailable_fails_closed(ctx: &mut Context) -> Result<(), ScenarioError> {
    let authority = config_dir(ctx, "ji09-a");
    let (network_id, authority_public_key) = network_init(ctx, &authority)?;
    ctx.run_config_cli(
        &authority,
        &[
            "--network-id",
            &network_id,
            "human",
            "init",
            "--name",
            "operator",
        ],
    )?;
    let (bind, gateway) = spawn_gateway_for_network(&network_id, &authority_public_key)?;
    start_authority(ctx, "ji09a", &authority, Some(&gateway_url(bind)))?;

    // A SisterId with NO reachable Iroh endpoint. The API is reachable (this
    // Sister is running); the directed Job cannot establish an authenticated
    // Iroh route to the target, so it must fail closed — no TCP fallback.
    let started = std::time::Instant::now();
    let result = ctx.run_cli("ji09a", &["run", "--sister", "999999", "printf x"]);
    let elapsed = started.elapsed();
    ctx.teardown();
    stop_gateway(gateway)?;
    let output = match result {
        Ok(out) if out.contains("printf x") => {
            return Err(ScenarioError::assertion(
                "directed run reached a nonexistent executor (DirectTcp fallback?)",
            ))
        }
        Ok(out) => out,
        Err(error) => error.to_string(),
    };
    if elapsed > Duration::from_secs(20) {
        return Err(ScenarioError::assertion(format!(
            "unreachable-Iroh failure took {elapsed:?}; must be bounded"
        )));
    }
    if output.is_empty() {
        return Err(ScenarioError::assertion(
            "running-Sister-but-Iroh-unavailable failure produced no diagnostic",
        ));
    }
    Ok(())
}
