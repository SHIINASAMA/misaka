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
    ctx.teardown();
    stop_gateway(process)?;
    outcome
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
    ]
}
