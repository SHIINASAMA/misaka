//! Opt-in LIVE smoke against a real, public Cloudflare (or any) Gateway.
//!
//! The ONLY Testament path that touches a live external Gateway, and only when
//! the operator explicitly runs `gateway-live-verify`. It exercises a single
//! real chain: two isolated test Sisters that know only the Gateway URL, with no
//! `--peer` / `--iroh-peer`, discovering each other and forming the authenticated
//! Iroh connection.
//!
//! Request budget (hard constraint): we reuse `start_iroh_pair_via_gateway` but
//! with `gateway_interval = 3600`, so the runtime's immediate first tick is the
//! only Gateway cycle per Sister. `GET /.well-known` + `POST /v1/announce` +
//! `POST /v1/peers` ≈ 3 requests each → **≈6 Gateway requests** on the happy
//! path. We never poll the Gateway, retry-loop it, or re-trigger cycles.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::run_manager::create_run;
use crate::scenario::context::Context;
use crate::types::{live_test_network_id, Report, ScenarioError};
use misaka_core::{AuthorityKeyPair, NetworkAuthority};

/// Ids assigned by `start_iroh_pair_via_gateway` (a = 10001, b = 10002).
const ID_A: u64 = 10001;
const ID_B: u64 = 10002;

/// Run the live smoke. See module docs. Returns a process exit code.
///
/// * `gateway_url` — the real public Gateway URL.
/// * `authority_key_file` — LOCAL operator Authority trust store (a directory
///   laid out like `NetworkAuthorityStore`, or a key file next to its `.bin`).
///   Read only to mint the two ephemeral test memberships; never sent anywhere.
pub fn run_gateway_live(
    gateway_url: &str,
    authority_key_file: &Path,
    timeout_secs: u64,
    json: bool,
) -> i32 {
    let run_id = format!("live-{}", std::process::id());
    let (report, code) = match run_live(&run_id, gateway_url, authority_key_file) {
        Ok(mut ctx) => {
            let outcome = wait_for_convergence(&mut ctx, gateway_url, timeout_secs);
            ctx.teardown();
            match outcome {
                Ok(()) => {
                    let r = ctx.report("gateway-live", Ok(()));
                    if !json {
                        println!("LIVE SMOKE: PASS");
                    }
                    (r, 0)
                }
                Err(err) => {
                    let r = ctx.report("gateway-live", Err(err));
                    let message = r.assertion.clone().unwrap_or_default();
                    if !json {
                        println!("LIVE SMOKE: FAIL — {message}");
                    }
                    (r, 1)
                }
            }
        }
        Err(err) => {
            let msg = err.to_string();
            if !json {
                println!("LIVE SMOKE: SETUP FAIL — {msg}");
            }
            (setup_report(&run_id, &msg), 1)
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    }
    code
}

fn run_live(
    run_id: &str,
    gateway_url: &str,
    authority_key_file: &Path,
) -> Result<Context, ScenarioError> {
    let gateway_url = gateway_url.trim_end_matches('/').to_string();
    if gateway_url.contains("iroh://") {
        return Err(ScenarioError::infra(format!(
            "--gateway must be an http(s) Gateway URL, not an iroh:// locator: {gateway_url}"
        )));
    }
    if !gateway_url.starts_with("https://") {
        eprintln!("note: live gateway URL is not https:// — a real deployment should be https");
    }

    let (authority, authority_key) = load_operator_authority(authority_key_file)?;

    // Fail fast on an unreachable Gateway: ONE TCP connect, not an HTTP request.
    gateway_reachable(&http_authority(&gateway_url)?, Duration::from_secs(10))?;

    let (id, layout) =
        create_run().map_err(|e| ScenarioError::infra(format!("create live run: {e}")))?;
    let mut ctx = Context::new(format!("{run_id}-{id}"), layout);
    // Seed the authority so membership issuance matches the real Gateway's
    // Network + authority, instead of minting an unrelated random one.
    ctx.set_gateway(authority, authority_key);
    // Reuse the tested gateway-pair helper (manual discovery, single
    // --stream-backend iroh, one --gateway, no --iroh-peer / --peer) with a
    // huge interval so only the initial cycle reaches the Gateway.
    ctx.start_iroh_pair_via_gateway(&[gateway_url], 3600)?;
    Ok(ctx)
}

fn wait_for_convergence(
    ctx: &mut Context,
    gateway_url: &str,
    timeout_secs: u64,
) -> Result<(), ScenarioError> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let log = |alias: &str| ctx.layout.sisters_dir.join(alias).join("stderr.log");
    loop {
        let a_ids: Vec<u64> = ctx.introspect("a")?.peers.iter().map(|p| p.id).collect();
        let b_ids: Vec<u64> = ctx.introspect("b")?.peers.iter().map(|p| p.id).collect();
        if a_ids.contains(&ID_B) && b_ids.contains(&ID_A) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ScenarioError::assertion(format!(
                "live Gateway discovery did not converge in {timeout_secs}s: \
                 gateway={gateway_url} network={} a({ID_A}) sees={a_ids:?} \
                 b({ID_B}) sees={b_ids:?} logs=[{}, {}]",
                live_test_network_id(),
                log("a").display(),
                log("b").display(),
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Read the operator's local Authority trust store (never printed / committed).
fn load_operator_authority(
    path: &Path,
) -> Result<(NetworkAuthority, AuthorityKeyPair), ScenarioError> {
    let (bytes, key) = if path.is_dir() {
        (
            std::fs::read(path.join("network-authority.bin")),
            std::fs::read(path.join("network-authority-key")),
        )
    } else {
        (
            std::fs::read(path.with_extension("bin")),
            std::fs::read(path),
        )
    };
    let authority_bytes =
        bytes.map_err(|e| ScenarioError::infra(format!("read authority descriptor: {e}")))?;
    let key_bytes = key.map_err(|e| ScenarioError::infra(format!("read authority key: {e}")))?;
    let authority: NetworkAuthority = bincode::deserialize(&authority_bytes)
        .map_err(|e| ScenarioError::infra(format!("authority descriptor: {e}")))?;
    let arr: [u8; 32] = <[u8; 32]>::try_from(key_bytes.as_slice())
        .map_err(|_| ScenarioError::infra("authority key must be 32 bytes"))?;
    let authority_key = AuthorityKeyPair::from_bytes(arr);
    if authority.network_id != live_test_network_id()
        || authority_key.public_key() != authority.authority_public_key
    {
        return Err(ScenarioError::infra(format!(
            "operator authority does not match the live test Network \
             (expected network id {expected}); refusing to touch the real Gateway",
            expected = live_test_network_id()
        )));
    }
    Ok((authority, authority_key))
}

/// One blocking TCP connect to the Gateway host:port (not a Gateway HTTP call).
fn gateway_reachable(host_port: &str, timeout: Duration) -> Result<(), ScenarioError> {
    let addrs: Vec<SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(host_port)
        .map_err(|e| ScenarioError::infra(format!("resolve gateway {host_port}: {e}")))?
        .collect();
    for addr in &addrs {
        if TcpStream::connect_timeout(addr, timeout).is_ok() {
            return Ok(());
        }
    }
    Err(ScenarioError::infra(format!(
        "gateway {host_port} unreachable (TCP)"
    )))
}

fn http_authority(url: &str) -> Result<String, ScenarioError> {
    let (rest, port) = url
        .strip_prefix("https://")
        .map(|r| (r, 443u16))
        .or_else(|| url.strip_prefix("http://").map(|r| (r, 80u16)))
        .ok_or_else(|| ScenarioError::infra(format!("gateway url must be http(s): {url}")))?;
    let host = rest
        .split('/')
        .next()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ScenarioError::infra(format!("gateway url has no host: {url}")))?;
    Ok(match host.split_once(':') {
        Some((h, p)) => format!("{h}:{p}"),
        None => format!("{host}:{port}"),
    })
}

fn setup_report(run_id: &str, message: &str) -> Report {
    Report {
        scenario: "gateway-live".to_string(),
        result: "infra_failed".to_string(),
        failed_step: None,
        assertion: Some(message.to_string()),
        expected: None,
        actual: None,
        run_id: run_id.to_string(),
        artifacts: crate::types::Artifacts {
            manifest: String::new(),
            events: String::new(),
            sister_logs: Vec::new(),
        },
    }
}
