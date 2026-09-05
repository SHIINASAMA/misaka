use super::*;
use crate::scenario::helpers::http_get;
fn gateway_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Spawn a native reference Gateway serving the Context's shared authority.
fn spawn_gateway(ctx: &mut Context) -> Result<(SocketAddr, CliProcess), ScenarioError> {
    let (authority, _authority_key) = ctx.ensure_iroh_authority();
    let port = alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?;
    let bind: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let config_dir = ctx.layout.root.join(format!("gateway-{port}"));
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| ScenarioError::infra(format!("create gateway config: {error}")))?;
    let bind_arg = bind.to_string();
    let network_arg = authority.network_id.to_string();
    let key_arg = authority.authority_public_key.to_string();
    let process = ctx.spawn_cli_with_config(
        &config_dir,
        &[
            "network",
            "gateway",
            "serve",
            "--bind",
            &bind_arg,
            "--network-id",
            &network_arg,
            "--authority-public-key",
            &key_arg,
        ],
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if http_get(bind, "/.well-known/misaka")
            .is_ok_and(|response| response.starts_with("HTTP/1.1 200"))
        {
            return Ok((bind, process));
        }
        std::thread::sleep(Duration::from_millis(20));
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

fn gateway_url(bind: SocketAddr) -> String {
    format!("http://{bind}")
}

/// POST a raw body to the Gateway and return (status, response-text).
fn gateway_post(bind: SocketAddr, path: &str, body: &[u8]) -> Result<(u16, String), ScenarioError> {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("http://{bind}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .send()
        .map_err(|error| ScenarioError::assertion(format!("gateway post: {error}")))?;
    let status = response.status().as_u16();
    let text = response.text().unwrap_or_default();
    Ok((status, text))
}

/// Build a well-formed signed announce request for a fresh Sister, using the
/// shared authority. `tamper` lets a scenario break one field to test rejection.
fn build_announce(
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
    sister_id: u64,
    nonce: [u8; 16],
    expires_in: Option<i64>,
    bad_record_identity: bool,
    bad_record_signature: bool,
) -> Vec<u8> {
    use misaka_core::{
        GatewayAnnounceRequest, GatewayAuth, IrohEndpointId, PeerRecord, TransportBinding,
    };
    let now = gateway_now_secs();
    let key = SisterKeyPair::generate();
    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        key.public_key(),
        sister_id,
        now.saturating_sub(10),
        expires_in.map(|e| (now as i64 + e).max(0) as u64),
        sister_id,
    );
    let record_sister_id = if bad_record_identity {
        sister_id + 1
    } else {
        sister_id
    };
    let signing_key = if bad_record_identity {
        SisterKeyPair::generate()
    } else {
        key.clone()
    };
    let binding = TransportBinding::sign(
        authority.network_id,
        record_sister_id,
        IrohEndpointId::from_bytes([7u8; 32]),
        1,
        &signing_key,
    );
    let mut record = PeerRecord::issue(
        authority.network_id,
        record_sister_id,
        "iroh://peer".to_string(),
        binding,
        now,
        &signing_key,
    );
    if bad_record_signature {
        record.sister_signature = misaka_core::SisterSignature::from_bytes([0u8; 64]);
    }
    let auth = GatewayAuth::sign_announce(
        authority.network_id,
        sister_id,
        now,
        nonce,
        &membership,
        &record,
        &key,
    );
    let request = GatewayAnnounceRequest {
        auth,
        membership,
        record,
    };
    serde_json::to_vec(&request).unwrap()
}

fn build_peers(
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
    sister_id: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    use misaka_core::{GatewayAuth, GatewayPeersRequest};
    let now = gateway_now_secs();
    let key = SisterKeyPair::generate();
    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        key.public_key(),
        sister_id,
        now.saturating_sub(10),
        Some(now.saturating_add(3600)),
        sister_id,
    );
    let auth = GatewayAuth::sign_peers(authority.network_id, sister_id, now, nonce, &key);
    let request = GatewayPeersRequest { auth, membership };
    serde_json::to_vec(&request).unwrap()
}

/// G01: a valid member announce is accepted, and a peers query returns it.
fn g01_valid_announce_accepted(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [1u8; 16],
        Some(3600),
        false,
        false,
    );
    let announce = gateway_post(bind, "/v1/announce", &body);
    let peers = gateway_post(
        bind,
        "/v1/peers",
        &build_peers(&authority, &authority_key, 10001, [9u8; 16]),
    );
    stop_gateway(process)?;
    let (status, _) = announce?;
    if status != 204 {
        return Err(ScenarioError::assertion(format!(
            "valid announce got {status}, want 204"
        )));
    }
    let (peers_status, text) = peers?;
    if peers_status != 200 || !text.contains("\"sister_id\":10001") {
        return Err(ScenarioError::assertion(format!(
            "peers query after valid announce got {peers_status}: {text}"
        )));
    }
    Ok(())
}

/// G02: a record whose identity does not match the presenting membership is rejected.
fn g02_forged_record_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [2u8; 16],
        Some(3600),
        true,
        false,
    );
    let result = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    let (status, _) = result?;
    if status != 403 {
        return Err(ScenarioError::assertion(format!(
            "forged record got {status}, want 403"
        )));
    }
    Ok(())
}

/// G03: an expired (or otherwise invalid) membership is rejected.
fn g03_invalid_membership_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    // Membership already lapsed (issued 10s ago, expired 5s before now).
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [3u8; 16],
        Some(-5),
        false,
        false,
    );
    let result = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    let (status, _) = result?;
    if status != 401 {
        return Err(ScenarioError::assertion(format!(
            "expired membership got {status}, want 401"
        )));
    }
    Ok(())
}

/// G04: a replayed nonce is rejected on the second use.
fn g04_replay_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    let (authority, authority_key) = ctx.ensure_iroh_authority();
    let body = build_announce(
        &authority,
        &authority_key,
        10001,
        [4u8; 16],
        Some(3600),
        false,
        false,
    );
    let first = gateway_post(bind, "/v1/announce", &body)?;
    let second = gateway_post(bind, "/v1/announce", &body);
    stop_gateway(process)?;
    if first.0 != 204 {
        return Err(ScenarioError::assertion(format!(
            "first announce got {}",
            first.0
        )));
    }
    let (status, _) = second?;
    if status != 401 {
        return Err(ScenarioError::assertion(format!(
            "replayed nonce got {status}, want 401"
        )));
    }
    Ok(())
}

/// G05 (Definition of Done): two Sisters that know only the Gateway domain
/// discover each other and complete the authenticated Iroh control connection.
fn g05_discovery_through_gateway(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)], 1)?;
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process)?;
    outcome
}

/// G07: with two Gateways configured and one taken down, discovery still
/// converges through the surviving Gateway (no cross-Gateway coordination).
fn g07_multi_gateway_failover(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind_a, process_a) = spawn_gateway(ctx)?;
    let (bind_b, process_b) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind_a), gateway_url(bind_b)], 1)?;
    stop_gateway(process_a)?; // drop one Gateway; B must carry discovery
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process_b)?;
    outcome
}

/// G08: after discovery, all Gateways down — the already-formed P2P persists.
fn g08_gateway_down_after_connect(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)], 1)?;
    wait_until_peers(ctx, 30)?; // both connected through the Gateway
    stop_gateway(process)?; // now remove the Gateway entirely
                            // Let a couple of heartbeat cycles pass with no Gateway available.
    std::thread::sleep(Duration::from_secs(3));
    let a = ctx.introspect("a")?;
    let b = ctx.introspect("b")?;
    let still = a.peers.iter().any(|p| p.id == 10002) && b.peers.iter().any(|p| p.id == 10001);
    ctx.teardown();
    if !still {
        return Err(ScenarioError::assertion(
            "network lost its peer after the Gateway went down",
        ));
    }
    Ok(())
}

/// G09: a Sister keeps operating (still serving introspection, peer retained)
/// after the Gateway it discovered through is gone.
fn g09_gateway_removed_continues(ctx: &mut Context) -> Result<(), ScenarioError> {
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)], 1)?;
    wait_until_peers(ctx, 30)?;
    stop_gateway(process)?;
    // The remaining Sister must still answer introspection (not crashed by the
    // Gateway disappearing) and still list the discovered peer.
    let a = ctx.introspect("a")?;
    let retained = a.peers.iter().any(|p| p.id == 10002);
    ctx.teardown();
    if !retained {
        return Err(ScenarioError::assertion(
            "Sister lost its discovered peer after the Gateway was removed",
        ));
    }
    Ok(())
}

/// G10: the normal discovery path never uses a manual `iroh://` bootstrap.
fn g10_no_manual_iroh_bootstrap(ctx: &mut Context) -> Result<(), ScenarioError> {
    // start_iroh_pair_via_gateway passes only --gateway (never --iroh-peer) and
    // seeds no peers. If discovery converges with an empty manual-peer list, the
    // normal path is proven free of any raw `iroh://` contact.
    let (bind, process) = spawn_gateway(ctx)?;
    ctx.start_iroh_pair_via_gateway(&[gateway_url(bind)], 1)?;
    let a_manual = ctx
        .entries
        .get("a")
        .map(|e| !e.peer_addrs.is_empty())
        .unwrap_or(true);
    let outcome = wait_until_peers(ctx, 30);
    ctx.teardown();
    stop_gateway(process)?;
    if a_manual {
        return Err(ScenarioError::assertion(
            "discovery path carried a manual peer_addrs entry",
        ));
    }
    outcome
}

fn wait_until_peers(ctx: &mut Context, timeout_secs: u64) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let a = ctx.introspect("a")?;
        let b = ctx.introspect("b")?;
        if a.peers.iter().any(|p| p.id == 10002) && b.peers.iter().any(|p| p.id == 10001) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::assertion("peers did not converge in time"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn gateway_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "G01",
            run: Box::new(g01_valid_announce_accepted),
        },
        ScenarioDef {
            name: "G02",
            run: Box::new(g02_forged_record_rejected),
        },
        ScenarioDef {
            name: "G03",
            run: Box::new(g03_invalid_membership_rejected),
        },
        ScenarioDef {
            name: "G04",
            run: Box::new(g04_replay_rejected),
        },
        ScenarioDef {
            name: "G05",
            run: Box::new(g05_discovery_through_gateway),
        },
        ScenarioDef {
            name: "G07",
            run: Box::new(g07_multi_gateway_failover),
        },
        ScenarioDef {
            name: "G08",
            run: Box::new(g08_gateway_down_after_connect),
        },
        ScenarioDef {
            name: "G09",
            run: Box::new(g09_gateway_removed_continues),
        },
        ScenarioDef {
            name: "G10",
            run: Box::new(g10_no_manual_iroh_bootstrap),
        },
    ]
}
