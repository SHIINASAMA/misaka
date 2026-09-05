use super::*;
pub(crate) fn start_relay(ctx: &Context, bind: SocketAddr) -> Result<CliProcess, ScenarioError> {
    let config_dir = ctx.layout.root.join("relay-only-config");
    std::fs::create_dir_all(&config_dir)
        .map_err(|error| ScenarioError::infra(format!("create relay config: {error}")))?;
    let bind_arg = bind.to_string();
    let process = ctx.spawn_cli_with_config(&config_dir, &["relay", "--bind", &bind_arg])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if http_get(bind, "/healthz").is_ok_and(|response| response.starts_with("HTTP/1.1 200")) {
            return Ok(process);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(ScenarioError::infra(format!(
        "relay did not listen on {bind}"
    )))
}

pub(crate) fn wait_cli(
    ctx: &Context,
    alias: &str,
    args: &[&str],
    label: &str,
) -> Result<std::process::Output, ScenarioError> {
    ctx.spawn_cli(alias, args)?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait {label}: {error}")))
}

pub(crate) fn stream_probe_result(
    ctx: &Context,
    client: &str,
    endpoint: &str,
    label: &str,
) -> Result<std::process::Output, ScenarioError> {
    wait_cli(
        ctx,
        client,
        &["stream-test", "--endpoint", endpoint, "--mode", "connect"],
        label,
    )
}

pub(crate) fn append_test_revocation(
    ctx: &Context,
    alias: &str,
    record: RevocationRecord,
) -> Result<(), ScenarioError> {
    let config_dir = ctx
        .entries
        .get(alias)
        .ok_or_else(|| ScenarioError::infra(format!("no {alias} entry")))?
        .config_dir
        .clone();
    let path = Path::new(&config_dir).join("revocations.json");
    let mut records: Vec<RevocationRecord> = if path.exists() {
        serde_json::from_str(
            &std::fs::read_to_string(&path)
                .map_err(|error| ScenarioError::infra(format!("read revocations: {error}")))?,
        )
        .map_err(|error| ScenarioError::infra(format!("decode revocations: {error}")))?
    } else {
        Vec::new()
    };
    records.push(record);
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&records)
            .map_err(|error| ScenarioError::infra(format!("encode revocations: {error}")))?,
    )
    .map_err(|error| ScenarioError::infra(format!("write revocations: {error}")))
}

pub(crate) fn stop_relay(mut process: CliProcess) -> Result<(), ScenarioError> {
    process.terminate();
    let output = process
        .wait_timeout(Duration::from_secs(5))
        .map_err(|error| ScenarioError::infra(format!("stop relay: {error}")))?;
    if output.status.success() || output.status.code().is_none() {
        return Ok(());
    }
    Ok(())
}

pub(crate) fn http_get(bind: SocketAddr, path: &str) -> Result<String, ScenarioError> {
    let mut stream = std::net::TcpStream::connect_timeout(&bind, Duration::from_secs(2))
        .map_err(|error| ScenarioError::assertion(format!("connect Iroh relay: {error}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| ScenarioError::assertion(format!("set relay read timeout: {error}")))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| ScenarioError::assertion(format!("write relay request: {error}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| ScenarioError::assertion(format!("read relay response: {error}")))?;
    Ok(response)
}

pub(crate) fn allocate_ports() -> Result<(u16, u16, u16), ScenarioError> {
    Ok((
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc listen port: {e}")))?,
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc stream port: {e}")))?,
        alloc_port().map_err(|e| ScenarioError::infra(format!("alloc introspection port: {e}")))?,
    ))
}

pub(crate) fn provision_tls_identity(
    config_dir: &str,
    id: u64,
    nickname: &str,
    listen_port: u16,
) -> Result<PathBuf, ScenarioError> {
    let directory = Path::new(config_dir);
    std::fs::create_dir_all(directory)
        .map_err(|e| ScenarioError::infra(format!("create TLS config directory: {e}")))?;
    let generated = rcgen::generate_simple_self_signed(vec![format!("sister-{id}")])
        .map_err(|e| ScenarioError::infra(format!("generate TLS identity: {e}")))?;
    let certificate_path = directory.join("stream-cert.der");
    let key_path = directory.join("stream-key.der");
    std::fs::write(&certificate_path, generated.cert.der())
        .map_err(|e| ScenarioError::infra(format!("write TLS certificate: {e}")))?;
    std::fs::write(&key_path, generated.key_pair.serialize_der())
        .map_err(|e| ScenarioError::infra(format!("write TLS private key: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ScenarioError::infra(format!("protect TLS private key: {e}")))?;
    }
    let identity = SisterIdentity::new(
        id,
        nickname.to_string(),
        "testament-secure-host".to_string(),
        "testament".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        listen_port,
    );
    let identity_path = directory.join("identity.json");
    let json = serde_json::to_vec_pretty(&identity)
        .map_err(|e| ScenarioError::infra(format!("serialize identity: {e}")))?;
    std::fs::write(identity_path, json)
        .map_err(|e| ScenarioError::infra(format!("write identity: {e}")))?;
    Ok(certificate_path)
}

pub(crate) fn provision_iroh_membership(
    config_dir: &str,
    id: u64,
    nickname: &str,
    listen_port: u16,
    authority: &NetworkAuthority,
    authority_key: &misaka_core::AuthorityKeyPair,
) -> Result<(), ScenarioError> {
    let directory = Path::new(config_dir);
    std::fs::create_dir_all(directory)
        .map_err(|e| ScenarioError::infra(format!("create Iroh config directory: {e}")))?;
    let sister_key = SisterKeyPair::generate();
    std::fs::write(directory.join("sister-identity-key"), sister_key.to_bytes())
        .map_err(|e| ScenarioError::infra(format!("write Sister identity key: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory.join("sister-identity-key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|e| ScenarioError::infra(format!("protect Sister identity key: {e}")))?;
    }

    let identity = SisterIdentity::new(
        id,
        nickname.to_string(),
        "testament-iroh-host".to_string(),
        "testament".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        listen_port,
    );
    std::fs::write(
        directory.join("identity.json"),
        serde_json::to_vec_pretty(&identity)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh identity: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh identity: {e}")))?;
    std::fs::write(
        directory.join("network.json"),
        serde_json::to_vec_pretty(authority)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh authority: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh authority: {e}")))?;

    let membership = MembershipCertificate::issue(
        authority,
        authority_key,
        sister_key.public_key(),
        id,
        unix_now(),
        None,
        id,
    );
    std::fs::write(
        directory.join("membership.bin"),
        bincode::serialize(&membership)
            .map_err(|e| ScenarioError::infra(format!("serialize Iroh membership: {e}")))?,
    )
    .map_err(|e| ScenarioError::infra(format!("write Iroh membership: {e}")))?;
    Ok(())
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn introspect_addr_of(ctx: &Context, alias: &str) -> Result<SocketAddr, ScenarioError> {
    ctx.entries
        .get(alias)
        .and_then(|entry| entry.introspection_addr.as_ref())
        .ok_or_else(|| ScenarioError::infra(format!("no introspection for {alias}")))?
        .parse()
        .map_err(|e| ScenarioError::infra(format!("parse {alias} introspection address: {e}")))
}

// ---------- T06–T12 ----------

/// T06: 自动调度 —— 网络模式下，A 把任务派给空闲 peer B 执行并拿回结果。
/// 调度器政策在单元层覆盖；E2E 只验证自动网络执行成功。
pub(crate) fn stream_client(
    ctx: &Context,
    client: &str,
    server: &str,
    mode: &str,
) -> Result<(), ScenarioError> {
    let address = ctx.stream_addr(server)?.to_string();
    let output = ctx
        .spawn_cli(client, &["stream-test", "--addr", &address, "--mode", mode])?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("stream test {mode}: {error}")))?;
    if !output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "stream test {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

pub(crate) fn wait_for_stream_ready(
    client: &mut CliProcess,
    ready_file: &Path,
    timeout: Duration,
) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if ready_file.exists() {
            return Ok(());
        }
        if !client
            .is_running()
            .map_err(|error| ScenarioError::infra(format!("check stream client: {error}")))?
        {
            let output = client
                .wait_timeout_mut(Duration::from_secs(1))
                .map_err(|error| ScenarioError::infra(format!("collect stream client: {error}")))?;
            return Err(ScenarioError::assertion(format!(
                "stream client exited before reporting readiness: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::infra(format!(
                "stream client did not become ready: {}",
                ready_file.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn start_stream_pair(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    Ok(())
}

pub(crate) fn wait_for_iroh_candidate(
    introspect: SocketAddr,
    sister_id: u64,
) -> Result<String, ScenarioError> {
    assert::eventually(
        introspect,
        "Sister advertises an Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == sister_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;
    let snapshot = observer::fetch(introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch Iroh candidate: {error}")))?;
    snapshot
        .peers
        .iter()
        .find(|peer| peer.id == sister_id)
        .and_then(|peer| {
            peer.stream_endpoints
                .iter()
                .find(|endpoint| endpoint.starts_with("iroh://"))
        })
        .cloned()
        .ok_or_else(|| ScenarioError::assertion("Iroh candidate disappeared unexpectedly"))
}

pub(crate) fn wait_for_tcp_listener(
    addr: SocketAddr,
    timeout: Duration,
) -> Result<(), ScenarioError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(ScenarioError::infra(format!(
                "TCP listener {} did not become ready",
                addr
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ===========================================================================
// Gateway scenarios (G01–G10): exercise the Gateway v0 discovery contract and
// the runtime loop end-to-end against a spawned native reference Gateway.
// ===========================================================================
