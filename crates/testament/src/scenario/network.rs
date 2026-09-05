use super::*;
use crate::scenario::helpers::{
    introspect_addr_of, start_stream_pair, stream_client, wait_for_iroh_candidate,
    wait_for_stream_ready, wait_for_tcp_listener,
};
pub fn network_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "N01_stream_connect",
            run: Box::new(n01_stream_connect),
        },
        ScenarioDef {
            name: "N02_bidirectional_stream",
            run: Box::new(n02_bidirectional_stream),
        },
        ScenarioDef {
            name: "N03_sustained_stream",
            run: Box::new(n03_sustained_stream),
        },
        ScenarioDef {
            name: "N04_large_stream",
            run: Box::new(n04_large_stream),
        },
        ScenarioDef {
            name: "N05_disconnect",
            run: Box::new(n05_disconnect),
        },
        ScenarioDef {
            name: "N06_restart_new_stream",
            run: Box::new(n06_restart_new_stream),
        },
        ScenarioDef {
            name: "N07_secure_lan_stream",
            run: Box::new(n07_secure_lan_stream),
        },
        ScenarioDef {
            name: "N08_transfer_v0",
            run: Box::new(n08_transfer_v0),
        },
        ScenarioDef {
            name: "N09_tunnel_v0",
            run: Box::new(n09_tunnel_v0),
        },
        ScenarioDef {
            name: "N10_transfer_v1_resume",
            run: Box::new(n10_transfer_v1_resume),
        },
        ScenarioDef {
            name: "N11_active_stream_observability",
            run: Box::new(n11_active_stream_observability),
        },
        ScenarioDef {
            name: "N12_iroh_transfer_v1",
            run: Box::new(n12_iroh_transfer_v1),
        },
        ScenarioDef {
            name: "N13_iroh_active_path_observability",
            run: Box::new(n13_iroh_active_path_observability),
        },
        ScenarioDef {
            name: "N14_iroh_restart_new_stream",
            run: Box::new(n14_iroh_restart_new_stream),
        },
        ScenarioDef {
            name: "N15_iroh_json_measurement",
            run: Box::new(n15_iroh_json_measurement),
        },
        ScenarioDef {
            name: "N16_connect_by_sister_id",
            run: Box::new(n16_connect_by_sister_id),
        },
        ScenarioDef {
            name: "N17_iroh_endpoint_bootstrap_without_control_plane",
            run: Box::new(n17_iroh_endpoint_bootstrap_without_control_plane),
        },
        ScenarioDef {
            name: "N18_stream_summary_observability",
            run: Box::new(n18_stream_summary_observability),
        },
        ScenarioDef {
            name: "N19_iroh_parallel_transfer",
            run: Box::new(n19_iroh_parallel_transfer),
        },
        ScenarioDef {
            name: "N20_iroh_object_store",
            run: Box::new(n20_iroh_object_store),
        },
        ScenarioDef {
            name: "N21_iroh_stability_probe",
            run: Box::new(n21_iroh_stability_probe),
        },
    ]
}

/// Black-box Iroh relay checks. These deliberately exercise the public
/// `misaka` binary so Testament remains an external harness rather than an
/// Iroh peer.
fn n01_stream_connect(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "connect")
}

fn n02_bidirectional_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "bidirectional")
}

fn n03_sustained_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "sustained")
}

fn n04_large_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    stream_client(ctx, "a", "b", "large")
}

fn n05_disconnect(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let ready_file = ctx.layout.root.join("n05-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    let status = ctx.kill_sister("b")?;
    if status.success() {
        return Err(ScenarioError::assertion(
            "remote Sister unexpectedly exited successfully after kill",
        ));
    }
    let output = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait disconnect client: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "stream client did not report remote disconnect",
        ));
    }
    Ok(())
}

fn n06_restart_new_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let ready_file = ctx.layout.root.join("n06-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    let status = ctx.kill_sister("b")?;
    if status.success() {
        return Err(ScenarioError::assertion(
            "remote Sister unexpectedly exited successfully after kill",
        ));
    }
    let output = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait old stream client: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "old stream did not fail after remote kill",
        ));
    }
    ctx.restart_sister("b")?;
    stream_client(ctx, "a", "b", "bidirectional")
}

/// N07: a secure stream is established between two real Sister processes.
/// Certificates are provisioned as test fixtures, while both the listener
/// and the client TLS handshake run inside `misaka` processes.
fn n07_secure_lan_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_secure_pair()?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_config = Path::new(
        &ctx.entries
            .get("b")
            .ok_or_else(|| ScenarioError::infra("no secure peer entry"))?
            .config_dir,
    )
    .to_path_buf();
    let a_config = Path::new(
        &ctx.entries
            .get("a")
            .ok_or_else(|| ScenarioError::infra("no secure client entry"))?
            .config_dir,
    )
    .to_path_buf();
    let trusted_certificate = b_config.join("stream-cert.der");
    let trusted_certificate = trusted_certificate.to_string_lossy().to_string();
    let output = ctx
        .spawn_cli_with_config(
            &a_config,
            &[
                "stream-test",
                "--addr",
                &address,
                "--mode",
                "bidirectional",
                "--secure",
                "--trust-cert",
                &trusted_certificate,
                "--server-name",
                "sister-10002",
            ],
        )?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait secure stream client: {error}")))?;
    if !output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "secure stream failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// N08: resolve a peer by SisterId and transfer a file through the stream
/// service, asserting the external result and the receiver's exact bytes.
fn n08_transfer_v0(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b stream candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("transfer-source.bin");
    let destination = ctx.layout.root.join("transfer-destination.bin");
    let payload = b"transfer-v0-integrity-check".repeat(4096);
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write transfer source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Copied", "transfer completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read received file: {error}")))?;
    assert::assert_eq(received, payload, "transferred bytes")?;
    Ok(())
}

/// N10: exercise the external `cp --resume` client against a real Sister.
/// The runtime unit test covers an interrupted first attempt; this scenario
/// proves that the public CLI speaks the same resumable protocol end to end.
fn n10_transfer_v1_resume(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b resumable transfer candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("transfer-v1-source.bin");
    let destination = ctx.layout.root.join("transfer-v1-destination.bin");
    let payload = (0..(64 * 1024 + 1234))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write transfer v1 source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", "--resume", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Resumed copy", "transfer v1 completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read v1 received file: {error}")))?;
    assert::assert_eq(received, payload, "resumable transferred bytes")?;
    if PathBuf::from(format!("{}.misaka-part", destination.display())).exists()
        || PathBuf::from(format!("{}.misaka-part.json", destination.display())).exists()
    {
        return Err(ScenarioError::assertion(
            "transfer v1 left durable partial state after completion",
        ));
    }
    Ok(())
}

/// N09: a real `misaka tunnel` process forwards bytes to a plain TCP fixture
/// reachable from the remote Sister's network namespace.
fn n09_tunnel_v0(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b tunnel candidate",
        Duration::from_secs(8),
        |s| s.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let fixture = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| ScenarioError::infra(format!("bind tunnel fixture: {error}")))?;
    let fixture_addr = fixture
        .local_addr()
        .map_err(|error| ScenarioError::infra(format!("read tunnel fixture address: {error}")))?;
    let fixture_thread = std::thread::spawn(move || loop {
        let Ok((mut stream, _)) = fixture.accept() else {
            return;
        };
        let mut buffer = [0u8; 4096];
        let read = {
            use std::io::Read;
            stream.read(&mut buffer)
        };
        let Ok(read) = read else {
            continue;
        };
        if read == 0 {
            continue;
        }
        use std::io::Write;
        if stream.write_all(&buffer[..read]).is_err() {
            return;
        }
        return;
    });

    let local_port = alloc_port()
        .map_err(|error| ScenarioError::infra(format!("alloc tunnel local port: {error}")))?;
    let remote_arg = fixture_addr.to_string();
    let local_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let mut tunnel = ctx.spawn_cli(
        "a",
        &[
            "tunnel",
            &b_id.to_string(),
            "--local",
            &local_port.to_string(),
            "--remote",
            &remote_arg,
        ],
    )?;
    wait_for_tcp_listener(local_addr, Duration::from_secs(8))?;

    let mut client = std::net::TcpStream::connect_timeout(&local_addr, Duration::from_secs(2))
        .map_err(|error| ScenarioError::assertion(format!("connect local tunnel: {error}")))?;
    use std::io::{Read, Write};
    let payload = b"tunnel-v0-ok";
    client
        .write_all(payload)
        .map_err(|error| ScenarioError::assertion(format!("write local tunnel: {error}")))?;
    let mut echoed = vec![0u8; payload.len()];
    client
        .read_exact(&mut echoed)
        .map_err(|error| ScenarioError::assertion(format!("read local tunnel: {error}")))?;
    assert::assert_eq(echoed, payload.to_vec(), "tunnel echoed bytes")?;
    drop(client);
    let _ = tunnel.wait_timeout_mut(Duration::from_millis(100));
    let _ = fixture_thread.join();
    Ok(())
}

/// N11: introspection reports the selected path and live counters while a
/// logical stream is still open, then removes it after the client exits.
fn n11_active_stream_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let ready_file = ctx.layout.root.join("n11-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    assert::eventually(
        b_introspect,
        "b reports an active stream",
        Duration::from_secs(8),
        |snapshot| !snapshot.active_streams.is_empty(),
    )?;
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch active stream snapshot: {error}")))?;
    let active = snapshot
        .active_streams
        .first()
        .ok_or_else(|| ScenarioError::assertion("active stream disappeared unexpectedly"))?;
    assert::assert_eq(
        active.backend.clone(),
        "direct-tcp".to_string(),
        "active stream backend",
    )?;
    assert::assert_eq(
        active.route.clone(),
        "direct".to_string(),
        "active stream route",
    )?;
    if active.tx_bytes < 5 || active.rx_bytes == 0 || active.remote_endpoint.is_none() {
        return Err(ScenarioError::assertion(format!(
            "active stream telemetry incomplete: {active:?}"
        )));
    }
    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode misaka ps JSON: {error}")))?;
    let ps_active = ps
        .get("active_streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| streams.first())
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report active stream"))?;
    assert::assert_eq(
        ps_active.get("backend").and_then(serde_json::Value::as_str),
        Some("direct-tcp"),
        "misaka ps active backend",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait observability client: {error}")))?;
    assert::eventually(
        b_introspect,
        "b removes the closed active stream",
        Duration::from_secs(8),
        |snapshot| snapshot.active_streams.is_empty(),
    )?;
    Ok(())
}

/// N18: expose aggregate live stream count and byte counters through the
/// public introspection and `misaka ps` JSON surfaces.
fn n18_stream_summary_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    start_stream_pair(ctx)?;
    let address = ctx.stream_addr("b")?.to_string();
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let ready_file = ctx.layout.root.join("n18-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--addr",
            &address,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(8))?;
    assert::eventually(
        b_introspect,
        "b reports an active stream summary",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.stream_summary.streams == snapshot.active_streams.len()
                && snapshot.stream_summary.streams > 0
                && snapshot.stream_summary.tx_bytes > 0
                && snapshot.stream_summary.rx_bytes > 0
        },
    )?;
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch stream summary: {error}")))?;
    assert::assert_eq(
        snapshot.stream_summary.streams,
        snapshot.active_streams.len(),
        "summary active stream count",
    )?;
    if snapshot.stream_summary.tx_bytes == 0 || snapshot.stream_summary.rx_bytes == 0 {
        return Err(ScenarioError::assertion(format!(
            "stream summary counters incomplete: {:?}",
            snapshot.stream_summary
        )));
    }

    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode summary ps JSON: {error}")))?;
    let summary = ps
        .get("stream_summary")
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report stream summary"))?;
    assert::assert_eq(
        summary.get("streams").and_then(serde_json::Value::as_u64),
        Some(snapshot.stream_summary.streams as u64),
        "misaka ps summary stream count",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| ScenarioError::infra(format!("wait summary client: {error}")))?;
    assert::eventually(
        b_introspect,
        "b clears the closed stream summary",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.stream_summary.streams == 0
                && snapshot.stream_summary.tx_bytes == 0
                && snapshot.stream_summary.rx_bytes == 0
        },
    )?;
    Ok(())
}

/// N19: resume a v2 transfer from a durable completed-chunk bitmap and finish
/// it through several real Iroh-backed worker streams.
fn n19_iroh_parallel_transfer(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate for parallel transfer",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-parallel-source.bin");
    let destination = ctx.layout.root.join("iroh-parallel-destination.bin");
    let payload = (0..(8 * 64 * 1024 + 1234))
        .map(|index| ((index * 13) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write parallel source: {error}")))?;

    let chunk_size = 64 * 1024u64;
    let chunk_count = (payload.len() as u64).div_ceil(chunk_size);
    let mut partial = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(format!("{}.misaka-part-v2", destination.display()))
        .map_err(|error| ScenarioError::infra(format!("create parallel partial: {error}")))?;
    partial
        .set_len(payload.len() as u64)
        .map_err(|error| ScenarioError::infra(format!("size parallel partial: {error}")))?;
    use std::io::{Seek, SeekFrom, Write};
    partial
        .seek(SeekFrom::Start(0))
        .and_then(|_| partial.write_all(&payload[..chunk_size as usize]))
        .map_err(|error| ScenarioError::infra(format!("seed parallel chunk: {error}")))?;
    drop(partial);
    let mut completed = vec![0u8; chunk_count.div_ceil(8) as usize];
    completed[0] = 1;
    let state = serde_json::json!({
        "size": payload.len() as u64,
        "digest": misaka_core::protocol::transfer_content_digest(&payload),
        "chunk_size": chunk_size,
        "chunk_count": chunk_count,
        "completed": completed,
    });
    std::fs::write(
        format!("{}.misaka-part-v2.json", destination.display()),
        serde_json::to_vec(&state)
            .map_err(|error| ScenarioError::infra(format!("encode parallel state: {error}")))?,
    )
    .map_err(|error| ScenarioError::infra(format!("write parallel state: {error}")))?;

    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli(
        "a",
        &[
            "cp",
            "--resume",
            "--parallel",
            "4",
            &source_arg,
            &destination_arg,
        ],
    )?;
    assert::assert_contains(
        &output,
        "Parallel copy",
        "parallel transfer completion output",
    )?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read parallel destination: {error}")))?;
    assert::assert_eq(received, payload, "parallel Iroh transfer bytes")?;
    if PathBuf::from(format!("{}.misaka-part-v2", destination.display())).exists()
        || PathBuf::from(format!("{}.misaka-part-v2.json", destination.display())).exists()
    {
        return Err(ScenarioError::assertion(
            "parallel transfer left durable partial state after completion",
        ));
    }
    Ok(())
}

/// N20: repeated identical parallel transfers reuse one digest-named object
/// on the receiving Sister and only materialize a new destination path.
fn n20_iroh_object_store(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate for object store",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-object-source.bin");
    let first_destination = ctx.layout.root.join("iroh-object-first.bin");
    let second_destination = ctx.layout.root.join("iroh-object-second.bin");
    let payload = (0..(2 * 64 * 1024 + 1234))
        .map(|index| ((index * 17) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write object source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();

    for (destination, label) in [
        (&first_destination, "first"),
        (&second_destination, "second"),
    ] {
        let destination_arg = format!("#{b_id}:{}", destination.display());
        let output = ctx.run_cli(
            "a",
            &[
                "cp",
                "--resume",
                "--parallel",
                "4",
                &source_arg,
                &destination_arg,
            ],
        )?;
        assert::assert_contains(
            &output,
            "Parallel copy",
            &format!("{label} object copy output"),
        )?;
        let received = std::fs::read(destination).map_err(|error| {
            ScenarioError::assertion(format!("read {label} object destination: {error}"))
        })?;
        assert::assert_eq(received, payload.clone(), &format!("{label} object bytes"))?;
    }

    let digest = misaka_core::protocol::transfer_content_digest(&payload);
    let digest_name = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let b_config = ctx
        .entries
        .get("b")
        .ok_or_else(|| ScenarioError::infra("no object-store Sister entry"))?;
    let object = Path::new(&b_config.config_dir)
        .join("objects")
        .join(digest_name);
    if !object.is_file() {
        return Err(ScenarioError::assertion(format!(
            "canonical object is missing: {}",
            object.display()
        )));
    }
    let object_size = std::fs::metadata(&object)
        .map_err(|error| ScenarioError::assertion(format!("stat canonical object: {error}")))?
        .len();
    assert::assert_eq(object_size, payload.len() as u64, "canonical object size")?;
    for destination in [&first_destination, &second_destination] {
        if PathBuf::from(format!("{}.misaka-part-v2", destination.display())).exists()
            || PathBuf::from(format!("{}.misaka-part-v2.json", destination.display())).exists()
        {
            return Err(ScenarioError::assertion(
                "object-store transfer left durable partial state",
            ));
        }
    }
    Ok(())
}

/// N21: exercise a bounded bidirectional heartbeat window through the public
/// Iroh stream probe and validate its machine-readable stability record.
fn n21_iroh_stability_probe(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "stability",
            "--duration-secs",
            "2",
            "--json",
        ],
    )?;
    let report: serde_json::Value = serde_json::from_str(output.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode stability report: {error}")))?;
    assert::assert_eq(
        report.get("mode").and_then(serde_json::Value::as_str),
        Some("stability"),
        "Iroh stability report mode",
    )?;
    assert::assert_eq(
        report.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "Iroh stability report backend",
    )?;
    assert::assert_eq(
        report.get("route").and_then(serde_json::Value::as_str),
        Some("direct"),
        "Iroh stability report route",
    )?;
    if report
        .get("exchanges")
        .and_then(serde_json::Value::as_u64)
        .is_none_or(|exchanges| exchanges < 2)
        || report
            .get("elapsed_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|elapsed| elapsed < 1_000)
        || report
            .get("path_switches")
            .and_then(serde_json::Value::as_u64)
            .is_none()
    {
        return Err(ScenarioError::assertion(format!(
            "Iroh stability report missing bounded measurements: {report}"
        )));
    }
    Ok(())
}

/// N12: run Transfer v1 over the opt-in Iroh backend using real Sister
/// processes and transport identities persisted in each isolated config dir.
fn n12_iroh_transfer_v1(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;

    let source = ctx.layout.root.join("iroh-transfer-source.bin");
    let destination = ctx.layout.root.join("iroh-transfer-destination.bin");
    let payload = (0..(64 * 1024 + 1234))
        .map(|index| ((index * 7) % 251) as u8)
        .collect::<Vec<_>>();
    std::fs::write(&source, &payload)
        .map_err(|error| ScenarioError::infra(format!("write Iroh source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = ctx.run_cli("a", &["cp", "--resume", &source_arg, &destination_arg])?;
    assert::assert_contains(&output, "Resumed copy", "Iroh transfer completion output")?;
    let received = std::fs::read(&destination)
        .map_err(|error| ScenarioError::assertion(format!("read Iroh destination: {error}")))?;
    assert::assert_eq(received, payload, "Iroh transfer bytes")?;
    Ok(())
}

/// N13: verify Iroh path metadata through real Sister processes while the
/// logical stream is still open, including the public ps view and cleanup.
fn n13_iroh_active_path_observability(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::eventually(
        a_introspect,
        "a learns b Iroh stream candidate",
        Duration::from_secs(12),
        |snapshot| {
            snapshot.peers.iter().any(|peer| {
                peer.id == b_id
                    && peer
                        .stream_endpoints
                        .iter()
                        .any(|endpoint| endpoint.starts_with("iroh://"))
            })
        },
    )?;
    let snapshot = observer::fetch(a_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch Iroh candidate: {error}")))?;
    let endpoint = snapshot
        .peers
        .iter()
        .find(|peer| peer.id == b_id)
        .and_then(|peer| {
            peer.stream_endpoints
                .iter()
                .find(|endpoint| endpoint.starts_with("iroh://"))
        })
        .cloned()
        .ok_or_else(|| ScenarioError::assertion("Iroh candidate disappeared unexpectedly"))?;

    let ready_file = ctx.layout.root.join("n13-iroh-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut client, &ready_file, Duration::from_secs(12))?;
    if let Err(error) = assert::eventually(
        b_introspect,
        "b reports an active Iroh stream",
        Duration::from_secs(8),
        |snapshot| {
            snapshot.active_streams.iter().any(|stream| {
                stream.backend == "iroh" && stream.route != "unknown" && stream.rtt_ms.is_some()
            })
        },
    ) {
        client.terminate();
        let output = client
            .wait_timeout(Duration::from_secs(2))
            .map_err(|wait_error| {
                ScenarioError::infra(format!("collect Iroh observability client: {wait_error}"))
            })?;
        return Err(ScenarioError::assertion(format!(
            "{error}; client stdout: {}; client stderr: {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let snapshot = observer::fetch(b_introspect, Duration::from_millis(500))
        .map_err(|error| ScenarioError::infra(format!("fetch active Iroh stream: {error}")))?;
    let active = snapshot
        .active_streams
        .iter()
        .find(|stream| stream.backend == "iroh")
        .ok_or_else(|| ScenarioError::assertion("active Iroh stream disappeared unexpectedly"))?;
    if !matches!(active.route.as_str(), "direct" | "relay" | "custom") {
        return Err(ScenarioError::assertion(format!(
            "active Iroh route is not a recognized transport path: {active:?}"
        )));
    }
    if active.local_endpoint.is_none()
        || !active
            .remote_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.starts_with("iroh://"))
        || active.rtt_ms.is_none()
        || active.rx_bytes == 0
    {
        return Err(ScenarioError::assertion(format!(
            "active Iroh path telemetry incomplete: {active:?}"
        )));
    }

    let introspect_arg = b_introspect.to_string();
    let ps_output = ctx.run_cli("b", &["ps", "--json", "--introspect", &introspect_arg])?;
    let ps: serde_json::Value = serde_json::from_str(&ps_output)
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh ps JSON: {error}")))?;
    let ps_active = ps
        .get("active_streams")
        .and_then(serde_json::Value::as_array)
        .and_then(|streams| {
            streams.iter().find(|stream| {
                stream.get("backend").and_then(serde_json::Value::as_str) == Some("iroh")
            })
        })
        .ok_or_else(|| ScenarioError::assertion("misaka ps did not report active Iroh stream"))?;
    assert::assert_eq(
        ps_active.get("route").and_then(serde_json::Value::as_str),
        Some(active.route.as_str()),
        "misaka ps active Iroh route",
    )?;
    assert::assert_eq(
        ps_active
            .get("path_switches")
            .and_then(serde_json::Value::as_u64),
        Some(active.path_switches),
        "misaka ps Iroh path switch count",
    )?;

    client.terminate();
    let _ = client
        .wait_timeout(Duration::from_secs(8))
        .map_err(|error| {
            ScenarioError::infra(format!("wait Iroh observability client: {error}"))
        })?;
    assert::eventually(
        b_introspect,
        "b removes the closed active Iroh stream",
        Duration::from_secs(8),
        |snapshot| snapshot.active_streams.is_empty(),
    )?;
    Ok(())
}

/// N14: after an Iroh Sister dies, its persisted transport identity and
/// explicit candidate are reused for a fresh stream after restart.
fn n14_iroh_restart_new_stream(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let ready_file = ctx.layout.root.join("n14-iroh-stream-ready");
    let ready_file_arg = ready_file.to_string_lossy().to_string();
    let mut old_client = ctx.spawn_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "hold",
            "--ready-file",
            &ready_file_arg,
        ],
    )?;
    wait_for_stream_ready(&mut old_client, &ready_file, Duration::from_secs(12))?;
    let status = ctx.terminate_sister("b")?;
    if !status.success() {
        return Err(ScenarioError::assertion(
            "Iroh Sister did not terminate cleanly",
        ));
    }
    let output = old_client
        .wait_timeout(Duration::from_secs(10))
        .map_err(|error| ScenarioError::infra(format!("wait old Iroh stream: {error}")))?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "old Iroh stream did not fail after remote kill",
        ));
    }

    ctx.restart_sister("b")?;
    let b2_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::assert_eq(b2_id, b_id, "Iroh Sister identity across restart")?;
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let new_output = ctx
        .spawn_cli(
            "a",
            &[
                "stream-test",
                "--endpoint",
                &endpoint,
                "--mode",
                "bidirectional",
            ],
        )?
        .wait_timeout(Duration::from_secs(20))
        .map_err(|error| ScenarioError::infra(format!("wait new Iroh stream: {error}")))?;
    if !new_output.status.success() {
        return Err(ScenarioError::assertion(format!(
            "new Iroh stream failed: {}",
            String::from_utf8_lossy(&new_output.stderr).trim()
        )));
    }
    Ok(())
}

/// N15: verify the public Iroh stream probe emits one parseable measurement
/// record when run against two real, isolated Sister processes.
fn n15_iroh_json_measurement(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let endpoint = wait_for_iroh_candidate(a_introspect, b_id)?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            &endpoint,
            "--mode",
            "bidirectional",
            "--json",
        ],
    )?;
    let report: serde_json::Value = serde_json::from_str(output.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh stream report: {error}")))?;
    assert::assert_eq(
        report.get("mode").and_then(serde_json::Value::as_str),
        Some("bidirectional"),
        "Iroh stream report mode",
    )?;
    assert::assert_eq(
        report.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "Iroh stream report backend",
    )?;
    assert::assert_eq(
        report.get("route").and_then(serde_json::Value::as_str),
        Some("direct"),
        "Iroh stream report route",
    )?;
    if report
        .get("setup_ms")
        .and_then(serde_json::Value::as_u64)
        .is_none()
        || report
            .get("rtt_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || report
            .get("path_switches")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || report
            .get("probe_rtt_ms")
            .and_then(serde_json::Value::as_u64)
            .is_none()
        || !report
            .get("remote_endpoint")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|endpoint| endpoint.starts_with("iroh://"))
    {
        return Err(ScenarioError::assertion(format!(
            "Iroh JSON stream report missing measurements: {report}"
        )));
    }
    Ok(())
}

/// N16: verify the public `connect` command resolves a Sister ID from the
/// local PeerStore and establishes an Iroh-backed stream.
fn n16_connect_by_sister_id(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair()?;
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let _ = wait_for_iroh_candidate(a_introspect, b_id)?;
    let sister_arg = format!("#{b_id}");
    let output = ctx.run_cli("a", &["connect", &sister_arg])?;
    assert::assert_contains(
        &output,
        &format!("Connected to Sister #{b_id}"),
        "connect target",
    )?;
    assert::assert_contains(&output, "backend=iroh", "connect backend")?;
    assert::assert_contains(&output, "route=direct", "connect route")?;
    Ok(())
}

/// N17: export the live Iroh endpoint and connect without control-plane
/// bootstrap, mDNS, or a persisted remote peer entry.
fn n17_iroh_endpoint_bootstrap_without_control_plane(
    ctx: &mut Context,
) -> Result<(), ScenarioError> {
    ctx.start_iroh_probe_only("b")?;
    ctx.start_iroh_probe_only("a")?;
    let b_snapshot = ctx.introspect("b")?;
    assert::assert_eq(
        b_snapshot.peers.len(),
        0,
        "endpoint-only Sister has no control-plane peers",
    )?;
    let record = ctx.run_cli("b", &["endpoint", "--json"])?;
    let record: serde_json::Value = serde_json::from_str(record.trim())
        .map_err(|error| ScenarioError::assertion(format!("decode endpoint record: {error}")))?;
    assert::assert_eq(
        record.get("network_id").and_then(serde_json::Value::as_str),
        Some("00000000-0000-0000-0000-000000000001"),
        "endpoint network id",
    )?;
    assert::assert_eq(
        record.get("backend").and_then(serde_json::Value::as_str),
        Some("iroh"),
        "endpoint backend",
    )?;
    let endpoint = record
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScenarioError::assertion("endpoint record has no endpoint"))?;
    let output = ctx.run_cli(
        "a",
        &[
            "stream-test",
            "--endpoint",
            endpoint,
            "--mode",
            "bidirectional",
            "--json",
        ],
    )?;
    assert::assert_contains(&output, "\"backend\":\"iroh\"", "endpoint-only probe")?;
    Ok(())
}
