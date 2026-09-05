use super::*;
use crate::scenario::helpers::{
    append_test_revocation, introspect_addr_of, stream_probe_result, unix_now, wait_cli,
};
pub fn security_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "S01_missing_human_authorization_is_rejected",
            run: Box::new(s01_missing_human_authorization_is_rejected),
        },
        ScenarioDef {
            name: "S02_revocation_domains_do_not_collide",
            run: Box::new(s02_revocation_domains_do_not_collide),
        },
        ScenarioDef {
            name: "S03_revoked_human_authorization_is_rejected",
            run: Box::new(s03_revoked_human_authorization_is_rejected),
        },
    ]
}

fn s01_missing_human_authorization_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister_secure("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister_secure("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a learns b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;

    let source = ctx.layout.root.join("security-no-human-source");
    let destination = ctx.layout.root.join("security-no-human-destination");
    std::fs::write(&source, b"must be denied")
        .map_err(|error| ScenarioError::infra(format!("write security source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let destination_arg = format!("#{b_id}:{}", destination.display());
    let output = wait_cli(
        ctx,
        "a",
        &["cp", &source_arg, &destination_arg],
        "unauthorized copy",
    )?;
    if output.status.success() {
        return Err(ScenarioError::assertion(
            "copy without Human Authorization unexpectedly succeeded",
        ));
    }
    assert::assert_eq(
        destination.exists(),
        false,
        "unauthorized copy leaves no file",
    )?;
    Ok(())
}

fn s02_revocation_domains_do_not_collide(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_iroh_pair_secure()?;
    let endpoint = ctx
        .run_cli("a", &["endpoint", "--json"])?
        .parse::<serde_json::Value>()
        .map_err(|error| ScenarioError::assertion(format!("decode Iroh endpoint: {error}")))?
        .get("endpoint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ScenarioError::assertion("Iroh endpoint export has no endpoint"))?
        .to_string();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let (authority, authority_key) = ctx.ensure_iroh_authority();

    let valid = stream_probe_result(ctx, "b", &endpoint, "valid Iroh probe")?;
    assert::assert_eq(valid.status.success(), true, "valid Iroh session")?;

    append_test_revocation(
        ctx,
        "a",
        RevocationRecord::issue(
            &authority,
            &authority_key,
            MembershipKind::Human,
            b_id,
            unix_now(),
            "human serial collision probe".into(),
        ),
    )?;
    let sister_survives_human_revoke =
        stream_probe_result(ctx, "b", &endpoint, "Sister after Human revoke")?;
    assert::assert_eq(
        sister_survives_human_revoke.status.success(),
        true,
        "Human revoke does not revoke Sister serial",
    )?;

    append_test_revocation(
        ctx,
        "a",
        RevocationRecord::issue(
            &authority,
            &authority_key,
            MembershipKind::Sister,
            b_id,
            unix_now(),
            "Sister revoked".into(),
        ),
    )?;
    let revoked = stream_probe_result(ctx, "b", &endpoint, "revoked Sister probe")?;
    assert::assert_eq(revoked.status.success(), false, "revoked Sister session")?;
    Ok(())
}

fn s03_revoked_human_authorization_is_rejected(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister_secure("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister_secure("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a learns b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;

    ctx.run_cli("a", &["network", "init"])?;
    let a_config = PathBuf::from(
        ctx.entries
            .get("a")
            .ok_or_else(|| ScenarioError::infra("no a entry"))?
            .config_dir
            .clone(),
    );
    let b_config = PathBuf::from(
        ctx.entries
            .get("b")
            .ok_or_else(|| ScenarioError::infra("no b entry"))?
            .config_dir
            .clone(),
    );
    for file in ["network.json", "network-authority-key"] {
        std::fs::copy(a_config.join(file), b_config.join(file))
            .map_err(|error| ScenarioError::infra(format!("copy {file}: {error}")))?;
    }
    ctx.run_cli("a", &["human", "init", "--name", "security-owner"])?;

    let source = ctx.layout.root.join("security-human-source");
    let first_destination = ctx.layout.root.join("security-human-ok");
    let revoked_destination = ctx.layout.root.join("security-human-revoked");
    std::fs::write(&source, b"authorized before revoke")
        .map_err(|error| ScenarioError::infra(format!("write human source: {error}")))?;
    let source_arg = source.to_string_lossy().to_string();
    let first_destination_arg = format!("#{b_id}:{}", first_destination.display());
    let first = ctx.run_cli("a", &["cp", &source_arg, &first_destination_arg])?;
    assert::assert_contains(&first, "Copied", "authorized copy")?;

    ctx.run_cli(
        "b",
        &[
            "network",
            "revoke",
            "--membership-kind",
            "human",
            "--membership-serial",
            "1",
        ],
    )?;
    let revoked_destination_arg = format!("#{b_id}:{}", revoked_destination.display());
    let second = wait_cli(
        ctx,
        "a",
        &["cp", &source_arg, &revoked_destination_arg],
        "revoked human copy",
    )?;
    if second.status.success() {
        return Err(ScenarioError::assertion(
            "copy with revoked Human membership unexpectedly succeeded",
        ));
    }
    assert::assert_eq(
        revoked_destination.exists(),
        false,
        "revoked Human copy leaves no file",
    )?;
    Ok(())
}
