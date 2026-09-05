use super::*;
use crate::scenario::helpers::{http_get, start_relay, stop_relay};
pub fn relay_scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "R01_relay_only_starts_without_sister",
            run: Box::new(r01_relay_only_starts_without_sister),
        },
        ScenarioDef {
            name: "R02_iroh_relay_health_endpoint",
            run: Box::new(r02_iroh_relay_health_endpoint),
        },
        ScenarioDef {
            name: "R03_iroh_relay_accepts_multiple_clients",
            run: Box::new(r03_iroh_relay_accepts_multiple_clients),
        },
        ScenarioDef {
            name: "R04_iroh_relay_handles_unknown_paths",
            run: Box::new(r04_iroh_relay_handles_unknown_paths),
        },
        ScenarioDef {
            name: "R05_sister_relay_keeps_sister_functional",
            run: Box::new(r05_sister_relay_keeps_sister_functional),
        },
        ScenarioDef {
            name: "R06_stopping_relay_preserves_sister",
            run: Box::new(r06_stopping_relay_preserves_sister),
        },
        ScenarioDef {
            name: "R07_stopping_sister_relay_process_is_clean",
            run: Box::new(r07_stopping_sister_relay_process_is_clean),
        },
    ]
}

fn r01_relay_only_starts_without_sister(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    if !ctx.sisters.is_empty() {
        return Err(ScenarioError::assertion("relay-only created a Sister"));
    }
    stop_relay(relay)
}

fn r02_iroh_relay_health_endpoint(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let result = http_get(bind, "/healthz").and_then(|response| {
        if response.starts_with("HTTP/1.1 200") {
            Ok(())
        } else {
            Err(ScenarioError::assertion(
                "Iroh relay health endpoint was not healthy",
            ))
        }
    });
    stop_relay(relay)?;
    result
}

fn r03_iroh_relay_accepts_multiple_clients(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let first = http_get(bind, "/healthz")?;
    let second = http_get(bind, "/healthz")?;
    stop_relay(relay)?;
    if !first.starts_with("HTTP/1.1 200") || !second.starts_with("HTTP/1.1 200") {
        return Err(ScenarioError::assertion(
            "Iroh relay did not serve multiple clients",
        ));
    }
    Ok(())
}

fn r04_iroh_relay_handles_unknown_paths(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, bind)?;
    let response = http_get(bind, "/not-found")?;
    stop_relay(relay)?;
    if !response.starts_with("HTTP/1.1 404") {
        return Err(ScenarioError::assertion(
            "Iroh relay did not return 404 for an unknown path",
        ));
    }
    Ok(())
}

fn r05_sister_relay_keeps_sister_functional(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    ctx.start_sister_with_relay("s1", "alpha", &[], bind)?;
    if ctx.introspect("s1")?.identity.id.as_u64() == 0 {
        return Err(ScenarioError::assertion(
            "integrated Sister is not functional",
        ));
    }
    if std::net::TcpStream::connect(bind).is_err() {
        return Err(ScenarioError::assertion(
            "integrated relay is not listening",
        ));
    }
    Ok(())
}

fn r06_stopping_relay_preserves_sister(ctx: &mut Context) -> Result<(), ScenarioError> {
    let relay_bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    let relay = start_relay(ctx, relay_bind)?;
    ctx.start_sister("s1", "alpha", &[])?;
    stop_relay(relay)?;
    let _ = ctx.introspect("s1")?;
    Ok(())
}

fn r07_stopping_sister_relay_process_is_clean(ctx: &mut Context) -> Result<(), ScenarioError> {
    let bind = format!(
        "127.0.0.1:{}",
        alloc_port().map_err(|error| ScenarioError::infra(error.to_string()))?
    )
    .parse()
    .unwrap();
    ctx.start_sister_with_relay("s1", "alpha", &[], bind)?;
    ctx.stop_sister("s1")?;
    if std::net::TcpStream::connect_timeout(&bind, Duration::from_millis(100)).is_ok() {
        return Err(ScenarioError::assertion(
            "relay remained listening after Sister+Relay shutdown",
        ));
    }
    Ok(())
}
