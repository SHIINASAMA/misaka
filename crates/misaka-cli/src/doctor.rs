//! `misaka doctor` — bounded, non-destructive deployment diagnostics.
//!
//! Default checks are strictly local and make no external network activity,
//! consistent with Misaka's loopback-only default posture. Only
//! `misaka doctor --network` performs bounded opt-in reachability checks
//! against configured infrastructure, and it never runs a smoke workload
//! (no transfer, Job, SSH, Tunnel, or Gateway mutation).

use serde::Serialize;
use std::path::Path;

use crate::MisakaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Error,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    fn new(checks: Vec<Check>) -> Self {
        let healthy = !checks.iter().any(|check| check.status == Status::Error);
        Self { healthy, checks }
    }
}

struct Doctor {
    checks: Vec<Check>,
}

impl Doctor {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }

    fn push(&mut self, name: &str, status: Status, message: impl Into<String>) {
        self.checks.push(Check {
            name: name.to_string(),
            status,
            message: message.into(),
        });
    }

    fn ok(&mut self, name: &str, message: impl Into<String>) {
        self.push(name, Status::Ok, message);
    }
    fn warn(&mut self, name: &str, message: impl Into<String>) {
        self.push(name, Status::Warn, message);
    }
    fn error(&mut self, name: &str, message: impl Into<String>) {
        self.push(name, Status::Error, message);
    }
    fn skip(&mut self, name: &str, message: impl Into<String>) {
        self.push(name, Status::Skip, message);
    }
}

/// Whether a file's permission bits are no broader than `max_mode` (Unix only;
/// always true elsewhere).
pub fn permissions_are_tight(path: &Path, max_mode: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777 == max_mode,
            Err(_) => true,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, max_mode);
        true
    }
}

/// Gateway discovery without a transport path is a common deployment mistake:
/// Gateway is *discovery*, Iroh direct/relay is *connectivity*. Returns a warning
/// when a Network has Gateways configured but the service posture is
/// loopback-only (no `--advertise-host`, no relay).
pub fn connectivity_gap_warning(
    gateways_configured: bool,
    advertise_host: Option<&str>,
    iroh_relay: Option<&str>,
) -> Option<String> {
    if gateways_configured && advertise_host.is_none() && iroh_relay.is_none() {
        Some(
            "Gateway discovery is configured, but this Sister has no non-local transport \
             path. Configure --advertise-host or --iroh-relay for multi-host use."
                .to_string(),
        )
    } else {
        None
    }
}

pub async fn run(json: bool, network: bool) -> Result<(), MisakaError> {
    let dir = crate::IdentityStore::config_dir()
        .map_err(|error| MisakaError::Other(error.to_string()))?;
    let mut doctor = Doctor::new();
    let mut start_posture_advertise = None;
    let mut start_posture_relay = None;

    // config directory
    if dir.is_dir() {
        doctor.ok("config-dir", dir.display().to_string());
    } else {
        doctor.warn(
            "config-dir",
            format!(
                "{} does not exist yet (run 'misaka network init' / 'misaka start')",
                dir.display()
            ),
        );
    }

    // state layout
    match misaka_runtime::state_layout::StateLayout::load(&dir) {
        Ok(Some(manifest)) => {
            if manifest.layout_version > misaka_runtime::state_layout::CURRENT_STATE_LAYOUT_VERSION
            {
                doctor.error(
                    "state-layout",
                    format!(
                        "layout v{} is newer than this binary supports (max v{})",
                        manifest.layout_version,
                        misaka_runtime::state_layout::CURRENT_STATE_LAYOUT_VERSION
                    ),
                );
            } else {
                doctor.ok("state-layout", format!("v{}", manifest.layout_version));
            }
        }
        Ok(None) => doctor.warn(
            "state-layout",
            "no state-layout.json yet; it is created/adopted on next start",
        ),
        Err(error) => doctor.error("state-layout", error.to_string()),
    }

    // local control token
    match misaka_runtime::local_control_token_store::LocalControlTokenStore::load(&dir) {
        Ok(Some(_)) => {
            if permissions_are_tight(
                &misaka_runtime::local_control_token_store::LocalControlTokenStore::path(&dir),
                0o600,
            ) {
                doctor.ok("local-control-token", "present (0600)");
            } else {
                doctor.warn(
                    "local-control-token",
                    "present but permissions are broader than 0600",
                );
            }
        }
        Ok(None) => doctor.warn(
            "local-control-token",
            "missing; it is created when a Sister starts",
        ),
        Err(error) => doctor.error("local-control-token", error.to_string()),
    }

    // Sister identity + key
    let identity = match misaka_runtime::identity_store::IdentityStore::load() {
        Ok(Some(identity)) => {
            doctor.ok(
                "sister-identity",
                format!("{} v{}", identity.display_name(), identity.version),
            );
            Some(identity)
        }
        Ok(None) => {
            doctor.skip("sister-identity", "not initialized");
            None
        }
        Err(error) => {
            doctor.error("sister-identity", error.to_string());
            None
        }
    };
    let sister_key = match misaka_runtime::sister_key_store::SisterKeyStore::load(&dir) {
        Ok(Some(key)) => {
            doctor.ok("sister-key", "valid 32-byte key");
            Some(key)
        }
        Ok(None) => {
            doctor.warn("sister-key", "missing");
            None
        }
        Err(error) => {
            doctor.error("sister-key", format!("{error} (never auto-replaced)"));
            None
        }
    };
    match misaka_runtime::iroh_identity_store::IrohIdentityStore::load(&dir) {
        Ok(_) => doctor.ok("iroh-key", "present"),
        Err(error) => doctor.error("iroh-key", error.to_string()),
    }

    // NetworkId
    match misaka_runtime::network_id_store::NetworkIdStore::load(&dir) {
        Ok(Some(network_id)) => doctor.ok("network-id", network_id.to_string()),
        Ok(None) => doctor.skip("network-id", "not initialized"),
        Err(error) => doctor.error("network-id", error.to_string()),
    }

    // authority descriptor + owner-key consistency
    let authority = match misaka_runtime::network_authority_store::NetworkAuthorityStore::load(&dir)
    {
        Ok(Some(authority)) => {
            doctor.ok("network-authority", "descriptor present");
            match misaka_runtime::network_authority_store::NetworkAuthorityStore::load_with_key(
                &dir,
            ) {
                Ok(Some((descriptor, key))) => {
                    if descriptor.authority_public_key == key.public_key() {
                        doctor.ok("authority-owner-key", "descriptor matches private key");
                    } else {
                        doctor.error(
                            "authority-owner-key",
                            "authority private key does not match the descriptor",
                        );
                    }
                }
                Ok(None) => {} // ordinary Sister: no authority key, expected
                Err(error) => doctor.error("authority-owner-key", error.to_string()),
            }
            Some(authority)
        }
        Ok(None) => {
            doctor.skip("network-authority", "not initialized");
            None
        }
        Err(error) => {
            doctor.error("network-authority", error.to_string());
            None
        }
    };

    // membership
    if let Some(authority) = &authority {
        match misaka_runtime::membership_store::MembershipStore::load(&dir) {
            Ok(Some(membership)) => {
                let now = crate::unix_now();
                let mut problems = Vec::new();
                if !membership.verify(authority) {
                    problems.push("signature invalid");
                }
                if !membership.is_valid_at(now) {
                    problems.push("expired or not yet valid");
                }
                if let (Some(identity), Some(key)) = (&identity, &sister_key) {
                    if membership.sister_id != identity.id {
                        problems.push("SisterId does not match local identity");
                    }
                    if membership.sister_public_key != key.public_key() {
                        problems.push("public key does not match local Sister key");
                    }
                }
                match misaka_runtime::revocation_store::RevocationStore::is_revoked(
                    &dir,
                    authority,
                    authority.network_id,
                    misaka_core::MembershipKind::Sister,
                    membership.serial,
                ) {
                    Ok(true) => problems.push("locally revoked"),
                    Ok(false) => {}
                    Err(error) => doctor.warn("membership", format!("revocation store: {error}")),
                }
                if problems.is_empty() {
                    doctor.ok(
                        "membership",
                        format!("valid (serial {})", membership.serial),
                    );
                } else {
                    doctor.error("membership", problems.join("; "));
                }
                if let Some(expires_at) = membership.expires_at {
                    let remaining = expires_at.saturating_sub(now);
                    if remaining < 7 * 24 * 3600 {
                        doctor.warn("membership-expiry", format!("expires in {}s", remaining));
                    }
                }
            }
            Ok(None) => doctor.skip("membership", "not enrolled"),
            Err(error) => doctor.error("membership", error.to_string()),
        }
    }

    // transport binding
    match misaka_runtime::transport_binding_store::TransportBindingStore::load(&dir) {
        Ok(Some(binding)) => {
            if binding.verify() {
                doctor.ok("transport-binding", "valid");
            } else {
                doctor.error("transport-binding", "signature invalid");
            }
        }
        Ok(None) => doctor.skip("transport-binding", "absent"),
        Err(error) => doctor.error("transport-binding", error.to_string()),
    }

    // human identity completeness
    let human = misaka_runtime::human_identity_store::HumanIdentityStore::load(&dir);
    let human_key = misaka_runtime::human_identity_store::HumanIdentityStore::load_key(&dir);
    let human_membership =
        misaka_runtime::human_identity_store::HumanIdentityStore::load_membership(&dir);
    match (human, human_key, human_membership) {
        (Ok(Some(identity)), Ok(Some(_)), Ok(Some(membership))) => {
            if let Some(authority) = &authority {
                if membership.verify(authority, crate::unix_now()) {
                    doctor.ok(
                        "human-identity",
                        format!("{} complete", identity.display_name),
                    );
                } else {
                    doctor.error("human-identity", "human membership is invalid or expired");
                }
            } else {
                doctor.warn(
                    "human-identity",
                    "present but no Network authority to verify",
                );
            }
        }
        (Ok(None), Ok(None), Ok(None)) => doctor.skip("human-identity", "not initialized"),
        (human, key, membership) => {
            // Partial human material is a deployment hazard.
            if human.is_err() || key.is_err() || membership.is_err() {
                doctor.error("human-identity", "human identity material is unreadable");
            } else {
                doctor.warn(
                    "human-identity",
                    "incomplete human identity material (need identity + key + membership)",
                );
            }
        }
    }

    // runtime marker
    let instance = misaka_runtime::runtime_instance_store::RuntimeInstanceStore::load(&dir);
    match instance {
        Ok(Some(instance)) => {
            let pid_alive = pid_is_alive(instance.pid);
            if pid_alive {
                doctor.ok(
                    "runtime",
                    format!("pid {} at {}", instance.pid, instance.api_endpoint),
                );
            } else {
                doctor.warn(
                    "runtime",
                    format!("stale runtime.json (pid {} is not running)", instance.pid),
                );
            }
            if instance.binary_version != crate::binary_version() {
                doctor.warn(
                    "runtime-version",
                    format!(
                        "running daemon reports {} but this binary is {}",
                        instance.binary_version,
                        crate::binary_version()
                    ),
                );
            }
        }
        Ok(None) => doctor.skip("runtime", "no running-Sister marker"),
        Err(error) => doctor.warn("runtime", format!("malformed runtime.json: {error}")),
    }

    // local daemon API reachability + authentication
    if let Ok(Some(instance)) =
        misaka_runtime::runtime_instance_store::RuntimeInstanceStore::load(&dir)
    {
        if let Ok(addr) = instance.api_endpoint.parse::<std::net::SocketAddr>() {
            match crate::probe_local_control(addr, &dir).await {
                Ok(200) => doctor.ok("local-control", "authenticated API responds"),
                Ok(401) => doctor.error(
                    "local-control",
                    "API rejected the local control token (authentication failure)",
                ),
                Ok(other) => doctor.warn("local-control", format!("API returned HTTP {other}")),
                Err(error) => doctor.warn("local-control", format!("API unreachable: {error}")),
            }
        }
    } else {
        doctor.skip("local-control", "no running Sister to probe");
    }

    // service + gateway posture
    match crate::service::ServiceConfigStore::load(&dir) {
        Ok(Some(service_config)) => {
            start_posture_advertise = service_config.start.advertise_host.clone();
            start_posture_relay = service_config.start.iroh_relay.clone();
            let manager = crate::service::ServiceManager::detect().ok();
            let installed = service_config.installed.is_some();
            if installed {
                doctor.ok("service", format!("installed as '{}'", service_config.name));
                if let Some(binary) = &service_config.installed {
                    if !Path::new(&binary.path).exists() {
                        doctor.warn(
                            "service-binary",
                            format!("configured executable no longer exists: {}", binary.path),
                        );
                    }
                }
                if let Some(manager) = manager {
                    if let Ok(path) = manager.definition_path(&service_config.name) {
                        if !path.exists() {
                            doctor.warn("service-definition", "definition file is missing");
                        }
                    }
                }
            } else {
                doctor.skip("service", "not installed as a service");
            }
        }
        Ok(None) => doctor.skip("service", "no service.json"),
        Err(error) => doctor.error("service", error.to_string()),
    }

    let gateways = misaka_runtime::gateway_store::GatewayStore::load(&dir);
    if !gateways.is_empty() {
        doctor.ok("gateways", format!("{} configured", gateways.len()));
        if let Some(warning) = connectivity_gap_warning(
            true,
            start_posture_advertise.as_deref(),
            start_posture_relay.as_deref(),
        ) {
            doctor.warn("gateway-connectivity", warning);
        }
    } else {
        doctor.skip("gateways", "none configured");
    }

    if network {
        network_checks(&mut doctor, &gateways, start_posture_relay.as_deref()).await;
    }

    let report = DoctorReport::new(doctor.checks);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| MisakaError::Other(error.to_string()))?
        );
    } else {
        for check in &report.checks {
            let tag = match check.status {
                Status::Ok => "OK   ",
                Status::Warn => "WARN ",
                Status::Error => "ERROR",
                Status::Skip => "SKIP ",
            };
            println!("{tag} {}: {}", check.name, check.message);
        }
        println!();
        if report.healthy {
            println!("no problems found");
        } else {
            println!("problems found");
        }
    }
    if report.healthy {
        Ok(())
    } else {
        Err(MisakaError::Other("doctor found problems".to_string()))
    }
}

fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Bounded, opt-in reachability checks. Only these contact configured
/// infrastructure; each is capped, and none performs a smoke workload.
async fn network_checks(doctor: &mut Doctor, gateways: &[String], relay: Option<&str>) {
    if gateways.is_empty() {
        doctor.skip("network:gateways", "no Gateways configured");
    }
    for gateway in gateways {
        let host_port = host_port_of(gateway);
        match host_port {
            Some((host, port)) => match tcp_reachable(&host, port).await {
                true => doctor.ok("network:gateway", format!("reachable: {gateway}")),
                false => doctor.warn("network:gateway", format!("unreachable: {gateway}")),
            },
            None => doctor.skip("network:gateway", format!("unsupported URL: {gateway}")),
        }
    }
    if let Some(relay) = relay {
        match host_port_of(relay) {
            Some((host, port)) => match tcp_reachable(&host, port).await {
                true => doctor.ok("network:relay", format!("reachable: {relay}")),
                false => doctor.warn("network:relay", format!("unreachable: {relay}")),
            },
            None => doctor.skip("network:relay", format!("unsupported URL: {relay}")),
        }
    }
}

/// Extract `host:port` from an `http(s)://` URL (default port 443).
pub fn host_port_of(url: &str) -> Option<(String, u16)> {
    let rest = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = rest.split(['/', '?']).next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), port.parse::<u16>().ok()?)
        }
        _ => (authority.to_string(), 443),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

async fn tcp_reachable(host: &str, port: u16) -> bool {
    let target = format!("{host}:{port}");
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(target),
    )
    .await
    .map(|result| result.is_ok())
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        connectivity_gap_warning, host_port_of, permissions_are_tight, DoctorReport, Status,
    };

    #[test]
    fn gateway_without_connectivity_is_warned() {
        assert!(connectivity_gap_warning(true, None, None).is_some());
        assert!(connectivity_gap_warning(false, None, None).is_none());
        assert!(connectivity_gap_warning(true, Some("192.168.1.2"), None).is_none());
        assert!(connectivity_gap_warning(true, None, Some("https://r")).is_none());
    }

    #[test]
    fn host_port_parsing_handles_schemes_and_default_ports() {
        assert_eq!(
            host_port_of("https://gateway.example.com"),
            Some(("gateway.example.com".into(), 443))
        );
        assert_eq!(
            host_port_of("https://gateway.example.com:8443/v1"),
            Some(("gateway.example.com".into(), 8443))
        );
        assert_eq!(host_port_of("not a url"), None);
    }

    #[test]
    fn permissions_check_rejects_broad_files() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = std::env::temp_dir().join(format!("misaka-perm-{}", uuid::Uuid::new_v4()));
            std::fs::write(&path, b"x").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(permissions_are_tight(&path, 0o600));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(!permissions_are_tight(&path, 0o600));
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn healthy_is_false_only_with_errors() {
        let report = DoctorReport::new(vec![
            super::Check {
                name: "a".into(),
                status: Status::Ok,
                message: String::new(),
            },
            super::Check {
                name: "b".into(),
                status: Status::Warn,
                message: String::new(),
            },
        ]);
        assert!(report.healthy);
        let report = DoctorReport::new(vec![super::Check {
            name: "c".into(),
            status: Status::Error,
            message: String::new(),
        }]);
        assert!(!report.healthy);
    }
}
