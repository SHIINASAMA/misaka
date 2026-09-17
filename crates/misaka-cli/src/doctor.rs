//! `misaka doctor` — bounded, non-destructive deployment diagnostics.
//!
//! Default checks are strictly local and make no external network activity,
//! consistent with Misaka's loopback-only default posture. Only
//! `misaka doctor --infra` performs bounded opt-in infrastructure checks
//! against configured infrastructure, and it never runs a smoke workload
//! (no transfer, Job, SSH, Tunnel, or Gateway mutation).

use serde::Serialize;
use std::path::Path;
use std::time::Duration;

use crate::MisakaError;
use misaka_core::gateway::{GatewayInfo, GATEWAY_PROTOCOL_VERSION};

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

pub async fn run(json: bool, infra: bool) -> Result<(), MisakaError> {
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

    // permissions: the config dir must not be group/other-writable, and the
    // identity/secret files must be owner-only.
    let mut broad = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&dir) {
            if metadata.permissions().mode() & 0o022 != 0 {
                broad.push("config directory is group/other-writable".to_string());
            }
        }
    }
    for secret in [
        "sister-identity-key",
        "iroh-stream-key.bin",
        "network-authority-key",
        "human-identity-key",
    ] {
        let path = dir.join(secret);
        if path.exists() && !permissions_are_tight(&path, 0o600) {
            broad.push(format!("{secret} is not 0600"));
        }
    }
    if broad.is_empty() {
        doctor.ok("permissions", "config dir and secrets are owner-only");
    } else {
        doctor.warn("permissions", broad.join("; "));
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
            // Authority owner only: the membership-serial allocator must be
            // readable (an unreadable allocator blocks new member issuance).
            if dir.join("network-authority-key").exists() {
                match misaka_runtime::membership_serial_store::MembershipSerialStore::open(&dir) {
                    Ok(_) => doctor.ok("membership-serial-store", "allocator readable"),
                    Err(error) => doctor.warn("membership-serial-store", error.to_string()),
                }
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
                    // Service-manager process state, cross-checked against the
                    // runtime marker so a crashed/stale daemon is visible.
                    let state = crate::service::manager_state(&service_config.name);
                    let marker_present =
                        misaka_runtime::runtime_instance_store::RuntimeInstanceStore::load(&dir)
                            .ok()
                            .flatten()
                            .is_some();
                    match state.as_deref() {
                        Some("running") if marker_present => {
                            doctor.ok("service-state", "service manager reports running")
                        }
                        Some("running") => doctor.warn(
                            "service-state",
                            "service manager reports running but there is no runtime marker",
                        ),
                        Some("stopped" | "inactive" | "failed") if marker_present => doctor.warn(
                            "service-state",
                            "a daemon marker exists but the service manager reports it stopped",
                        ),
                        Some(other) => {
                            doctor.warn("service-state", format!("service manager reports {other}"))
                        }
                        None => doctor.skip("service-state", "service manager unavailable"),
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

    if infra {
        // Only `--infra` may contact configured external infrastructure.
        for check in infra_checks(
            &gateways,
            authority.as_ref(),
            start_posture_relay.as_deref(),
        )
        .await
        {
            doctor.checks.push(check);
        }
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
/// One infrastructure probe result.
pub struct InfraProbe {
    pub status: Status,
    pub message: String,
}

fn infra_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .map_err(|error| error.to_string())
}

/// Describe a request failure precisely enough to be actionable, without an
/// elaborate taxonomy: timeout vs. connect/refused vs. TLS vs. other.
fn describe_request_error(error: &reqwest::Error) -> String {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if error.is_timeout() {
        format!("timeout: {text}")
    } else if lower.contains("certificate") || lower.contains("tls") || lower.contains("ssl") {
        format!("TLS validation failed: {text}")
    } else if error.is_connect() {
        format!("connection failed: {text}")
    } else {
        format!("request failed: {text}")
    }
}

/// Validate a Gateway's self-description (`GET /.well-known/misaka`).
///
/// This proves the Gateway is alive, speaks a supported Gateway protocol, and
/// belongs to *this* Network with *this* Authority. It does NOT prove that any
/// Sister can be reached through it, nor that discovery works.
pub async fn probe_gateway(
    base: &str,
    network_id: &misaka_core::NetworkId,
    authority_fingerprint: &str,
    timeout: Duration,
) -> InfraProbe {
    let client = match infra_client(timeout) {
        Ok(client) => client,
        Err(error) => {
            return InfraProbe {
                status: Status::Warn,
                message: format!("HTTP client unavailable: {error}"),
            }
        }
    };
    let url = format!("{}/.well-known/misaka", base.trim_end_matches('/'));
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return InfraProbe {
                status: Status::Warn,
                message: describe_request_error(&error),
            }
        }
    };
    let http_status = response.status();
    if !http_status.is_success() {
        return InfraProbe {
            status: Status::Warn,
            message: format!("Gateway is reachable but returned HTTP {http_status}"),
        };
    }
    let info: GatewayInfo = match response.json().await {
        Ok(info) => info,
        Err(error) => {
            return InfraProbe {
                status: Status::Warn,
                message: format!("Gateway returned an unexpected service response: {error}"),
            }
        }
    };
    if info.protocol_version != GATEWAY_PROTOCOL_VERSION {
        return InfraProbe {
            status: Status::Error,
            message: format!(
                "unsupported Gateway protocol v{} (this binary supports v{})",
                info.protocol_version, GATEWAY_PROTOCOL_VERSION
            ),
        };
    }
    if info.network_id != *network_id {
        return InfraProbe {
            status: Status::Error,
            message: format!(
                "Gateway serves Network {}, this Sister belongs to {}",
                info.network_id, network_id
            ),
        };
    }
    if !info
        .authority_fingerprint
        .eq_ignore_ascii_case(authority_fingerprint)
    {
        return InfraProbe {
            status: Status::Error,
            message: "Gateway Authority fingerprint does not match this Network".to_string(),
        };
    }
    InfraProbe {
        status: Status::Ok,
        message: "Gateway protocol healthy; Network and Authority match".to_string(),
    }
}

/// Validate the configured Relay service (`GET /healthz`).
///
/// This proves the configured Relay service is alive at that URL. It does NOT
/// prove the Sister can establish an Iroh relay path, that another Sister is
/// reachable through it, that the Relay admits this EndpointId, or that
/// application traffic works. The Relay has no Misaka Network authority role,
/// so it is never compared against NetworkId/Authority/membership.
pub async fn probe_relay(base: &str, timeout: Duration) -> InfraProbe {
    let client = match infra_client(timeout) {
        Ok(client) => client,
        Err(error) => {
            return InfraProbe {
                status: Status::Warn,
                message: format!("HTTP client unavailable: {error}"),
            }
        }
    };
    let url = format!("{}/healthz", base.trim_end_matches('/'));
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return InfraProbe {
                status: Status::Warn,
                message: describe_request_error(&error),
            }
        }
    };
    let http_status = response.status();
    if http_status.is_success() {
        InfraProbe {
            status: Status::Ok,
            message: "Relay health endpoint responded successfully".to_string(),
        }
    } else {
        InfraProbe {
            status: Status::Warn,
            message: format!("Relay health endpoint returned HTTP {http_status}"),
        }
    }
}

/// Infrastructure checks for `doctor --infra`.
///
/// Each Gateway is reported independently (`infra:gateway:<index>`), and the
/// Relay separately (`infra:relay`). A missing Network/Gateway/Relay is a SKIP,
/// not an error. A Network/Authority contradiction is an ERROR; a temporary
/// availability problem is a WARN.
pub async fn infra_checks(
    gateways: &[String],
    authority: Option<&misaka_core::NetworkAuthority>,
    relay: Option<&str>,
) -> Vec<Check> {
    fn push_check(checks: &mut Vec<Check>, name: String, probe: InfraProbe) {
        checks.push(Check {
            name,
            status: probe.status,
            message: probe.message,
        });
    }
    let mut checks = Vec::new();
    if gateways.is_empty() {
        checks.push(Check {
            name: "infra:gateways".to_string(),
            status: Status::Skip,
            message: "no Gateways configured".to_string(),
        });
    }
    for (index, gateway) in gateways.iter().enumerate() {
        let name = format!("infra:gateway:{index}");
        match authority {
            None => checks.push(Check {
                name,
                status: Status::Skip,
                message: "no local Network Authority to validate the Gateway against".to_string(),
            }),
            Some(authority) => {
                let probe = probe_gateway(
                    gateway,
                    &authority.network_id,
                    &authority.authority_public_key.to_string(),
                    Duration::from_secs(5),
                )
                .await;
                push_check(&mut checks, name, probe);
            }
        }
    }
    match relay {
        None => checks.push(Check {
            name: "infra:relay".to_string(),
            status: Status::Skip,
            message: "no Relay configured".to_string(),
        }),
        Some(url) => {
            let probe = probe_relay(url, Duration::from_secs(5)).await;
            push_check(&mut checks, "infra:relay".to_string(), probe);
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::permissions_are_tight;
    use super::{connectivity_gap_warning, DoctorReport, Status};

    #[test]
    fn gateway_without_connectivity_is_warned() {
        assert!(connectivity_gap_warning(true, None, None).is_some());
        assert!(connectivity_gap_warning(false, None, None).is_none());
        assert!(connectivity_gap_warning(true, Some("192.168.1.2"), None).is_none());
        assert!(connectivity_gap_warning(true, None, Some("https://r")).is_none());
    }

    // --- Gateway infrastructure probes (DGI01-DGI07) -----------------------
    //
    // All servers are local mocks; the deployed Cloudflare Gateway is never used.

    use misaka_core::gateway::GatewayInfo;
    use misaka_core::{NetworkAuthority, NetworkId};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    async fn canned_http(response: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // Read the request headers before replying. A server that
                // writes and closes immediately can cause a TCP RST on
                // Windows while the client is still sending its request.
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = match stream.read(&mut buffer).await {
                        Ok(read) => read,
                        Err(_) => return,
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.len() > 64 * 1024 {
                        return;
                    }
                }

                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.flush().await;
                    let _ = stream.shutdown().await;
                }
            }
        });
        addr
    }

    async fn dead_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn hanging_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                drop(stream);
            }
        });
        addr
    }

    async fn gateway_server(authority: NetworkAuthority) -> SocketAddr {
        let server = misaka_gatewayd::GatewayServer::bind(
            misaka_gatewayd::GatewayConfig::new(authority),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        addr
    }

    fn probe_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(3)
    }

    // DGI01: valid GatewayInfo + matching NetworkId + matching fingerprint → OK
    #[tokio::test]
    async fn dgi01_matching_gateway_is_ok() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let addr = gateway_server(authority).await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &authority.network_id,
            &authority.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Ok, "{}", probe.message);
    }

    // DGI02: unsupported Gateway protocol version → ERROR
    #[tokio::test]
    async fn dgi02_unsupported_protocol_is_error() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let info = GatewayInfo {
            protocol_version: misaka_core::gateway::GATEWAY_PROTOCOL_VERSION + 1,
            network_id: authority.network_id,
            authority_fingerprint: authority.authority_public_key.to_string(),
        };
        let addr = canned_http(json_response(&serde_json::to_string(&info).unwrap())).await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &authority.network_id,
            &authority.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Error, "{}", probe.message);
    }

    // DGI03: Gateway NetworkId mismatch → ERROR
    #[tokio::test]
    async fn dgi03_network_mismatch_is_error() {
        let (served, _key) = NetworkAuthority::generate(NetworkId::generate());
        let (expected, _key) = NetworkAuthority::generate(NetworkId::generate());
        let info = GatewayInfo {
            protocol_version: misaka_core::gateway::GATEWAY_PROTOCOL_VERSION,
            network_id: served.network_id,
            authority_fingerprint: served.authority_public_key.to_string(),
        };
        let addr = canned_http(json_response(&serde_json::to_string(&info).unwrap())).await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &expected.network_id,
            &expected.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Error, "{}", probe.message);
    }

    // DGI04: Gateway Authority fingerprint mismatch → ERROR
    #[tokio::test]
    async fn dgi04_authority_mismatch_is_error() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let info = GatewayInfo {
            protocol_version: misaka_core::gateway::GATEWAY_PROTOCOL_VERSION,
            network_id: authority.network_id,
            authority_fingerprint: "00".repeat(32),
        };
        let addr = canned_http(json_response(&serde_json::to_string(&info).unwrap())).await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &authority.network_id,
            &authority.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Error, "{}", probe.message);
    }

    // DGI05: HTTP success but malformed GatewayInfo → WARN (availability-shaped)
    #[tokio::test]
    async fn dgi05_malformed_info_is_warn() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let addr = canned_http(json_response("not a gateway info")).await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &authority.network_id,
            &authority.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Warn, "{}", probe.message);
    }

    // DGI06: connection failure / timeout → WARN
    #[tokio::test]
    async fn dgi06_connection_failure_is_warn() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let addr = dead_addr().await;
        let probe = super::probe_gateway(
            &format!("http://{addr}"),
            &authority.network_id,
            &authority.authority_public_key.to_string(),
            probe_timeout(),
        )
        .await;
        assert_eq!(probe.status, super::Status::Warn, "{}", probe.message);
    }

    // DGI07: multiple Gateways → an independent result for each
    #[tokio::test]
    async fn dgi07_multiple_gateways_are_independent() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let good = format!("http://{}", gateway_server(authority).await);
        let dead = format!("http://{}", dead_addr().await);
        let checks = super::infra_checks(&[good, dead], Some(&authority), None).await;
        let gateway0 = checks.iter().find(|c| c.name == "infra:gateway:0").unwrap();
        let gateway1 = checks.iter().find(|c| c.name == "infra:gateway:1").unwrap();
        assert_eq!(gateway0.status, super::Status::Ok, "{}", gateway0.message);
        assert_eq!(gateway1.status, super::Status::Warn, "{}", gateway1.message);
        assert!(checks
            .iter()
            .any(|c| c.name == "infra:relay" && c.status == super::Status::Skip));
    }

    // --- Relay infrastructure probes (DRI01-DRI04) -------------------------

    async fn relay_server() -> SocketAddr {
        let relay = misaka_relay::RelayService::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });
        addr
    }

    // DRI01: /healthz responds successfully → OK
    #[tokio::test]
    async fn dri01_relay_health_is_ok() {
        let addr = relay_server().await;
        let probe = super::probe_relay(&format!("http://{addr}"), probe_timeout()).await;
        assert_eq!(probe.status, super::Status::Ok, "{}", probe.message);
    }

    // DRI02: TCP succeeds but /healthz fails → WARN
    #[tokio::test]
    async fn dri02_relay_health_failure_is_warn() {
        let addr = canned_http(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        )
        .await;
        let probe = super::probe_relay(&format!("http://{addr}"), probe_timeout()).await;
        assert_eq!(probe.status, super::Status::Warn, "{}", probe.message);
    }

    // DRI03: endpoint unreachable → WARN
    #[tokio::test]
    async fn dri03_relay_unreachable_is_warn() {
        let addr = dead_addr().await;
        let probe = super::probe_relay(&format!("http://{addr}"), probe_timeout()).await;
        assert_eq!(probe.status, super::Status::Warn, "{}", probe.message);
    }

    // DRI04: timeout → WARN
    #[tokio::test]
    async fn dri04_relay_timeout_is_warn() {
        let addr = hanging_addr().await;
        let probe = super::probe_relay(
            &format!("http://{addr}"),
            std::time::Duration::from_millis(300),
        )
        .await;
        assert_eq!(probe.status, super::Status::Warn, "{}", probe.message);
    }

    // --- skips and aggregation --------------------------------------------

    #[tokio::test]
    async fn infra_skips_without_authority_gateways_or_relay() {
        let (authority, _key) = NetworkAuthority::generate(NetworkId::generate());
        let checks = super::infra_checks(&[], Some(&authority), None).await;
        assert!(checks
            .iter()
            .any(|c| c.name == "infra:gateways" && c.status == super::Status::Skip));
        assert!(checks
            .iter()
            .any(|c| c.name == "infra:relay" && c.status == super::Status::Skip));

        // No Network authority → the Gateway cannot be validated → SKIP (never a
        // manufactured Network identity).
        let checks = super::infra_checks(&["http://127.0.0.1:1".to_string()], None, None).await;
        let gateway = checks.iter().find(|c| c.name == "infra:gateway:0").unwrap();
        assert_eq!(gateway.status, super::Status::Skip, "{}", gateway.message);
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
