//! Per-user Sister service management (macOS LaunchAgent, Linux systemd --user).
//!
//! v1 targets developer/personal-device deployment only: no root, no
//! LaunchDaemon, no system-wide unit. Service definitions are deliberately thin
//! — they run `<absolute binary> service run` with `MISAKA_CONFIG_DIR` set and
//! read operational configuration from `service.json`, so launchd/systemd
//! definitions never become a mirror of every `misaka start` flag.
//!
//! Service management never changes the network posture by itself: a service is
//! only reachable beyond loopback if the operator passed an explicit
//! `--advertise-host` or `--iroh-relay` at install time.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Cli, MisakaError};

const SERVICE_FILE: &str = "service.json";
pub const CURRENT_SERVICE_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_SERVICE_NAME: &str = "default";
const LABEL_PREFIX: &str = "io.github.shiinasama.misaka";
const UNIT_PREFIX: &str = "misaka-";

/// Operational startup configuration for a persistent Sister service.
///
/// State that is owned elsewhere is deliberately NOT duplicated here:
/// NetworkId, Gateway list, nickname, and membership live in their own stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub schema_version: u32,
    pub name: String,
    pub start: ServiceStartOptions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<InstalledBinary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStartOptions {
    pub port: u16,
    pub api_port: u16,
    pub introspect: u16,
    pub discovery: String,
    pub heartbeat_secs: u64,
    pub peer_timeout_secs: u64,
    pub gateway_interval_secs: u64,
    /// `None` ⇒ loopback-only (the fail-safe default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_host: Option<String>,
    /// `None` ⇒ relay disabled (never contacts a relay implicitly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_relay: Option<String>,
    #[serde(default)]
    pub iroh_relay_only: bool,
}

impl Default for ServiceStartOptions {
    fn default() -> Self {
        Self {
            port: 31700,
            api_port: 31702,
            introspect: 0,
            discovery: "mdns".to_string(),
            heartbeat_secs: 10,
            peer_timeout_secs: 60,
            gateway_interval_secs: 120,
            advertise_host: None,
            iroh_relay: None,
            iroh_relay_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledBinary {
    pub path: String,
    pub version: String,
    pub installed_at: u64,
}

pub struct ServiceConfigStore;

impl ServiceConfigStore {
    pub fn path(directory: &Path) -> PathBuf {
        directory.join(SERVICE_FILE)
    }

    pub fn load(directory: &Path) -> Result<Option<ServiceConfig>, String> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid service.json: {error}"))
    }

    pub fn save(directory: &Path, config: &ServiceConfig) -> Result<(), String> {
        std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
        let path = Self::path(directory);
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, bytes).map_err(|error| error.to_string())?;
        std::fs::rename(&temp, &path).map_err(|error| error.to_string())
    }
}

/// A service name is restricted so it maps to a safe, deterministic label/unit.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 32 {
        return Err("service name must be 1–32 characters".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("service name may contain only [a-z0-9-]".to_string());
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("service name must not start or end with '-'".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    Launchd,
    Systemd,
}

impl ServiceManager {
    pub fn detect() -> Result<Self, String> {
        if cfg!(target_os = "macos") {
            Ok(ServiceManager::Launchd)
        } else if cfg!(target_os = "linux") {
            Ok(ServiceManager::Systemd)
        } else {
            Err("service management is supported on macOS and Linux only".to_string())
        }
    }

    pub fn label(self, name: &str) -> String {
        match self {
            ServiceManager::Launchd => format!("{LABEL_PREFIX}.{name}"),
            ServiceManager::Systemd => format!("{UNIT_PREFIX}{name}.service"),
        }
    }

    pub fn definition_path(self, name: &str) -> Result<PathBuf, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set".to_string())?;
        Ok(match self {
            ServiceManager::Launchd => home
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", self.label(name))),
            ServiceManager::Systemd => home.join(".config/systemd/user").join(self.label(name)),
        })
    }

    pub fn logs_dir(self, config_dir: &Path) -> PathBuf {
        match self {
            // Keep logs beside the config but not among the secret files.
            ServiceManager::Launchd => config_dir.join("logs"),
            ServiceManager::Systemd => config_dir.join("logs"),
        }
    }
}

/// Generate a macOS LaunchAgent plist.
///
/// Absolute program path; explicit `MISAKA_CONFIG_DIR`; `RunAtLoad`; restart on
/// failure; no reliance on the working directory or the interactive shell PATH.
/// Never contains the local control token.
pub fn launchd_plist(label: &str, program: &str, config_dir: &Path, logs_dir: &Path) -> String {
    let stdout = logs_dir.join("service.out.log");
    let stderr = logs_dir.join("service.err.log");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{program}</string>
        <string>service</string>
        <string>run</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MISAKA_CONFIG_DIR</key>
        <string>{config_dir}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        label = xml_escape(label),
        program = xml_escape(program),
        config_dir = xml_escape(&config_dir.to_string_lossy()),
        stdout = xml_escape(&stdout.to_string_lossy()),
        stderr = xml_escape(&stderr.to_string_lossy()),
    )
}

/// Generate a systemd --user unit.
///
/// Absolute `ExecStart`; explicit `MISAKA_CONFIG_DIR`; `Restart=on-failure`.
/// Never contains the local control token.
pub fn systemd_unit(name: &str, program: &str, config_dir: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Misaka Sister service ({name})\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={program} service run\n\
         Environment=MISAKA_CONFIG_DIR={config_dir}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        name = name,
        program = program,
        config_dir = config_dir.to_string_lossy(),
    )
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The argv a service-manager command expands to. Kept as pure data so it can
/// be unit-tested without invoking a live service manager.
pub fn launchd_load_argv(plist: &Path) -> Vec<String> {
    vec![
        "launchctl".into(),
        "load".into(),
        "-w".into(),
        plist.to_string_lossy().to_string(),
    ]
}

pub fn launchd_unload_argv(plist: &Path) -> Vec<String> {
    vec![
        "launchctl".into(),
        "unload".into(),
        "-w".into(),
        plist.to_string_lossy().to_string(),
    ]
}

pub fn launchd_status_argv(label: &str) -> Vec<String> {
    vec!["launchctl".into(), "list".into(), label.into()]
}

pub fn systemd_argv(action: &str, unit: &str) -> Vec<String> {
    match action {
        "daemon-reload" => vec!["systemctl".into(), "--user".into(), "daemon-reload".into()],
        _ => vec![
            "systemctl".into(),
            "--user".into(),
            action.into(),
            unit.into(),
        ],
    }
}

fn run_argv(argv: &[String]) -> Result<std::process::Output, String> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| "empty command".to_string())?;
    Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {program}: {error}"))
}

/// Build the synthetic `misaka start …` argv for a service profile from
/// `service.json`. Only normal authenticated-runtime flags are produced; no
/// insecure/test-only flags exist in the service schema.
pub fn start_argv(config: &ServiceConfig) -> Vec<String> {
    let s = &config.start;
    let mut argv = vec![
        "misaka".to_string(),
        "start".to_string(),
        "--port".to_string(),
        s.port.to_string(),
        "--api-port".to_string(),
        s.api_port.to_string(),
        "--discovery".to_string(),
        s.discovery.clone(),
        "--heartbeat".to_string(),
        s.heartbeat_secs.to_string(),
        "--peer-timeout".to_string(),
        s.peer_timeout_secs.to_string(),
        "--gateway-interval".to_string(),
        s.gateway_interval_secs.to_string(),
    ];
    if s.introspect != 0 {
        argv.push("--introspect".into());
        argv.push(s.introspect.to_string());
    }
    if let Some(advertise) = &s.advertise_host {
        argv.push("--advertise-host".into());
        argv.push(advertise.clone());
    }
    if let Some(relay) = &s.iroh_relay {
        argv.push("--iroh-relay".into());
        argv.push(relay.clone());
    }
    if s.iroh_relay_only {
        argv.push("--iroh-relay-only".into());
    }
    argv
}

/// Internal entrypoint used by the service definitions: read `service.json` and
/// start the normal Sister runtime by re-entering the shared dispatcher.
pub async fn run() -> Result<(), MisakaError> {
    let dir = crate::IdentityStore::config_dir()
        .map_err(|error| MisakaError::Other(error.to_string()))?;
    let config = ServiceConfigStore::load(&dir)
        .map_err(MisakaError::Other)?
        .ok_or_else(|| {
            MisakaError::Other(
                "no service.json in this config directory; run 'misaka service install' first"
                    .to_string(),
            )
        })?;
    let argv = start_argv(&config);
    let cli = Cli::try_parse_from(argv)
        .map_err(|error| MisakaError::Other(format!("service run: {error}")))?;
    // Boxed: `dispatch` reaches `service::run` again, so the async cycle must be
    // broken at one point.
    Box::pin(crate::dispatch(cli)).await
}

/// Everything `service install` needs, gathered by the CLI layer.
pub struct InstallRequest {
    pub name: String,
    pub start: ServiceStartOptions,
    pub no_start: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceStatus {
    pub name: String,
    pub installed: bool,
    pub running: String,
    pub config_dir: String,
    pub executable: Option<String>,
    pub installed_binary_version: Option<String>,
    pub running_daemon_version: Option<String>,
    pub api_endpoint: Option<String>,
    /// Whether the authenticated local control API responded. `None` = not
    /// probed (no marker / unreachable).
    pub api_authenticated: Option<bool>,
    /// Service-manager running + authenticated local API responding.
    pub healthy: bool,
}

pub fn install(request: InstallRequest) -> Result<(), MisakaError> {
    validate_name(&request.name).map_err(MisakaError::Other)?;
    let manager = ServiceManager::detect().map_err(MisakaError::Other)?;
    let config_dir = crate::IdentityStore::config_dir()
        .map_err(|error| MisakaError::Other(error.to_string()))?;
    let program = std::env::current_exe()
        .map_err(|error| MisakaError::Other(format!("cannot resolve binary path: {error}")))?;
    let program = program.to_string_lossy().to_string();

    // Safety: a persistent service always runs the normal authenticated runtime.
    debug_assert!(request.start.iroh_relay.is_some() || !request.start.iroh_relay_only);

    let config = ServiceConfig {
        schema_version: CURRENT_SERVICE_SCHEMA_VERSION,
        name: request.name.clone(),
        start: request.start,
        installed: Some(InstalledBinary {
            path: program.clone(),
            version: crate::binary_version().to_string(),
            installed_at: crate::unix_now(),
        }),
    };
    ServiceConfigStore::save(&config_dir, &config)
        .map_err(|error| MisakaError::Other(format!("save service.json: {error}")))?;

    let definition = manager
        .definition_path(&request.name)
        .map_err(MisakaError::Other)?;
    if let Some(parent) = definition.parent() {
        std::fs::create_dir_all(parent).map_err(|error| MisakaError::Other(error.to_string()))?;
    }
    let logs_dir = manager.logs_dir(&config_dir);
    std::fs::create_dir_all(&logs_dir)
        .map_err(|error| MisakaError::Other(format!("create logs dir: {error}")))?;
    let contents = match manager {
        ServiceManager::Launchd => launchd_plist(
            &manager.label(&request.name),
            &program,
            &config_dir,
            &logs_dir,
        ),
        ServiceManager::Systemd => systemd_unit(&request.name, &program, &config_dir),
    };
    std::fs::write(&definition, contents)
        .map_err(|error| MisakaError::Other(format!("write service definition: {error}")))?;

    // Register, and start unless the caller asked not to.
    let register: Vec<Vec<String>> = match manager {
        ServiceManager::Launchd => vec![launchd_load_argv(&definition)],
        ServiceManager::Systemd => vec![
            systemd_argv("daemon-reload", ""),
            systemd_argv("enable", &manager.label(&request.name)),
        ],
    };
    for argv in register {
        run_argv(&argv).map_err(MisakaError::Other)?;
    }
    if !request.no_start {
        let start = match manager {
            ServiceManager::Launchd => vec![], // load -w already starts it
            ServiceManager::Systemd => vec![systemd_argv("start", &manager.label(&request.name))],
        };
        for argv in start {
            run_argv(&argv).map_err(MisakaError::Other)?;
        }
    }
    println!(
        "installed service '{}' ({}) for {}",
        request.name,
        manager.label(&request.name),
        config_dir.display()
    );
    Ok(())
}

pub fn uninstall(name: &str) -> Result<(), MisakaError> {
    validate_name(name).map_err(MisakaError::Other)?;
    let manager = ServiceManager::detect().map_err(MisakaError::Other)?;
    let definition = manager.definition_path(name).map_err(MisakaError::Other)?;
    // Stop and deregister. This NEVER touches identity, keys, membership,
    // authority material, revocations, Gateway config, or the content store.
    let _ = match manager {
        ServiceManager::Launchd => run_argv(&launchd_unload_argv(&definition)),
        ServiceManager::Systemd => {
            let _ = run_argv(&systemd_argv("disable", &manager.label(name)));
            run_argv(&systemd_argv("stop", &manager.label(name)))
        }
    };
    if definition.exists() {
        std::fs::remove_file(&definition)
            .map_err(|error| MisakaError::Other(format!("remove definition: {error}")))?;
    }
    if manager == ServiceManager::Systemd {
        let _ = run_argv(&systemd_argv("daemon-reload", ""));
    }
    // Remove the deployment metadata but not the config directory itself.
    let config_dir = crate::IdentityStore::config_dir()
        .map_err(|error| MisakaError::Other(error.to_string()))?;
    if let Ok(Some(mut config)) = ServiceConfigStore::load(&config_dir) {
        if config.name == name {
            config.installed = None;
            let _ = ServiceConfigStore::save(&config_dir, &config);
        }
    }
    println!("uninstalled service '{name}'");
    Ok(())
}

fn lifecycle(name: &str, action: &str) -> Result<(), MisakaError> {
    validate_name(name).map_err(MisakaError::Other)?;
    let manager = ServiceManager::detect().map_err(MisakaError::Other)?;
    let definition = manager.definition_path(name).map_err(MisakaError::Other)?;
    let argv = match (manager, action) {
        (ServiceManager::Launchd, "start") => launchd_load_argv(&definition),
        (ServiceManager::Launchd, "stop") => launchd_unload_argv(&definition),
        (ServiceManager::Launchd, "restart") => {
            let _ = run_argv(&launchd_unload_argv(&definition));
            launchd_load_argv(&definition)
        }
        (ServiceManager::Systemd, action) => systemd_argv(action, &manager.label(name)),
        _ => return Err(MisakaError::Other(format!("unsupported action {action}"))),
    };
    run_argv(&argv).map_err(MisakaError::Other)?;
    println!("service '{name}' {action}");
    Ok(())
}

/// What the OS service manager currently reports for a profile, or `None` when
/// no manager is available / the query fails.
pub fn manager_state(name: &str) -> Option<String> {
    let manager = ServiceManager::detect().ok()?;
    match manager {
        ServiceManager::Launchd => {
            let output = run_argv(&launchd_status_argv(&manager.label(name))).ok()?;
            Some(if output.status.success() {
                "running".to_string()
            } else {
                "stopped".to_string()
            })
        }
        ServiceManager::Systemd => {
            let output = run_argv(&systemd_argv("is-active", &manager.label(name))).ok()?;
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Some(if state.is_empty() {
                "unknown".to_string()
            } else {
                state
            })
        }
    }
}

pub fn start(name: &str) -> Result<(), MisakaError> {
    lifecycle(name, "start")
}

pub fn stop(name: &str) -> Result<(), MisakaError> {
    lifecycle(name, "stop")
}

pub fn restart(name: &str) -> Result<(), MisakaError> {
    lifecycle(name, "restart")
}

pub async fn status(name: &str, json: bool) -> Result<(), MisakaError> {
    validate_name(name).map_err(MisakaError::Other)?;
    let manager = ServiceManager::detect().map_err(MisakaError::Other)?;
    let config_dir = crate::IdentityStore::config_dir()
        .map_err(|error| MisakaError::Other(error.to_string()))?;
    let definition = manager.definition_path(name).map_err(MisakaError::Other)?;
    let config = ServiceConfigStore::load(&config_dir).map_err(MisakaError::Other)?;
    let installed = definition.exists();
    let running = manager_state(name).unwrap_or_else(|| "unknown".to_string());
    let instance = misaka_runtime::runtime_instance_store::RuntimeInstanceStore::load(&config_dir)
        .ok()
        .flatten();

    // Preferred health model: service manager says running AND the
    // authenticated local API responds. Bounded (see probe_local_control).
    let mut api_authenticated = None;
    if let Some(instance) = &instance {
        if let Ok(addr) = instance.api_endpoint.parse::<std::net::SocketAddr>() {
            api_authenticated = Some(matches!(
                crate::probe_local_control(addr, &config_dir).await,
                Ok(200)
            ));
        }
    }
    let healthy = installed && running == "running" && api_authenticated == Some(true);

    let report = ServiceStatus {
        name: name.to_string(),
        installed,
        running,
        config_dir: config_dir.to_string_lossy().to_string(),
        executable: config
            .as_ref()
            .and_then(|config| config.installed.as_ref())
            .map(|binary| binary.path.clone()),
        installed_binary_version: config
            .as_ref()
            .and_then(|config| config.installed.as_ref())
            .map(|binary| binary.version.clone()),
        running_daemon_version: instance.as_ref().map(|i| i.binary_version.clone()),
        api_endpoint: instance.as_ref().map(|i| i.api_endpoint.clone()),
        api_authenticated,
        healthy,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| MisakaError::Other(error.to_string()))?
        );
    } else {
        println!("service:   {} ({})", report.name, manager.label(name));
        println!("installed: {}", if report.installed { "yes" } else { "no" });
        println!("running:   {}", report.running);
        println!("healthy:   {}", if report.healthy { "yes" } else { "no" });
        println!("config:    {}", report.config_dir);
        if let Some(executable) = &report.executable {
            println!("executable: {executable}");
        }
        if let (Some(installed), Some(running)) = (
            &report.installed_binary_version,
            &report.running_daemon_version,
        ) {
            println!("installed version: {installed}");
            println!("daemon version:    {running}");
            if installed != running {
                println!("WARN: configured binary version differs from the running daemon");
            }
        }
        if let Some(endpoint) = &report.api_endpoint {
            println!(
                "local API: {endpoint} (authenticated: {})",
                report.api_authenticated.unwrap_or(false)
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config_dir() -> PathBuf {
        PathBuf::from("/tmp/misaka-config")
    }

    #[test]
    fn rejects_unsafe_service_names() {
        assert!(validate_name("home").is_ok());
        assert!(validate_name("test-b").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("Home").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("-x").is_err());
        assert!(validate_name(&"a".repeat(33)).is_err());
    }

    #[test]
    fn launchd_plist_is_well_formed_and_secret_free() {
        let plist = launchd_plist(
            "io.github.shiinasama.misaka.default",
            "/usr/local/bin/misaka",
            &config_dir(),
            &config_dir().join("logs"),
        );
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>/usr/local/bin/misaka</string>"));
        assert!(plist.contains("<string>service</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>MISAKA_CONFIG_DIR</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("SuccessfulExit"));
        // The token is never written into a service definition.
        assert!(!plist.contains("local-control-token"));
        assert!(!plist.contains("Bearer"));
    }

    #[test]
    fn systemd_unit_is_well_formed_and_secret_free() {
        let unit = systemd_unit("home", "/usr/local/bin/misaka", &config_dir());
        assert!(unit.contains("ExecStart=/usr/local/bin/misaka service run"));
        assert!(unit.contains("Environment=MISAKA_CONFIG_DIR="));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("local-control-token"));
        assert!(!unit.contains("Bearer"));
    }

    #[test]
    fn labels_are_deterministic() {
        assert_eq!(
            ServiceManager::Launchd.label("default"),
            "io.github.shiinasama.misaka.default"
        );
        assert_eq!(
            ServiceManager::Systemd.label("test-b"),
            "misaka-test-b.service"
        );
    }

    #[test]
    fn start_argv_uses_only_safe_flags() {
        let config = ServiceConfig {
            schema_version: CURRENT_SERVICE_SCHEMA_VERSION,
            name: "lan".into(),
            start: ServiceStartOptions {
                advertise_host: Some("192.168.1.20".into()),
                iroh_relay: Some("https://127.0.0.1:3340".into()),
                ..Default::default()
            },
            installed: None,
        };
        let argv = start_argv(&config);
        assert!(argv.contains(&"--advertise-host".to_string()));
        assert!(argv.contains(&"--iroh-relay".to_string()));
        // Never the insecure/test flags.
        for forbidden in [
            "--insecure-development",
            "--peer",
            "--probe-only",
            "--stream-backend",
        ] {
            assert!(!argv.contains(&forbidden.to_string()), "leaked {forbidden}");
        }
    }

    #[test]
    fn service_config_roundtrips_and_defaults_to_loopback() {
        let dir = std::env::temp_dir().join(format!("misaka-svc-{}", uuid::Uuid::new_v4()));
        let config = ServiceConfig {
            schema_version: CURRENT_SERVICE_SCHEMA_VERSION,
            name: "default".into(),
            start: ServiceStartOptions::default(),
            installed: None,
        };
        ServiceConfigStore::save(&dir, &config).unwrap();
        let loaded = ServiceConfigStore::load(&dir).unwrap().unwrap();
        assert_eq!(loaded, config);
        assert!(loaded.start.advertise_host.is_none());
        assert!(loaded.start.iroh_relay.is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
