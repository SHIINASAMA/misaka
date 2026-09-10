//! `testament service-verify` — opt-in, operator-only live service check.
//!
//! NEVER part of normal CI and never touches a developer's real config
//! directory: it uses a fresh isolated config dir and a uniquely named service
//! instance, then uninstalls it (unconditional cleanup). It exercises the real
//! OS service manager (launchd / systemd --user).

use crate::run_manager::{alloc_port, misaka_binary};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run(json: bool) -> Result<i32, String> {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return Err("service-verify is supported on macOS and Linux only".to_string());
    }
    let binary = misaka_binary();
    let base = std::env::temp_dir().join(format!("misaka-service-verify-{}", uuid::Uuid::new_v4()));
    let name = format!("verify-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let port = alloc_port().map_err(|error| error.to_string())?;
    let guard = Guard {
        binary: binary.clone(),
        config: base.clone(),
        name: name.clone(),
        installed: std::cell::Cell::new(false),
    };

    let mut steps: Vec<(String, bool, String)> = Vec::new();
    let mut result = Ok(());

    let step =
        |steps: &mut Vec<(String, bool, String)>, label: &str, outcome: Result<String, String>| {
            match outcome {
                Ok(message) => steps.push((label.to_string(), true, message)),
                Err(error) => steps.push((label.to_string(), false, error)),
            }
        };

    let run_misaka = |args: &[&str]| -> Result<String, String> { run_binary(&binary, &base, args) };

    let install = run_misaka(&[
        "service",
        "install",
        "--name",
        &name,
        "--api-port",
        &port.to_string(),
        "--discovery",
        "off",
    ]);
    match install {
        Ok(_) => {
            guard.installed.set(true);
            step(&mut steps, "install", Ok("installed".to_string()));
        }
        Err(error) => {
            step(&mut steps, "install", Err(error.clone()));
            result = Err(error);
        }
    }

    if result.is_ok() {
        let healthy = wait_healthy(&base, Duration::from_secs(30));
        step(
            &mut steps,
            "health",
            healthy
                .as_ref()
                .map(|_| "authenticated local API responds".to_string())
                .map_err(|error| error.clone()),
        );
        if let Err(error) = healthy {
            result = Err(error);
        }
    }

    if result.is_ok() {
        match run_misaka(&["service", "status", "--name", &name, "--json"]).and_then(|out| {
            let value: serde_json::Value =
                serde_json::from_str(&out).map_err(|error| error.to_string())?;
            if value["healthy"] == serde_json::Value::Bool(true) {
                Ok("status reports healthy".to_string())
            } else {
                Err(format!("status not healthy: {out}"))
            }
        }) {
            Ok(message) => step(&mut steps, "status", Ok(message)),
            Err(error) => {
                step(&mut steps, "status", Err(error.clone()));
                result = Err(error);
            }
        }
    }

    if result.is_ok() {
        match run_misaka(&["service", "restart", "--name", &name])
            .and_then(|_| wait_healthy(&base, Duration::from_secs(30)))
        {
            Ok(_) => step(
                &mut steps,
                "restart",
                Ok("healthy after restart".to_string()),
            ),
            Err(error) => {
                step(&mut steps, "restart", Err(error.clone()));
                result = Err(error);
            }
        }
    }

    if let Err(error) = run_misaka(&["service", "stop", "--name", &name]) {
        step(&mut steps, "stop", Err(error));
    } else {
        step(&mut steps, "stop", Ok("stopped".to_string()));
    }

    drop(guard);

    // Config/identity must survive uninstall.
    let preserved = ["identity.json", "sister-identity-key"]
        .iter()
        .all(|file| base.join(file).exists());
    step(
        &mut steps,
        "preserved",
        if preserved {
            Ok("identity preserved after uninstall".to_string())
        } else {
            Err("identity was deleted by uninstall".to_string())
        },
    );
    if !preserved {
        result = Err("identity was deleted by uninstall".to_string());
    }
    let _ = std::fs::remove_dir_all(&base);

    if json {
        let report = serde_json::json!({
            "name": name,
            "result": if result.is_ok() { "passed" } else { "failed" },
            "steps": steps.iter().map(|(label, ok, message)| serde_json::json!({
                "step": label, "ok": ok, "message": message
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        for (label, ok, message) in &steps {
            println!("{} {label}: {message}", if *ok { "OK  " } else { "FAIL" });
        }
    }
    result.map(|_| 0)
}

/// Installs an unconditional `service uninstall` on drop so a failed run never
/// leaves a stray service registration behind.
struct Guard {
    binary: PathBuf,
    config: PathBuf,
    name: String,
    installed: std::cell::Cell<bool>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.installed.get() {
            let _ = run_binary(
                &self.binary,
                &self.config,
                &["service", "uninstall", "--name", &self.name],
            );
        }
    }
}

fn run_binary(binary: &Path, config_dir: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(binary)
        .args(args)
        .env("MISAKA_CONFIG_DIR", config_dir)
        .output()
        .map_err(|error| format!("run {binary:?} {args:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`misaka {}` exited with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn wait_healthy(config_dir: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(token) = std::fs::read_to_string(config_dir.join("local-control-token")) {
            let token = token.trim().to_string();
            if let Ok(raw) = std::fs::read_to_string(config_dir.join("runtime.json")) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(addr) = value
                        .get("api_endpoint")
                        .and_then(|value| value.as_str())
                        .and_then(|addr| addr.parse::<std::net::SocketAddr>().ok())
                    {
                        if probe(addr, &token) {
                            return Ok(());
                        }
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("daemon did not become healthy within the bound".to_string());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Bounded authenticated `GET /api/v1/overview`.
fn probe(addr: std::net::SocketAddr, token: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!(
        "GET /api/v1/overview HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.contains(" 200 ")
}
