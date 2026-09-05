use clap::{Parser, Subcommand};
use std::time::Duration;
use testament::run_manager::{
    clear_current_run, create_run, layout_for_run, resolve_run_id, run_root, runs_dir,
    set_current_run,
};
use testament::scenario::{
    gateway_scenarios, network_scenarios, relay_scenarios, run_gateway_live, scenarios,
    security_scenarios, Context, ScenarioDef,
};
use testament::types::{Manifest, RunLayout, SisterEntry};

#[derive(Parser)]
#[command(name = "testament")]
#[command(about = "Misaka Network external test harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start N interconnected Sisters.
    Up {
        /// Number of Sisters (`-n 5` / `--sisters 5`).
        #[arg(short = 'n', long = "sisters", default_value_t = 1)]
        sisters: u32,
        #[arg(long)]
        json: bool,
    },
    /// Show static manifest metadata for a run.
    Status {
        /// Optional legacy positional run ID; defaults to the current run.
        run_id: Option<String>,
        #[arg(long)]
        run: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show live process and network state for the current run.
    Ps {
        #[arg(long)]
        run: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show Sister logs; omit the alias to show the whole current run.
    Logs {
        /// Sister alias (for example, s3), or a legacy run ID.
        target: Option<String>,
        #[arg(long)]
        run: Option<String>,
    },
    /// Gracefully stop one Sister.
    Stop {
        alias: String,
        #[arg(long)]
        run: Option<String>,
    },
    /// Immediately kill one Sister.
    Kill {
        alias: String,
        #[arg(long)]
        run: Option<String>,
    },
    /// Restart one Sister using persisted identity, ports, and topology.
    Restart {
        alias: String,
        #[arg(long)]
        run: Option<String>,
    },
    /// Stop and remove a run; omit the run ID to use the current run.
    Down {
        run_id: Option<String>,
        #[arg(long)]
        run: Option<String>,
    },
    /// Run one built-in scenario.
    Run {
        scenario: String,
        #[arg(long)]
        json: bool,
    },
    /// Run all built-in scenarios.
    Verify {
        #[arg(long)]
        json: bool,
    },
    /// Run the Network Stream, Transfer, Tunnel, Iroh, and observability scenarios (N01-N21).
    #[command(name = "network-verify")]
    NetworkVerify {
        #[arg(long)]
        json: bool,
    },
    /// Run relay-only and Sister+Relay black-box scenarios (R01-R07).
    #[command(name = "relay-verify")]
    RelayVerify {
        #[arg(long)]
        json: bool,
    },
    /// Run adversarial authorization and revocation scenarios (S01-S03).
    #[command(name = "security-verify")]
    SecurityVerify {
        #[arg(long)]
        json: bool,
    },
    /// Run the Operator UX v1 black-box smoke suite (O01-O07).
    #[command(name = "operator-verify")]
    OperatorVerify,

    /// Run Gateway v0 discovery scenarios (G01-G10).
    #[command(name = "gateway-verify")]
    GatewayVerify {
        #[arg(long)]
        json: bool,
    },

    /// Opt-in LIVE smoke against a real, public Gateway (NOT in CI). Verifies one
    /// chain: two test Sisters that know only the Gateway URL, no manual peer,
    /// discover each other over the real Network. Deliberately low-volume
    /// (≈6 Gateway requests) and run only when you explicitly invoke it.
    #[command(name = "gateway-live-verify")]
    GatewayLiveVerify {
        /// The real, public Gateway URL to smoke-test.
        #[arg(long)]
        gateway: String,
        /// Local operator Authority trust store (a NetworkAuthorityStore-style
        /// directory, or a `network-authority-key` file beside its `.bin`). The
        /// private key is read only to mint ephemeral test memberships and is
        /// never sent anywhere or committed.
        #[arg(long)]
        authority_key_file: String,
        /// Max seconds to wait for authenticated-Iroh convergence.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        #[arg(long)]
        json: bool,
    },

    /// Remove all run directories.
    Clean,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Verify { json } => verify(json),
        Command::NetworkVerify { json } => {
            verify_definitions(json, network_scenarios(), "network stream scenarios")
        }
        Command::RelayVerify { json } => {
            verify_definitions(json, relay_scenarios(), "relay scenarios")
        }
        Command::SecurityVerify { json } => {
            verify_definitions(json, security_scenarios(), "security scenarios")
        }
        Command::GatewayVerify { json } => {
            verify_definitions(json, gateway_scenarios(), "gateway scenarios")
        }
        Command::GatewayLiveVerify {
            gateway,
            authority_key_file,
            timeout_secs,
            json,
        } => run_gateway_live(
            &gateway,
            std::path::Path::new(&authority_key_file),
            timeout_secs,
            json,
        ),
        Command::Run { scenario, json } => run_one(&scenario, json),
        Command::Up { sisters, json } => up(sisters, json),
        Command::Status { run_id, run, json } => status(run.as_deref().or(run_id.as_deref()), json),
        Command::Ps { run, json } => ps(run.as_deref(), json),
        Command::Logs { target, run } => logs(target.as_deref(), run.as_deref()),
        Command::Stop { alias, run } => stop_one(&alias, run.as_deref()),
        Command::Kill { alias, run } => kill_one(&alias, run.as_deref()),
        Command::Restart { alias, run } => restart_one(&alias, run.as_deref()),
        Command::Down { run_id, run } => down(run.as_deref().or(run_id.as_deref())),
        Command::OperatorVerify => operator_verify(),
        Command::Clean => clean(),
    };
    std::process::exit(code);
}

fn verify(json: bool) -> i32 {
    verify_definitions(json, scenarios(), "scenarios")
}

fn verify_definitions(json: bool, definitions: Vec<ScenarioDef>, label: &str) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: cannot create run: {}", e);
            return 2;
        }
    };
    if !json {
        println!("[testament] run {} — verifying {}", run_id, label);
    }

    let mut worst = 0;
    let mut suite = testament::types::SuiteReport {
        run_id: run_id.clone(),
        scenarios: Vec::new(),
        passed: 0,
        failed: 0,
        infra_failed: 0,
        skipped: 0,
        exit_code: 0,
    };
    let mut manifest_sisters = Vec::new();
    for def in definitions {
        let mut scenario_layout = layout.clone();
        scenario_layout.sisters_dir = layout.sisters_dir.join(def.name);
        if let Err(e) = std::fs::create_dir_all(&scenario_layout.sisters_dir) {
            eprintln!("testament: create scenario directory: {}", e);
            worst = worst.max(2);
            continue;
        }
        let mut ctx = Context::new(run_id.clone(), scenario_layout);
        let result = (def.run)(&mut ctx);
        let report = ctx.report(def.name, result);

        let scenario_report_path = layout.sisters_dir.join(def.name).join("report.json");
        let _ = testament::reporter::write_report(&scenario_report_path, &report);

        let code = testament::reporter::exit_code_for(&report);
        suite.count(&report);
        if !json {
            println!(
                "[testament]   {} -> {}",
                def.name,
                match report.result.as_str() {
                    "passed" => "passed",
                    "skipped" => "skipped",
                    "failed" => "FAILED",
                    "infra_failed" => "INFRA-FAILED",
                    other => other,
                }
            );
        }
        worst = worst.max(code);
        if code != 0 && !json {
            eprintln!("  {}", report.assertion.clone().unwrap_or_default());
        }
        suite.scenarios.push(report);
        ctx.teardown();
        manifest_sisters.extend(ctx.manifest.sisters.clone());
    }
    suite.exit_code = worst;

    if let Err(e) = testament::reporter::write_suite_report(&layout.report_path, &suite) {
        eprintln!("testament: write suite report: {}", e);
        worst = worst.max(2);
    }
    let manifest = Manifest {
        run_id: run_id.clone(),
        sisters: manifest_sisters,
    };
    if let Err(e) = testament::run_manager::write_manifest(&layout, &manifest) {
        eprintln!("testament: write manifest: {}", e);
        worst = worst.max(2);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&suite).unwrap_or_else(|e| {
                format!("{{\"error\":\"failed to encode reports: {}\"}}", e)
            })
        );
    } else {
        println!("[testament] done; exit {}", worst);
    }
    worst
}

fn run_one(scenario: &str, json: bool) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: {}", e);
            return 2;
        }
    };
    let mut ctx = Context::new(run_id, layout.clone());
    let Some(def) = scenarios()
        .into_iter()
        .chain(network_scenarios())
        .chain(relay_scenarios())
        .find(|d| d.name == scenario)
    else {
        eprintln!("testament: unknown scenario {:?}", scenario);
        return 2;
    };
    let result = (def.run)(&mut ctx);
    let report = ctx.report(def.name, result);
    let mut code = testament::reporter::exit_code_for(&report);
    if let Err(e) = testament::reporter::write_report(&layout.report_path, &report) {
        eprintln!("testament: write report: {}", e);
        code = code.max(2);
    }
    ctx.teardown();
    if let Err(e) = testament::run_manager::write_manifest(&layout, &ctx.manifest) {
        eprintln!("testament: write manifest: {}", e);
        code = code.max(2);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                format!("{{\"error\":\"failed to encode report: {}\"}}", e)
            })
        );
    } else {
        println!("[testament] {} -> {}", def.name, report.result);
        if code != 0 {
            eprintln!("{}", report.assertion.unwrap_or_default());
        }
    }
    code
}

fn up(sisters: u32, json: bool) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: {}", e);
            return 2;
        }
    };
    let mut ctx = Context::new(run_id.clone(), layout.clone());
    if let Err(error) = ctx.start_full_mesh(sisters) {
        eprintln!("testament: up: {}", error);
        ctx.teardown();
        return 3;
    }
    if let Err(e) = testament::run_manager::write_manifest(&layout, &ctx.manifest) {
        eprintln!("testament: write manifest: {}", e);
        ctx.teardown();
        return 2;
    }
    if let Err(e) = set_current_run(&run_id) {
        eprintln!("testament: set current run: {}", e);
        ctx.teardown();
        return 2;
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&ctx.manifest).unwrap_or_default()
        );
    } else {
        println!("[testament] run {} up with {} sisters", run_id, sisters);
        for entry in &ctx.manifest.sisters {
            println!(
                "  {}  id={:?}  pid={:?}  listen={}",
                entry.alias, entry.id, entry.pid, entry.listen_addr
            );
        }
    }
    0
}

fn selected_manifest(explicit: Option<&str>) -> Result<(String, RunLayout, Manifest), String> {
    let run_id = resolve_run_id(explicit).map_err(|error| {
        if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound {
            "no current run; run `testament up` first".to_string()
        } else {
            format!("cannot resolve run: {error}")
        }
    })?;
    let layout = layout_for_run(&run_id);
    let manifest = match testament::run_manager::load_manifest(&layout) {
        Ok(manifest) => manifest,
        Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
            return Err("current run no longer exists".to_string())
        }
        Err(error) => return Err(format!("no run {:?} (or no manifest): {}", run_id, error)),
    };
    Ok((run_id, layout, manifest))
}

fn status(explicit: Option<&str>, _json: bool) -> i32 {
    let (_, layout, _) = match selected_manifest(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("testament: {error}");
            return 2;
        }
    };
    match std::fs::read_to_string(&layout.manifest_path) {
        Ok(contents) => {
            println!("{}", contents);
            0
        }
        Err(error) => {
            eprintln!("testament: read manifest: {error}");
            2
        }
    }
}

fn ps(explicit: Option<&str>, json: bool) -> i32 {
    let (_, _, manifest) = match selected_manifest(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("testament: {error}");
            return 2;
        }
    };
    let report = testament::operator::collect(&manifest);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("testament: encode ps: {error}");
                return 2;
            }
        }
    } else {
        print!("{}", testament::operator::render_human(&report));
    }
    0
}

fn logs(target: Option<&str>, explicit_run: Option<&str>) -> i32 {
    let (run_id, _, manifest, alias) = if explicit_run.is_some() {
        let selected = match selected_manifest(explicit_run) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("testament: {error}");
                return 2;
            }
        };
        (selected.0, selected.1, selected.2, target)
    } else if let Some(target) = target {
        // Preserve `logs <run-id>` while making `logs s3` the convenient
        // current-run form.
        if layout_for_run(target).manifest_path.exists() {
            let selected = match selected_manifest(Some(target)) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("testament: {error}");
                    return 2;
                }
            };
            (selected.0, selected.1, selected.2, None)
        } else {
            let selected = match selected_manifest(None) {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("testament: {error}");
                    return 2;
                }
            };
            (selected.0, selected.1, selected.2, Some(target))
        }
    } else {
        let selected = match selected_manifest(None) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("testament: {error}");
                return 2;
            }
        };
        (selected.0, selected.1, selected.2, None)
    };

    let entries: Vec<&SisterEntry> = manifest
        .sisters
        .iter()
        .filter(|entry| alias.is_none_or(|alias| alias == entry.alias))
        .collect();
    if let Some(alias) = alias.filter(|_| entries.is_empty()) {
        eprintln!("testament: no sister {:?} in run {}", alias, run_id);
        return 2;
    }
    for entry in entries {
        println!("=== {} stdout ===", entry.alias);
        println!(
            "{}",
            std::fs::read_to_string(&entry.stdout_log).unwrap_or_default()
        );
        println!("=== {} stderr ===", entry.alias);
        println!(
            "{}",
            std::fs::read_to_string(&entry.stderr_log).unwrap_or_default()
        );
    }
    0
}

fn stop_one(alias: &str, explicit: Option<&str>) -> i32 {
    signal_one(alias, explicit, "TERM", "stop")
}

fn kill_one(alias: &str, explicit: Option<&str>) -> i32 {
    signal_one(alias, explicit, "KILL", "kill")
}

fn signal_one(alias: &str, explicit: Option<&str>, signal: &str, operation: &str) -> i32 {
    let (run_id, layout, manifest) = match selected_manifest(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("testament: {error}");
            return 2;
        }
    };
    let Some(entry) = manifest.sisters.iter().find(|entry| entry.alias == alias) else {
        eprintln!("testament: no sister {:?} in run {}", alias, run_id);
        return 2;
    };
    let Some(pid) = entry.pid else {
        eprintln!("testament: sister {} has no recorded pid", alias);
        return 2;
    };
    if !testament::supervisor::pid_alive(pid) {
        println!(
            "[testament] {} {} already dead (pid {})",
            operation, alias, pid
        );
        return 0;
    }
    if let Err(error) = testament::supervisor::signal_process(pid, signal) {
        eprintln!(
            "testament: {} {} (pid {}): {}",
            operation, alias, pid, error
        );
        return 3;
    }
    let exited = testament::supervisor::wait_pid_exit(pid, Duration::from_secs(5));
    if !exited {
        eprintln!("testament: {} {} timed out (pid {})", operation, alias, pid);
        return 3;
    }
    if let Err(error) = testament::run_manager::write_manifest(&layout, &manifest) {
        eprintln!("testament: write manifest: {}", error);
        return 2;
    }
    println!("[testament] {} {} (pid {})", operation, alias, pid);
    0
}

struct SurvivorTarget {
    alias: String,
    id: u64,
    introspection: std::net::SocketAddr,
    prior_uptime: Option<u64>,
}

fn survivor_targets(
    manifest: &Manifest,
    restarted_alias: &str,
    restarted_id: Option<u64>,
) -> Vec<SurvivorTarget> {
    manifest
        .sisters
        .iter()
        .filter(|entry| entry.alias != restarted_alias)
        .filter(|entry| entry.pid.is_some_and(testament::supervisor::pid_alive))
        .filter_map(|entry| {
            let id = entry.id?;
            let introspection = entry.introspection_addr.as_deref()?.parse().ok()?;
            let prior_uptime = restarted_id.and_then(|restarted_id| {
                testament::observer::fetch(introspection, Duration::from_millis(300))
                    .ok()
                    .and_then(|snapshot| {
                        snapshot
                            .peers
                            .iter()
                            .find(|peer| peer.id == restarted_id)
                            .map(|peer| peer.uptime_secs)
                    })
            });
            Some(SurvivorTarget {
                alias: entry.alias.clone(),
                id,
                introspection,
                prior_uptime,
            })
        })
        .collect()
}

fn wait_for_rejoin(
    restarted_addr: std::net::SocketAddr,
    restarted_id: u64,
    survivors: &[SurvivorTarget],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let restarted_snapshot =
            testament::observer::fetch(restarted_addr, Duration::from_millis(300)).ok();
        let restarted_sees_survivors = restarted_snapshot.as_ref().is_some_and(|snapshot| {
            survivors
                .iter()
                .all(|survivor| snapshot.peers.iter().any(|peer| peer.id == survivor.id))
        });
        let survivor_sees_restarted = survivors.iter().any(|survivor| {
            testament::observer::fetch(survivor.introspection, Duration::from_millis(300))
                .ok()
                .is_some_and(|snapshot| {
                    snapshot.peers.iter().any(|peer| {
                        peer.id == restarted_id
                            && survivor
                                .prior_uptime
                                .is_none_or(|prior| peer.uptime_secs != prior)
                    })
                })
        });
        if restarted_sees_survivors && (survivors.is_empty() || survivor_sees_restarted) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let expected = survivors
                .iter()
                .map(|survivor| survivor.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "restarted Sister did not rejoin; expected visibility for survivors [{}]",
                expected
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn restart_one(alias: &str, explicit: Option<&str>) -> i32 {
    let (run_id, layout, mut manifest) = match selected_manifest(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("testament: {error}");
            return 2;
        }
    };
    let Some(index) = manifest
        .sisters
        .iter()
        .position(|entry| entry.alias == alias)
    else {
        eprintln!("testament: no sister {:?} in run {}", alias, run_id);
        return 2;
    };
    let entry = manifest.sisters[index].clone();
    if let Some(pid) = entry
        .pid
        .filter(|pid| testament::supervisor::pid_alive(*pid))
    {
        if let Err(error) = testament::supervisor::signal_process(pid, "TERM") {
            eprintln!("testament: restart {}: {}", alias, error);
            return 3;
        }
        if !testament::supervisor::wait_pid_exit(pid, Duration::from_secs(5)) {
            let _ = testament::supervisor::signal_process(pid, "KILL");
            if !testament::supervisor::wait_pid_exit(pid, Duration::from_secs(2)) {
                eprintln!("testament: restart {}: old process did not exit", alias);
                return 3;
            }
        }
    }

    // Capture the survivor baseline after the old process has exited. This
    // prevents a final pre-stop State update from looking like a rejoin.
    let survivors = survivor_targets(&manifest, alias, entry.id);
    let binary = testament::run_manager::misaka_binary();
    let mut process = match testament::supervisor::spawn_from_entry(entry.clone(), &binary) {
        Ok(process) => process,
        Err(error) => {
            eprintln!("testament: restart {}: {}", alias, error);
            return 3;
        }
    };
    if process.entry.listen_addr != entry.listen_addr
        || process.entry.introspection_addr != entry.introspection_addr
        || process.entry.config_dir != entry.config_dir
        || process.entry.peer_addrs != entry.peer_addrs
    {
        eprintln!(
            "testament: restart {}: persisted launch invariants changed",
            alias
        );
        process.kill();
        return 3;
    }
    let Some(introspection) = entry
        .introspection_addr
        .as_deref()
        .and_then(|addr| addr.parse().ok())
    else {
        eprintln!(
            "testament: restart {}: missing introspection address",
            alias
        );
        process.kill();
        return 3;
    };
    let Some(snapshot) =
        testament::observer::wait_until(introspection, Duration::from_secs(15), |_| true)
    else {
        eprintln!("testament: restart {}: Sister did not become ready", alias);
        process.kill();
        return 3;
    };
    if entry
        .id
        .is_some_and(|id| id != snapshot.identity.id.as_u64())
    {
        eprintln!("testament: restart {}: identity changed", alias);
        process.kill();
        return 3;
    }
    let restarted_id = snapshot.identity.id.as_u64();
    if let Err(error) = wait_for_rejoin(
        introspection,
        restarted_id,
        &survivors,
        Duration::from_secs(15),
    ) {
        eprintln!("testament: restart {}: {}", alias, error);
        process.kill();
        return 3;
    }
    manifest.sisters[index].pid = process.pid();
    manifest.sisters[index].id = Some(snapshot.identity.id.as_u64());
    if let Err(error) = testament::run_manager::write_manifest(&layout, &manifest) {
        eprintln!("testament: write manifest: {}", error);
        process.kill();
        return 2;
    }
    println!(
        "[testament] restarted {} in run {} (pid {})",
        alias,
        run_id,
        process.pid().unwrap_or_default()
    );
    0
}

fn down(explicit: Option<&str>) -> i32 {
    let (run_id, _, manifest) = match selected_manifest(explicit) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("testament: {error}");
            return 2;
        }
    };
    stop_manifest_sisters(&manifest);
    match std::fs::remove_dir_all(run_root(&run_id)) {
        Ok(()) => {
            if let Err(error) = clear_current_run(&run_id) {
                eprintln!("testament: clear current run: {}", error);
                return 2;
            }
            println!("[testament] removed run {}", run_id);
            0
        }
        Err(e) => {
            eprintln!("testament: remove run {}: {}", run_id, e);
            2
        }
    }
}

fn stop_manifest_sisters(manifest: &Manifest) {
    for sister in &manifest.sisters {
        let Some(pid) = sister.pid else { continue };
        if !testament::supervisor::pid_alive(pid) {
            continue;
        }
        let _ = testament::supervisor::signal_process(pid, "TERM");
        if !testament::supervisor::wait_pid_exit(pid, Duration::from_secs(5)) {
            let _ = testament::supervisor::signal_process(pid, "KILL");
            let _ = testament::supervisor::wait_pid_exit(pid, Duration::from_secs(2));
        }
    }
}

fn operator_verify() -> i32 {
    match testament::smoke::run() {
        Ok(checks) => {
            for check in checks {
                println!("[testament] {} -> passed", check);
            }
            0
        }
        Err(error) => {
            eprintln!("[testament] operator smoke failed: {}", error);
            3
        }
    }
}

fn clean() -> i32 {
    if let Ok(runs) = std::fs::read_dir(runs_dir()) {
        for run in runs.flatten() {
            let manifest_path = run.path().join("manifest.json");
            if let Ok(contents) = std::fs::read_to_string(manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<Manifest>(&contents) {
                    stop_manifest_sisters(&manifest);
                }
            }
        }
    }
    match std::fs::remove_dir_all(".testament") {
        Ok(()) => {
            println!("[testament] cleaned all runs");
            0
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("[testament] cleaned all runs");
            0
        }
        Err(e) => {
            eprintln!("testament: clean: {}", e);
            2
        }
    }
}
