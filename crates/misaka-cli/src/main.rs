use clap::{Parser, Subcommand};
use misaka_core::protocol::{Envelope, HelloData, MessageType};
use serde::Serialize;

use misaka_runtime::error::MisakaError;
use misaka_runtime::identity_store::IdentityStore;
use misaka_runtime::node::SisterNode;
use misaka_runtime::peer_store::PeerStore;
use misaka_runtime::resources::{ResourceProvider, SysinfoResourceProvider};
use misaka_runtime::runtime::{default_encryption_key, SisterRuntime};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "misaka")]
#[command(about = "Misaka Network - decentralized computing network")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start one Sister node.
    Start {
        /// Peer listen port.
        #[arg(long, default_value_t = 31700)]
        port: u16,

        /// Known peer address; may be repeated (manual discovery).
        #[arg(long)]
        peer: Vec<String>,

        /// Set the local nickname.
        #[arg(long)]
        nickname: Option<String>,

        /// Discovery mode (mdns | manual | off).
        #[arg(long, default_value = "mdns")]
        discovery: String,

        /// Heartbeat and state broadcast interval in seconds.
        #[arg(long, default_value_t = 10)]
        heartbeat: u64,

        /// Peer offline timeout in seconds.
        #[arg(long, default_value_t = 60)]
        peer_timeout: u64,

        /// LAN address advertised to peers.
        #[arg(long)]
        advertise_host: Option<IpAddr>,

        /// Log format (human | json).
        #[arg(long, default_value = "human")]
        log_format: String,

        /// Read-only loopback introspection port (0 disables it).
        #[arg(long, default_value_t = 0)]
        introspect: u16,
    },

    /// Update the local Sister nickname.
    Nickname {
        /// New nickname.
        nickname: String,
    },

    /// Show local details and nearby Sisters.
    Status,

    /// Quickly list the local identity and known Sisters.
    Ps {
        #[arg(long)]
        json: bool,
    },

    /// Submit a job (use --local to force local execution).
    Run {
        /// Command to execute.
        command: String,

        /// Force local execution instead of dispatching to another Sister.
        #[arg(long)]
        local: bool,

        /// Target Sister ID.
        #[arg(long)]
        sister: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<(), MisakaError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start {
            port,
            peer,
            nickname,
            discovery,
            heartbeat,
            peer_timeout,
            advertise_host,
            log_format,
            introspect,
        } => {
            init_tracing(&log_format);
            // 加载或生成身份 (持久化)
            let data_dir =
                IdentityStore::config_dir().map_err(|e| MisakaError::Other(e.to_string()))?;
            let identity = IdentityStore::load_or_init(nickname.clone(), port)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            if nickname.clone().is_some() {
                tracing::info!(
                    event = "nickname_updated",
                    nickname = %identity.nickname,
                    "nickname updated"
                );
            }

            tracing::info!(
                event = "sister_identity",
                sister_id = identity.id.as_u64(),
                nickname = %identity.nickname,
                hostname = %identity.hostname,
                platform = %identity.platform,
                version = %identity.version,
                "Sister identity loaded"
            );

            let discovery_mode = match discovery.as_str() {
                "manual" => misaka_runtime::config::DiscoveryMode::Manual,
                "off" => misaka_runtime::config::DiscoveryMode::Off,
                _ => misaka_runtime::config::DiscoveryMode::Mdns,
            };
            let config = misaka_runtime::config::RuntimeConfig {
                listen_port: port,
                data_dir,
                heartbeat_interval: std::time::Duration::from_secs(heartbeat),
                peer_timeout: std::time::Duration::from_secs(peer_timeout),
                advertise_host,
                discovery: discovery_mode,
                introspection_addr: if introspect != 0 {
                    Some(format!("127.0.0.1:{}", introspect).parse().unwrap())
                } else {
                    None
                },
                ..Default::default()
            };
            let runtime = SisterRuntime::new(
                identity,
                default_encryption_key(),
                config,
                peer.iter()
                    .filter_map(|p| p.parse::<SocketAddr>().ok())
                    .collect(),
            )
            .await?;
            let shutdown = runtime.shutdown();
            let signal_task = shutdown.install_signal_handler();
            let result = runtime.run().await;
            signal_task.abort();
            result?;
        }

        Command::Nickname { nickname } => {
            let identity = IdentityStore::update_nickname(nickname)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            println!("[Misaka] nickname updated to {}", identity.nickname);
        }

        Command::Status => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not running. Run 'misaka start' first.".into())
                })?;

            // 本机实时资源
            let mut state = misaka_runtime::state::LocalState::new();
            let mut resource_provider = SysinfoResourceProvider::new();
            state.apply_snapshot(resource_provider.snapshot());
            let mem_gb = |b: u64| b as f64 / 1024.0 / 1024.0 / 1024.0;

            println!("Misaka Network\n");
            println!("This Sister");
            println!("────────────────────────────────");
            println!(
                "{}  ({} {})",
                identity.display_name(),
                identity.hostname,
                identity.platform
            );
            println!("  Port     : {}", identity.listen_port);
            println!("  CPU      : {:.1}%", state.cpu_usage);
            println!(
                "  Memory   : {:.1} / {:.1} GB",
                mem_gb(state.memory_used),
                mem_gb(state.memory_total)
            );
            println!("  Queued   : {} job(s)", state.queued_jobs);

            // 附近 Sister (来自 peers.json)
            let nearby = PeerStore::load_from_file();
            println!("\nNearby Sisters");
            println!("────────────────────────────────");
            if nearby.is_empty() {
                println!("  (none discovered yet)");
            } else {
                for bp in &nearby {
                    let online = check_online(bp.addr.parse::<SocketAddr>().ok());
                    let mark = if online { "●" } else { "○" };
                    println!(
                        "{mark} #{}  \"{}\"  @ {}  {}",
                        bp.id,
                        bp.nickname,
                        bp.addr,
                        if online { "online" } else { "offline" }
                    );
                }
            }
        }

        Command::Ps { json } => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not initialized. Run 'misaka start' first.".into())
                })?;
            let known = PeerStore::load_from_file();
            let report = network_ps(identity, known).await;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|e| MisakaError::Other(e.to_string()))?
                );
            } else {
                print_network_ps(&report);
            }
        }

        Command::Run {
            command,
            local,
            sister,
        } => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not running. Run 'misaka start' first.".into())
                })?;
            let data_dir =
                IdentityStore::config_dir().map_err(|e| MisakaError::Other(e.to_string()))?;
            let config = misaka_runtime::config::RuntimeConfig {
                listen_port: identity.listen_port,
                data_dir,
                ..Default::default()
            };
            let node = SisterNode::new(identity, default_encryption_key(), config);

            if local {
                println!("[Misaka] run --local: {}", command);
                // 独立进程：不启动完整 runtime，直接同步执行并输出结果
                let result = node.run_local_sync(&command).await;
                print_result(&result);
            } else if let Some(sid) = sister {
                println!("[Misaka] run --sister #{}: {}", sid, command);
                let result = node.submit_to_sister(sid, &command).await?;
                print_result(&result);
            } else {
                println!("[Misaka] run (network): {}", command);
                let result = node.submit_job(&command).await?;
                print_result(&result);
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct NetworkPsEntry {
    id: u64,
    nickname: String,
    address: Option<String>,
    status: String,
    #[serde(rename = "self")]
    is_self: bool,
}

#[derive(Debug, Clone, Serialize)]
struct NetworkPsReport {
    #[serde(rename = "self")]
    self_id: u64,
    sisters: Vec<NetworkPsEntry>,
}

async fn network_ps(
    identity: misaka_core::SisterIdentity,
    known: Vec<misaka_core::PeerBlueprint>,
) -> NetworkPsReport {
    let self_id = identity.id.as_u64();
    let mut sisters = vec![NetworkPsEntry {
        id: self_id,
        nickname: identity.nickname.as_str().to_string(),
        address: None,
        status: "online".into(),
        is_self: true,
    }];
    let mut seen = std::collections::HashSet::new();
    seen.insert(self_id);
    let probe_identity = identity.clone();
    let mut probes = tokio::task::JoinSet::new();
    for (index, peer) in known.into_iter().enumerate() {
        if !seen.insert(peer.id) {
            continue;
        }
        let address = peer.addr.clone();
        let identity = probe_identity.clone();
        probes.spawn(async move {
            let online = match address.parse::<SocketAddr>() {
                Ok(addr) => probe_peer(&identity, addr).await,
                Err(_) => false,
            };
            (index, peer, online)
        });
    }
    let mut probed = Vec::new();
    while let Some(result) = probes.join_next().await {
        if let Ok((index, peer, online)) = result {
            probed.push((index, peer, online));
        }
    }
    probed.sort_by_key(|(index, _, _)| *index);
    for (_, peer, online) in probed {
        sisters.push(NetworkPsEntry {
            id: peer.id,
            nickname: peer.nickname,
            address: Some(peer.addr),
            status: if online { "online" } else { "offline" }.into(),
            is_self: false,
        });
    }
    NetworkPsReport { self_id, sisters }
}

async fn probe_peer(identity: &misaka_core::SisterIdentity, addr: SocketAddr) -> bool {
    let Ok(crypto) = misaka_runtime::crypto::Crypto::new(&default_encryption_key()) else {
        return false;
    };
    let Ok(data) = bincode::serialize(&HelloData {
        identity: identity.clone(),
        listen_addr: format!("127.0.0.1:{}", identity.listen_port),
    }) else {
        return false;
    };
    let hello = Envelope::new(MessageType::Hello, identity.id.as_u64(), 0, data);
    let transport = misaka_runtime::network::PeerTransport::new(crypto);
    tokio::time::timeout(Duration::from_millis(400), transport.send_to(addr, &hello))
        .await
        .ok()
        .and_then(Result::ok)
        .is_some_and(|response| response.msg_type == MessageType::Hello)
}

fn print_network_ps(report: &NetworkPsReport) {
    println!("SISTER               ADDRESS             STATUS");
    for sister in &report.sisters {
        let name = format!("#{} \"{}\"", sister.id, sister.nickname);
        let address = sister.address.as_deref().unwrap_or("local");
        println!("{:<20} {:<19} {}", name, address, sister.status);
    }
    let online = report
        .sisters
        .iter()
        .filter(|sister| sister.status == "online")
        .count();
    println!("\n{} online / {} known", online, report.sisters.len());
}

fn init_tracing(format: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if format == "json" {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_target(false)
            .with_env_filter(filter)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_target(false)
            .with_env_filter(filter)
            .try_init();
    }
}
fn print_result(result: &misaka_core::protocol::JobResultData) {
    println!("────────────────────────────────");
    println!(
        "Job {} completed by #{}{}",
        result.job_id,
        result.executor,
        if result.success {
            " (success)"
        } else {
            " (failed)"
        }
    );
    if !result.output.is_empty() {
        println!("Output:\n{}", result.output);
    }
}

/// Probe a peer address with a lightweight Misaka Hello handshake.
fn check_online(addr: Option<SocketAddr>) -> bool {
    let Some(addr) = addr else { return false };
    // 阻塞式 TCP 连接尝试，超时 800ms
    use std::net::TcpStream;
    use std::time::Duration;
    TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok()
}
