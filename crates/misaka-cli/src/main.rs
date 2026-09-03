use clap::{Parser, Subcommand};
use misaka_core::protocol::{
    finalize_transfer_digest, update_transfer_digest, Envelope, MessageType, TransferRequest,
    TransferResult, TunnelRequest, TRANSFER_MAGIC, TUNNEL_MAGIC,
};
use misaka_network::{NetworkBackend, NetworkEndpoint};
use serde::Serialize;

use misaka_runtime::error::MisakaError;
use misaka_runtime::identity_store::IdentityStore;
use misaka_runtime::node::SisterNode;
use misaka_runtime::peer_store::PeerStore;
use misaka_runtime::resources::{ResourceProvider, SysinfoResourceProvider};
use misaka_runtime::runtime::{default_encryption_key, SisterRuntime};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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

        /// Experimental long-lived Network Stream port (0 disables it).
        #[arg(long, default_value_t = 0)]
        stream_port: u16,

        /// Enable the TLS 1.3/mTLS stream listener.
        #[arg(long)]
        stream_secure: bool,

        /// Stream backend (direct-tcp | iroh).
        #[arg(long, default_value = "direct-tcp")]
        stream_backend: String,

        /// DER certificate of a trusted peer; may be repeated in secure mode.
        #[arg(long, value_name = "PATH")]
        stream_trust_cert: Vec<PathBuf>,

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

    /// Experimental Network Stream v0 black-box client.
    StreamTest {
        /// Stream endpoint to connect to.
        #[arg(long)]
        addr: SocketAddr,

        /// Test mode: connect | bidirectional | sustained | large | hold.
        #[arg(long, default_value = "connect")]
        mode: String,

        /// Write this marker after the stream handshake and mode setup succeed.
        #[arg(long)]
        ready_file: Option<PathBuf>,

        /// Use the local persisted TLS identity and mutual authentication.
        #[arg(long)]
        secure: bool,

        /// DER certificate of the server to trust in secure mode.
        #[arg(long, value_name = "PATH")]
        trust_cert: Option<PathBuf>,

        /// TLS server name to validate, for example sister-42.
        #[arg(long)]
        server_name: Option<String>,
    },

    /// Copy one local file to a known Sister over its stream endpoint.
    Cp {
        /// Local source file.
        source: PathBuf,

        /// Remote target in the form #<sister-id>:/absolute/path.
        destination: String,
    },

    /// Forward a local TCP port to a remote Sister-local TCP endpoint.
    Tunnel {
        /// Target Sister ID.
        sister: u64,

        /// Local loopback port to listen on.
        #[arg(long)]
        local: u16,

        /// Remote TCP endpoint as seen by the target Sister.
        #[arg(long)]
        remote: SocketAddr,
    },

    /// Open an OpenSSH client through a temporary Sister tunnel.
    Ssh {
        /// Target Sister ID, with or without a leading #.
        sister: String,

        /// SSH username at the remote host, if different from the local user.
        #[arg(long)]
        user: Option<String>,

        /// Remote SSH port as seen by the target Sister.
        #[arg(long, default_value_t = 22)]
        remote_port: u16,
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
            stream_port,
            stream_secure,
            stream_backend,
            stream_trust_cert,
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
            let stream_security = if stream_secure {
                let stream_identity =
                    misaka_runtime::tls_identity_store::TlsIdentityStore::load_or_init(
                        &data_dir,
                        &format!("sister-{}", identity.id.as_u64()),
                    )
                    .map_err(|e| MisakaError::Other(e.to_string()))?;
                let trusted_peer_certificates = stream_trust_cert
                    .iter()
                    .map(|path| {
                        std::fs::read(path).map_err(|error| {
                            MisakaError::Other(format!(
                                "read trusted stream certificate {}: {error}",
                                path.display()
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                misaka_runtime::config::StreamSecurity::MutualTls {
                    identity: stream_identity,
                    trusted_peer_certificates,
                }
            } else {
                misaka_runtime::config::StreamSecurity::InsecureLoopback
            };
            let stream_backend = match stream_backend.as_str() {
                "direct-tcp" => misaka_runtime::config::StreamBackend::DirectTcp,
                "iroh" => {
                    if stream_secure {
                        return Err(MisakaError::Other(
                            "--stream-secure cannot be combined with --stream-backend iroh"
                                .to_string(),
                        ));
                    }
                    misaka_runtime::config::StreamBackend::Iroh(
                        misaka_network::IrohBackend::bind_with_secret_key(
                            misaka_runtime::iroh_identity_store::IrohIdentityStore::load_or_init(
                                &data_dir,
                            )
                            .map_err(|error| MisakaError::Other(error.to_string()))?,
                        )
                        .await
                        .map_err(|error| MisakaError::Other(error.to_string()))?,
                    )
                }
                other => {
                    return Err(MisakaError::Other(format!(
                        "unsupported stream backend: {other}"
                    )))
                }
            };
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
                stream_port: (stream_port != 0).then_some(stream_port),
                stream_backend,
                stream_security,
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

        Command::StreamTest {
            addr,
            mode,
            ready_file,
            secure,
            trust_cert,
            server_name,
        } => {
            run_stream_test(
                addr,
                &mode,
                ready_file.as_deref(),
                secure,
                trust_cert.as_deref(),
                server_name.as_deref(),
            )
            .await
            .map_err(MisakaError::Other)?;
        }

        Command::Cp {
            source,
            destination,
        } => {
            run_copy(&source, &destination)
                .await
                .map_err(MisakaError::Other)?;
        }

        Command::Tunnel {
            sister,
            local,
            remote,
        } => {
            run_tunnel(sister, local, remote)
                .await
                .map_err(MisakaError::Other)?;
        }

        Command::Ssh {
            sister,
            user,
            remote_port,
        } => {
            run_ssh(&sister, user.as_deref(), remote_port)
                .await
                .map_err(MisakaError::Other)?;
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
    stream: Option<String>,
    path: Option<String>,
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
        stream: None,
        path: None,
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
            stream: peer.stream_endpoints.first().cloned(),
            path: peer
                .stream_endpoints
                .first()
                .and_then(|endpoint| endpoint.parse::<NetworkEndpoint>().ok())
                .map(|endpoint| {
                    match misaka_network::resolver::EndpointCandidate::tcp(endpoint).kind {
                        misaka_network::resolver::PathKind::Lan => "lan".to_string(),
                        misaka_network::resolver::PathKind::Direct => "direct".to_string(),
                        misaka_network::resolver::PathKind::Relay => "relay".to_string(),
                    }
                }),
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
    let ping = Envelope::new(MessageType::Ping, identity.id.as_u64(), 0, vec![]);
    let transport = misaka_runtime::network::PeerTransport::new(crypto);
    tokio::time::timeout(Duration::from_millis(400), transport.send_to(addr, &ping))
        .await
        .ok()
        .and_then(Result::ok)
        .is_some_and(|response| response.msg_type == MessageType::Pong)
}

fn print_network_ps(report: &NetworkPsReport) {
    println!("SISTER               CONTROL             STREAM              PATH     STATUS");
    for sister in &report.sisters {
        let name = format!("#{} \"{}\"", sister.id, sister.nickname);
        let address = sister.address.as_deref().unwrap_or("local");
        let stream = sister.stream.as_deref().unwrap_or("-");
        let path = sister.path.as_deref().unwrap_or("-");
        println!(
            "{:<20} {:<19} {:<19} {:<8} {}",
            name, address, stream, path, sister.status
        );
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

const STREAM_CHUNK_SIZE: usize = 64 * 1024;
const LARGE_STREAM_SIZE: u64 = 64 * 1024 * 1024;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

async fn run_stream_test(
    addr: SocketAddr,
    mode: &str,
    ready_file: Option<&Path>,
    secure: bool,
    trust_cert: Option<&Path>,
    server_name: Option<&str>,
) -> Result<(), String> {
    let mut stream = if secure {
        let trust_cert = trust_cert.ok_or("--trust-cert is required with --secure")?;
        let server_name = server_name.ok_or("--server-name is required with --secure")?;
        let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
        let identity = misaka_runtime::tls_identity_store::TlsIdentityStore::load(&data_dir)
            .map_err(|error| error.to_string())?
            .ok_or("no persisted TLS identity in MISAKA_CONFIG_DIR")?;
        let trusted_certificate = std::fs::read(trust_cert)
            .map_err(|error| format!("read trusted certificate: {error}"))?;
        let config = identity
            .client_config(&trusted_certificate)
            .map_err(|error| error.to_string())?;
        let client = misaka_network::tls::TlsClient::new(config, server_name)
            .map_err(|error| error.to_string())?;
        tokio::time::timeout(
            Duration::from_secs(5),
            client.connect(NetworkEndpoint::Tcp(addr)),
        )
        .await
        .map_err(|_| "secure stream connect timed out".to_string())?
        .map_err(|error| error.to_string())?
    } else {
        let backend = misaka_network::DirectTcpBackend;
        tokio::time::timeout(
            Duration::from_secs(5),
            backend.connect(NetworkEndpoint::Tcp(addr)),
        )
        .await
        .map_err(|_| "stream connect timed out".to_string())?
        .map_err(|error| error.to_string())?
    };

    let mut greeting = [0u8; 5];
    read_exact_timeout(&mut stream, &mut greeting).await?;
    if greeting != *b"world" {
        return Err(format!("unexpected stream greeting: {greeting:?}"));
    }

    match mode {
        "connect" => mark_ready(ready_file),
        "bidirectional" => {
            exchange(&mut stream, b"hello").await?;
            mark_ready(ready_file)
        }
        "sustained" => {
            sustained(&mut stream).await?;
            mark_ready(ready_file)
        }
        "large" => {
            large_stream(stream).await?;
            mark_ready(ready_file)
        }
        "hold" => {
            exchange(&mut stream, b"hold-open").await?;
            mark_ready(ready_file)?;
            let mut buffer = [0u8; STREAM_CHUNK_SIZE];
            loop {
                let read = tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio::io::AsyncReadExt::read(&mut stream, &mut buffer),
                )
                .await
                .map_err(|_| "stream hold timed out".to_string())?
                .map_err(|error| format!("stream hold read failed: {error}"))?;
                if read == 0 {
                    return Err("stream closed while hold mode was active".to_string());
                }
            }
        }
        other => Err(format!("unknown stream test mode: {other}")),
    }
}

async fn run_copy(source: &Path, destination: &str) -> Result<(), String> {
    let (peer_id, remote_path) = parse_copy_destination(destination)?;
    let peer = PeerStore::load_from_file()
        .into_iter()
        .find(|peer| peer.id == peer_id)
        .ok_or_else(|| format!("Sister #{peer_id} is not in the local peer store"))?;
    let endpoint = peer
        .stream_endpoints
        .first()
        .ok_or_else(|| format!("Sister #{peer_id} has no stream endpoint"))?
        .parse::<NetworkEndpoint>()
        .map_err(|error| error.to_string())?;
    let mut stream =
        connect_peer_stream(endpoint, peer_id, peer.stream_certificate.as_deref()).await?;

    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let size = file
        .metadata()
        .await
        .map_err(|error| format!("stat source {}: {error}", source.display()))?
        .len();
    let digest = hash_file(&mut file).await?;
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(0))
        .await
        .map_err(|error| format!("rewind source: {error}"))?;

    stream
        .write_all(TRANSFER_MAGIC)
        .await
        .map_err(|error| format!("write transfer preamble: {error}"))?;
    let request = TransferRequest {
        destination: remote_path.display().to_string(),
        size,
        digest,
    };
    let encoded = bincode::serialize(&request).map_err(|error| error.to_string())?;
    stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .await
        .map_err(|error| format!("write transfer header: {error}"))?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|error| format!("write transfer metadata: {error}"))?;

    let mut sent = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    while sent < size {
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer)
            .await
            .map_err(|error| format!("read source: {error}"))?;
        if read == 0 {
            return Err("source changed while it was being copied".to_string());
        }
        stream
            .write_all(&buffer[..read])
            .await
            .map_err(|error| format!("write transfer payload: {error}"))?;
        sent += read as u64;
    }
    stream
        .flush()
        .await
        .map_err(|error| format!("flush transfer payload: {error}"))?;

    let mut length = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut length)
        .await
        .map_err(|error| format!("read transfer result: {error}"))?;
    let result_len = u32::from_be_bytes(length) as usize;
    if result_len > 1024 * 1024 {
        return Err("transfer result exceeds 1 MiB".to_string());
    }
    let mut encoded_result = vec![0u8; result_len];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut encoded_result)
        .await
        .map_err(|error| format!("read transfer result body: {error}"))?;
    let result: TransferResult = bincode::deserialize(&encoded_result)
        .map_err(|error| format!("decode transfer result: {error}"))?;
    if !result.success || result.bytes_written != size || result.digest != digest {
        return Err(result
            .error
            .unwrap_or_else(|| "remote transfer integrity check failed".to_string()));
    }
    println!(
        "Copied {} bytes to Sister #{peer_id}:{}",
        size,
        remote_path.display()
    );
    Ok(())
}

async fn run_tunnel(sister_id: u64, local_port: u16, remote: SocketAddr) -> Result<(), String> {
    let peer = PeerStore::load_from_file()
        .into_iter()
        .find(|peer| peer.id == sister_id)
        .ok_or_else(|| format!("Sister #{sister_id} is not in the local peer store"))?;
    let endpoint = peer
        .stream_endpoints
        .first()
        .ok_or_else(|| format!("Sister #{sister_id} has no stream endpoint"))?
        .parse::<NetworkEndpoint>()
        .map_err(|error| error.to_string())?;
    let peer_certificate = peer.stream_certificate;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|error| format!("bind local tunnel port {local_port}: {error}"))?;
    serve_tunnel(sister_id, endpoint, peer_certificate, remote, listener).await
}

async fn serve_tunnel(
    sister_id: u64,
    endpoint: NetworkEndpoint,
    peer_certificate: Option<Vec<u8>>,
    remote: SocketAddr,
    listener: tokio::net::TcpListener,
) -> Result<(), String> {
    let local_port = listener
        .local_addr()
        .map_err(|error| format!("read local tunnel address: {error}"))?
        .port();
    println!("Tunnel listening on 127.0.0.1:{local_port} -> {remote} via Sister #{sister_id}");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (local, _) = accepted.map_err(|error| format!("accept tunnel client: {error}"))?;
                let endpoint = endpoint.clone();
                let peer_certificate = peer_certificate.clone();
                tokio::spawn(async move {
                    if let Err(error) = proxy_tunnel(local, endpoint, sister_id, peer_certificate.as_deref(), remote).await {
                        tracing::debug!(sister_id, error = %error, "tunnel connection closed");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

async fn run_ssh(sister: &str, user: Option<&str>, remote_port: u16) -> Result<(), String> {
    let sister_id = parse_sister_id(sister)?;
    let peer = PeerStore::load_from_file()
        .into_iter()
        .find(|peer| peer.id == sister_id)
        .ok_or_else(|| format!("Sister #{sister_id} is not in the local peer store"))?;
    let endpoint = peer
        .stream_endpoints
        .first()
        .ok_or_else(|| format!("Sister #{sister_id} has no stream endpoint"))?
        .parse::<NetworkEndpoint>()
        .map_err(|error| error.to_string())?;
    let remote = SocketAddr::from(([127, 0, 0, 1], remote_port));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("bind temporary SSH tunnel: {error}"))?;
    let local_port = listener
        .local_addr()
        .map_err(|error| format!("read temporary SSH tunnel: {error}"))?
        .port();
    let tunnel = tokio::spawn(serve_tunnel(
        sister_id,
        endpoint,
        peer.stream_certificate,
        remote,
        listener,
    ));
    let destination = user
        .map(|user| format!("{user}@127.0.0.1"))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let status = tokio::process::Command::new("ssh")
        .arg("-p")
        .arg(local_port.to_string())
        .arg(destination)
        .status()
        .await
        .map_err(|error| format!("start ssh: {error}"))?;
    tunnel.abort();
    let _ = tunnel.await;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ssh exited with {status}"))
    }
}

fn parse_sister_id(value: &str) -> Result<u64, String> {
    value
        .strip_prefix('#')
        .unwrap_or(value)
        .parse::<u64>()
        .map_err(|error| format!("invalid Sister ID {value}: {error}"))
}

async fn proxy_tunnel(
    mut local: tokio::net::TcpStream,
    endpoint: NetworkEndpoint,
    sister_id: u64,
    peer_certificate: Option<&[u8]>,
    remote: SocketAddr,
) -> Result<(), String> {
    let mut stream = connect_peer_stream(endpoint, sister_id, peer_certificate).await?;
    let request = bincode::serialize(&TunnelRequest {
        remote: remote.to_string(),
    })
    .map_err(|error| error.to_string())?;
    stream
        .write_all(TUNNEL_MAGIC)
        .await
        .map_err(|error| format!("write tunnel preamble: {error}"))?;
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .await
        .map_err(|error| format!("write tunnel header: {error}"))?;
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("write tunnel request: {error}"))?;
    tokio::io::copy_bidirectional(&mut local, &mut stream)
        .await
        .map_err(|error| format!("proxy tunnel bytes: {error}"))?;
    Ok(())
}

fn parse_copy_destination(value: &str) -> Result<(u64, PathBuf), String> {
    let (id, path) = value
        .strip_prefix('#')
        .and_then(|value| value.split_once(':'))
        .ok_or("destination must be #<sister-id>:/path")?;
    let id = id
        .parse::<u64>()
        .map_err(|error| format!("invalid Sister ID: {error}"))?;
    if path.is_empty() {
        return Err("destination path must not be empty".to_string());
    }
    Ok((id, PathBuf::from(path)))
}

async fn connect_peer_stream(
    endpoint: NetworkEndpoint,
    peer_id: u64,
    peer_certificate: Option<&[u8]>,
) -> Result<misaka_network::NetworkStream, String> {
    let stream = if matches!(&endpoint, NetworkEndpoint::Iroh(_)) {
        if peer_certificate.is_some() {
            return Err("Iroh streams use endpoint-authenticated encryption; do not provide a TLS certificate".to_string());
        }
        let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
        let backend = misaka_network::IrohBackend::bind_with_secret_key(
            misaka_runtime::iroh_identity_store::IrohIdentityStore::load_or_init(&data_dir)
                .map_err(|error| error.to_string())?,
        )
        .await
        .map_err(|error| error.to_string())?;
        tokio::time::timeout(Duration::from_secs(10), backend.connect(endpoint))
            .await
            .map_err(|_| "Iroh stream connect timed out".to_string())?
            .map_err(|error| error.to_string())?
    } else if let Some(peer_certificate) = peer_certificate {
        let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
        let identity = misaka_runtime::tls_identity_store::TlsIdentityStore::load(&data_dir)
            .map_err(|error| error.to_string())?
            .ok_or("secure peer requires a local persisted TLS identity")?;
        let config = identity
            .client_config(peer_certificate)
            .map_err(|error| error.to_string())?;
        let client = misaka_network::tls::TlsClient::new(config, format!("sister-{peer_id}"))
            .map_err(|error| error.to_string())?;
        tokio::time::timeout(Duration::from_secs(10), client.connect(endpoint))
            .await
            .map_err(|_| "secure stream connect timed out".to_string())?
            .map_err(|error| error.to_string())?
    } else {
        let backend = misaka_network::DirectTcpBackend;
        tokio::time::timeout(Duration::from_secs(10), backend.connect(endpoint))
            .await
            .map_err(|_| "stream connect timed out".to_string())?
            .map_err(|error| error.to_string())?
    };
    let mut stream = stream;
    let mut greeting = [0u8; 5];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut greeting)
        .await
        .map_err(|error| format!("read stream greeting: {error}"))?;
    if greeting != *b"world" {
        return Err(format!("unexpected stream greeting: {greeting:?}"));
    }
    Ok(stream)
}

async fn hash_file(file: &mut tokio::fs::File) -> Result<[u8; 32], String> {
    let mut hasher = [
        0xcbf29ce484222325,
        0x84222325cbf29ce4,
        0x9e3779b185ebca87,
        0xd6e8feb86659fd93,
    ];
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = tokio::io::AsyncReadExt::read(file, &mut buffer)
            .await
            .map_err(|error| format!("hash source: {error}"))?;
        if read == 0 {
            break;
        }
        update_transfer_digest(&mut hasher, &buffer[..read]);
    }
    Ok(finalize_transfer_digest(hasher))
}

fn mark_ready(path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = path {
        std::fs::write(path, b"ready")
            .map_err(|error| format!("write stream ready marker {}: {error}", path.display()))?;
    }
    Ok(())
}

async fn exchange(
    stream: &mut misaka_network::NetworkStream,
    payload: &[u8],
) -> Result<(), String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncWriteExt::write_all(stream, payload),
    )
    .await
    .map_err(|_| "stream write timed out".to_string())?
    .map_err(|error| format!("stream write failed: {error}"))?;
    let mut echoed = vec![0u8; payload.len()];
    read_exact_timeout(stream, &mut echoed).await?;
    if echoed != payload {
        return Err("stream echo did not match payload".to_string());
    }
    Ok(())
}

async fn sustained(stream: &mut misaka_network::NetworkStream) -> Result<(), String> {
    let payload = b"sustained-stream-message";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut exchanges = 0u64;
    while tokio::time::Instant::now() < deadline {
        exchange(stream, payload).await?;
        exchanges += 1;
    }
    if exchanges < 2 {
        return Err("sustained stream completed fewer than two exchanges".to_string());
    }
    Ok(())
}

async fn large_stream(stream: misaka_network::NetworkStream) -> Result<(), String> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let writer_task = tokio::spawn(async move {
        let mut buffer = [0u8; STREAM_CHUNK_SIZE];
        let mut offset = 0u64;
        let mut hash = FNV_OFFSET;
        while offset < LARGE_STREAM_SIZE {
            let size = (LARGE_STREAM_SIZE - offset).min(buffer.len() as u64) as usize;
            fill_deterministic(&mut buffer[..size], offset);
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::io::AsyncWriteExt::write_all(&mut writer, &buffer[..size]),
            )
            .await
            .map_err(|_| "large stream write timed out")?
            .map_err(|error| format!("large stream write failed: {error}"))?;
            hash = hash_update(hash, &buffer[..size]);
            offset += size as u64;
        }
        tokio::io::AsyncWriteExt::shutdown(&mut writer)
            .await
            .map_err(|error| format!("large stream shutdown failed: {error}"))?;
        Ok::<u64, String>(hash)
    });

    let mut buffer = [0u8; STREAM_CHUNK_SIZE];
    let mut received = 0u64;
    let mut hash = FNV_OFFSET;
    while received < LARGE_STREAM_SIZE {
        let read = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read(&mut reader, &mut buffer),
        )
        .await
        .map_err(|_| "large stream read timed out".to_string())?
        .map_err(|error| format!("large stream read failed: {error}"))?;
        if read == 0 {
            return Err(format!("large stream ended after {received} bytes"));
        }
        hash = hash_update(hash, &buffer[..read]);
        received += read as u64;
    }
    let sent_hash = writer_task
        .await
        .map_err(|error| format!("large stream writer task failed: {error}"))??;
    if received != LARGE_STREAM_SIZE || hash != sent_hash {
        return Err(format!(
            "large stream verification failed: sent={LARGE_STREAM_SIZE}, received={received}, sent_hash={sent_hash}, received_hash={hash}"
        ));
    }
    Ok(())
}

async fn read_exact_timeout(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    buffer: &mut [u8],
) -> Result<(), String> {
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read_exact(stream, buffer),
    )
    .await
    .map_err(|_| "stream read timed out".to_string())?
    .map(|_| ())
    .map_err(|error| format!("stream read failed: {error}"))
}

fn fill_deterministic(buffer: &mut [u8], offset: u64) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = ((offset + index as u64) % 251) as u8;
    }
}

#[cfg(test)]
fn deterministic_hash(bytes: &[u8]) -> u64 {
    hash_update(FNV_OFFSET, bytes)
}

fn hash_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Probe a peer address with a lightweight Misaka Hello handshake.
fn check_online(addr: Option<SocketAddr>) -> bool {
    let Some(addr) = addr else { return false };
    // 阻塞式 TCP 连接尝试，超时 800ms
    use std::net::TcpStream;
    use std::time::Duration;
    TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok()
}

#[cfg(test)]
mod stream_tests {
    use super::{deterministic_hash, fill_deterministic, Cli, Command};
    use clap::Parser;
    use std::net::SocketAddr;

    #[test]
    fn stream_test_accepts_mode_and_address() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--addr",
            "127.0.0.1:31701",
            "--mode",
            "large",
            "--ready-file",
            "/tmp/misaka-stream-ready",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::StreamTest {
                addr,
                mode,
                ready_file,
                ..
            } if addr == "127.0.0.1:31701".parse::<SocketAddr>().unwrap()
                && mode == "large"
                && ready_file.as_deref().is_some_and(|path| path == std::path::Path::new("/tmp/misaka-stream-ready"))
        ));
    }

    #[test]
    fn deterministic_payload_hash_is_chunk_boundary_independent() {
        let mut first = vec![0u8; 8192];
        let mut second = vec![0u8; 8192];
        fill_deterministic(&mut first, 0);
        fill_deterministic(&mut second, 0);
        assert_eq!(deterministic_hash(&first), deterministic_hash(&second));
        assert_ne!(
            deterministic_hash(&first[..4096]),
            deterministic_hash(&first[4096..])
        );
    }

    #[test]
    fn sister_id_accepts_display_prefix() {
        assert_eq!(super::parse_sister_id("#10032").unwrap(), 10032);
        assert_eq!(super::parse_sister_id("10032").unwrap(), 10032);
    }
}
