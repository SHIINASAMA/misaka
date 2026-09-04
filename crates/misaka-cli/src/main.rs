use clap::{Parser, Subcommand};
use misaka_core::introspection::{
    ActiveStreamSnapshot, IntrospectionSnapshot, NetworkStreamSummary,
};
use misaka_core::protocol::{
    finalize_transfer_digest, transfer_digest, update_transfer_digest, Envelope, MessageType,
    TransferRequest, TransferResult, TransferV1Ack, TransferV1Chunk, TransferV1Request,
    TransferV1Resume, TransferV2Ack, TransferV2Operation, TransferV2Request, TransferV2Resume,
    TunnelRequest, TRANSFER_MAGIC, TRANSFER_V1_CHUNK_SIZE, TRANSFER_V1_MAGIC, TRANSFER_V2_MAGIC,
    TUNNEL_MAGIC,
};
use misaka_core::{
    IrohEndpointId, MembershipCertificate, NetworkId, NetworkInvite, PeerRecord, SisterKeyPair,
    SisterPublicKey,
};
use misaka_network::{NetworkBackend, NetworkEndpoint};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};

use misaka_runtime::error::MisakaError;
use misaka_runtime::identity_store::IdentityStore;
use misaka_runtime::membership_store::MembershipStore;
use misaka_runtime::network_authority_store::NetworkAuthorityStore;
use misaka_runtime::network_id_store::NetworkIdStore;
use misaka_runtime::node::SisterNode;
use misaka_runtime::peer_record_store::PeerRecordStore;
use misaka_runtime::peer_store::PeerStore;
use misaka_runtime::resources::{ResourceProvider, SysinfoResourceProvider};
use misaka_runtime::runtime::{default_encryption_key, SisterRuntime};
use misaka_runtime::sister_key_store::SisterKeyStore;
use misaka_runtime::transport_binding_store::TransportBindingStore;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;

#[derive(Parser)]
#[command(name = "misaka")]
#[command(about = "Misaka Network - decentralized computing network")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Override the relay used by Iroh transport endpoints.
    #[arg(long, global = true, value_name = "URL")]
    iroh_relay: Option<String>,

    /// Force Iroh to use the configured relay and disable direct IP transports.
    #[arg(long, global = true, requires = "iroh_relay")]
    iroh_relay_only: bool,

    /// Explicit independent Misaka Network namespace.
    #[arg(long, global = true, value_name = "UUID")]
    network_id: Option<String>,
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

        /// Start a stream listener for handshake/echo probes only.
        #[arg(long)]
        probe_only: bool,

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

        /// Also host the native Iroh relay service alongside this Sister.
        #[arg(long)]
        relay: bool,

        /// Relay bind address when --relay is enabled.
        #[arg(long, default_value = "0.0.0.0:443")]
        relay_bind: SocketAddr,

        /// Plain HTTP bind address for the relay captive-portal service when
        /// TLS is enabled.
        #[arg(long)]
        relay_http_bind: Option<SocketAddr>,

        /// PEM certificate chain for the integrated Iroh relay.
        #[arg(long)]
        relay_tls_cert: Option<PathBuf>,

        /// PEM private key for the integrated Iroh relay.
        #[arg(long)]
        relay_tls_key: Option<PathBuf>,
    },

    /// Form a Network or install membership from a signed invite.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },

    /// Export the local Iroh endpoint address for cross-domain preflight.
    Endpoint {
        /// Emit one machine-readable endpoint record as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Run only the native Iroh relay service.
    Relay {
        /// Public address on which the Iroh relay listens.
        #[arg(long, default_value = "0.0.0.0:443")]
        bind: SocketAddr,

        /// Plain HTTP bind address for the relay captive-portal service when
        /// TLS is enabled.
        #[arg(long)]
        http_bind: Option<SocketAddr>,

        /// PEM certificate chain for HTTPS mode.
        #[arg(long)]
        tls_cert: Option<PathBuf>,

        /// PEM private key for HTTPS mode.
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },

    /// Experimental Network Stream v0 black-box client.
    StreamTest {
        /// TCP stream endpoint to connect to (legacy form).
        #[arg(
            long,
            conflicts_with = "endpoint",
            required_unless_present = "endpoint"
        )]
        addr: Option<SocketAddr>,

        /// Transport-neutral endpoint, for example iroh://<EndpointAddr>.
        #[arg(long, conflicts_with = "addr", required_unless_present = "addr")]
        endpoint: Option<String>,

        /// Test mode: connect | bidirectional | sustained | large | stability | hold.
        #[arg(long, default_value = "connect")]
        mode: String,

        /// Stability test duration; required with --mode stability.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=3600))]
        duration_secs: Option<u64>,

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

        /// Emit one machine-readable measurement report as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Establish and verify a stream to a known Sister by identity.
    Connect {
        /// Target Sister ID, with or without a leading #.
        sister: String,
    },

    /// Copy one local file to a known Sister over its stream endpoint.
    Cp {
        /// Local source file.
        source: PathBuf,

        /// Remote target in the form #<sister-id>:/absolute/path.
        destination: String,

        /// Resume from the remote Sister's durable chunk boundary.
        #[arg(long)]
        resume: bool,

        /// Number of concurrent Transfer v2 chunk workers (1 keeps v1).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=8))]
        parallel: u8,
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

        /// Optional local loopback introspection address for active streams.
        #[arg(long, value_name = "ADDR")]
        introspect: Option<SocketAddr>,
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

#[derive(Subcommand)]
enum NetworkCommand {
    /// Initialize the local Network authority and owner Sister membership.
    Init,

    /// Issue a signed invite for a pre-identified Sister.
    Invite {
        /// Write the invite JSON to this file; print it when omitted.
        #[arg(long)]
        output: Option<PathBuf>,

        /// Sister ID that will receive the membership certificate.
        #[arg(long)]
        sister_id: Option<String>,

        /// Hex-encoded Sister public key that will receive the certificate.
        #[arg(long)]
        sister_public_key: Option<String>,

        /// Lifetime of the invite and membership certificate in seconds.
        #[arg(long, default_value_t = 86_400)]
        expires_in_secs: u64,
    },

    /// Install a signed invite without installing the authority private key.
    Join {
        /// Invite JSON file produced by `misaka network invite`.
        invite: PathBuf,
    },
}

fn main() -> Result<(), MisakaError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), MisakaError> {
    let cli = Cli::parse();
    let requested_network_id = cli
        .network_id
        .as_deref()
        .map(misaka_core::NetworkId::parse)
        .transpose()
        .map_err(|error| MisakaError::Other(format!("invalid --network-id: {error}")))?;
    let iroh_relay = cli
        .iroh_relay
        .map(|value| {
            value
                .parse::<iroh::RelayUrl>()
                .map_err(|error| MisakaError::Other(format!("invalid --iroh-relay URL: {error}")))
        })
        .transpose()?;
    let iroh_options = IrohTransportOptions {
        relay: iroh_relay,
        relay_only: cli.iroh_relay_only,
    };
    match cli.command {
        Command::Start {
            port,
            stream_port,
            stream_secure,
            probe_only,
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
            relay,
            relay_bind,
            relay_http_bind,
            relay_tls_cert,
            relay_tls_key,
        } => {
            init_tracing(&log_format);
            // 加载或生成身份 (持久化)
            let data_dir =
                IdentityStore::config_dir().map_err(|e| MisakaError::Other(e.to_string()))?;
            let network_id = NetworkIdStore::load_or_init(&data_dir, requested_network_id)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            let identity = IdentityStore::load_or_init(nickname.clone(), port)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            let sister_key = SisterKeyStore::load_or_init(&data_dir)
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
                    let backend = bind_iroh_backend(&data_dir, iroh_options.clone())
                        .await
                        .map_err(|error| MisakaError::Other(error.to_string()))?;
                    let endpoint = backend.endpoint().clone();
                    let online =
                        misaka_runtime::iroh_endpoint_store::IrohEndpointStore::wait_for_online(
                            &endpoint,
                            Duration::from_secs(5),
                        )
                        .await;
                    if !online {
                        tracing::warn!(
                            "Iroh endpoint did not become online before export; persisting current address and waiting for updates"
                        );
                    }
                    misaka_runtime::iroh_endpoint_store::IrohEndpointStore::save(
                        &data_dir,
                        &backend.endpoint_addr(),
                    )
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                    misaka_runtime::iroh_endpoint_store::IrohEndpointStore::spawn_refresh(
                        data_dir.clone(),
                        endpoint,
                    );
                    let binding = TransportBindingStore::load_or_update(
                        &data_dir,
                        network_id,
                        identity.id.as_u64(),
                        IrohEndpointId::from_bytes(*backend.endpoint().id().as_bytes()),
                        &sister_key,
                    )
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                    tracing::info!(
                        event = "transport_binding",
                        sister_public_key = %binding.sister_public_key,
                        iroh_endpoint_id = %binding.iroh_endpoint_id,
                        sequence = binding.sequence,
                        "Iroh endpoint bound to Sister identity"
                    );
                    misaka_runtime::config::StreamBackend::Iroh(backend)
                }
                other => {
                    return Err(MisakaError::Other(format!(
                        "unsupported stream backend: {other}"
                    )))
                }
            };
            let authenticated_session = match &stream_backend {
                misaka_runtime::config::StreamBackend::Iroh(_) => {
                    load_authenticated_session(&data_dir, network_id, &identity, &sister_key)
                        .map_err(MisakaError::Other)?
                }
                misaka_runtime::config::StreamBackend::DirectTcp => None,
            };
            let peer_record = match &stream_backend {
                misaka_runtime::config::StreamBackend::Iroh(backend) => {
                    let binding = TransportBindingStore::load(&data_dir)
                        .map_err(|error| MisakaError::Other(error.to_string()))?
                        .ok_or_else(|| {
                            MisakaError::Other(
                                "Iroh backend requires a persisted transport binding".to_string(),
                            )
                        })?;
                    Some(misaka_core::PeerRecord::issue(
                        network_id,
                        identity.id.as_u64(),
                        NetworkEndpoint::Iroh(backend.endpoint_addr()).to_string(),
                        binding,
                        unix_now(),
                        &sister_key,
                    ))
                }
                misaka_runtime::config::StreamBackend::DirectTcp => None,
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
                sister_public_key = %sister_key.public_key(),
                "Sister identity loaded"
            );

            let discovery_mode = match discovery.as_str() {
                "manual" => misaka_runtime::config::DiscoveryMode::Manual,
                "off" => misaka_runtime::config::DiscoveryMode::Off,
                _ => misaka_runtime::config::DiscoveryMode::Mdns,
            };
            let config = misaka_runtime::config::RuntimeConfig {
                network_id,
                listen_port: port,
                stream_port: (stream_port != 0).then_some(stream_port),
                stream_backend,
                stream_security,
                probe_only,
                authenticated_session,
                peer_record,
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
            let relay_service = if relay {
                let options = misaka_relay::RelayOptions {
                    bind: relay_bind,
                    http_bind: relay_http_bind,
                    tls_cert: relay_tls_cert,
                    tls_key: relay_tls_key,
                };
                Some(
                    misaka_relay::RelayService::bind_with_options(options)
                        .await
                        .map_err(|error| MisakaError::Other(error.to_string()))?,
                )
            } else {
                None
            };
            let shutdown = runtime.shutdown();
            let signal_task = shutdown.install_signal_handler();
            let relay_task = relay_service.map(|service| tokio::spawn(service.run()));
            let result = runtime.run().await;
            signal_task.abort();
            if let Some(task) = relay_task {
                task.abort();
            }
            result?;
        }

        Command::Network { command } => match command {
            NetworkCommand::Init => {
                let data_dir = IdentityStore::config_dir()
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let network_id = NetworkIdStore::load_or_init(&data_dir, requested_network_id)
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let authority = NetworkAuthorityStore::init(&data_dir, Some(network_id))
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                if authority.network_id != network_id {
                    return Err(MisakaError::Other(
                        "existing Network authority does not match the requested NetworkId"
                            .to_string(),
                    ));
                }
                let identity = IdentityStore::load_or_init(None, 31700)
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let sister_key = SisterKeyStore::load_or_init(&data_dir)
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let now = unix_now();
                let membership = if let Some(existing) = MembershipStore::load(&data_dir)
                    .map_err(|error| MisakaError::Other(error.to_string()))?
                {
                    if existing.network_id != network_id
                        || existing.sister_id != identity.id
                        || existing.sister_public_key != sister_key.public_key()
                        || !existing.verify(&authority)
                    {
                        return Err(MisakaError::Other(
                            "existing membership does not match the local Network authority or Sister"
                                .to_string(),
                        ));
                    }
                    existing
                } else {
                    let membership = MembershipCertificate::issue(
                        &authority,
                        &authority_key(&data_dir)?,
                        sister_key.public_key(),
                        identity.id.as_u64(),
                        now,
                        None,
                        1,
                    );
                    MembershipStore::save(&data_dir, &membership)
                        .map_err(|error| MisakaError::Other(error.to_string()))?;
                    membership
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "network_id": network_id.to_string(),
                        "sister_id": identity.id.as_u64(),
                        "sister_public_key": sister_key.public_key().to_string(),
                        "authority_public_key": authority.authority_public_key.to_string(),
                        "membership_serial": membership.serial,
                    })
                );
            }
            NetworkCommand::Invite {
                output,
                sister_id,
                sister_public_key,
                expires_in_secs,
            } => {
                let data_dir = IdentityStore::config_dir()
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let (authority, authority_key) = NetworkAuthorityStore::load_with_key(&data_dir)
                    .map_err(|error| MisakaError::Other(error.to_string()))?
                    .ok_or_else(|| {
                        MisakaError::Other(
                            "network invite requires an initialized Network authority".to_string(),
                        )
                    })?;
                if let Some(requested) = requested_network_id {
                    if requested != authority.network_id {
                        return Err(MisakaError::Other(
                            "--network-id does not match the local Network authority".to_string(),
                        ));
                    }
                }
                let _ = NetworkIdStore::load_or_init(&data_dir, Some(authority.network_id))
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                let target_id = sister_id
                    .as_deref()
                    .map(parse_sister_id)
                    .transpose()
                    .map_err(MisakaError::Other)?;
                let target_key = sister_public_key
                    .as_deref()
                    .map(parse_sister_public_key)
                    .transpose()
                    .map_err(MisakaError::Other)?;
                if target_id.is_none() != target_key.is_none() {
                    return Err(MisakaError::Other(
                        "--sister-id and --sister-public-key must be supplied together".to_string(),
                    ));
                }
                let target_id = target_id.ok_or_else(|| {
                    MisakaError::Other(
                        "this v0 invite flow requires --sister-id and --sister-public-key"
                            .to_string(),
                    )
                })?;
                let target_key = target_key.expect("target key checked above");
                let now = unix_now();
                let expires_at = now.saturating_add(expires_in_secs);
                let mut records = PeerRecordStore::load_from_dir(&data_dir, authority.network_id);
                let local_identity =
                    IdentityStore::load().map_err(|error| MisakaError::Other(error.to_string()))?;
                let local_key = SisterKeyStore::load(&data_dir)
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                if let (Some(local_identity), Some(local_key)) =
                    (local_identity.as_ref(), local_key.as_ref())
                {
                    if let Some(local_record) = load_local_peer_record(
                        &data_dir,
                        authority.network_id,
                        local_identity,
                        local_key,
                    )
                    .map_err(MisakaError::Other)?
                    {
                        records.insert(local_record.sister_id.as_u64(), local_record);
                    }
                }
                if records.is_empty() {
                    return Err(MisakaError::Other(
                        "network invite requires at least one persisted bootstrap PeerRecord"
                            .to_string(),
                    ));
                }
                let membership = MembershipCertificate::issue(
                    &authority,
                    &authority_key,
                    target_key,
                    target_id,
                    now,
                    Some(expires_at),
                    now.max(1),
                );
                let invite = NetworkInvite::issue(
                    authority,
                    &authority_key,
                    records.into_values().collect(),
                    now,
                    expires_at,
                    uuid::Uuid::new_v4().into_bytes(),
                    Some(membership),
                );
                let json = serde_json::to_string_pretty(&invite)
                    .map_err(|error| MisakaError::Other(error.to_string()))?;
                if let Some(output) = output {
                    std::fs::write(&output, json)
                        .map_err(|error| MisakaError::Other(error.to_string()))?;
                    println!("wrote Network invite to {}", output.display());
                } else {
                    println!("{json}");
                }
            }
            NetworkCommand::Join { invite } => {
                join_network_invite(&invite, requested_network_id).map_err(MisakaError::Other)?;
            }
        },

        Command::StreamTest {
            addr,
            endpoint,
            mode,
            duration_secs,
            ready_file,
            secure,
            trust_cert,
            server_name,
            json,
        } => {
            run_stream_test(
                match (addr, endpoint) {
                    (Some(addr), None) => NetworkEndpoint::Tcp(addr),
                    (None, Some(endpoint)) => endpoint
                        .parse::<NetworkEndpoint>()
                        .map_err(MisakaError::Other)?,
                    _ => {
                        return Err(MisakaError::Other(
                            "exactly one of --addr or --endpoint is required".to_string(),
                        ))
                    }
                },
                &mode,
                StreamTestOptions {
                    ready_file: ready_file.as_deref(),
                    secure,
                    trust_cert: trust_cert.as_deref(),
                    server_name: server_name.as_deref(),
                    json,
                    duration_secs,
                    network_id: NetworkIdStore::load_or_init(
                        &IdentityStore::config_dir()
                            .map_err(|error| MisakaError::Other(error.to_string()))?,
                        requested_network_id,
                    )
                    .map_err(|error| MisakaError::Other(error.to_string()))?,
                    iroh_options: iroh_options.clone(),
                },
            )
            .await
            .map_err(MisakaError::Other)?;
        }

        Command::Endpoint { json } => {
            let data_dir = IdentityStore::config_dir()
                .map_err(|error| MisakaError::Other(error.to_string()))?;
            let network_id = NetworkIdStore::load_or_init(&data_dir, requested_network_id)
                .map_err(|error| MisakaError::Other(error.to_string()))?;
            let identity = IdentityStore::load()
                .map_err(|error| MisakaError::Other(error.to_string()))?
                .ok_or_else(|| MisakaError::Other("no local Sister identity".to_string()))?;
            let sister_public_key = SisterKeyStore::public_key(&data_dir)
                .map_err(|error| MisakaError::Other(error.to_string()))?
                .ok_or_else(|| MisakaError::Other("no local Sister identity key".to_string()))?;
            let endpoint_addr = misaka_runtime::iroh_endpoint_store::IrohEndpointStore::load(
                &data_dir,
            )
            .map_err(|error| MisakaError::Other(error.to_string()))?
            .ok_or_else(|| {
                MisakaError::Other(
                    "no persisted Iroh listener endpoint; start the Sister with --stream-backend iroh first"
                        .to_string(),
                )
            })?;
            let binding = TransportBindingStore::load(&data_dir)
                .map_err(|error| MisakaError::Other(error.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other(
                        "no persisted Iroh transport binding; start the Sister with --stream-backend iroh first"
                            .to_string(),
                    )
                })?;
            if !binding.verify()
                || binding.network_id != network_id
                || binding.sister_id != identity.id
                || binding.sister_public_key != sister_public_key
            {
                return Err(MisakaError::Other(
                    "persisted Iroh transport binding does not match local Sister identity"
                        .to_string(),
                ));
            }
            let endpoint = NetworkEndpoint::Iroh(endpoint_addr).to_string();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "network_id": network_id.to_string(),
                        "sister_id": identity.id.as_u64(),
                        "sister_public_key": sister_public_key.to_string(),
                        "backend": "iroh",
                        "endpoint": endpoint,
                        "transport_binding_sequence": binding.sequence,
                    })
                );
            } else {
                println!("Network ID: {network_id}");
                println!("Sister: #{}", identity.id.as_u64());
                println!("Sister public key: {sister_public_key}");
                println!("Backend: iroh");
                println!("Iroh endpoint: {endpoint}");
                println!("Transport binding sequence: {}", binding.sequence);
            }
        }

        Command::Relay {
            bind,
            http_bind,
            tls_cert,
            tls_key,
        } => {
            tracing_subscriber::fmt().with_target(false).init();
            misaka_relay::RelayService::bind_with_options(misaka_relay::RelayOptions {
                bind,
                http_bind,
                tls_cert,
                tls_key,
            })
            .await
            .map_err(|error| MisakaError::Other(error.to_string()))?
            .run()
            .await
            .map_err(|error| MisakaError::Other(error.to_string()))?;
        }

        Command::Connect { sister } => {
            run_connect(&sister, iroh_options.clone())
                .await
                .map_err(MisakaError::Other)?;
        }

        Command::Cp {
            source,
            destination,
            resume,
            parallel,
        } => {
            run_copy(
                &source,
                &destination,
                resume,
                parallel,
                iroh_options.clone(),
            )
            .await
            .map_err(MisakaError::Other)?;
        }

        Command::Tunnel {
            sister,
            local,
            remote,
        } => {
            run_tunnel(sister, local, remote, iroh_options.clone())
                .await
                .map_err(MisakaError::Other)?;
        }

        Command::Ssh {
            sister,
            user,
            remote_port,
        } => {
            run_ssh(&sister, user.as_deref(), remote_port, iroh_options.clone())
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

        Command::Ps { json, introspect } => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not initialized. Run 'misaka start' first.".into())
                })?;
            let known = PeerStore::load_from_file();
            let (active_streams, stream_summary) = match introspect {
                Some(addr) => {
                    let snapshot = fetch_introspection(addr).await?;
                    (snapshot.active_streams, snapshot.stream_summary)
                }
                None => (Vec::new(), NetworkStreamSummary::default()),
            };
            let report = network_ps(identity, known, active_streams, stream_summary).await;
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
            let network_id = NetworkIdStore::load_or_init(&data_dir, requested_network_id)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            let config = misaka_runtime::config::RuntimeConfig {
                network_id,
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
    active_streams: Vec<ActiveStreamSnapshot>,
    stream_summary: NetworkStreamSummary,
}

async fn network_ps(
    identity: misaka_core::SisterIdentity,
    known: Vec<misaka_core::PeerBlueprint>,
    active_streams: Vec<ActiveStreamSnapshot>,
    stream_summary: NetworkStreamSummary,
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
                    match misaka_network::resolver::EndpointCandidate::for_endpoint(endpoint).kind {
                        misaka_network::resolver::PathKind::Lan => "lan".to_string(),
                        misaka_network::resolver::PathKind::Direct => "direct".to_string(),
                        misaka_network::resolver::PathKind::Iroh => "iroh".to_string(),
                        misaka_network::resolver::PathKind::Relay => "relay".to_string(),
                    }
                }),
            status: if online { "online" } else { "offline" }.into(),
            is_self: false,
        });
    }
    NetworkPsReport {
        self_id,
        sisters,
        active_streams,
        stream_summary,
    }
}

async fn fetch_introspection(addr: SocketAddr) -> Result<IntrospectionSnapshot, MisakaError> {
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
            .await
            .map_err(|_| MisakaError::Other(format!("introspection connection timed out: {addr}")))?
            .map_err(|error| {
                MisakaError::Other(format!("connect introspection {addr}: {error}"))
            })?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut bytes),
    )
    .await
    .map_err(|_| MisakaError::Other(format!("introspection read timed out: {addr}")))?
    .map_err(|error| MisakaError::Other(format!("read introspection {addr}: {error}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| MisakaError::Other(format!("decode introspection {addr}: {error}")))
}

async fn probe_peer(identity: &misaka_core::SisterIdentity, addr: SocketAddr) -> bool {
    let Ok(crypto) = misaka_runtime::crypto::Crypto::new(&default_encryption_key()) else {
        return false;
    };
    let Ok(network_id) = local_network_id() else {
        return false;
    };
    let ping = Envelope::new(
        network_id,
        MessageType::Ping,
        identity.id.as_u64(),
        0,
        vec![],
    );
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
    if !report.active_streams.is_empty() {
        println!("\nACTIVE STREAMS");
        println!("────────────────────────────────");
        for stream in &report.active_streams {
            println!(
                "  #{}  {} / {}  rtt={}  switches={}  remote={}  tx={}  rx={}  age={}ms",
                stream.stream_id,
                stream.backend,
                stream.route,
                stream
                    .rtt_ms
                    .map(|rtt| format!("{rtt}ms"))
                    .unwrap_or_else(|| "-".to_string()),
                stream.path_switches,
                stream.remote_endpoint.as_deref().unwrap_or("-"),
                stream.tx_bytes,
                stream.rx_bytes,
                stream.connected_for_ms,
            );
        }
    }
    if report.stream_summary.streams > 0
        || report.stream_summary.tx_bytes > 0
        || report.stream_summary.rx_bytes > 0
    {
        println!(
            "\nSTREAM SUMMARY\n  streams={}  tx={}  rx={}",
            report.stream_summary.streams,
            report.stream_summary.tx_bytes,
            report.stream_summary.rx_bytes,
        );
    }
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

#[derive(Debug, Clone, Serialize)]
struct StreamProbeReport {
    mode: String,
    backend: String,
    route: String,
    rtt_ms: Option<u64>,
    path_switches: u64,
    local_endpoint: Option<String>,
    remote_endpoint: Option<String>,
    setup_ms: u128,
    probe_rtt_ms: Option<u128>,
    exchanges: Option<u64>,
    bytes: Option<u64>,
    elapsed_ms: Option<u128>,
    throughput_mib_s: Option<f64>,
}

#[derive(Debug, Default)]
struct StreamProbeMetrics {
    probe_rtt_ms: Option<u128>,
    exchanges: Option<u64>,
    bytes: Option<u64>,
    elapsed_ms: Option<u128>,
    throughput_mib_s: Option<f64>,
}

#[derive(Clone, Default)]
struct IrohTransportOptions {
    relay: Option<iroh::RelayUrl>,
    relay_only: bool,
}

struct StreamTestOptions<'a> {
    ready_file: Option<&'a Path>,
    secure: bool,
    trust_cert: Option<&'a Path>,
    server_name: Option<&'a str>,
    json: bool,
    duration_secs: Option<u64>,
    network_id: misaka_core::NetworkId,
    iroh_options: IrohTransportOptions,
}

async fn run_stream_test(
    endpoint: NetworkEndpoint,
    mode: &str,
    options: StreamTestOptions<'_>,
) -> Result<(), String> {
    let StreamTestOptions {
        ready_file,
        secure,
        trust_cert,
        server_name,
        json,
        duration_secs,
        network_id,
        iroh_options,
    } = options;
    let connect_started = tokio::time::Instant::now();
    let is_iroh_endpoint = matches!(&endpoint, NetworkEndpoint::Iroh(_));
    let mut stream = if secure {
        let NetworkEndpoint::Tcp(addr) = endpoint else {
            return Err("--secure only supports a TCP endpoint".to_string());
        };
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
        match endpoint {
            NetworkEndpoint::Tcp(addr) => {
                let backend = misaka_network::DirectTcpBackend;
                tokio::time::timeout(
                    Duration::from_secs(5),
                    backend.connect_for_network(NetworkEndpoint::Tcp(addr), network_id),
                )
                .await
                .map_err(|_| "stream connect timed out".to_string())?
                .map_err(|error| error.to_string())?
            }
            NetworkEndpoint::Iroh(endpoint) => {
                let backend = bind_iroh_client_backend(iroh_options).await?;
                tokio::time::timeout(
                    Duration::from_secs(10),
                    backend.connect_for_network(NetworkEndpoint::Iroh(endpoint), network_id),
                )
                .await
                .map_err(|_| "Iroh stream connect timed out".to_string())?
                .map_err(|error| error.to_string())?
            }
        }
    };

    if is_iroh_endpoint {
        if let Some(auth) = load_cli_authenticated_session(network_id)? {
            stream =
                misaka_runtime::authenticated_session::authenticate_client(stream, &auth, None)
                    .await
                    .map_err(|error| format!("Iroh stream authentication failed: {error}"))?;
        }
    }

    let connect_ms = connect_started.elapsed().as_millis();
    let path = stream.path_info();
    let mut final_path = path.clone();
    if !json {
        println!(
            "Stream path: backend={} route={} rtt_ms={} local={} remote={} setup_ms={connect_ms}",
            path.backend,
            path.route,
            path.rtt_ms
                .map(|rtt| rtt.to_string())
                .unwrap_or_else(|| "-".to_string()),
            path.local_endpoint.as_deref().unwrap_or("-"),
            path.remote_endpoint.as_deref().unwrap_or("-"),
        );
    }

    let mut greeting = [0u8; 5];
    read_exact_timeout(&mut stream, &mut greeting).await?;
    if greeting != *b"world" {
        return Err(format!("unexpected stream greeting: {greeting:?}"));
    }

    let metrics = match mode {
        "connect" => {
            mark_ready(ready_file)?;
            StreamProbeMetrics::default()
        }
        "bidirectional" => {
            let started = std::time::Instant::now();
            exchange(&mut stream, b"hello").await?;
            let probe_rtt_ms = started.elapsed().as_millis();
            final_path = stream.path_info();
            if !json {
                println!("Stream RTT: payload_bytes=5 rtt_ms={probe_rtt_ms}");
            }
            mark_ready(ready_file)?;
            StreamProbeMetrics {
                probe_rtt_ms: Some(probe_rtt_ms),
                ..StreamProbeMetrics::default()
            }
        }
        "sustained" => {
            let metrics = sustained(&mut stream).await?;
            final_path = stream.path_info();
            if !json {
                println!(
                    "Sustained stream: exchanges={} elapsed_ms={}",
                    metrics.exchanges.expect("sustained exchanges"),
                    metrics.elapsed_ms.expect("sustained elapsed")
                );
            }
            mark_ready(ready_file)?;
            metrics
        }
        "large" => {
            let (metrics, path_after) = large_stream(stream).await?;
            final_path = path_after;
            if !json {
                println!(
                    "Large stream: bytes={} elapsed_ms={} throughput_mib_s={:.2}",
                    metrics.bytes.expect("large stream bytes"),
                    metrics.elapsed_ms.expect("large stream elapsed"),
                    metrics.throughput_mib_s.expect("large stream throughput")
                );
            }
            mark_ready(ready_file)?;
            metrics
        }
        "stability" => {
            let duration_secs =
                duration_secs.ok_or("--duration-secs is required with --mode stability")?;
            mark_ready(ready_file)?;
            let metrics = stability(&mut stream, duration_secs).await?;
            final_path = stream.path_info();
            if !json {
                println!(
                    "Stability stream: exchanges={} elapsed_ms={}",
                    metrics.exchanges.expect("stability exchanges"),
                    metrics.elapsed_ms.expect("stability elapsed")
                );
            }
            metrics
        }
        "hold" => {
            exchange(&mut stream, b"hold-open").await?;
            mark_ready(ready_file)?;
            if json {
                print_stream_probe_report(&StreamProbeReport {
                    mode: mode.to_string(),
                    backend: path.backend.clone(),
                    route: path.route.clone(),
                    rtt_ms: path.rtt_ms,
                    path_switches: path.path_switches,
                    local_endpoint: path.local_endpoint.clone(),
                    remote_endpoint: path.remote_endpoint.clone(),
                    setup_ms: connect_ms,
                    probe_rtt_ms: None,
                    exchanges: None,
                    bytes: None,
                    elapsed_ms: None,
                    throughput_mib_s: None,
                })?;
            }
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
        other => return Err(format!("unknown stream test mode: {other}")),
    };

    if json {
        print_stream_probe_report(&StreamProbeReport {
            mode: mode.to_string(),
            backend: final_path.backend,
            route: final_path.route,
            rtt_ms: final_path.rtt_ms,
            path_switches: final_path.path_switches,
            local_endpoint: final_path.local_endpoint,
            remote_endpoint: final_path.remote_endpoint,
            setup_ms: connect_ms,
            probe_rtt_ms: metrics.probe_rtt_ms,
            exchanges: metrics.exchanges,
            bytes: metrics.bytes,
            elapsed_ms: metrics.elapsed_ms,
            throughput_mib_s: metrics.throughput_mib_s,
        })?;
    }
    Ok(())
}

fn print_stream_probe_report(report: &StreamProbeReport) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(report)
            .map_err(|error| format!("serialize stream report: {error}"))?
    );
    Ok(())
}

async fn run_connect(sister: &str, iroh_options: IrohTransportOptions) -> Result<(), String> {
    let sister_id = parse_sister_id(sister)?;
    let peer = PeerStore::load_from_file()
        .into_iter()
        .find(|peer| peer.id == sister_id)
        .ok_or_else(|| format!("Sister #{sister_id} is not in the local peer store"))?;
    if peer.stream_endpoints.is_empty() {
        return Err(format!("Sister #{sister_id} has no stream endpoint"));
    }

    let mut last_error = None;
    for raw_endpoint in &peer.stream_endpoints {
        let endpoint = match raw_endpoint.parse::<NetworkEndpoint>() {
            Ok(endpoint) => endpoint,
            Err(error) => {
                last_error = Some(format!("parse endpoint {raw_endpoint}: {error}"));
                continue;
            }
        };
        match connect_peer_stream(
            endpoint,
            sister_id,
            peer.stream_certificate.as_deref(),
            iroh_options.clone(),
        )
        .await
        {
            Ok(mut stream) => {
                exchange(&mut stream, b"connect").await?;
                let path = stream.path_info();
                println!(
                    "Connected to Sister #{sister_id}: backend={} route={} rtt_ms={} local={} remote={}",
                    path.backend,
                    path.route,
                    path.rtt_ms
                        .map(|rtt| rtt.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    path.local_endpoint.as_deref().unwrap_or("-"),
                    path.remote_endpoint.as_deref().unwrap_or("-"),
                );
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| format!("all stream endpoints for Sister #{sister_id} failed")))
}

async fn run_copy(
    source: &Path,
    destination: &str,
    resume: bool,
    parallel: u8,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
    if parallel > 1 {
        if !resume {
            return Err("--parallel requires --resume".to_string());
        }
        return run_copy_v2(source, destination, parallel, iroh_options).await;
    }
    if resume {
        return run_copy_v1(source, destination, iroh_options).await;
    }
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
    let mut stream = connect_peer_stream(
        endpoint,
        peer_id,
        peer.stream_certificate.as_deref(),
        iroh_options,
    )
    .await?;

    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let size = file
        .metadata()
        .await
        .map_err(|error| format!("stat source {}: {error}", source.display()))?
        .len();
    let digest = hash_file_v0(&mut file).await?;
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

async fn run_copy_v1(
    source: &Path,
    destination: &str,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
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
    let mut stream = connect_peer_stream(
        endpoint,
        peer_id,
        peer.stream_certificate.as_deref(),
        iroh_options,
    )
    .await?;

    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let size = file
        .metadata()
        .await
        .map_err(|error| format!("stat source {}: {error}", source.display()))?
        .len();
    let digest = hash_file_v1(&mut file).await?;
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(0))
        .await
        .map_err(|error| format!("rewind source: {error}"))?;

    stream
        .write_all(TRANSFER_V1_MAGIC)
        .await
        .map_err(|error| format!("write transfer v1 preamble: {error}"))?;
    write_cli_bincode_frame(
        &mut stream,
        &TransferV1Request {
            destination: remote_path.display().to_string(),
            size,
            digest,
            chunk_size: TRANSFER_V1_CHUNK_SIZE,
        },
    )
    .await?;
    let resume: TransferV1Resume = read_cli_bincode_frame(&mut stream, 1024 * 1024).await?;
    if let Some(error) = resume.error {
        return Err(format!("remote transfer resume rejected: {error}"));
    }
    if resume.offset > size
        || !resume
            .offset
            .is_multiple_of(u64::from(TRANSFER_V1_CHUNK_SIZE))
    {
        return Err(format!(
            "remote returned invalid resume offset {}",
            resume.offset
        ));
    }
    if resume.complete {
        return finish_copy_v1(&mut stream, peer_id, &remote_path, size, digest).await;
    }

    let mut sent = resume.offset;
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(sent))
        .await
        .map_err(|error| format!("seek to resume offset: {error}"))?;
    let mut buffer = vec![0u8; TRANSFER_V1_CHUNK_SIZE as usize];
    while sent < size {
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer)
            .await
            .map_err(|error| format!("read source: {error}"))?;
        if read == 0 {
            return Err("source changed while it was being copied".to_string());
        }
        write_cli_bincode_frame(
            &mut stream,
            &TransferV1Chunk {
                index: sent / u64::from(TRANSFER_V1_CHUNK_SIZE),
                offset: sent,
                len: read as u32,
                digest: transfer_digest(&buffer[..read]),
            },
        )
        .await?;
        stream
            .write_all(&buffer[..read])
            .await
            .map_err(|error| format!("write transfer v1 chunk: {error}"))?;
        stream
            .flush()
            .await
            .map_err(|error| format!("flush transfer v1 chunk: {error}"))?;
        let ack: TransferV1Ack = read_cli_bincode_frame(&mut stream, 1024 * 1024).await?;
        if let Some(error) = ack.error {
            return Err(format!("remote transfer chunk rejected: {error}"));
        }
        let expected = sent + read as u64;
        if ack.next_offset != expected {
            return Err(format!(
                "remote acknowledged offset {}, expected {expected}",
                ack.next_offset
            ));
        }
        sent = ack.next_offset;
    }

    finish_copy_v1(&mut stream, peer_id, &remote_path, size, digest).await
}

async fn run_copy_v2(
    source: &Path,
    destination: &str,
    parallel: u8,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
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

    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let size = file
        .metadata()
        .await
        .map_err(|error| format!("stat source {}: {error}", source.display()))?
        .len();
    let digest = hash_file_v1(&mut file).await?;
    let chunk_size = u64::from(TRANSFER_V1_CHUNK_SIZE);
    let chunk_count = size.div_ceil(chunk_size);
    let base_request = TransferV2Request {
        operation: TransferV2Operation::Prepare,
        destination: remote_path.display().to_string(),
        size,
        digest,
        chunk_size: TRANSFER_V1_CHUNK_SIZE,
        chunk_count,
        index: 0,
        offset: 0,
        len: 0,
        chunk_digest: [0; 32],
    };
    let transport = TransferV2Transport::new(
        endpoint,
        peer_id,
        peer.stream_certificate.clone(),
        iroh_options,
    )
    .await?;
    let resume = match send_transfer_v2_control(&transport, base_request.clone()).await? {
        TransferV2ResumeOrAck::Resume(resume) => resume,
        TransferV2ResumeOrAck::Ack(_) => {
            return Err("remote returned an acknowledgement for transfer v2 prepare".to_string())
        }
    };
    if let Some(error) = resume.error {
        return Err(format!(
            "remote parallel transfer prepare rejected: {error}"
        ));
    }
    if resume
        .completed_indices
        .iter()
        .any(|index| *index >= chunk_count)
    {
        return Err("remote returned an invalid completed chunk index".to_string());
    }
    let completed: HashSet<u64> = resume.completed_indices.into_iter().collect();
    let worker_count = usize::from(parallel);
    let mut workers = JoinSet::new();
    for index in (0..chunk_count).filter(|index| !completed.contains(index)) {
        let source = source.to_owned();
        let transport = transport.clone();
        let request = base_request.clone();
        workers.spawn(
            async move { send_transfer_v2_chunk(&source, &transport, request, index).await },
        );
        if workers.len() >= worker_count {
            match workers.join_next().await {
                Some(Ok(Ok(()))) => {}
                Some(Ok(Err(error))) => {
                    workers.abort_all();
                    return Err(error);
                }
                Some(Err(error)) => {
                    workers.abort_all();
                    return Err(format!("parallel transfer worker failed: {error}"));
                }
                None => return Err("parallel transfer worker set ended unexpectedly".to_string()),
            }
        }
    }
    while let Some(result) = workers.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                workers.abort_all();
                return Err(error);
            }
            Err(error) => {
                workers.abort_all();
                return Err(format!("parallel transfer worker failed: {error}"));
            }
        }
    }

    let finalize = match send_transfer_v2_control(
        &transport,
        TransferV2Request {
            operation: TransferV2Operation::Finalize,
            ..base_request
        },
    )
    .await?
    {
        TransferV2ResumeOrAck::Ack(ack) => ack,
        TransferV2ResumeOrAck::Resume(_) => {
            return Err("remote returned a resume response for transfer v2 finalize".to_string())
        }
    };
    transport.close().await;
    if !finalize.accepted || !finalize.complete {
        return Err(finalize
            .error
            .unwrap_or_else(|| "remote parallel transfer finalization failed".to_string()));
    }
    println!(
        "Parallel copy of {} bytes to Sister #{peer_id}:{} (workers={worker_count})",
        size,
        remote_path.display()
    );
    Ok(())
}

async fn send_transfer_v2_control(
    transport: &TransferV2Transport,
    request: TransferV2Request,
) -> Result<TransferV2ResumeOrAck, String> {
    let mut stream = transport.open_stream().await?;
    stream
        .write_all(TRANSFER_V2_MAGIC)
        .await
        .map_err(|error| format!("write transfer v2 preamble: {error}"))?;
    write_cli_bincode_frame(&mut stream, &request).await?;
    match request.operation {
        TransferV2Operation::Prepare => read_cli_bincode_frame(&mut stream, 1024 * 1024)
            .await
            .map(TransferV2ResumeOrAck::Resume),
        TransferV2Operation::Finalize => read_cli_bincode_frame(&mut stream, 1024 * 1024)
            .await
            .map(TransferV2ResumeOrAck::Ack),
        TransferV2Operation::Chunk => {
            Err("transfer v2 control helper received chunk operation".to_string())
        }
    }
}

#[derive(Clone)]
enum TransferV2Transport {
    Direct {
        endpoint: NetworkEndpoint,
        peer_id: u64,
        peer_certificate: Option<Vec<u8>>,
        iroh_options: IrohTransportOptions,
    },
    Iroh {
        backend: misaka_network::IrohBackend,
        endpoint: iroh::EndpointAddr,
        peer_id: u64,
    },
}

impl TransferV2Transport {
    async fn new(
        endpoint: NetworkEndpoint,
        peer_id: u64,
        peer_certificate: Option<Vec<u8>>,
        iroh_options: IrohTransportOptions,
    ) -> Result<Self, String> {
        match endpoint {
            NetworkEndpoint::Iroh(endpoint_addr) => {
                if peer_certificate.is_some() {
                    return Err(
                        "Iroh streams use endpoint-authenticated encryption; do not provide a TLS certificate"
                            .to_string(),
                    );
                }
                let backend = bind_iroh_client_backend(iroh_options.clone()).await?;
                Ok(Self::Iroh {
                    backend,
                    endpoint: endpoint_addr,
                    peer_id,
                })
            }
            endpoint => Ok(Self::Direct {
                endpoint,
                peer_id,
                peer_certificate,
                iroh_options,
            }),
        }
    }

    async fn open_stream(&self) -> Result<misaka_network::NetworkStream, String> {
        let stream = match self {
            Self::Direct {
                endpoint,
                peer_id,
                peer_certificate,
                iroh_options,
            } => {
                connect_peer_stream(
                    endpoint.clone(),
                    *peer_id,
                    peer_certificate.as_deref(),
                    iroh_options.clone(),
                )
                .await?
            }
            Self::Iroh {
                backend,
                endpoint,
                peer_id,
            } => {
                let network_id = local_network_id()?;
                let stream = tokio::time::timeout(
                    Duration::from_secs(10),
                    backend
                        .connect_for_network(NetworkEndpoint::Iroh(endpoint.clone()), network_id),
                )
                .await
                .map_err(|_| "Iroh transfer stream connect timed out".to_string())?
                .map_err(|error| error.to_string())?;
                if let Some(auth) = load_cli_authenticated_session(network_id)? {
                    misaka_runtime::authenticated_session::authenticate_client(
                        stream,
                        &auth,
                        Some(*peer_id),
                    )
                    .await
                    .map_err(|error| format!("Iroh transfer authentication failed: {error}"))?
                } else {
                    stream
                }
            }
        };
        if matches!(self, Self::Iroh { .. }) {
            let mut stream = stream;
            let mut greeting = [0u8; 5];
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut greeting),
            )
            .await
            .map_err(|_| "Iroh transfer greeting timed out".to_string())?
            .map_err(|error| format!("read Iroh transfer greeting: {error}"))?;
            if greeting != *b"world" {
                return Err(format!("unexpected stream greeting: {greeting:?}"));
            }
            return Ok(stream);
        }
        Ok(stream)
    }

    async fn close(&self) {
        if let Self::Iroh { backend, .. } = self {
            backend.close().await;
        }
    }
}

enum TransferV2ResumeOrAck {
    Resume(TransferV2Resume),
    Ack(TransferV2Ack),
}

async fn send_transfer_v2_chunk(
    source: &Path,
    transport: &TransferV2Transport,
    base_request: TransferV2Request,
    index: u64,
) -> Result<(), String> {
    let offset = index * u64::from(base_request.chunk_size);
    let len = base_request
        .size
        .saturating_sub(offset)
        .min(u64::from(base_request.chunk_size)) as usize;
    let mut file = tokio::fs::File::open(source)
        .await
        .map_err(|error| format!("open source chunk: {error}"))?;
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(offset))
        .await
        .map_err(|error| format!("seek source chunk: {error}"))?;
    let mut payload = vec![0u8; len];
    tokio::io::AsyncReadExt::read_exact(&mut file, &mut payload)
        .await
        .map_err(|error| format!("read source chunk: {error}"))?;

    let mut stream = transport.open_stream().await?;
    stream
        .write_all(TRANSFER_V2_MAGIC)
        .await
        .map_err(|error| format!("write transfer v2 chunk preamble: {error}"))?;
    write_cli_bincode_frame(
        &mut stream,
        &TransferV2Request {
            operation: TransferV2Operation::Chunk,
            index,
            offset,
            len: len as u32,
            chunk_digest: transfer_digest(&payload),
            ..base_request
        },
    )
    .await?;
    stream
        .write_all(&payload)
        .await
        .map_err(|error| format!("write transfer v2 chunk: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush transfer v2 chunk: {error}"))?;
    let ack: TransferV2Ack = read_cli_bincode_frame(&mut stream, 1024 * 1024).await?;
    if ack.index != index || !ack.accepted {
        return Err(ack
            .error
            .unwrap_or_else(|| format!("remote rejected transfer v2 chunk {index}")));
    }
    Ok(())
}

async fn finish_copy_v1(
    stream: &mut misaka_network::NetworkStream,
    peer_id: u64,
    remote_path: &Path,
    size: u64,
    digest: [u8; 32],
) -> Result<(), String> {
    let result: TransferResult = read_cli_bincode_frame(stream, 1024 * 1024).await?;
    if !result.success || result.bytes_written != size || result.digest != digest {
        return Err(result
            .error
            .unwrap_or_else(|| "resumable transfer integrity check failed".to_string()));
    }
    println!(
        "Resumed copy of {} bytes to Sister #{peer_id}:{}",
        size,
        remote_path.display()
    );
    Ok(())
}

async fn run_tunnel(
    sister_id: u64,
    local_port: u16,
    remote: SocketAddr,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
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
    serve_tunnel(
        sister_id,
        endpoint,
        peer_certificate,
        remote,
        listener,
        iroh_options,
    )
    .await
}

async fn serve_tunnel(
    sister_id: u64,
    endpoint: NetworkEndpoint,
    peer_certificate: Option<Vec<u8>>,
    remote: SocketAddr,
    listener: tokio::net::TcpListener,
    iroh_options: IrohTransportOptions,
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
                let iroh_options = iroh_options.clone();
                tokio::spawn(async move {
                    if let Err(error) = proxy_tunnel(
                        local,
                        endpoint,
                        sister_id,
                        peer_certificate.as_deref(),
                        remote,
                        iroh_options,
                    )
                    .await
                    {
                        tracing::debug!(sister_id, error = %error, "tunnel connection closed");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

async fn run_ssh(
    sister: &str,
    user: Option<&str>,
    remote_port: u16,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
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
        iroh_options,
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

fn authority_key(data_dir: &Path) -> Result<misaka_core::AuthorityKeyPair, MisakaError> {
    NetworkAuthorityStore::load_key(data_dir)
        .map_err(|error| MisakaError::Other(error.to_string()))?
        .ok_or_else(|| {
            MisakaError::Other(
                "Network authority private key is missing; only the Network owner can do this"
                    .to_string(),
            )
        })
}

fn parse_sister_public_key(value: &str) -> Result<SisterPublicKey, String> {
    if value.len() != 64 {
        return Err(format!(
            "invalid Sister public key: expected 64 hexadecimal characters, got {}",
            value.len()
        ));
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| format!("invalid Sister public key hex at byte {index}"))?;
    }
    Ok(SisterPublicKey::from_bytes(bytes))
}

fn load_local_peer_record(
    data_dir: &Path,
    network_id: NetworkId,
    identity: &misaka_core::SisterIdentity,
    sister_key: &SisterKeyPair,
) -> Result<Option<PeerRecord>, String> {
    let endpoint = misaka_runtime::iroh_endpoint_store::IrohEndpointStore::load(data_dir)
        .map_err(|error| error.to_string())?;
    let binding = TransportBindingStore::load(data_dir).map_err(|error| error.to_string())?;
    let (Some(endpoint), Some(binding)) = (endpoint, binding) else {
        return Ok(None);
    };
    if !binding.verify()
        || binding.network_id != network_id
        || binding.sister_id != identity.id
        || binding.sister_public_key != sister_key.public_key()
    {
        return Err("persisted Iroh transport binding does not match the local Sister".to_string());
    }
    Ok(Some(PeerRecord::issue(
        network_id,
        identity.id.as_u64(),
        NetworkEndpoint::Iroh(endpoint).to_string(),
        binding,
        unix_now(),
        sister_key,
    )))
}

fn join_network_invite(
    invite_path: &Path,
    requested_network_id: Option<NetworkId>,
) -> Result<(), String> {
    let json = std::fs::read_to_string(invite_path)
        .map_err(|error| format!("read Network invite {}: {error}", invite_path.display()))?;
    let invite: NetworkInvite = serde_json::from_str(&json)
        .map_err(|error| format!("decode Network invite {}: {error}", invite_path.display()))?;
    let now = unix_now();
    if !invite.verify(now) {
        return Err(
            "Network invite signature, membership, or validity window is invalid".to_string(),
        );
    }
    if let Some(requested) = requested_network_id {
        if requested != invite.network_id {
            return Err("--network-id does not match the Network invite".to_string());
        }
    }
    let membership = invite.membership.as_ref().ok_or_else(|| {
        "this v0 join flow requires an invite with a target membership certificate".to_string()
    })?;
    let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
    let identity = IdentityStore::load_or_init(None, 31700).map_err(|error| error.to_string())?;
    let sister_key = SisterKeyStore::load_or_init(&data_dir).map_err(|error| error.to_string())?;
    if membership.sister_id != identity.id
        || membership.sister_public_key != sister_key.public_key()
    {
        return Err(format!(
            "invite is for Sister {} / {}, but local Sister is {} / {}",
            membership.sister_id,
            membership.sister_public_key,
            identity.id,
            sister_key.public_key()
        ));
    }

    NetworkIdStore::load_or_init(&data_dir, Some(invite.network_id))
        .map_err(|error| error.to_string())?;
    NetworkAuthorityStore::install_descriptor(&data_dir, &invite.authority)
        .map_err(|error| error.to_string())?;
    if let Some(existing) = MembershipStore::load(&data_dir).map_err(|error| error.to_string())? {
        if existing != *membership {
            return Err(
                "a different local membership certificate is already installed".to_string(),
            );
        }
    } else {
        MembershipStore::save(&data_dir, membership).map_err(|error| error.to_string())?;
    }

    let records = invite
        .bootstrap_records
        .into_iter()
        .map(|record| (record.sister_id.as_u64(), record))
        .collect::<HashMap<_, _>>();
    PeerRecordStore::save_to_dir(&data_dir, &records).map_err(|error| error.to_string())?;
    println!(
        "joined Network {} as Sister {} with {} bootstrap peer record(s)",
        invite.network_id,
        identity.id,
        records.len()
    );
    Ok(())
}

async fn proxy_tunnel(
    mut local: tokio::net::TcpStream,
    endpoint: NetworkEndpoint,
    sister_id: u64,
    peer_certificate: Option<&[u8]>,
    remote: SocketAddr,
    iroh_options: IrohTransportOptions,
) -> Result<(), String> {
    let mut stream =
        connect_peer_stream(endpoint, sister_id, peer_certificate, iroh_options).await?;
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
    iroh_options: IrohTransportOptions,
) -> Result<misaka_network::NetworkStream, String> {
    let network_id = local_network_id()?;
    let stream = if matches!(&endpoint, NetworkEndpoint::Iroh(_)) {
        if peer_certificate.is_some() {
            return Err("Iroh streams use endpoint-authenticated encryption; do not provide a TLS certificate".to_string());
        }
        let backend = bind_iroh_client_backend(iroh_options).await?;
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            backend.connect_for_network(endpoint, network_id),
        )
        .await
        .map_err(|_| "Iroh stream connect timed out".to_string())?
        .map_err(|error| error.to_string())?;
        if let Some(auth) = load_cli_authenticated_session(network_id)? {
            misaka_runtime::authenticated_session::authenticate_client(stream, &auth, Some(peer_id))
                .await
                .map_err(|error| format!("Iroh stream authentication failed: {error}"))?
        } else {
            stream
        }
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
        tokio::time::timeout(
            Duration::from_secs(10),
            backend.connect_for_network(endpoint, network_id),
        )
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

fn local_network_id() -> Result<misaka_core::NetworkId, String> {
    let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
    NetworkIdStore::load_or_init(&data_dir, None).map_err(|error| error.to_string())
}

fn load_cli_authenticated_session(
    network_id: misaka_core::NetworkId,
) -> Result<Option<misaka_runtime::authenticated_session::AuthenticatedSessionConfig>, String> {
    let data_dir = IdentityStore::config_dir().map_err(|error| error.to_string())?;
    let authority = misaka_runtime::network_authority_store::NetworkAuthorityStore::load(&data_dir)
        .map_err(|error| error.to_string())?;
    let membership = misaka_runtime::membership_store::MembershipStore::load(&data_dir)
        .map_err(|error| error.to_string())?;
    let binding = TransportBindingStore::load(&data_dir).map_err(|error| error.to_string())?;
    if authority.is_none() && membership.is_none() && binding.is_none() {
        return Ok(None);
    }
    let identity = IdentityStore::load()
        .map_err(|error| error.to_string())?
        .ok_or("Iroh authentication requires a persisted Sister identity")?;
    let sister_key = misaka_runtime::sister_key_store::SisterKeyStore::load(&data_dir)
        .map_err(|error| error.to_string())?
        .ok_or("Iroh authentication requires a persisted Sister identity key")?;
    load_authenticated_session(&data_dir, network_id, &identity, &sister_key)
}

async fn bind_iroh_backend(
    data_dir: &Path,
    iroh_options: IrohTransportOptions,
) -> Result<misaka_network::IrohBackend, String> {
    let secret_key = misaka_runtime::iroh_identity_store::IrohIdentityStore::load_or_init(data_dir)
        .map_err(|error| error.to_string())?;
    match (iroh_options.relay, iroh_options.relay_only) {
        (Some(relay_url), true) => {
            misaka_network::IrohBackend::bind_with_secret_key_and_relay_only(secret_key, relay_url)
                .await
        }
        (Some(relay_url), false) => {
            misaka_network::IrohBackend::bind_with_secret_key_and_relay(secret_key, relay_url).await
        }
        (None, false) => misaka_network::IrohBackend::bind_with_secret_key(secret_key).await,
        (None, true) => unreachable!("CLI requires --iroh-relay with --iroh-relay-only"),
    }
    .map_err(|error| error.to_string())
}

fn load_authenticated_session(
    data_dir: &Path,
    network_id: misaka_core::NetworkId,
    identity: &misaka_core::SisterIdentity,
    sister_key: &misaka_core::SisterKeyPair,
) -> Result<Option<misaka_runtime::authenticated_session::AuthenticatedSessionConfig>, String> {
    let authority = misaka_runtime::network_authority_store::NetworkAuthorityStore::load(data_dir)
        .map_err(|error| error.to_string())?;
    let membership = misaka_runtime::membership_store::MembershipStore::load(data_dir)
        .map_err(|error| error.to_string())?;
    let binding = TransportBindingStore::load(data_dir).map_err(|error| error.to_string())?;

    match (authority, membership, binding) {
        (None, None, None) => Ok(None),
        (Some(authority), Some(membership), Some(binding)) => {
            if authority.network_id != network_id
                || membership.sister_id != identity.id
                || membership.sister_public_key != sister_key.public_key()
                || !membership.verify(&authority)
                || !membership.is_valid_at(unix_now())
                || binding.network_id != network_id
                || binding.sister_id != identity.id
                || binding.sister_public_key != sister_key.public_key()
                || !binding.verify()
            {
                return Err(
                    "local Network authority, membership, or transport binding is invalid"
                        .to_string(),
                );
            }
            let mut auth =
                misaka_runtime::authenticated_session::AuthenticatedSessionConfig::new(
                    network_id,
                    identity.id.as_u64(),
                    sister_key.clone(),
                    authority,
                    membership,
                    binding,
                );
            let revocations =
                misaka_runtime::revocation_store::RevocationStore::load(data_dir)
                    .map_err(|error| error.to_string())?;
            for record in revocations {
                if record.network_id == network_id {
                    if !record.verify(&auth.authority) {
                        return Err("local revocation record has an invalid signature".to_string());
                    }
                    auth.revoked_membership_serials.push(record.membership_serial);
                }
            }
            if auth
                .revoked_membership_serials
                .contains(&auth.membership_certificate.serial)
            {
                return Err("local Sister membership has been revoked".to_string());
            }
            Ok(Some(auth))
        }
        _ => Err(
            "authenticated Iroh mode requires network.json, membership.bin, and transport-binding.json"
                .to_string(),
        ),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn bind_iroh_client_backend(
    iroh_options: IrohTransportOptions,
) -> Result<misaka_network::IrohBackend, String> {
    let secret_key = iroh::SecretKey::generate();
    match (iroh_options.relay, iroh_options.relay_only) {
        (Some(relay_url), true) => {
            misaka_network::IrohBackend::bind_with_secret_key_and_relay_only(secret_key, relay_url)
                .await
        }
        (Some(relay_url), false) => {
            misaka_network::IrohBackend::bind_with_secret_key_and_relay(secret_key, relay_url).await
        }
        (None, false) => misaka_network::IrohBackend::bind_with_secret_key(secret_key).await,
        (None, true) => unreachable!("CLI requires --iroh-relay with --iroh-relay-only"),
    }
    .map_err(|error| error.to_string())
}

async fn hash_file_v0(file: &mut tokio::fs::File) -> Result<[u8; 32], String> {
    let mut state = [
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
        update_transfer_digest(&mut state, &buffer[..read]);
    }
    Ok(finalize_transfer_digest(state))
}

async fn hash_file_v1(file: &mut tokio::fs::File) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = tokio::io::AsyncReadExt::read(file, &mut buffer)
            .await
            .map_err(|error| format!("hash source: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn mark_ready(path: Option<&Path>) -> Result<(), String> {
    if let Some(path) = path {
        std::fs::write(path, b"ready")
            .map_err(|error| format!("write stream ready marker {}: {error}", path.display()))?;
    }
    Ok(())
}

async fn read_cli_bincode_frame<T: DeserializeOwned>(
    stream: &mut misaka_network::NetworkStream,
    max_len: usize,
) -> Result<T, String> {
    let mut length = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(stream, &mut length)
        .await
        .map_err(|error| format!("read transfer frame length: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max_len {
        return Err("transfer frame exceeds limit".to_string());
    }
    let mut bytes = vec![0u8; length];
    tokio::io::AsyncReadExt::read_exact(stream, &mut bytes)
        .await
        .map_err(|error| format!("read transfer frame: {error}"))?;
    bincode::deserialize(&bytes).map_err(|error| format!("decode transfer frame: {error}"))
}

async fn write_cli_bincode_frame<T: Serialize>(
    stream: &mut misaka_network::NetworkStream,
    value: &T,
) -> Result<(), String> {
    let bytes =
        bincode::serialize(value).map_err(|error| format!("encode transfer frame: {error}"))?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|error| format!("write transfer frame length: {error}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|error| format!("write transfer frame: {error}"))
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

async fn sustained(
    stream: &mut misaka_network::NetworkStream,
) -> Result<StreamProbeMetrics, String> {
    let payload = b"sustained-stream-message";
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut exchanges = 0u64;
    while tokio::time::Instant::now() < deadline {
        exchange(stream, payload).await?;
        exchanges += 1;
    }
    if exchanges < 2 {
        return Err("sustained stream completed fewer than two exchanges".to_string());
    }
    Ok(StreamProbeMetrics {
        exchanges: Some(exchanges),
        elapsed_ms: Some(started.elapsed().as_millis()),
        ..StreamProbeMetrics::default()
    })
}

async fn stability(
    stream: &mut misaka_network::NetworkStream,
    duration_secs: u64,
) -> Result<StreamProbeMetrics, String> {
    let payload = b"stability-heartbeat";
    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(duration_secs);
    let mut exchanges = 0u64;
    while tokio::time::Instant::now() < deadline {
        exchange(stream, payload).await?;
        exchanges += 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(StreamProbeMetrics {
        exchanges: Some(exchanges),
        elapsed_ms: Some(started.elapsed().as_millis()),
        ..StreamProbeMetrics::default()
    })
}

async fn large_stream(
    stream: misaka_network::NetworkStream,
) -> Result<(StreamProbeMetrics, misaka_network::PathInfo), String> {
    let started = std::time::Instant::now();
    let initial_path = stream.path_info();
    let path_provider = stream.path_info_provider();
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
    let elapsed = started.elapsed();
    let throughput_mib_s =
        received as f64 / elapsed.as_secs_f64().max(f64::EPSILON) / (1024.0 * 1024.0);
    Ok((
        StreamProbeMetrics {
            bytes: Some(received),
            elapsed_ms: Some(elapsed.as_millis()),
            throughput_mib_s: Some(throughput_mib_s),
            ..StreamProbeMetrics::default()
        },
        path_provider
            .map(|provider| provider())
            .unwrap_or(initial_path),
    ))
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
    use super::{
        deterministic_hash, fill_deterministic, Cli, Command, NetworkCommand, StreamProbeReport,
    };
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
                endpoint: None,
                mode,
                ready_file,
                ..
            } if addr == Some("127.0.0.1:31701".parse::<SocketAddr>().unwrap())
                && mode == "large"
                && ready_file.as_deref().is_some_and(|path| path == std::path::Path::new("/tmp/misaka-stream-ready"))
        ));
    }

    #[test]
    fn stream_test_accepts_a_transport_neutral_endpoint() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--endpoint",
            "iroh://endpoint-address",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::StreamTest {
                addr: None,
                endpoint: Some(endpoint),
                ..
            } if endpoint == "iroh://endpoint-address"
        ));
    }

    #[test]
    fn stream_test_accepts_an_explicit_iroh_relay() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--endpoint",
            "iroh://endpoint-address",
            "--iroh-relay",
            "https://relay.example",
        ])
        .unwrap();
        assert_eq!(cli.iroh_relay.as_deref(), Some("https://relay.example"));
    }

    #[test]
    fn stream_test_accepts_relay_only_measurement_mode() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--endpoint",
            "iroh://endpoint-address",
            "--iroh-relay",
            "https://relay.example",
            "--iroh-relay-only",
        ])
        .unwrap();
        assert!(cli.iroh_relay_only);
    }

    #[test]
    fn relay_only_requires_an_explicit_relay() {
        assert!(Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--endpoint",
            "iroh://endpoint-address",
            "--iroh-relay-only",
        ])
        .is_err());
    }

    #[test]
    fn stream_test_accepts_json_measurement_output() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--addr",
            "127.0.0.1:31701",
            "--mode",
            "bidirectional",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::StreamTest { json: true, .. }
        ));
    }

    #[test]
    fn endpoint_command_accepts_json_output_and_network_id() {
        let cli = Cli::try_parse_from([
            "misaka",
            "--network-id",
            "01234567-89ab-cdef-0123-456789abcdef",
            "endpoint",
            "--json",
        ])
        .unwrap();
        assert_eq!(
            cli.network_id.as_deref(),
            Some("01234567-89ab-cdef-0123-456789abcdef")
        );
        assert!(matches!(cli.command, Command::Endpoint { json: true }));
    }

    #[test]
    fn start_accepts_probe_only_mode() {
        let cli = Cli::try_parse_from(["misaka", "start", "--probe-only"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Start {
                probe_only: true,
                ..
            }
        ));
    }

    #[test]
    fn network_commands_accept_init_invite_and_join() {
        let init = Cli::try_parse_from(["misaka", "network", "init"]).unwrap();
        assert!(matches!(
            init.command,
            Command::Network {
                command: NetworkCommand::Init
            }
        ));

        let invite = Cli::try_parse_from([
            "misaka",
            "network",
            "invite",
            "--output",
            "/tmp/invite.json",
            "--sister-id",
            "#42",
            "--sister-public-key",
            "00".repeat(32).as_str(),
        ])
        .unwrap();
        assert!(matches!(
            invite.command,
            Command::Network {
                command: NetworkCommand::Invite { .. }
            }
        ));

        let join = Cli::try_parse_from(["misaka", "network", "join", "/tmp/invite.json"]).unwrap();
        assert!(matches!(
            join.command,
            Command::Network {
                command: NetworkCommand::Join { .. }
            }
        ));
    }

    #[test]
    fn relay_commands_accept_integrated_and_relay_only_modes() {
        let sister = Cli::try_parse_from([
            "misaka",
            "start",
            "--relay",
            "--relay-bind",
            "127.0.0.1:4430",
        ])
        .unwrap();
        assert!(matches!(
            sister.command,
            Command::Start {
                relay: true,
                relay_bind,
                ..
            } if relay_bind == "127.0.0.1:4430".parse::<SocketAddr>().unwrap()
        ));

        let relay = Cli::try_parse_from(["misaka", "relay", "--bind", "127.0.0.1:4430"]).unwrap();
        assert!(matches!(
            relay.command,
            Command::Relay { bind, .. } if bind == "127.0.0.1:4430".parse::<SocketAddr>().unwrap()
        ));
    }

    #[test]
    fn relay_commands_accept_tls_configuration() {
        let cli = Cli::try_parse_from([
            "misaka",
            "relay",
            "--bind",
            "0.0.0.0:443",
            "--http-bind",
            "0.0.0.0:80",
            "--tls-cert",
            "/etc/misaka/relay.crt",
            "--tls-key",
            "/etc/misaka/relay.key",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Relay {
                http_bind: Some(http_bind),
                tls_cert: Some(tls_cert),
                tls_key: Some(tls_key),
                ..
            } if http_bind == "0.0.0.0:80".parse::<SocketAddr>().unwrap()
                && tls_cert == std::path::Path::new("/etc/misaka/relay.crt")
                && tls_key == std::path::Path::new("/etc/misaka/relay.key")
        ));
    }

    #[test]
    fn stream_test_accepts_a_bounded_stability_duration() {
        let cli = Cli::try_parse_from([
            "misaka",
            "stream-test",
            "--endpoint",
            "iroh://endpoint-address",
            "--mode",
            "stability",
            "--duration-secs",
            "1800",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::StreamTest {
                mode,
                duration_secs: Some(1800),
                ..
            } if mode == "stability"
        ));
    }

    #[test]
    fn connect_accepts_a_display_sister_id() {
        let cli = Cli::try_parse_from(["misaka", "connect", "#10032"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Connect { sister } if sister == "#10032"
        ));
    }

    #[test]
    fn stream_probe_report_uses_nullable_optional_measurements() {
        let report = StreamProbeReport {
            mode: "connect".into(),
            backend: "direct-tcp".into(),
            route: "direct".into(),
            rtt_ms: None,
            path_switches: 0,
            local_endpoint: Some("127.0.0.1:40000".into()),
            remote_endpoint: Some("127.0.0.1:31701".into()),
            setup_ms: 4,
            probe_rtt_ms: None,
            exchanges: None,
            bytes: None,
            elapsed_ms: None,
            throughput_mib_s: None,
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["mode"], "connect");
        assert_eq!(json["setup_ms"], 4);
        assert!(json["rtt_ms"].is_null());
        assert!(json["throughput_mib_s"].is_null());
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

    #[test]
    fn parallel_copy_accepts_bounded_worker_count() {
        let cli = Cli::try_parse_from([
            "misaka",
            "cp",
            "source",
            "#10032:/tmp/result",
            "--resume",
            "--parallel",
            "4",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Cp {
                resume: true,
                parallel: 4,
                ..
            }
        ));
    }

    #[test]
    fn parallel_copy_rejects_zero_workers() {
        assert!(Cli::try_parse_from([
            "misaka",
            "cp",
            "source",
            "#10032:/tmp/result",
            "--parallel",
            "0",
        ])
        .is_err());
    }

    #[test]
    fn resumable_copy_defaults_to_sequential_v1() {
        let cli = Cli::try_parse_from(["misaka", "cp", "source", "#10032:/tmp/result", "--resume"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Command::Cp {
                resume: true,
                parallel: 1,
                ..
            }
        ));
    }
}
