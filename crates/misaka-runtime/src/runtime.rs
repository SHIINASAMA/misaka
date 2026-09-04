//! SisterRuntime orchestration.
//!
//! This type owns the lifecycle of one Sister. Protocol handling and domain
//! behavior stay in `SisterNode`; this module assembles services, starts
//! cancellable background loops, and accepts inbound connections.

use crate::config::{RuntimeConfig, StreamBackend};
use crate::content_store::ContentStore;
use crate::node::SisterNode;
use crate::shutdown::Shutdown;
use misaka_core::protocol::{
    finalize_transfer_digest, transfer_digest, update_transfer_digest, TransferRequest,
    TransferResult, TransferV1Ack, TransferV1Chunk, TransferV1Request, TransferV1Resume,
    TransferV2Ack, TransferV2Operation, TransferV2Request, TransferV2Resume, TunnelRequest,
    TRANSFER_MAGIC, TRANSFER_V1_CHUNK_SIZE, TRANSFER_V1_MAGIC, TRANSFER_V2_MAGIC, TUNNEL_MAGIC,
};
use misaka_core::{CommandAuthorization, Permission, SisterIdentity};
use misaka_network::{NetworkBackend, NetworkEndpoint};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};

/// Orchestrates one complete Sister runtime.
pub struct SisterRuntime {
    node: SisterNode,
    /// Legacy TCP control listener. Iroh nodes use the authenticated Iroh
    /// control channel instead and deliberately do not bind :31700.
    listener: Option<TcpListener>,
    stream_listener: Option<StreamAcceptor>,
    shutdown: Shutdown,
    configured_peers: Vec<SocketAddr>,
}

enum StreamAcceptor {
    Direct(misaka_network::NetworkListener),
    Iroh(misaka_network::IrohBackend),
}

impl SisterRuntime {
    /// Construct the runtime and bind its listeners. Configured peers are
    /// connected by a cancellable retry task once `run` starts.
    pub async fn new(
        identity: SisterIdentity,
        encryption_key: [u8; 32],
        config: RuntimeConfig,
        peers: Vec<SocketAddr>,
    ) -> crate::Result<Self> {
        let advertise_host = config.advertise_host;
        let introspection_addr = config.introspection_addr;
        let stream_port = config.stream_port;
        let network_id = config.network_id;
        let stream_security = config.stream_security.clone();
        let stream_backend = config.stream_backend.clone();
        let shutdown = Shutdown::new();
        let mut node = SisterNode::new(identity, encryption_key, config);
        node.set_shutdown_token(shutdown.token());
        if let Some(host) = advertise_host {
            node.set_advertise_host(&host.to_string());
        }

        if let Some(addr) = introspection_addr {
            let bound = node.spawn_introspection_server(addr).await?;
            tracing::info!(
                event = "introspection_started",
                address = %bound,
                "introspection endpoint started"
            );
        }
        let listener = if matches!(&stream_backend, StreamBackend::DirectTcp) {
            Some(node.start_listener().await?)
        } else {
            tracing::info!(
                event = "legacy_control_listener_disabled",
                "Iroh backend owns the control plane; legacy TCP listener is disabled"
            );
            None
        };
        let backend = misaka_network::DirectTcpBackend;
        let stream_listener = match (stream_port, stream_backend) {
            (Some(port), StreamBackend::DirectTcp) => match stream_security {
                crate::config::StreamSecurity::InsecureLoopback => Some(StreamAcceptor::Direct(
                    backend
                        .listen_for_network(
                            NetworkEndpoint::Tcp(format!("127.0.0.1:{port}").parse()?),
                            network_id,
                        )
                        .await
                        .map_err(|error| crate::Error::Network(error.to_string()))?,
                )),
                crate::config::StreamSecurity::MutualTls {
                    identity,
                    trusted_peer_certificates,
                } => {
                    if trusted_peer_certificates.is_empty() {
                        return Err(crate::Error::Network(
                            "secure stream requires at least one trusted peer certificate"
                                .to_string(),
                        ));
                    }
                    Some(StreamAcceptor::Direct(
                        misaka_network::tls::TlsServer::new(
                            identity
                                .server_config_with_trusted_client_certificates(
                                    &trusted_peer_certificates,
                                )
                                .map_err(|error| crate::Error::Network(error.to_string()))?,
                        )
                        .listen(NetworkEndpoint::Tcp(format!("0.0.0.0:{port}").parse()?))
                        .await
                        .map_err(|error| crate::Error::Network(error.to_string()))?,
                    ))
                }
            },
            (None, StreamBackend::DirectTcp) => None,
            (stream_port, StreamBackend::Iroh(backend)) => {
                if stream_security.is_secure() {
                    return Err(crate::Error::Network(
                        "--stream-secure is only valid with the direct-tcp backend".to_string(),
                    ));
                }
                if stream_port.is_some() {
                    tracing::debug!(
                        event = "iroh_stream_port_ignored",
                        "Iroh selects its own UDP bind port"
                    );
                }
                let endpoint = NetworkEndpoint::Iroh(backend.endpoint_addr());
                backend
                    .listen_for_network(endpoint, network_id)
                    .await
                    .map_err(|error| crate::Error::Network(error.to_string()))?;
                Some(StreamAcceptor::Iroh(backend))
            }
        };

        // Configured peers are connected after `run` starts accepting inbound
        // sockets. Connecting synchronously here can deadlock when two fresh
        // Sisters simultaneously wait for each other's Hello response.
        Ok(Self {
            node,
            listener,
            stream_listener,
            shutdown,
            configured_peers: peers,
        })
    }

    /// Clone the cancellation handle used to request a graceful stop.
    pub fn shutdown(&self) -> Shutdown {
        self.shutdown.clone()
    }

    /// Return the loopback address for the optional experimental stream listener.
    pub fn stream_addr(&self) -> Option<SocketAddr> {
        if matches!(self.node.config.stream_backend, StreamBackend::Iroh(_)) {
            return None;
        }
        match self.stream_listener.as_ref()? {
            StreamAcceptor::Direct(listener) => {
                let port = listener.local_addr().port();
                Some(SocketAddr::new(self.node.listen_addr.ip(), port))
            }
            StreamAcceptor::Iroh(_) => None,
        }
    }

    /// Start discovery, state exchange, execution, cleanup, and work stealing.
    /// Returns after the shared shutdown handle is cancelled.
    pub async fn run(self) -> crate::Result<()> {
        let SisterRuntime {
            node,
            listener,
            stream_listener,
            shutdown: _shutdown,
            configured_peers,
        } = self;
        let background = spawn_background_tasks(&node, configured_peers, stream_listener);
        let mut inbound = JoinSet::new();
        let mut runtime_error = None;

        loop {
            tokio::select! {
                _ = node.shutdown.cancelled() => break,
                accepted = async {
                    match &listener {
                        Some(listener) => listener.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match accepted {
                        Ok((stream, addr)) => {
                            let node = node.clone();
                            inbound.spawn(async move {
                                let _ = node.handle_inbound(stream, addr).await;
                            });
                        }
                        Err(error) => {
                            runtime_error = Some(crate::Error::Io(error));
                            _shutdown.cancel();
                            break;
                        }
                    }
                }
            }
        }

        let reason = if runtime_error.is_some() {
            "listener_error"
        } else {
            "shutdown"
        };
        tracing::info!(
            event = "sister_stopped",
            sister_id = node.identity.id.as_u64(),
            reason,
            "Sister stopped"
        );

        // Inbound connections are request-scoped. Abort any that are still
        // blocked on a socket, then drain the service loops within the bound.
        inbound.abort_all();
        while inbound.join_next().await.is_some() {}
        let drain = futures_util::future::join_all(background);
        if tokio::time::timeout(node.config.shutdown_timeout, drain)
            .await
            .is_err()
        {
            tracing::warn!(
                event = "shutdown_timeout",
                sister_id = node.identity.id.as_u64(),
                timeout_ms = node.config.shutdown_timeout.as_millis() as u64,
                "runtime shutdown drain timed out"
            );
        }
        if let StreamBackend::Iroh(backend) = &node.config.stream_backend {
            backend.close().await;
        }
        if let Some(error) = runtime_error {
            return Err(error);
        }
        Ok(())
    }
}

async fn configured_peer_loop(node: SisterNode, peers: Vec<SocketAddr>) {
    tracing::info!(
        event = "configured_peer_retry_started",
        sister_id = node.identity.id.as_u64(),
        peer_count = peers.len(),
        "configured peer retry loop started"
    );
    let mut reported_failures = HashSet::new();
    let mut connected = HashSet::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = node.shutdown.cancelled() => break,
            _ = interval.tick() => {
                for peer in &peers {
                    if connected.contains(peer) {
                        continue;
                    }
                    let result = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        node.add_known_peer(*peer),
                    )
                    .await;
                    match result {
                        Ok(Ok(())) => {
                            connected.insert(*peer);
                        }
                        Ok(Err(error)) => {
                            if reported_failures.insert(*peer) {
                                tracing::warn!(
                                    event = "configured_peer_connect_failed",
                                    sister_id = node.identity.id.as_u64(),
                                    peer_addr = %peer,
                                    error = %error,
                                    "configured peer connection failed; retrying"
                                );
                            }
                        }
                        Err(_) => {
                            if reported_failures.insert(*peer) {
                                tracing::warn!(
                                    event = "configured_peer_connect_failed",
                                    sister_id = node.identity.id.as_u64(),
                                    peer_addr = %peer,
                                    error = "timeout",
                                    "configured peer connection failed; retrying"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn spawn_background_tasks(
    node: &SisterNode,
    configured_peers: Vec<SocketAddr>,
    stream_listener: Option<StreamAcceptor>,
) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();
    if !configured_peers.is_empty() {
        let peer_node = node.clone();
        tasks.push(tokio::spawn(async move {
            configured_peer_loop(peer_node, configured_peers).await;
        }));
    }

    let discovery_node = node.clone();
    let discovery = tokio::spawn(async move {
        if matches!(
            discovery_node.config.discovery,
            crate::config::DiscoveryMode::Mdns
        ) {
            let _ = discovery_node.mdns_loop().await;
        } else {
            discovery_node.shutdown.cancelled().await;
        }
    });

    let state_node = node.clone();
    let state = tokio::spawn(async move {
        let _ = state_node.state_broadcast_loop().await;
    });

    let cleanup_node = node.clone();
    let cleanup = tokio::spawn(async move {
        let _ = cleanup_node.cleanup_loop().await;
    });

    let executor_node = node.clone();
    let executor = tokio::spawn(async move {
        let _ = executor_node.local_executor_loop().await;
    });

    let stealing_node = node.clone();
    let stealing = tokio::spawn(async move {
        let _ = stealing_node.work_stealing_loop(1).await;
    });

    tasks.extend([discovery, state, cleanup, executor, stealing]);
    if let Some(acceptor) = stream_listener {
        let stream_node = node.clone();
        tasks.push(tokio::spawn(async move {
            match acceptor {
                StreamAcceptor::Direct(listener) => stream_accept_loop(stream_node, listener).await,
                StreamAcceptor::Iroh(backend) => {
                    iroh_session_accept_loop(stream_node, backend).await;
                }
            }
        }));
    }
    tasks
}

async fn stream_accept_loop(node: SisterNode, listener: misaka_network::NetworkListener) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = node.shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        let session_node = node.clone();
                        sessions.spawn(async move {
                            log_and_echo_stream(session_node, stream, addr).await;
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            event = "stream_handshake_failed",
                            sister_id = node.identity.id.as_u64(),
                            error = %error,
                            "network stream handshake failed"
                        );
                    }
                }
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
}

async fn iroh_session_accept_loop(node: SisterNode, backend: misaka_network::IrohBackend) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            _ = node.shutdown.cancelled() => break,
            accepted = backend.accept_session_for_network(node.config.network_id) => {
                match accepted {
                    Ok(session) => {
                        let session_node = node.clone();
                        sessions.spawn(async move {
                            iroh_session_loop(session_node, session).await;
                        });
                    }
                    Err(error) => {
                        if !matches!(error, misaka_network::NetworkError::Closed) {
                            tracing::warn!(
                                event = "iroh_session_accept_failed",
                                sister_id = node.identity.id.as_u64(),
                                error = %error,
                                "Iroh session accept failed"
                            );
                        }
                    }
                }
            }
        }
    }
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
}

async fn iroh_session_loop(node: SisterNode, session: misaka_network::IrohSession) {
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            _ = node.shutdown.cancelled() => break,
            accepted = session.accept_stream() => {
                match accepted {
                    Ok(stream) => {
                        let stream_node = node.clone();
                        let auth = node.config.authenticated_session.clone();
                        streams.spawn(async move {
                            let stream = match auth.as_ref() {
                                Some(auth) => {
                                    match crate::authenticated_session::authenticate_server(
                                        stream, auth,
                                    )
                                    .await
                                    {
                                        Ok(stream) => stream,
                                        Err(error) => {
                                            tracing::warn!(
                                                event = "iroh_authenticated_session_rejected",
                                                sister_id = stream_node.identity.id.as_u64(),
                                                error = %error,
                                                "Iroh stream rejected before service dispatch"
                                            );
                                            return;
                                        }
                                    }
                                }
                                None => stream,
                            };
                            serve_iroh_stream(stream_node, stream).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
}

async fn serve_iroh_stream(node: SisterNode, mut stream: misaka_network::NetworkStream) {
    if let Err(error) = stream.write_all(b"world").await {
        tracing::debug!(
            event = "iroh_stream_greeting_failed",
            sister_id = node.identity.id.as_u64(),
            error = %error,
            "Iroh logical stream closed before service selection"
        );
        return;
    }
    if let Err(error) = stream.flush().await {
        tracing::debug!(
            event = "iroh_stream_greeting_flush_failed",
            sister_id = node.identity.id.as_u64(),
            error = %error,
            "Iroh logical stream failed to flush service greeting"
        );
        return;
    }
    let mut prefix = [0u8; 4];
    if let Err(error) = stream.read_exact(&mut prefix).await {
        tracing::debug!(
            event = "iroh_stream_prefix_failed",
            sister_id = node.identity.id.as_u64(),
            error = %error,
            "Iroh logical stream closed before service dispatch"
        );
        return;
    }
    if prefix == *crate::control_channel::CONTROL_MAGIC {
        if let Err(error) = crate::control_channel::serve(&node, stream).await {
            tracing::warn!(
                event = "iroh_control_channel_failed",
                sister_id = node.identity.id.as_u64(),
                error = %error,
                "Iroh control channel failed"
            );
        }
        return;
    }
    let stream = crate::control_channel::prepend(stream, prefix);
    log_and_echo_stream_after_greeting(node, stream, SocketAddr::from(([0, 0, 0, 0], 0))).await;
}

async fn log_and_echo_stream(
    session_node: SisterNode,
    stream: misaka_network::NetworkStream,
    addr: SocketAddr,
) {
    let registration = session_node
        .stream_registry
        .register(&stream, (addr.port() != 0).then_some(addr));
    let stats = stream.stats();
    let connected_for = stream.connected_for();
    let path = stream.path_info();
    let object_store_root = session_node.peers.data_dir().join("objects");
    let result = echo_stream(
        stream,
        &object_store_root,
        session_node.config.probe_only,
        Some(&session_node),
    )
    .await;
    log_stream_close(&session_node, &stats, connected_for, &path, addr, result);
    drop(registration);
}

async fn log_and_echo_stream_after_greeting(
    session_node: SisterNode,
    stream: misaka_network::NetworkStream,
    addr: SocketAddr,
) {
    let registration = session_node
        .stream_registry
        .register(&stream, (addr.port() != 0).then_some(addr));
    let stats = stream.stats();
    let connected_for = stream.connected_for();
    let path = stream.path_info();
    let object_store_root = session_node.peers.data_dir().join("objects");
    let result = echo_stream_after_greeting(
        stream,
        &object_store_root,
        session_node.config.probe_only,
        Some(&session_node),
    )
    .await;
    log_stream_close(&session_node, &stats, connected_for, &path, addr, result);
    drop(registration);
}

fn log_stream_close(
    session_node: &SisterNode,
    stats: &misaka_network::StreamStats,
    connected_for: std::time::Duration,
    path: &misaka_network::PathInfo,
    addr: SocketAddr,
    result: std::io::Result<()>,
) {
    tracing::debug!(
        event = "stream_closed",
        sister_id = session_node.identity.id.as_u64(),
        peer_addr = %addr,
        backend = %path.backend,
        route = %path.route,
        local_endpoint = ?path.local_endpoint,
        remote_endpoint = ?path.remote_endpoint,
        connected_for_ms = connected_for.as_millis() as u64,
        tx_bytes = stats.tx_bytes(),
        rx_bytes = stats.rx_bytes(),
        error = ?result.as_ref().err(),
        "network stream closed"
    );
}

async fn echo_stream(
    mut stream: misaka_network::NetworkStream,
    object_store_root: &Path,
    probe_only: bool,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    stream.write_all(b"world").await?;
    echo_stream_after_greeting(stream, object_store_root, probe_only, node).await
}

async fn echo_stream_after_greeting(
    mut stream: misaka_network::NetworkStream,
    object_store_root: &Path,
    probe_only: bool,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    let mut preamble = [0u8; TRANSFER_MAGIC.len()];
    if stream.read_exact(&mut preamble).await.is_err() {
        return Ok(());
    }
    if preamble == *TRANSFER_MAGIC {
        if probe_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "probe-only listener rejects file transfer",
            ));
        }
        return receive_transfer_with_node(stream, node).await;
    }
    if preamble == *TRANSFER_V1_MAGIC {
        if probe_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "probe-only listener rejects file transfer",
            ));
        }
        return receive_transfer_v1_with_node(stream, node).await;
    }
    if preamble == *TRANSFER_V2_MAGIC {
        if probe_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "probe-only listener rejects file transfer",
            ));
        }
        return receive_transfer_v2_with_store_and_node(
            stream,
            Some(object_store_root.to_owned()),
            node,
        )
        .await;
    }
    if preamble == *TUNNEL_MAGIC {
        if probe_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "probe-only listener rejects tunnel",
            ));
        }
        return receive_tunnel_with_node(stream, node).await;
    }
    stream.write_all(&preamble).await?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        stream.write_all(&buffer[..read]).await?;
    }
}

async fn receive_transfer_with_node(
    mut stream: misaka_network::NetworkStream,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let header_len = u32::from_be_bytes(length) as usize;
    if header_len > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer header exceeds 1 MiB",
        ));
    }
    let mut header = vec![0u8; header_len];
    stream.read_exact(&mut header).await?;
    let request: TransferRequest = bincode::deserialize(&header)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    authorize_stream_operation(
        node,
        request.authorization.as_ref(),
        Permission::FileSend,
        &[format!("destination={}", request.destination)],
        true,
    )
    .await?;
    let destination = std::path::PathBuf::from(&request.destination);
    if let Some(parent) = destination.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::File::create(&destination).await?;
    let mut remaining = request.size;
    let mut written = 0u64;
    let mut digest = [
        0xcbf29ce484222325,
        0x84222325cbf29ce4,
        0x9e3779b185ebca87,
        0xd6e8feb86659fd93,
    ];
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let read_limit = remaining.min(buffer.len() as u64) as usize;
        let read = stream.read(&mut buffer[..read_limit]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "transfer ended before declared size",
            ));
        }
        file.write_all(&buffer[..read]).await?;
        update_transfer_digest(&mut digest, &buffer[..read]);
        remaining -= read as u64;
        written += read as u64;
    }
    file.flush().await?;
    let digest = finalize_transfer_digest(digest);
    let result = TransferResult {
        success: written == request.size && digest == request.digest,
        bytes_written: written,
        digest,
        error: (digest != request.digest).then(|| "SHA-256 digest mismatch".to_string()),
    };
    if !result.success {
        let _ = tokio::fs::remove_file(&destination).await;
    }
    let encoded = bincode::serialize(&result)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&encoded).await?;
    stream.flush().await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferV1State {
    size: u64,
    digest: [u8; 32],
    chunk_size: u32,
    offset: u64,
}

#[cfg(test)]
async fn receive_transfer_v1(stream: misaka_network::NetworkStream) -> std::io::Result<()> {
    receive_transfer_v1_with_node(stream, None).await
}

async fn receive_transfer_v1_with_node(
    mut stream: misaka_network::NetworkStream,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    let request: TransferV1Request = read_bincode_frame(&mut stream, 1024 * 1024).await?;
    authorize_stream_operation(
        node,
        request.authorization.as_ref(),
        Permission::FileSend,
        &[format!("destination={}", request.destination)],
        true,
    )
    .await?;
    if request.chunk_size != TRANSFER_V1_CHUNK_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported transfer v1 chunk size",
        ));
    }

    let destination = std::path::PathBuf::from(&request.destination);
    let part_path = std::path::PathBuf::from(format!("{}.misaka-part", destination.display()));
    let state_path =
        std::path::PathBuf::from(format!("{}.misaka-part.json", destination.display()));
    if let Some(parent) = part_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut state = load_transfer_v1_state(&state_path).await?;
    let part_exists = tokio::fs::try_exists(&part_path).await?;
    if !state.as_ref().is_some_and(|state| {
        state.size == request.size
            && state.digest == request.digest
            && state.chunk_size == request.chunk_size
    }) || !part_exists
    {
        state = None;
        let _ = tokio::fs::remove_file(&part_path).await;
        let _ = tokio::fs::remove_file(&state_path).await;
    }

    let mut state = state.unwrap_or(TransferV1State {
        size: request.size,
        digest: request.digest,
        chunk_size: request.chunk_size,
        offset: 0,
    });
    if state.offset > request.size
        || tokio::fs::metadata(&part_path)
            .await
            .map(|metadata| metadata.len() != state.offset)
            .unwrap_or(true)
    {
        state.offset = 0;
        let _ = tokio::fs::remove_file(&part_path).await;
    }
    if !tokio::fs::try_exists(&part_path).await? {
        tokio::fs::File::create(&part_path).await?;
    }

    let complete =
        state.offset == request.size && hash_file_path(&part_path).await? == request.digest;
    if complete {
        finalize_transfer_part(&part_path, &destination).await?;
        let _ = tokio::fs::remove_file(&state_path).await;
    } else if state.offset == request.size {
        state.offset = 0;
        tokio::fs::File::create(&part_path).await?;
        save_transfer_v1_state(&state_path, &state).await?;
    }

    write_bincode_frame(
        &mut stream,
        &TransferV1Resume {
            offset: state.offset,
            complete,
            error: None,
        },
    )
    .await?;
    if complete {
        return write_transfer_result(
            &mut stream,
            TransferResult {
                success: true,
                bytes_written: request.size,
                digest: request.digest,
                error: None,
            },
        )
        .await;
    }

    loop {
        let chunk: TransferV1Chunk = read_bincode_frame(&mut stream, 64 * 1024).await?;
        let expected_index = state.offset / u64::from(request.chunk_size);
        if chunk.index != expected_index
            || chunk.offset != state.offset
            || chunk.len == 0
            || chunk.len > request.chunk_size
            || state.offset + u64::from(chunk.len) > request.size
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid transfer v1 chunk boundary",
            ));
        }
        let mut payload = vec![0u8; chunk.len as usize];
        stream.read_exact(&mut payload).await?;
        if transfer_digest(&payload) != chunk.digest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer v1 chunk digest mismatch",
            ));
        }

        let mut part = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&part_path)
            .await?;
        part.write_all(&payload).await?;
        part.flush().await?;
        state.offset += u64::from(chunk.len);
        save_transfer_v1_state(&state_path, &state).await?;

        let complete = state.offset == request.size;
        write_bincode_frame(
            &mut stream,
            &TransferV1Ack {
                next_offset: state.offset,
                complete,
                error: None,
            },
        )
        .await?;
        if complete {
            let digest = hash_file_path(&part_path).await?;
            let success = digest == request.digest;
            let result = TransferResult {
                success,
                bytes_written: state.offset,
                digest,
                error: (!success).then(|| "SHA-256 digest mismatch".to_string()),
            };
            if success {
                finalize_transfer_part(&part_path, &destination).await?;
                let _ = tokio::fs::remove_file(&state_path).await;
            }
            return write_transfer_result(&mut stream, result).await;
        }
    }
}

const TRANSFER_V2_MAX_CHUNKS: u64 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransferV2State {
    size: u64,
    digest: [u8; 32],
    chunk_size: u32,
    chunk_count: u64,
    completed: Vec<u8>,
}

static TRANSFER_V2_LOCKS: OnceLock<std::sync::Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
    OnceLock::new();

#[cfg(test)]
async fn receive_transfer_v2(stream: misaka_network::NetworkStream) -> std::io::Result<()> {
    receive_transfer_v2_with_store(stream, None).await
}

#[cfg(test)]
async fn receive_transfer_v2_with_store(
    stream: misaka_network::NetworkStream,
    store_root: Option<PathBuf>,
) -> std::io::Result<()> {
    receive_transfer_v2_with_store_and_node(stream, store_root, None).await
}

async fn receive_transfer_v2_with_store_and_node(
    mut stream: misaka_network::NetworkStream,
    store_root: Option<PathBuf>,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    let request: TransferV2Request = read_bincode_frame(&mut stream, 1024 * 1024).await?;
    authorize_stream_operation(
        node,
        request.authorization.as_ref(),
        Permission::FileSend,
        &[format!("destination={}", request.destination)],
        request.operation == TransferV2Operation::Prepare,
    )
    .await?;
    validate_transfer_v2_request(&request)?;
    let (part_path, state_path) = transfer_v2_paths(&request.destination);
    let fallback_store_root = part_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".misaka-objects");
    let store = ContentStore::new(store_root.unwrap_or(fallback_store_root));
    let lock = transfer_v2_lock(&state_path);

    match request.operation {
        TransferV2Operation::Prepare => {
            if store.contains(request.digest).await? {
                return write_bincode_frame(
                    &mut stream,
                    &TransferV2Resume {
                        completed_indices: (0..request.chunk_count).collect(),
                        complete: true,
                        error: None,
                    },
                )
                .await;
            }
            let _guard = lock.lock().await;
            let state = ensure_transfer_v2_state(&request, &part_path, &state_path).await?;
            write_bincode_frame(
                &mut stream,
                &TransferV2Resume {
                    completed_indices: completed_transfer_v2_indices(&state),
                    complete: transfer_v2_complete(&state),
                    error: None,
                },
            )
            .await
        }
        TransferV2Operation::Chunk => {
            let mut payload = vec![0u8; request.len as usize];
            stream.read_exact(&mut payload).await?;
            if transfer_digest(&payload) != request.chunk_digest {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "transfer v2 chunk digest mismatch",
                ));
            }

            let already_completed = {
                let _guard = lock.lock().await;
                let state = ensure_transfer_v2_state(&request, &part_path, &state_path).await?;
                transfer_v2_is_completed(&state, request.index)
            };
            if !already_completed {
                let mut part = tokio::fs::OpenOptions::new()
                    .write(true)
                    .open(&part_path)
                    .await?;
                tokio::io::AsyncSeekExt::seek(&mut part, std::io::SeekFrom::Start(request.offset))
                    .await?;
                part.write_all(&payload).await?;
                part.flush().await?;

                let _guard = lock.lock().await;
                let mut state = ensure_transfer_v2_state(&request, &part_path, &state_path).await?;
                if !transfer_v2_is_completed(&state, request.index) {
                    transfer_v2_mark_completed(&mut state, request.index);
                    save_transfer_v2_state(&state_path, &state).await?;
                }
            }

            let _guard = lock.lock().await;
            let state = ensure_transfer_v2_state(&request, &part_path, &state_path).await?;
            write_bincode_frame(
                &mut stream,
                &TransferV2Ack {
                    index: request.index,
                    accepted: true,
                    complete: transfer_v2_complete(&state),
                    error: None,
                },
            )
            .await
        }
        TransferV2Operation::Finalize => {
            if store.contains(request.digest).await? {
                let destination = PathBuf::from(&request.destination);
                store.materialize(request.digest, &destination).await?;
                let _ = tokio::fs::remove_file(&state_path).await;
                return write_bincode_frame(
                    &mut stream,
                    &TransferV2Ack {
                        index: 0,
                        accepted: true,
                        complete: true,
                        error: None,
                    },
                )
                .await;
            }
            let _guard = lock.lock().await;
            let state = ensure_transfer_v2_state(&request, &part_path, &state_path).await?;
            if !transfer_v2_complete(&state) {
                return write_bincode_frame(
                    &mut stream,
                    &TransferV2Ack {
                        index: 0,
                        accepted: false,
                        complete: false,
                        error: Some("transfer has incomplete chunks".to_string()),
                    },
                )
                .await;
            }
            let digest = hash_file_path(&part_path).await?;
            if digest != request.digest {
                let _ = tokio::fs::remove_file(&part_path).await;
                let _ = tokio::fs::remove_file(&state_path).await;
                return write_bincode_frame(
                    &mut stream,
                    &TransferV2Ack {
                        index: 0,
                        accepted: false,
                        complete: false,
                        error: Some("SHA-256 digest mismatch".to_string()),
                    },
                )
                .await;
            }
            let destination = PathBuf::from(&request.destination);
            store
                .commit_verified_file(&part_path, request.digest)
                .await?;
            store.materialize(request.digest, &destination).await?;
            let _ = tokio::fs::remove_file(&state_path).await;
            write_bincode_frame(
                &mut stream,
                &TransferV2Ack {
                    index: 0,
                    accepted: true,
                    complete: true,
                    error: None,
                },
            )
            .await
        }
    }
}

fn validate_transfer_v2_request(request: &TransferV2Request) -> std::io::Result<()> {
    if request.chunk_size != TRANSFER_V1_CHUNK_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported transfer v2 chunk size",
        ));
    }
    let expected_count = request.size.div_ceil(u64::from(request.chunk_size));
    if request.chunk_count != expected_count || request.chunk_count > TRANSFER_V2_MAX_CHUNKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid transfer v2 chunk count",
        ));
    }
    match request.operation {
        TransferV2Operation::Prepare | TransferV2Operation::Finalize => {
            if request.index != 0 || request.offset != 0 || request.len != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "control transfer v2 request carries chunk metadata",
                ));
            }
        }
        TransferV2Operation::Chunk => {
            if request.index >= request.chunk_count {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "transfer v2 chunk index is out of range",
                ));
            }
            let expected_offset = request.index * u64::from(request.chunk_size);
            let expected_len = request
                .size
                .saturating_sub(expected_offset)
                .min(u64::from(request.chunk_size));
            if request.offset != expected_offset || u64::from(request.len) != expected_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid transfer v2 chunk boundary",
                ));
            }
        }
    }
    Ok(())
}

fn transfer_v2_paths(destination: &str) -> (PathBuf, PathBuf) {
    let part_path = PathBuf::from(format!("{destination}.misaka-part-v2"));
    let state_path = PathBuf::from(format!("{destination}.misaka-part-v2.json"));
    (part_path, state_path)
}

fn transfer_v2_lock(path: &Path) -> Arc<Mutex<()>> {
    let locks = TRANSFER_V2_LOCKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut locks = locks.lock().expect("transfer v2 lock map poisoned");
    locks
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

async fn ensure_transfer_v2_state(
    request: &TransferV2Request,
    part_path: &Path,
    state_path: &Path,
) -> std::io::Result<TransferV2State> {
    let valid = load_transfer_v2_state(state_path).await?.filter(|state| {
        state.size == request.size
            && state.digest == request.digest
            && state.chunk_size == request.chunk_size
            && state.chunk_count == request.chunk_count
            && state.completed.len() == transfer_v2_bitmap_len(state.chunk_count)
    });
    if let Some(state) = valid {
        if tokio::fs::try_exists(part_path).await? {
            return Ok(state);
        }
    }

    let _ = tokio::fs::remove_file(part_path).await;
    let _ = tokio::fs::remove_file(state_path).await;
    if let Some(parent) = part_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let part = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(part_path)
        .await?;
    part.set_len(request.size).await?;
    drop(part);
    let state = TransferV2State {
        size: request.size,
        digest: request.digest,
        chunk_size: request.chunk_size,
        chunk_count: request.chunk_count,
        completed: vec![0; transfer_v2_bitmap_len(request.chunk_count)],
    };
    save_transfer_v2_state(state_path, &state).await?;
    Ok(state)
}

async fn load_transfer_v2_state(path: &Path) -> std::io::Result<Option<TransferV2State>> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(None);
    }
    let bytes = tokio::fs::read(path).await?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn save_transfer_v2_state(path: &Path, state: &TransferV2State) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let temp_path = PathBuf::from(format!("{}.tmp", path.display()));
    tokio::fs::write(&temp_path, bytes).await?;
    tokio::fs::rename(temp_path, path).await
}

fn transfer_v2_bitmap_len(chunk_count: u64) -> usize {
    chunk_count.div_ceil(8) as usize
}

fn transfer_v2_is_completed(state: &TransferV2State, index: u64) -> bool {
    let byte = state.completed[(index / 8) as usize];
    byte & (1 << (index % 8)) != 0
}

fn transfer_v2_mark_completed(state: &mut TransferV2State, index: u64) {
    state.completed[(index / 8) as usize] |= 1 << (index % 8);
}

fn transfer_v2_complete(state: &TransferV2State) -> bool {
    (0..state.chunk_count).all(|index| transfer_v2_is_completed(state, index))
}

fn completed_transfer_v2_indices(state: &TransferV2State) -> Vec<u64> {
    (0..state.chunk_count)
        .filter(|index| transfer_v2_is_completed(state, *index))
        .collect()
}

async fn load_transfer_v1_state(
    path: &std::path::Path,
) -> std::io::Result<Option<TransferV1State>> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(None);
    }
    let bytes = tokio::fs::read(path).await?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn save_transfer_v1_state(
    path: &std::path::Path,
    state: &TransferV1State,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    tokio::fs::write(path, bytes).await
}

async fn hash_file_path(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

async fn finalize_transfer_part(
    part_path: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    match tokio::fs::rename(part_path, destination).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            tokio::fs::remove_file(destination).await?;
            tokio::fs::rename(part_path, destination).await
        }
        Err(error) => Err(error),
    }
}

async fn read_bincode_frame<T: DeserializeOwned>(
    stream: &mut misaka_network::NetworkStream,
    max_len: usize,
) -> std::io::Result<T> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer frame exceeds limit",
        ));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    bincode::deserialize(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

async fn write_bincode_frame<T: Serialize>(
    stream: &mut misaka_network::NetworkStream,
    value: &T,
) -> std::io::Result<()> {
    let bytes = bincode::serialize(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&bytes).await
}

async fn write_transfer_result(
    stream: &mut misaka_network::NetworkStream,
    result: TransferResult,
) -> std::io::Result<()> {
    write_bincode_frame(stream, &result).await
}

async fn receive_tunnel_with_node(
    mut stream: misaka_network::NetworkStream,
    node: Option<&SisterNode>,
) -> std::io::Result<()> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let request_len = u32::from_be_bytes(length) as usize;
    if request_len > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tunnel request exceeds 64 KiB",
        ));
    }
    let mut encoded = vec![0u8; request_len];
    stream.read_exact(&mut encoded).await?;
    let request: TunnelRequest = bincode::deserialize(&encoded)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let permission = request
        .authorization
        .as_ref()
        .map(|authorization| authorization.permission)
        .unwrap_or(Permission::TunnelOpen);
    authorize_stream_operation(
        node,
        request.authorization.as_ref(),
        permission,
        &[format!("remote={}", request.remote)],
        true,
    )
    .await?;
    let remote = request
        .remote
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let mut remote = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(remote),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "remote tunnel connect timed out",
        )
    })??;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

async fn authorize_stream_operation(
    node: Option<&SisterNode>,
    authorization: Option<&CommandAuthorization>,
    permission: Permission,
    constraints: &[String],
    record_nonce: bool,
) -> std::io::Result<()> {
    let Some(authorization) = authorization else {
        return Ok(());
    };
    let node = node.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "authorized stream request requires a runtime authorization context",
        )
    })?;
    let authority =
        crate::network_authority_store::NetworkAuthorityStore::load(&node.config.data_dir)
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authorized stream request requires network.json",
                )
            })?;
    if authorization.permission != permission
        || !matches!(
            authorization.permission,
            Permission::FileSend | Permission::TunnelOpen | Permission::ShellOpen
        )
        || authorization.target.is_some()
        || authorization.network_id != node.config.network_id
        || !authorization.verify(&authority, crate::node::now_secs())
        || authorization.constraints != constraints
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "stream authorization is invalid",
        ));
    }
    if crate::revocation_store::RevocationStore::is_revoked(
        &node.config.data_dir,
        &authority,
        authorization.network_id,
        authorization.membership.serial,
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "stream authorization membership has been revoked",
        ));
    }
    if record_nonce {
        let _nonce_guard = node.authorization_nonce_lock.lock().await;
        crate::authorization_nonce_store::AuthorizationNonceStore::record(
            &node.config.data_dir,
            authorization,
            crate::node::now_secs(),
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
    }
    Ok(())
}

/// Default development encryption key shared by the current toy protocol.
///
/// This remains deliberately simple for compatibility with the existing wire
/// format; identity-bound key exchange is outside the normalization pass.
pub fn default_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let seed = b"misaka_network_default_key_";
    key[..seed.len()].copy_from_slice(seed);
    key
}

#[cfg(test)]
mod tests {
    use super::{iroh_session_accept_loop, SisterRuntime};
    use crate::config::{DiscoveryMode, RuntimeConfig, StreamBackend, StreamSecurity};
    use crate::content_store::ContentStore;
    use crate::node::SisterNode;
    use crate::runtime::default_encryption_key;
    use crate::shutdown::Shutdown;
    use misaka_core::protocol::{
        transfer_content_digest, transfer_digest, TransferResult, TransferV1Ack, TransferV1Chunk,
        TransferV1Request, TransferV1Resume, TransferV2Ack, TransferV2Operation, TransferV2Request,
        TransferV2Resume, TRANSFER_V1_CHUNK_SIZE,
    };
    use misaka_core::SisterIdentity;
    use misaka_network::NetworkBackend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[tokio::test]
    async fn optional_stream_listener_accepts_and_echoes_a_valid_stream() {
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                1,
                "test".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_port: Some(0),
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        let stream_addr = runtime.stream_addr().unwrap();
        assert!(matches!(
            runtime.stream_listener.as_ref(),
            Some(super::StreamAcceptor::Direct(listener))
                if listener.local_addr().ip().is_loopback()
        ));
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let mut stream = misaka_network::connect(stream_addr).await.unwrap();
        let mut greeting = [0u8; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"world");
        stream.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");

        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn probe_only_listener_rejects_transfer_preambles() {
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                2,
                "probe".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_port: Some(0),
                probe_only: true,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        assert!(runtime
            .listener
            .as_ref()
            .unwrap()
            .local_addr()
            .unwrap()
            .ip()
            .is_loopback());
        let stream_addr = runtime.stream_addr().unwrap();
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let mut stream = misaka_network::connect(stream_addr).await.unwrap();
        let mut greeting = [0u8; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        stream
            .write_all(misaka_core::protocol::TRANSFER_MAGIC)
            .await
            .unwrap();
        let mut response = [0u8; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read, 0);

        shutdown.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn iroh_stream_backend_accepts_and_echoes_a_valid_stream() {
        let network_id = misaka_core::NetworkId::generate();
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend =
            misaka_network::IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend =
            misaka_network::IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_address = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                1,
                "iroh-test".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_backend: StreamBackend::Iroh(server_backend),
                network_id,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let mut stream = client_backend
            .connect_for_network(
                misaka_network::NetworkEndpoint::Iroh(server_address),
                network_id,
            )
            .await
            .unwrap();
        let mut greeting = [0u8; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"world");
        stream.write_all(b"hello").await.unwrap();
        let mut echo = [0u8; 5];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"hello");

        shutdown.cancel();
        task.await.unwrap().unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn iroh_runtime_routes_control_channel_without_tcp_listener() {
        let network_id = misaka_core::NetworkId::generate();
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend =
            misaka_network::IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend =
            misaka_network::IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_address = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                1,
                "iroh-control".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_port: Some(0),
                stream_backend: StreamBackend::Iroh(server_backend),
                network_id,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        assert!(runtime.listener.is_none());
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let request = misaka_core::protocol::Envelope::new(
            network_id,
            misaka_core::protocol::MessageType::Ping,
            2,
            1,
            vec![],
        );
        let response = crate::control_channel::send(
            &client_backend,
            misaka_network::NetworkEndpoint::Iroh(server_address),
            network_id,
            None,
            &request,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.msg_type, misaka_core::protocol::MessageType::Pong);
        assert_eq!(response.from, 1);
        assert_eq!(response.to, 2);

        shutdown.cancel();
        task.await.unwrap().unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn iroh_control_channel_exchanges_signed_peer_records() {
        let network_id = misaka_core::NetworkId::generate();
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend =
            misaka_network::IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend =
            misaka_network::IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_addr = server_backend.endpoint_addr();
        let client_addr = client_backend.endpoint_addr();
        let server_key = misaka_core::SisterKeyPair::generate();
        let client_key = misaka_core::SisterKeyPair::generate();
        let third_key = misaka_core::SisterKeyPair::generate();
        let server_record = misaka_core::PeerRecord::issue(
            network_id,
            1,
            misaka_network::NetworkEndpoint::Iroh(server_addr.clone()).to_string(),
            misaka_core::TransportBinding::sign(
                network_id,
                1,
                misaka_core::IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes()),
                0,
                &server_key,
            ),
            1,
            &server_key,
        );
        let client_record = misaka_core::PeerRecord::issue(
            network_id,
            2,
            misaka_network::NetworkEndpoint::Iroh(client_addr).to_string(),
            misaka_core::TransportBinding::sign(
                network_id,
                2,
                misaka_core::IrohEndpointId::from_bytes(*client_backend.endpoint().id().as_bytes()),
                0,
                &client_key,
            ),
            1,
            &client_key,
        );
        let third_endpoint_id =
            iroh::EndpointId::from_bytes(&third_key.public_key().to_bytes()).unwrap();
        let third_addr = iroh::EndpointAddr::new(third_endpoint_id);
        let third_record = misaka_core::PeerRecord::issue(
            network_id,
            3,
            misaka_network::NetworkEndpoint::Iroh(third_addr).to_string(),
            misaka_core::TransportBinding::sign(
                network_id,
                3,
                misaka_core::IrohEndpointId::from_bytes(third_key.public_key().to_bytes()),
                0,
                &third_key,
            ),
            1,
            &third_key,
        );
        let server_dir =
            std::env::temp_dir().join(format!("misaka-record-server-{}", uuid::Uuid::new_v4()));
        let client_dir =
            std::env::temp_dir().join(format!("misaka-record-client-{}", uuid::Uuid::new_v4()));
        let mut server_node = SisterNode::new(
            SisterIdentity::new(
                1,
                "server".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                data_dir: server_dir.clone(),
                network_id,
                stream_backend: StreamBackend::Iroh(server_backend.clone()),
                peer_record: Some(server_record),
                ..Default::default()
            },
        );
        let mut client_node = SisterNode::new(
            SisterIdentity::new(
                2,
                "client".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                data_dir: client_dir.clone(),
                network_id,
                stream_backend: StreamBackend::Iroh(client_backend.clone()),
                peer_record: Some(client_record),
                ..Default::default()
            },
        );
        server_node
            .peers
            .upsert_peer_record(third_record.clone())
            .await;
        let server_shutdown = Shutdown::new();
        let client_shutdown = Shutdown::new();
        server_node.set_shutdown_token(server_shutdown.token());
        client_node.set_shutdown_token(client_shutdown.token());
        let server_task = tokio::spawn(iroh_session_accept_loop(
            server_node.clone(),
            server_backend,
        ));
        let client_task = tokio::spawn(iroh_session_accept_loop(
            client_node.clone(),
            client_backend.clone(),
        ));

        let discovered = crate::discovery::DiscoveredPeer {
            network_id,
            id: 1,
            nickname: "server".into(),
            control_addr: "127.0.0.1:1".parse().unwrap(),
            stream_endpoint: Some(misaka_network::NetworkEndpoint::Iroh(server_addr)),
        };
        client_node
            .add_known_discovered_peer(&discovered)
            .await
            .unwrap();
        let received = client_node.peers.peer_record(3).await;
        assert!(received.is_some_and(|record| record.verify()));

        server_shutdown.cancel();
        client_shutdown.cancel();
        server_task.await.unwrap();
        client_task.await.unwrap();
        client_backend.close().await;
        let _ = std::fs::remove_dir_all(server_dir);
        let _ = std::fs::remove_dir_all(client_dir);
    }

    #[tokio::test]
    async fn iroh_runtime_reuses_one_session_for_multiple_logical_streams() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend =
            misaka_network::IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend =
            misaka_network::IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_address = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                1,
                "iroh-session-test".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_backend: StreamBackend::Iroh(server_backend),
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let session = client_backend
            .connect_session(misaka_network::NetworkEndpoint::Iroh(server_address))
            .await
            .unwrap();
        let mut first = session.open_stream().await.unwrap();
        let mut second = session.open_stream().await.unwrap();
        for stream in [&mut first, &mut second] {
            let mut greeting = [0u8; 5];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"world");
            stream.write_all(b"ping").await.unwrap();
        }
        for stream in [&mut first, &mut second] {
            let mut echo = [0u8; 4];
            stream.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"ping");
        }

        shutdown.cancel();
        task.await.unwrap().unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn transfer_v1_resumes_from_the_last_committed_chunk() {
        let directory =
            std::env::temp_dir().join(format!("misaka-transfer-v1-{}", uuid::Uuid::new_v4()));
        let destination = directory.join("nested/result.bin");
        let mut payload = vec![0u8; TRANSFER_V1_CHUNK_SIZE as usize + 1234];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let request = TransferV1Request {
            destination: destination.display().to_string(),
            size: payload.len() as u64,
            digest: transfer_content_digest(&payload),
            chunk_size: TRANSFER_V1_CHUNK_SIZE,
            authorization: None,
        };

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v1(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        // `receive_transfer_v1` is invoked after `echo_stream` has consumed the
        // transfer preamble, so the direct handler test starts at the request.
        write_test_frame(&mut client_io, &request).await;
        let resume: TransferV1Resume = read_test_frame(&mut client_io).await;
        assert_eq!(resume.offset, 0);
        let first_len = TRANSFER_V1_CHUNK_SIZE as usize;
        write_test_frame(
            &mut client_io,
            &TransferV1Chunk {
                index: 0,
                offset: 0,
                len: first_len as u32,
                digest: transfer_digest(&payload[..first_len]),
            },
        )
        .await;
        client_io.write_all(&payload[..first_len]).await.unwrap();
        client_io.flush().await.unwrap();
        let ack: TransferV1Ack = read_test_frame(&mut client_io).await;
        assert_eq!(ack.next_offset, first_len as u64);
        drop(client_io);
        assert!(server_task.await.unwrap().is_err());

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v1(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(&mut client_io, &request).await;
        let resume: TransferV1Resume = read_test_frame(&mut client_io).await;
        assert_eq!(resume.offset, first_len as u64);
        assert!(!resume.complete);
        let second_len = payload.len() - first_len;
        write_test_frame(
            &mut client_io,
            &TransferV1Chunk {
                index: 1,
                offset: first_len as u64,
                len: second_len as u32,
                digest: transfer_digest(&payload[first_len..]),
            },
        )
        .await;
        client_io.write_all(&payload[first_len..]).await.unwrap();
        client_io.flush().await.unwrap();
        let ack: TransferV1Ack = read_test_frame(&mut client_io).await;
        assert_eq!(ack.next_offset, payload.len() as u64);
        assert!(ack.complete);
        let result: TransferResult = read_test_frame(&mut client_io).await;
        assert!(result.success);
        assert_eq!(result.bytes_written, payload.len() as u64);
        drop(client_io);
        server_task.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), payload);
        assert!(
            !std::path::PathBuf::from(format!("{}.misaka-part", destination.display())).exists()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn transfer_v2_accepts_out_of_order_chunks_and_persists_bitmap() {
        let directory =
            std::env::temp_dir().join(format!("misaka-transfer-v2-{}", uuid::Uuid::new_v4()));
        let destination = directory.join("nested/result.bin");
        let mut payload = vec![0u8; TRANSFER_V1_CHUNK_SIZE as usize + 1234];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        let request = TransferV2Request {
            operation: TransferV2Operation::Prepare,
            destination: destination.display().to_string(),
            size: payload.len() as u64,
            digest: transfer_content_digest(&payload),
            chunk_size: TRANSFER_V1_CHUNK_SIZE,
            chunk_count: 2,
            index: 0,
            offset: 0,
            len: 0,
            chunk_digest: [0; 32],
            authorization: None,
        };

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v2(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(&mut client_io, &request).await;
        let resume: TransferV2Resume = read_test_frame(&mut client_io).await;
        assert!(resume.completed_indices.is_empty());
        assert!(!resume.complete);
        drop(client_io);
        server_task.await.unwrap().unwrap();

        let first_len = TRANSFER_V1_CHUNK_SIZE as usize;
        for (index, offset, bytes) in [
            (1, first_len as u64, &payload[first_len..]),
            (0, 0, &payload[..first_len]),
        ] {
            let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
            let server_task = tokio::spawn(super::receive_transfer_v2(
                misaka_network::NetworkStream::from_stream(server_io),
            ));
            write_test_frame(
                &mut client_io,
                &TransferV2Request {
                    operation: TransferV2Operation::Chunk,
                    index,
                    offset,
                    len: bytes.len() as u32,
                    chunk_digest: transfer_digest(bytes),
                    ..request.clone()
                },
            )
            .await;
            client_io.write_all(bytes).await.unwrap();
            let ack: TransferV2Ack = read_test_frame(&mut client_io).await;
            assert!(ack.accepted);
            drop(client_io);
            server_task.await.unwrap().unwrap();
        }

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v2(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(
            &mut client_io,
            &TransferV2Request {
                operation: TransferV2Operation::Chunk,
                index: 0,
                offset: 0,
                len: first_len as u32,
                chunk_digest: transfer_digest(&payload[..first_len]),
                ..request.clone()
            },
        )
        .await;
        client_io.write_all(&payload[..first_len]).await.unwrap();
        let ack: TransferV2Ack = read_test_frame(&mut client_io).await;
        assert!(ack.accepted);
        drop(client_io);
        server_task.await.unwrap().unwrap();

        let bad_destination = directory.join("nested/bad.bin");
        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v2(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(
            &mut client_io,
            &TransferV2Request {
                operation: TransferV2Operation::Chunk,
                destination: bad_destination.display().to_string(),
                digest: [9; 32],
                index: 0,
                offset: 0,
                len: first_len as u32,
                chunk_digest: [0; 32],
                ..request.clone()
            },
        )
        .await;
        client_io.write_all(&payload[..first_len]).await.unwrap();
        drop(client_io);
        assert!(server_task.await.unwrap().is_err());

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v2(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(
            &mut client_io,
            &TransferV2Request {
                operation: TransferV2Operation::Prepare,
                ..request.clone()
            },
        )
        .await;
        let resume: TransferV2Resume = read_test_frame(&mut client_io).await;
        assert_eq!(resume.completed_indices, vec![0, 1]);
        assert!(resume.complete);
        drop(client_io);
        server_task.await.unwrap().unwrap();

        let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
        let server_task = tokio::spawn(super::receive_transfer_v2(
            misaka_network::NetworkStream::from_stream(server_io),
        ));
        write_test_frame(
            &mut client_io,
            &TransferV2Request {
                operation: TransferV2Operation::Finalize,
                ..request
            },
        )
        .await;
        let ack: TransferV2Ack = read_test_frame(&mut client_io).await;
        assert!(ack.accepted);
        assert!(ack.complete);
        drop(client_io);
        server_task.await.unwrap().unwrap();
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), payload);
        assert!(
            !std::path::PathBuf::from(format!("{}.misaka-part-v2", destination.display())).exists()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn transfer_v2_finalization_reuses_one_content_object_for_two_destinations() {
        let directory =
            std::env::temp_dir().join(format!("misaka-transfer-store-{}", uuid::Uuid::new_v4()));
        let store_root = directory.join("objects");
        let payload = b"shared content object".repeat(1024);
        let digest = transfer_content_digest(&payload);
        let chunk_count = (payload.len() as u64).div_ceil(u64::from(TRANSFER_V1_CHUNK_SIZE));

        for name in ["first.bin", "second.bin"] {
            let destination = directory.join(name);
            let base = TransferV2Request {
                operation: TransferV2Operation::Prepare,
                destination: destination.display().to_string(),
                size: payload.len() as u64,
                digest,
                chunk_size: TRANSFER_V1_CHUNK_SIZE,
                chunk_count,
                index: 0,
                offset: 0,
                len: 0,
                chunk_digest: [0; 32],
                authorization: None,
            };

            let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
            let server_task = tokio::spawn(super::receive_transfer_v2_with_store(
                misaka_network::NetworkStream::from_stream(server_io),
                Some(store_root.clone()),
            ));
            write_test_frame(&mut client_io, &base).await;
            let resume: TransferV2Resume = read_test_frame(&mut client_io).await;
            assert_eq!(resume.complete, name == "second.bin");
            if name == "first.bin" {
                assert!(resume.completed_indices.is_empty());
            } else {
                assert_eq!(resume.completed_indices, vec![0]);
            }
            drop(client_io);
            server_task.await.unwrap().unwrap();

            if name == "first.bin" {
                let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
                let server_task = tokio::spawn(super::receive_transfer_v2_with_store(
                    misaka_network::NetworkStream::from_stream(server_io),
                    Some(store_root.clone()),
                ));
                write_test_frame(
                    &mut client_io,
                    &TransferV2Request {
                        operation: TransferV2Operation::Chunk,
                        index: 0,
                        offset: 0,
                        len: payload.len() as u32,
                        chunk_digest: transfer_digest(&payload),
                        ..base.clone()
                    },
                )
                .await;
                client_io.write_all(&payload).await.unwrap();
                let ack: TransferV2Ack = read_test_frame(&mut client_io).await;
                assert!(ack.accepted);
                drop(client_io);
                server_task.await.unwrap().unwrap();
            }

            let (server_io, mut client_io) = tokio::io::duplex(1024 * 1024);
            let server_task = tokio::spawn(super::receive_transfer_v2_with_store(
                misaka_network::NetworkStream::from_stream(server_io),
                Some(store_root.clone()),
            ));
            write_test_frame(
                &mut client_io,
                &TransferV2Request {
                    operation: TransferV2Operation::Finalize,
                    ..base
                },
            )
            .await;
            let ack: TransferV2Ack = read_test_frame(&mut client_io).await;
            assert!(ack.accepted);
            assert!(ack.complete);
            drop(client_io);
            server_task.await.unwrap().unwrap();
        }

        assert!(ContentStore::new(&store_root).object_path(digest).exists());
        assert_eq!(
            tokio::fs::read(directory.join("first.bin")).await.unwrap(),
            payload
        );
        assert_eq!(
            tokio::fs::read(directory.join("second.bin")).await.unwrap(),
            payload
        );
        let _ = tokio::fs::remove_dir_all(directory).await;
    }

    async fn write_test_frame<T: serde::Serialize>(
        stream: &mut (impl tokio::io::AsyncWrite + Unpin),
        value: &T,
    ) {
        let bytes = bincode::serialize(value).unwrap();
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
    }

    async fn read_test_frame<T: serde::de::DeserializeOwned>(
        stream: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> T {
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).await.unwrap();
        let mut bytes = vec![0u8; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    #[tokio::test]
    async fn secure_stream_listener_accepts_only_mutually_authenticated_clients() {
        install_test_crypto_provider();
        let server_dir =
            std::env::temp_dir().join(format!("misaka-runtime-server-{}", uuid::Uuid::new_v4()));
        let client_dir =
            std::env::temp_dir().join(format!("misaka-runtime-client-{}", uuid::Uuid::new_v4()));
        let server_identity =
            crate::tls_identity_store::TlsIdentityStore::load_or_init(&server_dir, "sister-1")
                .unwrap();
        let client_identity =
            crate::tls_identity_store::TlsIdentityStore::load_or_init(&client_dir, "sister-2")
                .unwrap();
        let runtime = SisterRuntime::new(
            SisterIdentity::new(
                1,
                "server".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                listen_port: 0,
                stream_port: Some(0),
                stream_security: StreamSecurity::MutualTls {
                    identity: server_identity.clone(),
                    trusted_peer_certificates: vec![client_identity.certificate_der().to_vec()],
                },
                discovery: DiscoveryMode::Off,
                data_dir: server_dir.clone(),
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();
        assert!(matches!(
            runtime.stream_listener.as_ref(),
            Some(super::StreamAcceptor::Direct(listener))
                if listener.local_addr().ip().is_unspecified()
        ));
        let stream_addr = runtime.stream_addr().unwrap();
        let shutdown = runtime.shutdown();
        let task = tokio::spawn(runtime.run());

        let client = misaka_network::tls::TlsClient::new(
            client_identity
                .client_config(server_identity.certificate_der())
                .unwrap(),
            "sister-1",
        )
        .unwrap();
        let mut stream = client
            .connect(misaka_network::NetworkEndpoint::Tcp(stream_addr))
            .await
            .unwrap();
        let mut greeting = [0u8; 5];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"world");

        shutdown.cancel();
        task.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(server_dir);
        let _ = std::fs::remove_dir_all(client_dir);
    }
}
