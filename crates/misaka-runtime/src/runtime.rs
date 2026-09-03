//! SisterRuntime orchestration.
//!
//! This type owns the lifecycle of one Sister. Protocol handling and domain
//! behavior stay in `SisterNode`; this module assembles services, starts
//! cancellable background loops, and accepts inbound connections.

use crate::config::RuntimeConfig;
use crate::node::SisterNode;
use crate::shutdown::Shutdown;
use misaka_core::protocol::{
    finalize_transfer_digest, update_transfer_digest, TransferRequest, TransferResult,
    TunnelRequest, TRANSFER_MAGIC, TUNNEL_MAGIC,
};
use misaka_core::SisterIdentity;
use misaka_network::{NetworkBackend, NetworkEndpoint};
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// Orchestrates one complete Sister runtime.
pub struct SisterRuntime {
    node: SisterNode,
    listener: TcpListener,
    stream_listener: Option<misaka_network::NetworkListener>,
    shutdown: Shutdown,
    configured_peers: Vec<SocketAddr>,
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
        let stream_security = config.stream_security.clone();
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
        let listener = node.start_listener().await?;
        let backend = misaka_network::DirectTcpBackend;
        let stream_listener = match stream_port {
            Some(port) => match stream_security {
                crate::config::StreamSecurity::InsecureLoopback => Some(
                    backend
                        .listen(NetworkEndpoint::Tcp(format!("127.0.0.1:{port}").parse()?))
                        .await
                        .map_err(|error| crate::Error::Network(error.to_string()))?,
                ),
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
                    Some(
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
                    )
                }
            },
            None => None,
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
        self.stream_listener.as_ref().map(|listener| {
            let port = listener.local_addr().port();
            SocketAddr::new(self.node.listen_addr.ip(), port)
        })
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
                accepted = listener.accept() => {
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
    stream_listener: Option<misaka_network::NetworkListener>,
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
    if let Some(listener) = stream_listener {
        let stream_node = node.clone();
        tasks.push(tokio::spawn(async move {
            stream_accept_loop(stream_node, listener).await;
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
                            let stats = stream.stats();
                            let connected_for = stream.connected_for();
                            let result = echo_stream(stream).await;
                            tracing::debug!(
                                event = "stream_closed",
                                sister_id = session_node.identity.id.as_u64(),
                                peer_addr = %addr,
                                connected_for_ms = connected_for.as_millis() as u64,
                                tx_bytes = stats.tx_bytes(),
                                rx_bytes = stats.rx_bytes(),
                                error = ?result.as_ref().err(),
                                "network stream closed"
                            );
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

async fn echo_stream(mut stream: misaka_network::NetworkStream) -> std::io::Result<()> {
    stream.write_all(b"world").await?;
    let mut preamble = [0u8; TRANSFER_MAGIC.len()];
    if stream.read_exact(&mut preamble).await.is_err() {
        return Ok(());
    }
    if preamble == *TRANSFER_MAGIC {
        return receive_transfer(stream).await;
    }
    if preamble == *TUNNEL_MAGIC {
        return receive_tunnel(stream).await;
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

async fn receive_transfer(mut stream: misaka_network::NetworkStream) -> std::io::Result<()> {
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

async fn receive_tunnel(mut stream: misaka_network::NetworkStream) -> std::io::Result<()> {
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
    use super::SisterRuntime;
    use crate::config::{DiscoveryMode, RuntimeConfig, StreamSecurity};
    use crate::runtime::default_encryption_key;
    use misaka_core::SisterIdentity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        assert!(runtime
            .stream_listener
            .as_ref()
            .unwrap()
            .local_addr()
            .ip()
            .is_loopback());
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
    async fn secure_stream_listener_accepts_only_mutually_authenticated_clients() {
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
        assert!(runtime
            .stream_listener
            .as_ref()
            .unwrap()
            .local_addr()
            .ip()
            .is_unspecified());
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
