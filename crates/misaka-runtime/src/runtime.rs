//! SisterRuntime orchestration.
//!
//! This type owns the lifecycle of one Sister. Protocol handling and domain
//! behavior stay in `SisterNode`; this module assembles services, starts
//! cancellable background loops, and accepts inbound connections.

use crate::config::RuntimeConfig;
use crate::node::SisterNode;
use crate::shutdown::Shutdown;
use misaka_core::SisterIdentity;
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

/// Orchestrates one complete Sister runtime.
pub struct SisterRuntime {
    node: SisterNode,
    listener: TcpListener,
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

        // Configured peers are connected after `run` starts accepting inbound
        // sockets. Connecting synchronously here can deadlock when two fresh
        // Sisters simultaneously wait for each other's Hello response.
        Ok(Self {
            node,
            listener,
            shutdown,
            configured_peers: peers,
        })
    }

    /// Clone the cancellation handle used to request a graceful stop.
    pub fn shutdown(&self) -> Shutdown {
        self.shutdown.clone()
    }

    /// Start discovery, state exchange, execution, cleanup, and work stealing.
    /// Returns after the shared shutdown handle is cancelled.
    pub async fn run(self) -> crate::Result<()> {
        let SisterRuntime {
            node,
            listener,
            shutdown: _shutdown,
            configured_peers,
        } = self;
        let background = spawn_background_tasks(&node, configured_peers);
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
    tasks
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
