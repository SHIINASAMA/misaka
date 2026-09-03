//! SisterRuntime orchestration.
//!
//! This type owns the lifecycle of one Sister. Protocol handling and domain
//! behavior stay in `SisterNode`; this module assembles services, starts
//! cancellable background loops, and accepts inbound connections.

use crate::config::RuntimeConfig;
use crate::node::SisterNode;
use crate::shutdown::Shutdown;
use misaka_core::SisterIdentity;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

/// Orchestrates one complete Sister runtime.
pub struct SisterRuntime {
    node: SisterNode,
    listener: TcpListener,
    shutdown: Shutdown,
}

impl SisterRuntime {
    /// Construct the runtime, bind its listeners, and connect configured peers.
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

        for peer in peers {
            // A configured peer may be temporarily unavailable. The normal
            // state/discovery loops can learn it later, so startup continues.
            let _ = node.add_known_peer(peer).await;
        }

        Ok(Self {
            node,
            listener,
            shutdown,
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
        } = self;
        let background = spawn_background_tasks(&node);
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

fn spawn_background_tasks(node: &SisterNode) -> Vec<JoinHandle<()>> {
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

    vec![discovery, state, cleanup, executor, stealing]
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
