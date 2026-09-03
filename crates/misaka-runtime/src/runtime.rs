//! SisterRuntime orchestration.
//!
//! This type owns the lifecycle of one Sister. Protocol handling and domain
//! behavior stay in `SisterNode`; this module only assembles services, starts
//! background loops, and accepts inbound connections.

use crate::config::RuntimeConfig;
use crate::node::SisterNode;
use misaka_core::SisterIdentity;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Orchestrates one complete Sister runtime.
pub struct SisterRuntime {
    node: SisterNode,
    listener: TcpListener,
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
        let mut node = SisterNode::new(identity, encryption_key, config);
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

        Ok(Self { node, listener })
    }

    /// Start discovery, state exchange, execution, cleanup, and work stealing.
    pub async fn run(self) -> crate::Result<()> {
        let SisterRuntime { node, listener } = self;
        spawn_background_tasks(&node);

        loop {
            let (stream, addr) = listener.accept().await?;
            let node = node.clone();
            tokio::spawn(async move {
                let _ = node.handle_inbound(stream, addr).await;
            });
        }
    }
}

fn spawn_background_tasks(node: &SisterNode) {
    let discovery_node = node.clone();
    tokio::spawn(async move {
        if matches!(
            discovery_node.config.discovery,
            crate::config::DiscoveryMode::Mdns
        ) {
            let _ = discovery_node.mdns_loop().await;
        } else {
            std::future::pending::<()>().await;
        }
    });

    let state_node = node.clone();
    tokio::spawn(async move {
        let _ = state_node.state_broadcast_loop().await;
    });

    let cleanup_node = node.clone();
    tokio::spawn(async move {
        let _ = cleanup_node.cleanup_loop().await;
    });

    let executor_node = node.clone();
    tokio::spawn(async move {
        let _ = executor_node.local_executor_loop().await;
    });

    let stealing_node = node.clone();
    tokio::spawn(async move {
        let _ = stealing_node.work_stealing_loop(1).await;
    });
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
