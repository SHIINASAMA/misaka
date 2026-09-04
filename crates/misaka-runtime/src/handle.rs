use crate::node::SisterNode;
use crate::Result;
use misaka_core::introspection::IntrospectionSnapshot;
use misaka_core::protocol::{Envelope, MessageType};
use misaka_core::NetworkId;

/// Cloneable application facade for the live state owned by one Sister.
///
/// The handle is a view over the existing node, not a second runtime or
/// another owner of peer, job, or scheduler state.
#[derive(Clone)]
pub struct SisterHandle {
    node: SisterNode,
}

impl SisterHandle {
    pub(crate) fn new(node: SisterNode) -> Self {
        Self { node }
    }

    /// Read the current live snapshot without touching persistence directly.
    pub async fn snapshot(&self) -> Result<IntrospectionSnapshot> {
        Ok(self.node.introspection_snapshot().await)
    }

    /// Send the side-effect-free reachability probe to a known Sister.
    pub async fn ping(&self, sister_id: u64) -> Result<()> {
        let envelope = Self::ping_envelope(
            self.node.config.network_id,
            self.node.identity.id.as_u64(),
            sister_id,
        );
        let response = self.node.send_to_peer(sister_id, &envelope).await?;
        if response.msg_type == MessageType::Pong
            && response.from == sister_id
            && response.to == self.node.identity.id.as_u64()
        {
            Ok(())
        } else {
            Err(crate::Error::Protocol(
                "ping returned an unexpected response".to_string(),
            ))
        }
    }

    fn ping_envelope(network_id: NetworkId, from: u64, to: u64) -> Envelope {
        Envelope::new(network_id, MessageType::Ping, from, to, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::SisterHandle;
    use crate::config::{DiscoveryMode, RuntimeConfig};
    use crate::runtime::{default_encryption_key, SisterRuntime};
    use misaka_core::protocol::MessageType;
    use misaka_core::{NetworkId, SisterIdentity};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn isolated_dir() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("misaka-web-handle-test-{suffix}"))
    }

    #[tokio::test]
    async fn handle_snapshot_reads_the_live_runtime_identity() {
        let data_dir = isolated_dir();
        let network_id = NetworkId::generate();
        let runtime = SisterRuntime::new(
            SisterIdentity::new(42, "console".into(), "host".into(), "test".into(), "0.1".into(), 0),
            default_encryption_key(),
            RuntimeConfig {
                data_dir: data_dir.clone(),
                network_id,
                listen_port: 0,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap();

        let handle = runtime.handle();
        let snapshot = handle.snapshot().await.unwrap();

        assert_eq!(snapshot.network_id, network_id);
        assert_eq!(snapshot.identity.id.as_u64(), 42);
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[test]
    fn ping_envelope_targets_a_sister_in_the_runtime_network() {
        let network_id = NetworkId::generate();
        let envelope = SisterHandle::ping_envelope(network_id, 42, 7);

        assert_eq!(envelope.network_id, network_id);
        assert_eq!(envelope.msg_type, MessageType::Ping);
        assert_eq!(envelope.from, 42);
        assert_eq!(envelope.to, 7);
    }
}
