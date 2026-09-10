//! Filesystem persistence for the currently advertised Iroh endpoint address.
//!
//! The address is public transport metadata, not a secret. It is written by
//! the running Sister after binding its endpoint so `misaka endpoint` can
//! export the actual live UDP/relay address without binding a second endpoint
//! with the same identity.

use futures_util::StreamExt;
use iroh::{EndpointAddr, Watcher};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

const ENDPOINT_FILE: &str = "iroh-endpoint.json";

#[derive(Debug, Error)]
pub enum IrohEndpointStoreError {
    #[error("Iroh endpoint I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid persisted Iroh endpoint: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct IrohEndpointStore;

impl IrohEndpointStore {
    pub fn load(directory: &Path) -> Result<Option<EndpointAddr>, IrohEndpointStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let value = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&value)?))
    }

    pub fn save(directory: &Path, endpoint: &EndpointAddr) -> Result<(), IrohEndpointStoreError> {
        std::fs::create_dir_all(directory)?;
        let value = serde_json::to_string_pretty(endpoint)?;
        std::fs::write(Self::path(directory), value)?;
        Ok(())
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(ENDPOINT_FILE)
    }

    /// Wait for a bounded period for at least one Iroh relay to establish.
    ///
    /// Direct addresses may be usable before this completes, so callers can
    /// still export the current address after a timeout and let the watcher
    /// refresh it when relay connectivity becomes available.
    pub async fn wait_for_online(endpoint: &iroh::Endpoint, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, endpoint.online())
            .await
            .is_ok()
    }

    /// Keep the persisted endpoint address in sync with Iroh's address watcher.
    pub fn spawn_refresh(directory: PathBuf, endpoint: iroh::Endpoint) {
        tokio::spawn(async move {
            let mut addresses = endpoint.watch_addr().stream();
            loop {
                tokio::select! {
                    _ = endpoint.closed() => break,
                    address = addresses.next() => {
                        let Some(address) = address else { break };
                        if let Err(error) = Self::save(&directory, &address) {
                            tracing::warn!(?error, "failed to refresh persisted Iroh endpoint");
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::IrohEndpointStore;
    use std::time::Duration;

    #[test]
    fn endpoint_address_roundtrips_without_binding_a_second_endpoint() {
        let directory =
            std::env::temp_dir().join(format!("misaka-iroh-endpoint-{}", uuid::Uuid::new_v4()));
        let endpoint = iroh::EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("127.0.0.1:31701".parse().unwrap());

        IrohEndpointStore::save(&directory, &endpoint).unwrap();
        assert_eq!(IrohEndpointStore::load(&directory).unwrap(), Some(endpoint));

        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn online_wait_is_bounded_when_no_relay_is_available() {
        // Loopback bind + no relay: guaranteed offline, and never an
        // any-interface listener that macOS would firewall-prompt for.
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![b"misaka/test".to_vec()])
            .clear_ip_transports()
            .relay_mode(iroh::RelayMode::Disabled)
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        assert!(!IrohEndpointStore::wait_for_online(&endpoint, Duration::from_millis(20)).await);
        endpoint.close().await;
    }
}
