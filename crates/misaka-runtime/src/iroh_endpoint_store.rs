//! Filesystem persistence for the currently advertised Iroh endpoint address.
//!
//! The address is public transport metadata, not a secret. It is written by
//! the running Sister after binding its endpoint so `misaka endpoint` can
//! export the actual live UDP/relay address without binding a second endpoint
//! with the same identity.

use iroh::EndpointAddr;
use std::path::{Path, PathBuf};
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
}

#[cfg(test)]
mod tests {
    use super::IrohEndpointStore;

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
}
