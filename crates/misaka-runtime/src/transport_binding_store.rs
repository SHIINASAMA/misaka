//! Persistence and monotonic rotation of the signed Iroh transport binding.

use misaka_core::{IrohEndpointId, NetworkId, SisterKeyPair, TransportBinding};
use std::path::{Path, PathBuf};
use thiserror::Error;

const BINDING_FILE: &str = "transport-binding.json";

#[derive(Debug, Error)]
pub enum TransportBindingStoreError {
    #[error("transport binding I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid persisted transport binding: {0}")]
    Json(#[from] serde_json::Error),
    #[error("persisted transport binding signature is invalid")]
    InvalidSignature,
    #[error("persisted transport binding belongs to another Network or Sister")]
    IdentityMismatch,
}

pub struct TransportBindingStore;

impl TransportBindingStore {
    pub fn load(directory: &Path) -> Result<Option<TransportBinding>, TransportBindingStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let value = std::fs::read_to_string(path)?;
        Ok(Some(serde_json::from_str(&value)?))
    }

    pub fn save(
        directory: &Path,
        binding: &TransportBinding,
    ) -> Result<(), TransportBindingStoreError> {
        std::fs::create_dir_all(directory)?;
        let value = serde_json::to_string_pretty(binding)?;
        std::fs::write(Self::path(directory), value)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                Self::path(directory),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        Ok(())
    }

    /// Return the existing valid binding or create the next signed binding
    /// when the Iroh endpoint identity has changed.
    pub fn load_or_update(
        directory: &Path,
        network_id: NetworkId,
        sister_id: u64,
        endpoint_id: IrohEndpointId,
        key: &SisterKeyPair,
    ) -> Result<TransportBinding, TransportBindingStoreError> {
        if let Some(existing) = Self::load(directory)? {
            if !existing.verify() {
                return Err(TransportBindingStoreError::InvalidSignature);
            }
            if existing.network_id != network_id
                || existing.sister_id.as_u64() != sister_id
                || existing.sister_public_key != key.public_key()
            {
                return Err(TransportBindingStoreError::IdentityMismatch);
            }
            if existing.iroh_endpoint_id == endpoint_id {
                return Ok(existing);
            }
            let next = TransportBinding::sign(
                network_id,
                sister_id,
                endpoint_id,
                existing.sequence.saturating_add(1),
                key,
            );
            Self::save(directory, &next)?;
            return Ok(next);
        }

        let binding = TransportBinding::sign(network_id, sister_id, endpoint_id, 0, key);
        Self::save(directory, &binding)?;
        Ok(binding)
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(BINDING_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::TransportBindingStore;
    use misaka_core::{IrohEndpointId, NetworkId, SisterKeyPair};

    #[test]
    fn binding_is_persisted_and_endpoint_rotation_increments_sequence() {
        let directory =
            std::env::temp_dir().join(format!("misaka-transport-binding-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();

        let first = TransportBindingStore::load_or_update(
            &directory,
            network_id,
            42,
            IrohEndpointId::from_bytes([1u8; 32]),
            &key,
        )
        .unwrap();
        let same = TransportBindingStore::load_or_update(
            &directory,
            network_id,
            42,
            IrohEndpointId::from_bytes([1u8; 32]),
            &key,
        )
        .unwrap();
        let rotated = TransportBindingStore::load_or_update(
            &directory,
            network_id,
            42,
            IrohEndpointId::from_bytes([2u8; 32]),
            &key,
        )
        .unwrap();

        assert_eq!(first.sequence, 0);
        assert_eq!(same, first);
        assert_eq!(rotated.sequence, 1);
        assert!(rotated.verify());
        assert_eq!(
            TransportBindingStore::load(&directory).unwrap(),
            Some(rotated)
        );

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn invalid_binding_is_rejected() {
        let directory = std::env::temp_dir().join(format!(
            "misaka-transport-binding-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();
        let mut binding = misaka_core::TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([1u8; 32]),
            0,
            &key,
        );
        binding.sequence = 99;
        TransportBindingStore::save(&directory, &binding).unwrap();

        let error = TransportBindingStore::load_or_update(
            &directory,
            network_id,
            42,
            IrohEndpointId::from_bytes([1u8; 32]),
            &key,
        )
        .unwrap_err();
        assert!(error.to_string().contains("signature is invalid"));

        let _ = std::fs::remove_dir_all(directory);
    }
}
