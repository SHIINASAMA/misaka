use misaka_core::NetworkId;
use std::path::{Path, PathBuf};
use thiserror::Error;

const NETWORK_ID_FILE: &str = "network-id";

#[derive(Debug, Error)]
pub enum NetworkIdStoreError {
    #[error("NetworkId I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid persisted NetworkId: {0}")]
    Invalid(String),
    #[error("requested NetworkId {requested} does not match persisted NetworkId {persisted}")]
    Mismatch {
        requested: NetworkId,
        persisted: NetworkId,
    },
}

/// Persists the namespace identifier independently from Sister and transport identities.
pub struct NetworkIdStore;

impl NetworkIdStore {
    pub fn path(directory: &Path) -> PathBuf {
        directory.join(NETWORK_ID_FILE)
    }

    pub fn load(directory: &Path) -> Result<Option<NetworkId>, NetworkIdStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let value = std::fs::read_to_string(path)?;
        let value = value.trim();
        if value.is_empty() {
            return Err(NetworkIdStoreError::Invalid("value is empty".to_string()));
        }
        NetworkId::parse(value)
            .map(Some)
            .map_err(|error| NetworkIdStoreError::Invalid(error.to_string()))
    }

    pub fn load_or_init(
        directory: &Path,
        requested: Option<NetworkId>,
    ) -> Result<NetworkId, NetworkIdStoreError> {
        if let Some(persisted) = Self::load(directory)? {
            if let Some(requested) = requested {
                if requested != persisted {
                    return Err(NetworkIdStoreError::Mismatch {
                        requested,
                        persisted,
                    });
                }
            }
            return Ok(persisted);
        }

        let network_id = requested.unwrap_or_else(NetworkId::generate);
        std::fs::create_dir_all(directory)?;
        std::fs::write(Self::path(directory), network_id.to_string())?;
        Ok(network_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_is_stable_across_load_or_init() {
        let directory =
            std::env::temp_dir().join(format!("misaka-network-id-{}", uuid::Uuid::new_v4()));
        let requested = NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();

        let first = NetworkIdStore::load_or_init(&directory, Some(requested)).unwrap();
        let second = NetworkIdStore::load_or_init(&directory, None).unwrap();

        assert_eq!(first, requested);
        assert_eq!(second, requested);
        assert_eq!(
            std::fs::read_to_string(NetworkIdStore::path(&directory)).unwrap(),
            first.to_string()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn explicit_network_id_cannot_silently_switch_a_persisted_network() {
        let directory = std::env::temp_dir().join(format!(
            "misaka-network-id-mismatch-{}",
            uuid::Uuid::new_v4()
        ));
        let first = NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let second = NetworkId::parse("fedcba98-7654-3210-fedc-ba9876543210").unwrap();
        NetworkIdStore::load_or_init(&directory, Some(first)).unwrap();

        let error = NetworkIdStore::load_or_init(&directory, Some(second)).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        let _ = std::fs::remove_dir_all(directory);
    }
}
