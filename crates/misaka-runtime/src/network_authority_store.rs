//! Persistence for a Network's trust root.
//!
//! The authority is a governance key, not a Sister role. Only an explicit
//! network initialization creates it; ordinary Sister startup never generates
//! or replaces an authority.

use misaka_core::{AuthorityKeyPair, NetworkAuthority, NetworkId};
use std::path::{Path, PathBuf};
use thiserror::Error;

const DESCRIPTOR_FILE: &str = "network.json";
const KEY_FILE: &str = "network-authority-key";

#[derive(Debug, Error)]
pub enum NetworkAuthorityStoreError {
    #[error("Network authority I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Network authority descriptor: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Network authority key must be exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("Network authority descriptor and private key are inconsistent")]
    KeyMismatch,
}

pub struct NetworkAuthorityStore;

impl NetworkAuthorityStore {
    /// Explicitly initialize a Network authority. Existing state is never
    /// silently replaced.
    pub fn init(
        directory: &Path,
        network_id: Option<NetworkId>,
    ) -> Result<NetworkAuthority, NetworkAuthorityStoreError> {
        if let Some(existing) = Self::load(directory)? {
            return Ok(existing);
        }

        std::fs::create_dir_all(directory)?;
        let (authority, key) =
            NetworkAuthority::generate(network_id.unwrap_or_else(NetworkId::generate));
        write_key(&Self::key_path(directory), &key.to_bytes())?;
        std::fs::write(
            Self::descriptor_path(directory),
            serde_json::to_string_pretty(&authority)?,
        )?;
        Ok(authority)
    }

    pub fn load(directory: &Path) -> Result<Option<NetworkAuthority>, NetworkAuthorityStoreError> {
        let path = Self::descriptor_path(directory);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(path)?)?))
    }

    pub fn load_key(
        directory: &Path,
    ) -> Result<Option<AuthorityKeyPair>, NetworkAuthorityStoreError> {
        let path = Self::key_path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| NetworkAuthorityStoreError::InvalidKeyLength(bytes.len()))?;
        Ok(Some(AuthorityKeyPair::from_bytes(bytes)))
    }

    pub fn load_with_key(
        directory: &Path,
    ) -> Result<Option<(NetworkAuthority, AuthorityKeyPair)>, NetworkAuthorityStoreError> {
        let Some(authority) = Self::load(directory)? else {
            return Ok(None);
        };
        let Some(key) = Self::load_key(directory)? else {
            return Ok(None);
        };
        if key.public_key() != authority.authority_public_key {
            return Err(NetworkAuthorityStoreError::KeyMismatch);
        }
        Ok(Some((authority, key)))
    }

    pub fn descriptor_path(directory: &Path) -> PathBuf {
        directory.join(DESCRIPTOR_FILE)
    }

    pub fn key_path(directory: &Path) -> PathBuf {
        directory.join(KEY_FILE)
    }
}

fn write_key(path: &Path, bytes: &[u8; 32]) -> Result<(), NetworkAuthorityStoreError> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::NetworkAuthorityStore;
    use misaka_core::NetworkId;

    #[test]
    fn authority_initialization_is_explicit_and_persistent() {
        let directory =
            std::env::temp_dir().join(format!("misaka-network-authority-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let first = NetworkAuthorityStore::init(&directory, Some(network_id)).unwrap();
        let second = NetworkAuthorityStore::init(&directory, Some(NetworkId::generate())).unwrap();
        let loaded = NetworkAuthorityStore::load_with_key(&directory)
            .unwrap()
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(loaded.0, first);
        assert_eq!(loaded.1.public_key(), first.authority_public_key);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(NetworkAuthorityStore::key_path(&directory))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = std::fs::remove_dir_all(directory);
    }
}
