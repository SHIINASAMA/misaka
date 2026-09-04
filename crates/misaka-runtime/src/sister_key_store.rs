//! Filesystem persistence for the cryptographic Sister identity.
//!
//! The private Ed25519 key is intentionally separate from `identity.json` and
//! the Iroh transport key. It is the long-lived Misaka identity used to sign
//! membership and transport contracts.

use misaka_core::{SisterKeyPair, SisterPublicKey};
use std::path::{Path, PathBuf};
use thiserror::Error;

const KEY_FILE: &str = "sister-identity-key";

#[derive(Debug, Error)]
pub enum SisterKeyStoreError {
    #[error("Sister identity key I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Sister identity key must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),
}

pub struct SisterKeyStore;

impl SisterKeyStore {
    pub fn load(directory: &Path) -> Result<Option<SisterKeyPair>, SisterKeyStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| SisterKeyStoreError::InvalidLength(bytes.len()))?;
        Ok(Some(SisterKeyPair::from_bytes(bytes)))
    }

    pub fn load_or_init(directory: &Path) -> Result<SisterKeyPair, SisterKeyStoreError> {
        if let Some(key) = Self::load(directory)? {
            return Ok(key);
        }
        std::fs::create_dir_all(directory)?;
        let key = SisterKeyPair::generate();
        write_key(&Self::path(directory), &key.to_bytes())?;
        Ok(key)
    }

    pub fn public_key(directory: &Path) -> Result<Option<SisterPublicKey>, SisterKeyStoreError> {
        Ok(Self::load(directory)?.map(|key| key.public_key()))
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(KEY_FILE)
    }
}

fn write_key(path: &Path, bytes: &[u8; 32]) -> Result<(), SisterKeyStoreError> {
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
    use super::SisterKeyStore;

    #[test]
    fn sister_key_is_stable_and_private() {
        let directory =
            std::env::temp_dir().join(format!("misaka-sister-key-{}", uuid::Uuid::new_v4()));

        let first = SisterKeyStore::load_or_init(&directory).unwrap();
        let second = SisterKeyStore::load_or_init(&directory).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(SisterKeyStore::path(&directory))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn malformed_sister_key_is_rejected_without_replacement() {
        let directory = std::env::temp_dir().join(format!(
            "misaka-sister-key-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(SisterKeyStore::path(&directory), [5u8; 31]).unwrap();

        let error = SisterKeyStore::load_or_init(&directory).unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
        assert_eq!(
            std::fs::read(SisterKeyStore::path(&directory))
                .unwrap()
                .len(),
            31
        );

        let _ = std::fs::remove_dir_all(directory);
    }
}
