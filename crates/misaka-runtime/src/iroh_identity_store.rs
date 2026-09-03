//! Filesystem persistence for the Iroh transport identity.
//!
//! Sister identity and transport identity are separate on purpose. The
//! numeric Sister ID remains the application identity, while this key keeps
//! the Iroh endpoint address stable across process restarts.

use iroh::SecretKey;
use std::path::{Path, PathBuf};
use thiserror::Error;

const KEY_FILE: &str = "iroh-stream-key.bin";

#[derive(Debug, Error)]
pub enum IrohIdentityStoreError {
    #[error("Iroh identity I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Iroh identity must be exactly 32 bytes, got {0}")]
    InvalidLength(usize),
}

/// Persists only the 32-byte Iroh secret key, never printing or serializing it
/// into peer state or diagnostics.
pub struct IrohIdentityStore;

impl IrohIdentityStore {
    pub fn load(directory: &Path) -> Result<Option<SecretKey>, IrohIdentityStoreError> {
        let path = directory.join(KEY_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| IrohIdentityStoreError::InvalidLength(bytes.len()))?;
        Ok(Some(SecretKey::from_bytes(&bytes)))
    }

    pub fn load_or_init(directory: &Path) -> Result<SecretKey, IrohIdentityStoreError> {
        if let Some(key) = Self::load(directory)? {
            return Ok(key);
        }
        std::fs::create_dir_all(directory)?;
        let key = SecretKey::generate();
        write_key(&directory.join(KEY_FILE), &key.to_bytes())?;
        Ok(key)
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(KEY_FILE)
    }
}

fn write_key(path: &Path, bytes: &[u8; 32]) -> Result<(), IrohIdentityStoreError> {
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
    use super::IrohIdentityStore;

    #[test]
    fn generated_iroh_identity_is_stable_in_a_data_directory() {
        let directory =
            std::env::temp_dir().join(format!("misaka-iroh-identity-{}", uuid::Uuid::new_v4()));

        let first = IrohIdentityStore::load_or_init(&directory).unwrap();
        let second = IrohIdentityStore::load_or_init(&directory).unwrap();

        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(IrohIdentityStore::path(&directory))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn malformed_iroh_identity_is_rejected_without_replacement() {
        let directory =
            std::env::temp_dir().join(format!("misaka-iroh-invalid-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(IrohIdentityStore::path(&directory), [7u8; 31]).unwrap();

        let error = IrohIdentityStore::load_or_init(&directory).unwrap_err();
        assert!(error.to_string().contains("exactly 32 bytes"));
        assert_eq!(
            std::fs::read(IrohIdentityStore::path(&directory))
                .unwrap()
                .len(),
            31
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn load_does_not_generate_missing_iroh_identity() {
        let directory =
            std::env::temp_dir().join(format!("misaka-iroh-load-{}", uuid::Uuid::new_v4()));

        assert!(IrohIdentityStore::load(&directory).unwrap().is_none());
        assert!(!directory.exists());
    }
}
