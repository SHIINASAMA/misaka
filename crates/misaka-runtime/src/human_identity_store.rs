//! Persistence for the human operator identity used to authorize commands.
//!
//! The public descriptor may be shared with peers. The private key is kept in
//! a separate mode-0600 file and never enters a protocol payload by itself.

use misaka_core::{HumanIdentity, HumanKeyPair, HumanMembershipCertificate};
use std::path::{Path, PathBuf};
use thiserror::Error;

const IDENTITY_FILE: &str = "human-identity.json";
const KEY_FILE: &str = "human-identity-key";
const MEMBERSHIP_FILE: &str = "human-membership.bin";

#[derive(Debug, Error)]
pub enum HumanIdentityStoreError {
    #[error("human identity I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid human identity descriptor: {0}")]
    Json(#[from] serde_json::Error),
    #[error("human identity key must be exactly 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("human identity descriptor and private key are inconsistent")]
    KeyMismatch,
    #[error("invalid human membership certificate: {0}")]
    MembershipCodec(#[from] Box<bincode::ErrorKind>),
}

pub struct HumanIdentityStore;

impl HumanIdentityStore {
    pub fn load(directory: &Path) -> Result<Option<HumanIdentity>, HumanIdentityStoreError> {
        let path = Self::identity_path(directory);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(path)?)?))
    }

    pub fn load_key(directory: &Path) -> Result<Option<HumanKeyPair>, HumanIdentityStoreError> {
        let path = Self::key_path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| HumanIdentityStoreError::InvalidKeyLength(bytes.len()))?;
        Ok(Some(HumanKeyPair::from_bytes(bytes)))
    }

    pub fn load_with_key(
        directory: &Path,
    ) -> Result<Option<(HumanIdentity, HumanKeyPair)>, HumanIdentityStoreError> {
        let Some(identity) = Self::load(directory)? else {
            return Ok(None);
        };
        let Some(key) = Self::load_key(directory)? else {
            return Ok(None);
        };
        if key.public_key() != identity.public_key {
            return Err(HumanIdentityStoreError::KeyMismatch);
        }
        Ok(Some((identity, key)))
    }

    pub fn load_membership(
        directory: &Path,
    ) -> Result<Option<HumanMembershipCertificate>, HumanIdentityStoreError> {
        let path = Self::membership_path(directory);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(bincode::deserialize(&std::fs::read(path)?)?))
    }

    pub fn save_membership(
        directory: &Path,
        membership: &HumanMembershipCertificate,
    ) -> Result<(), HumanIdentityStoreError> {
        std::fs::create_dir_all(directory)?;
        std::fs::write(
            Self::membership_path(directory),
            bincode::serialize(membership)?,
        )?;
        Ok(())
    }

    pub fn load_or_init(
        directory: &Path,
        display_name: Option<&str>,
    ) -> Result<(HumanIdentity, HumanKeyPair), HumanIdentityStoreError> {
        if let Some(existing) = Self::load_with_key(directory)? {
            return Ok(existing);
        }
        if Self::identity_path(directory).exists() || Self::key_path(directory).exists() {
            return Err(HumanIdentityStoreError::KeyMismatch);
        }

        std::fs::create_dir_all(directory)?;
        let key = HumanKeyPair::generate();
        let identity = HumanIdentity::new(
            misaka_core::HumanId::generate(),
            display_name
                .filter(|name| !name.is_empty())
                .unwrap_or("misaka operator")
                .to_string(),
            key.public_key(),
        );
        write_key(&Self::key_path(directory), &key.to_bytes())?;
        std::fs::write(
            Self::identity_path(directory),
            serde_json::to_string_pretty(&identity)?,
        )?;
        Ok((identity, key))
    }

    pub fn identity_path(directory: &Path) -> PathBuf {
        directory.join(IDENTITY_FILE)
    }

    pub fn key_path(directory: &Path) -> PathBuf {
        directory.join(KEY_FILE)
    }

    pub fn membership_path(directory: &Path) -> PathBuf {
        directory.join(MEMBERSHIP_FILE)
    }
}

fn write_key(path: &Path, bytes: &[u8; 32]) -> Result<(), HumanIdentityStoreError> {
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
    use super::HumanIdentityStore;

    #[test]
    fn human_identity_is_stable_and_private() {
        let directory =
            std::env::temp_dir().join(format!("misaka-human-identity-{}", uuid::Uuid::new_v4()));
        let (first, _) = HumanIdentityStore::load_or_init(&directory, Some("operator")).unwrap();
        let (second, key) = HumanIdentityStore::load_or_init(&directory, Some("changed")).unwrap();

        assert_eq!(first, second);
        assert_eq!(key.public_key(), first.public_key);
        assert_eq!(HumanIdentityStore::load(&directory).unwrap(), Some(first));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(HumanIdentityStore::key_path(&directory))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(directory);
    }
}
