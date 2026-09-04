//! Persistence and validation of one Sister's membership certificate.

use misaka_core::{MembershipCertificate, NetworkAuthority};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MEMBERSHIP_FILE: &str = "membership.bin";

#[derive(Debug, Error)]
pub enum MembershipStoreError {
    #[error("membership I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid membership certificate: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
}

pub struct MembershipStore;

impl MembershipStore {
    pub fn load(directory: &Path) -> Result<Option<MembershipCertificate>, MembershipStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(bincode::deserialize(&std::fs::read(path)?)?))
    }

    pub fn save(
        directory: &Path,
        certificate: &MembershipCertificate,
    ) -> Result<(), MembershipStoreError> {
        std::fs::create_dir_all(directory)?;
        std::fs::write(Self::path(directory), bincode::serialize(certificate)?)?;
        Ok(())
    }

    pub fn validate(
        certificate: &MembershipCertificate,
        authority: &NetworkAuthority,
        now: u64,
    ) -> bool {
        certificate.verify(authority) && certificate.is_valid_at(now)
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(MEMBERSHIP_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::MembershipStore;
    use crate::sister_key_store::SisterKeyStore;
    use misaka_core::{MembershipCertificate, NetworkAuthority, NetworkId};

    #[test]
    fn membership_certificate_roundtrips_and_validates() {
        let directory =
            std::env::temp_dir().join(format!("misaka-membership-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyStore::load_or_init(&directory).unwrap();
        let certificate = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            42,
            10,
            Some(20),
            1,
        );

        MembershipStore::save(&directory, &certificate).unwrap();
        let loaded = MembershipStore::load(&directory).unwrap().unwrap();
        assert_eq!(loaded, certificate);
        assert!(MembershipStore::validate(&loaded, &authority, 10));
        assert!(!MembershipStore::validate(&loaded, &authority, 21));

        let _ = std::fs::remove_dir_all(directory);
    }
}
