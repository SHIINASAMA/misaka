//! Persistence for the signed revocation records distributed by a Network.

use misaka_core::{MembershipKind, NetworkAuthority, NetworkId, RevocationRecord};
use std::path::{Path, PathBuf};
use thiserror::Error;

const REVOCATION_FILE: &str = "revocations.json";

#[derive(Debug, Error)]
pub enum RevocationStoreError {
    #[error("revocation I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid revocation list: {0}")]
    Json(#[from] serde_json::Error),
    #[error("revocation record is not signed by this Network authority")]
    InvalidSignature,
}

pub struct RevocationStore;

impl RevocationStore {
    pub fn load(directory: &Path) -> Result<Vec<RevocationRecord>, RevocationStoreError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn save(
        directory: &Path,
        records: &[RevocationRecord],
    ) -> Result<(), RevocationStoreError> {
        std::fs::create_dir_all(directory)?;
        std::fs::write(
            Self::path(directory),
            serde_json::to_string_pretty(records)?,
        )?;
        Ok(())
    }

    pub fn append(
        directory: &Path,
        authority: &NetworkAuthority,
        record: RevocationRecord,
    ) -> Result<(), RevocationStoreError> {
        if !record.verify(authority) {
            return Err(RevocationStoreError::InvalidSignature);
        }
        let mut records = Self::load(directory)?;
        if !records.iter().any(|existing| {
            existing.network_id == record.network_id
                && existing.membership_kind == record.membership_kind
                && existing.membership_serial == record.membership_serial
        }) {
            records.push(record);
            Self::save(directory, &records)?;
        }
        Ok(())
    }

    pub fn is_revoked(
        directory: &Path,
        authority: &NetworkAuthority,
        network_id: NetworkId,
        membership_kind: MembershipKind,
        membership_serial: u64,
    ) -> Result<bool, RevocationStoreError> {
        for record in Self::load(directory)? {
            if record.network_id != network_id {
                continue;
            }
            if !record.verify(authority) {
                return Err(RevocationStoreError::InvalidSignature);
            }
            if record.membership_kind == membership_kind
                && record.membership_serial == membership_serial
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(REVOCATION_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::RevocationStore;
    use misaka_core::{MembershipKind, NetworkAuthority, NetworkId, RevocationRecord};

    #[test]
    fn signed_revocation_is_persisted_and_detected() {
        let directory =
            std::env::temp_dir().join(format!("misaka-revocations-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let (authority, key) = NetworkAuthority::generate(network_id);
        let record = RevocationRecord::issue(
            &authority,
            &key,
            MembershipKind::Sister,
            9,
            100,
            "retired".into(),
        );

        RevocationStore::append(&directory, &authority, record).unwrap();
        assert!(RevocationStore::is_revoked(
            &directory,
            &authority,
            network_id,
            MembershipKind::Sister,
            9
        )
        .unwrap());
        assert!(!RevocationStore::is_revoked(
            &directory,
            &authority,
            network_id,
            MembershipKind::Sister,
            10
        )
        .unwrap());

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn sister_and_human_serials_are_independent() {
        let directory =
            std::env::temp_dir().join(format!("misaka-revocations-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let (authority, key) = NetworkAuthority::generate(network_id);
        RevocationStore::append(
            &directory,
            &authority,
            RevocationRecord::issue(
                &authority,
                &key,
                MembershipKind::Human,
                1,
                100,
                "human retired".into(),
            ),
        )
        .unwrap();

        assert!(RevocationStore::is_revoked(
            &directory,
            &authority,
            network_id,
            MembershipKind::Human,
            1
        )
        .unwrap());
        assert!(!RevocationStore::is_revoked(
            &directory,
            &authority,
            network_id,
            MembershipKind::Sister,
            1
        )
        .unwrap());

        let _ = std::fs::remove_dir_all(directory);
    }
}
