//! Durable replay protection for human-signed command authorizations.

use misaka_core::{CommandAuthorization, NetworkId};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

const NONCES_FILE: &str = "used-command-nonces.json";

#[derive(Debug, Error)]
pub enum AuthorizationNonceStoreError {
    #[error("authorization nonce I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid authorization nonce store: {0}")]
    Json(#[from] serde_json::Error),
    #[error("command authorization nonce has already been used")]
    Replay,
    #[error("command authorization belongs to another Network")]
    NetworkMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NonceEntry {
    network_id: NetworkId,
    nonce: [u8; 16],
    expires_at: u64,
}

pub struct AuthorizationNonceStore;

impl AuthorizationNonceStore {
    /// Atomically from the caller's perspective check and persist a nonce.
    /// Expired entries are compacted on every write so this file stays small.
    pub fn record(
        directory: &Path,
        authorization: &CommandAuthorization,
        now: u64,
    ) -> Result<(), AuthorizationNonceStoreError> {
        if authorization.network_id != authorization.membership.network_id {
            return Err(AuthorizationNonceStoreError::NetworkMismatch);
        }
        let path = Self::path(directory);
        let mut entries = if path.exists() {
            serde_json::from_str::<Vec<NonceEntry>>(&std::fs::read_to_string(&path)?)?
        } else {
            Vec::new()
        };
        entries.retain(|entry| entry.expires_at >= now);
        if entries.iter().any(|entry| {
            entry.network_id == authorization.network_id && entry.nonce == authorization.nonce
        }) {
            return Err(AuthorizationNonceStoreError::Replay);
        }
        entries.push(NonceEntry {
            network_id: authorization.network_id,
            nonce: authorization.nonce,
            expires_at: authorization.expires_at,
        });
        std::fs::create_dir_all(directory)?;
        std::fs::write(path, serde_json::to_string_pretty(&entries)?)?;
        Ok(())
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(NONCES_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationNonceStore, AuthorizationNonceStoreError};
    use misaka_core::{
        CommandAuthorization, HumanIdentity, HumanKeyPair, HumanMembershipCertificate,
        NetworkAuthority, NetworkId, Permission, Role,
    };

    #[test]
    fn command_nonce_is_rejected_when_replayed_and_expired_entries_are_compacted() {
        let directory =
            std::env::temp_dir().join(format!("misaka-command-nonces-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let key = HumanKeyPair::generate();
        let human = HumanIdentity::new(
            misaka_core::HumanId::generate(),
            "operator".into(),
            key.public_key(),
        );
        let membership = HumanMembershipCertificate::issue(
            &authority,
            &authority_key,
            human.clone(),
            Role::Operator,
            10,
            Some(20),
            1,
        );
        let authorization = CommandAuthorization::issue(
            network_id,
            human,
            membership,
            Role::Operator,
            Permission::JobSubmit,
            None,
            vec![],
            10,
            20,
            [1; 16],
            &key,
        );

        AuthorizationNonceStore::record(&directory, &authorization, 10).unwrap();
        assert!(matches!(
            AuthorizationNonceStore::record(&directory, &authorization, 10),
            Err(AuthorizationNonceStoreError::Replay)
        ));
        AuthorizationNonceStore::record(&directory, &authorization, 21).unwrap();

        let _ = std::fs::remove_dir_all(directory);
    }
}
