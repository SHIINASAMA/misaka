//! Atomic installation of a joined Network.
//!
//! The ordinary stores write files directly and are deliberately simple
//! (single `fs::write`). Enrollment, however, must not be able to leave a
//! half-installed Network: a `network-id` without a `membership.bin`, or a
//! `network.json` whose certificate failed to arrive. This module stages every
//! network-scoped artifact into a throwaway subdirectory using the *same* stores
//! the rest of the runtime uses — so the on-disk format is identical — validates
//! the staged result, and only then renames each file into place.
//!
//! IMPORTANT — what is and is not atomic here. Each individual rename is atomic
//! on a same-filesystem path, and NOTHING is renamed until every artifact has
//! been staged and re-verified, so a *failure before commit* leaves the existing
//! config directory completely untouched (and a fresh directory stays
//! retryable). But the commit itself is a sequence of independent renames, not a
//! single multi-file transaction: a crash *during* commit (after some renames,
//! before the rest) could leave a partially-renamed set. Closing that last gap
//! needs a durable manifest/recovery step or a single-file bundle and is left as
//! a documented follow-up rather than claimed as solved here.
//!
//! Sister-local preparation (the identity and its key) is intentionally *not*
//! part of this transaction: a Sister identity without a Network membership is
//! inert, is created idempotently, and lets a failed join be retried with the
//! same key. Only the Network itself is staged-then-committed.

use crate::gateway_store::GatewayStore;
use crate::membership_store::MembershipStore;
use crate::network_authority_store::NetworkAuthorityStore;
use crate::network_id_store::NetworkIdStore;
use crate::peer_record_store::PeerRecordStore;
use misaka_core::enrollment::EnrollmentBundle;
use misaka_core::{NetworkId, PeerRecord};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JoinError {
    #[error("join I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("join store write failed: {0}")]
    Store(String),
    #[error("a different Network is already installed here: {reason}")]
    Conflict { reason: String },
    #[error("staged enrollment failed its post-write verification: {0}")]
    Verification(String),
}

/// The complete set of files that constitute an installed Network. `gateways` is
/// only written when the operator supplied one to `network join`.
pub struct NetworkInstall {
    bundle: EnrollmentBundle,
    gateways: Option<Vec<String>>,
}

impl NetworkInstall {
    pub fn new(bundle: EnrollmentBundle, gateways: Option<Vec<String>>) -> Self {
        Self { bundle, gateways }
    }

    fn network_id(&self) -> NetworkId {
        self.bundle.authority.network_id
    }
}

/// Install a validated enrollment bundle. Staging + verification happen before
/// any rename, so any failure up to the commit leaves the existing config
/// directory untouched and the staging directory removed (safely retryable). A
/// crash *during* the commit's rename sequence can still leave a partially
/// installed set — see the module note (durable recovery is a follow-up).
pub fn install(data_dir: &Path, install: &NetworkInstall) -> Result<(), JoinError> {
    std::fs::create_dir_all(data_dir)?;

    // Pre-flight: refuse to touch a directory that already belongs to a
    // different Network before staging anything.
    guard_existing_network(data_dir, install.network_id())?;

    let staging = prepare_staging(data_dir)?;

    let outcome = stage_and_validate(&staging, install)
        .and_then(|staged| commit_staged(&staging, data_dir, &staged).map_err(JoinError::Io));

    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    outcome
}

/// Refuse to modify a config directory that already belongs to a different
/// Network. This runs before anything is staged, so the existing state is never
/// brought into doubt.
fn guard_existing_network(data_dir: &Path, network_id: NetworkId) -> Result<(), JoinError> {
    if let Some(existing) =
        NetworkIdStore::load(data_dir).map_err(|error| JoinError::Store(error.to_string()))?
    {
        if existing != network_id {
            return Err(JoinError::Conflict {
                reason: format!("persisted NetworkId {existing} != {network_id}"),
            });
        }
    }
    if let Some(existing) = NetworkAuthorityStore::load(data_dir)
        .map_err(|error| JoinError::Store(error.to_string()))?
    {
        if existing.network_id != network_id {
            return Err(JoinError::Conflict {
                reason: "an authority descriptor for a different Network is installed".to_string(),
            });
        }
    }
    Ok(())
}

fn prepare_staging(data_dir: &Path) -> Result<PathBuf, JoinError> {
    let staging = data_dir.join(format!(".misaka-join-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&staging)?;
    Ok(staging)
}

/// Serialize the bundle through the ordinary stores into `staging`, then read it
/// back to confirm the staged Network is self-consistent before committing.
fn stage_and_validate(
    staging: &Path,
    install: &NetworkInstall,
) -> Result<Vec<&'static str>, JoinError> {
    let bundle = &install.bundle;

    NetworkIdStore::load_or_init(staging, Some(install.network_id()))
        .map_err(|error| JoinError::Store(error.to_string()))?;
    NetworkAuthorityStore::install_descriptor(staging, &bundle.authority)
        .map_err(|error| JoinError::Store(error.to_string()))?;
    MembershipStore::save(staging, &bundle.membership)
        .map_err(|error| JoinError::Store(error.to_string()))?;

    let records: HashMap<u64, PeerRecord> = bundle
        .bootstrap_records
        .iter()
        .map(|record| (record.sister_id.as_u64(), record.clone()))
        .collect();
    PeerRecordStore::save_to_dir(staging, &records).map_err(JoinError::Io)?;

    let mut staged = vec![
        "network-id",
        "network.json",
        "membership.bin",
        "peer-records.json",
    ];
    if let Some(gateways) = &install.gateways {
        GatewayStore::save(staging, gateways).map_err(JoinError::Io)?;
        staged.push("gateways.json");
    }

    // Read back and re-verify the staged Network: a rename cannot then expose a
    // membership the descriptor would reject.
    let reloaded_authority = NetworkAuthorityStore::load(staging)
        .map_err(|error| JoinError::Store(error.to_string()))?
        .ok_or_else(|| JoinError::Verification("descriptor missing after stage".into()))?;
    let reloaded_membership = MembershipStore::load(staging)
        .map_err(|error| JoinError::Store(error.to_string()))?
        .ok_or_else(|| JoinError::Verification("membership missing after stage".into()))?;
    if reloaded_membership != bundle.membership
        || !reloaded_membership.verify(&reloaded_authority)
        || reloaded_authority != bundle.authority
    {
        return Err(JoinError::Verification(
            "staged membership does not match the staged authority".into(),
        ));
    }
    Ok(staged)
}

fn commit_staged(
    staging: &Path,
    data_dir: &Path,
    staged: &[&'static str],
) -> Result<(), std::io::Error> {
    for name in staged {
        std::fs::rename(staging.join(name), data_dir.join(name))?;
    }
    let _ = std::fs::remove_dir_all(staging);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_core::{
        EnrollmentBundle, MembershipCertificate, NetworkAuthority, NetworkId, SisterKeyPair,
        TransportBinding,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("misaka-join-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_bundle() -> (NetworkId, EnrollmentBundle) {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let joiner_key = SisterKeyPair::generate();
        let membership = MembershipCertificate::issue(
            &authority,
            &authority_key,
            joiner_key.public_key(),
            7,
            100,
            None,
            5,
        );
        let boot_key = SisterKeyPair::generate();
        let binding = TransportBinding::sign(
            network_id,
            1,
            misaka_core::IrohEndpointId::from_bytes([2u8; 32]),
            1,
            &boot_key,
        );
        let record = PeerRecord::issue(network_id, 1, "iroh://a".into(), binding, 100, &boot_key);
        (
            network_id,
            EnrollmentBundle {
                authority,
                membership,
                bootstrap_records: vec![record],
            },
        )
    }

    #[test]
    fn install_writes_every_artifact_atomically() {
        let (network_id, bundle) = fixture_bundle();
        let dir = temp_dir("ok");
        install(
            &dir,
            &NetworkInstall::new(bundle.clone(), Some(vec!["http://gw".into()])),
        )
        .unwrap();

        assert_eq!(NetworkIdStore::load(&dir).unwrap(), Some(network_id));
        assert_eq!(
            NetworkAuthorityStore::load(&dir).unwrap().unwrap(),
            bundle.authority
        );
        assert_eq!(
            MembershipStore::load(&dir).unwrap().unwrap(),
            bundle.membership
        );
        assert_eq!(GatewayStore::load(&dir), vec!["http://gw"]);
        assert_eq!(PeerRecordStore::load_from_dir(&dir, network_id).len(), 1);
        // No staging residue.
        assert!(!std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".misaka-join")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_foreign_installed_network_is_never_touched() {
        let (_network_id, bundle) = fixture_bundle();
        let dir = temp_dir("conflict");
        // Pre-existing, different Network.
        let original = NetworkIdStore::load_or_init(&dir, Some(NetworkId::generate()))
            .unwrap()
            .to_string();

        let error = install(&dir, &NetworkInstall::new(bundle.clone(), None)).unwrap_err();
        assert!(matches!(error, JoinError::Conflict { .. }));

        // The unrelated NetworkId survives untouched, and none of the bundle's
        // network artifacts leaked in.
        assert_eq!(
            NetworkIdStore::load(&dir).unwrap().unwrap().to_string(),
            original
        );
        assert!(NetworkAuthorityStore::load(&dir).unwrap().is_none());
        assert!(MembershipStore::load(&dir).unwrap().is_none());
        assert!(!PeerRecordStore::path(&dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
