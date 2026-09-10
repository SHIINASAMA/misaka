//! Top-level state layout version for one Sister config directory.
//!
//! A single `state-layout.json` manifest gates on-disk format compatibility.
//! It exists so a future upgrade has one stable boundary to check before
//! touching identity/security state. It is deliberately NOT a per-file
//! versioning scheme; individual artifacts gain their own version fields only
//! when they actually evolve.
//!
//! Startup behavior:
//! ```text
//! no manifest, empty/new dir        → create layout v1
//! no manifest, existing Misaka dir  → adopt into layout v1 (no rewriting)
//! manifest version > supported      → FAIL CLOSED
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

const LAYOUT_FILE: &str = "state-layout.json";

/// Current supported on-disk state layout version.
pub const CURRENT_STATE_LAYOUT_VERSION: u32 = 1;

/// Durable markers whose presence means "this is an existing Misaka config
/// directory" (legacy layout 0) rather than a brand-new one. Deliberately a
/// broad, read-only probe — it never creates or rewrites anything.
const KNOWN_STATE_MARKERS: &[&str] = &[
    "identity.json",
    "sister-identity-key",
    "iroh-stream-key.bin",
    "network-id",
    "network.json",
    "network-authority-key",
    "membership.bin",
    "membership-serial",
    "human-identity.json",
    "human-identity-key",
    "human-membership.bin",
    "transport-binding.json",
    "revocations.json",
    "used-command-nonces.json",
    "gateways.json",
    "peer-records.json",
    "peers.json",
    "service.json",
    "local-control-token",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateLayoutManifest {
    pub layout_version: u32,
    /// Non-authoritative metadata; never used as the schema identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_opened_by_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutOpen {
    /// A brand-new config directory; layout v1 was created.
    Created,
    /// An existing pre-manifest directory; adopted into v1 without rewriting.
    Adopted,
    /// The manifest was already present and compatible.
    Existing,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateLayoutError {
    #[error("state layout I/O error: {0}")]
    Io(String),
    #[error("state-layout.json is malformed: {0}")]
    Malformed(String),
    #[error(
        "Misaka state layout v{found} is newer than this binary supports (max v{supported}). \
         Refusing to start."
    )]
    TooNew { found: u32, supported: u32 },
    #[error("unsupported migration from layout v{from} to v{to}")]
    UnsupportedMigration { from: u32, to: u32 },
}

impl From<std::io::Error> for StateLayoutError {
    fn from(error: std::io::Error) -> Self {
        StateLayoutError::Io(error.to_string())
    }
}

pub struct StateLayout;

impl StateLayout {
    pub fn path(directory: &Path) -> PathBuf {
        directory.join(LAYOUT_FILE)
    }

    /// Load the manifest if present. A malformed manifest is an error.
    pub fn load(directory: &Path) -> Result<Option<StateLayoutManifest>, StateLayoutError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| StateLayoutError::Malformed(error.to_string()))
    }

    /// Open (and if necessary create or adopt) the layout for `directory`.
    ///
    /// Fails closed when the stored layout is newer than this binary supports.
    pub fn open(directory: &Path) -> Result<LayoutOpen, StateLayoutError> {
        Self::open_with_version(directory, env!("CARGO_PKG_VERSION"))
    }

    fn open_with_version(
        directory: &Path,
        binary_version: &str,
    ) -> Result<LayoutOpen, StateLayoutError> {
        match Self::load(directory)? {
            Some(manifest) if manifest.layout_version > CURRENT_STATE_LAYOUT_VERSION => {
                Err(StateLayoutError::TooNew {
                    found: manifest.layout_version,
                    supported: CURRENT_STATE_LAYOUT_VERSION,
                })
            }
            Some(mut manifest) => {
                if manifest.last_opened_by_version.as_deref() != Some(binary_version) {
                    manifest.last_opened_by_version = Some(binary_version.to_string());
                    Self::write(directory, &manifest)?;
                }
                Ok(LayoutOpen::Existing)
            }
            None => {
                let has_existing_state = KNOWN_STATE_MARKERS
                    .iter()
                    .any(|marker| directory.join(marker).exists());
                let manifest = StateLayoutManifest {
                    layout_version: CURRENT_STATE_LAYOUT_VERSION,
                    created_by_version: Some(binary_version.to_string()),
                    last_opened_by_version: Some(binary_version.to_string()),
                };
                Self::write(directory, &manifest)?;
                Ok(if has_existing_state {
                    LayoutOpen::Adopted
                } else {
                    LayoutOpen::Created
                })
            }
        }
    }

    fn write(directory: &Path, manifest: &StateLayoutManifest) -> Result<(), StateLayoutError> {
        std::fs::create_dir_all(directory)?;
        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|error| StateLayoutError::Malformed(error.to_string()))?;
        let path = Self::path(directory);
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }
}

/// Minimal migration contract. No real migrations exist yet; the point is to
/// establish the shape: inspect the old version, stage, validate, commit, then
/// advance `state-layout.json`. The manifest is never advanced unless the
/// migration succeeds.
///
/// This is intentionally not a general framework, and it does not claim
/// cross-file atomicity. A future multi-file migration must add a staging
/// directory + recovery marker; see `docs/deployment-v1.md`.
pub fn migrate(directory: &Path, from: u32, to: u32) -> Result<(), StateLayoutError> {
    if from > CURRENT_STATE_LAYOUT_VERSION || to > CURRENT_STATE_LAYOUT_VERSION {
        return Err(StateLayoutError::UnsupportedMigration { from, to });
    }
    if to < from {
        return Err(StateLayoutError::UnsupportedMigration { from, to });
    }
    // from == to (no-op) and 0 → 1 (adoption) are the only supported steps.
    if from != to && !(from == 0 && to == 1) {
        return Err(StateLayoutError::UnsupportedMigration { from, to });
    }
    let mut manifest = StateLayout::load(directory)?.unwrap_or(StateLayoutManifest {
        layout_version: 0,
        created_by_version: None,
        last_opened_by_version: None,
    });
    // Migration work would be staged and validated here. There is none yet.
    manifest.layout_version = to;
    StateLayout::write(directory, &manifest)
}

#[cfg(test)]
mod tests {
    use super::{
        migrate, LayoutOpen, StateLayout, StateLayoutError, StateLayoutManifest,
        CURRENT_STATE_LAYOUT_VERSION,
    };
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("misaka-layout-{}", uuid::Uuid::new_v4()))
    }

    // SL01: a new empty directory gets layout v1.
    #[test]
    fn new_directory_creates_layout_v1() {
        let dir = temp_dir();
        assert_eq!(StateLayout::open(&dir).unwrap(), LayoutOpen::Created);
        let manifest = StateLayout::load(&dir).unwrap().unwrap();
        assert_eq!(manifest.layout_version, CURRENT_STATE_LAYOUT_VERSION);
        let _ = std::fs::remove_dir_all(dir);
    }

    // SL02: an existing legacy directory is adopted into v1.
    #[test]
    fn legacy_directory_is_adopted() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("identity.json"), b"{}").unwrap();
        std::fs::write(dir.join("membership.bin"), b"legacy").unwrap();
        assert_eq!(StateLayout::open(&dir).unwrap(), LayoutOpen::Adopted);
        assert_eq!(
            StateLayout::load(&dir).unwrap().unwrap().layout_version,
            CURRENT_STATE_LAYOUT_VERSION
        );
        // Existing files are untouched by adoption.
        assert_eq!(
            std::fs::read(dir.join("membership.bin")).unwrap(),
            b"legacy"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // SL03: a newer unsupported layout fails closed.
    #[test]
    fn newer_layout_fails_closed() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = StateLayoutManifest {
            layout_version: CURRENT_STATE_LAYOUT_VERSION + 2,
            created_by_version: Some("future".into()),
            last_opened_by_version: None,
        };
        std::fs::write(
            StateLayout::path(&dir),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            StateLayout::open(&dir),
            Err(StateLayoutError::TooNew { .. })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    // SL04: a failed migration does not advance the layout version.
    #[test]
    fn failed_migration_does_not_advance_version() {
        let dir = temp_dir();
        StateLayout::open(&dir).unwrap();
        let before = StateLayout::load(&dir).unwrap().unwrap().layout_version;
        assert!(migrate(&dir, 1, 3).is_err());
        let after = StateLayout::load(&dir).unwrap().unwrap().layout_version;
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(dir);
    }

    // SL05/SL06: adoption never rewrites identity/secret files — even a
    // malformed one is left exactly as found (never regenerated here).
    #[test]
    fn adoption_never_touches_identity_or_secret_files() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let key_bytes = [7u8; 32];
        std::fs::write(dir.join("sister-identity-key"), key_bytes).unwrap();
        std::fs::write(dir.join("iroh-stream-key.bin"), b"malformed-not-32-bytes").unwrap();
        StateLayout::open(&dir).unwrap();
        assert_eq!(
            std::fs::read(dir.join("sister-identity-key")).unwrap(),
            key_bytes
        );
        assert_eq!(
            std::fs::read(dir.join("iroh-stream-key.bin")).unwrap(),
            b"malformed-not-32-bytes"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // A malformed manifest is an error, not a silently recreated one.
    #[test]
    fn malformed_manifest_is_an_error() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(StateLayout::path(&dir), b"{not json").unwrap();
        assert!(matches!(
            StateLayout::open(&dir),
            Err(StateLayoutError::Malformed(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
