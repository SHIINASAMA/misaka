//! Structured ephemeral runtime metadata for one running Sister.
//!
//! `runtime.json` records where the local control API is bound and which
//! process owns it. It is EPHEMERAL runtime state — not Network state,
//! identity, membership, configuration, or authorization — and is safe to
//! delete; a stale file is detected by the caller, never trusted blindly.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

const RUNTIME_FILE: &str = "runtime.json";
/// Schema version of the `runtime.json` record itself.
pub const CURRENT_RUNTIME_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInstance {
    pub schema_version: u32,
    /// Random per-process id; used so an old process never removes the marker
    /// written by a newer one.
    pub instance_id: String,
    pub pid: u32,
    pub started_at: u64,
    pub api_endpoint: String,
    pub api_result_timeout_secs: u64,
    pub binary_version: String,
}

#[derive(Debug, Error)]
pub enum RuntimeInstanceError {
    #[error("runtime marker I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime marker is malformed: {0}")]
    Malformed(String),
}

pub struct RuntimeInstanceStore;

impl RuntimeInstanceStore {
    pub fn path(directory: &Path) -> PathBuf {
        directory.join(RUNTIME_FILE)
    }

    /// Write the marker atomically (temp file + rename).
    pub fn write(directory: &Path, instance: &RuntimeInstance) -> Result<(), RuntimeInstanceError> {
        std::fs::create_dir_all(directory)?;
        let bytes = serde_json::to_vec_pretty(instance)
            .map_err(|error| RuntimeInstanceError::Malformed(error.to_string()))?;
        let path = Self::path(directory);
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, bytes)?;
        std::fs::rename(&temp, &path)?;
        Ok(())
    }

    /// Load the marker. `Ok(None)` means no marker; a malformed marker is an
    /// error (the caller decides whether that is stale or fatal).
    pub fn load(directory: &Path) -> Result<Option<RuntimeInstance>, RuntimeInstanceError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| RuntimeInstanceError::Malformed(error.to_string()))
    }

    /// Remove the marker only if it belongs to `instance_id`. Returns whether a
    /// file was removed. An old process therefore cannot delete the state
    /// written by a newer process.
    pub fn remove_if_matches(directory: &Path, instance_id: &str) -> bool {
        match Self::load(directory) {
            Ok(Some(instance)) if instance.instance_id == instance_id => {
                std::fs::remove_file(Self::path(directory)).is_ok()
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeInstance, RuntimeInstanceStore, CURRENT_RUNTIME_SCHEMA_VERSION};
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("misaka-runtime-{}", uuid::Uuid::new_v4()))
    }

    fn instance(id: &str) -> RuntimeInstance {
        RuntimeInstance {
            schema_version: CURRENT_RUNTIME_SCHEMA_VERSION,
            instance_id: id.to_string(),
            pid: 1234,
            started_at: 99,
            api_endpoint: "127.0.0.1:31702".to_string(),
            api_result_timeout_secs: 60,
            binary_version: "0.1.0".to_string(),
        }
    }

    #[test]
    fn roundtrips_and_reports_the_loopback_endpoint() {
        let dir = temp_dir();
        RuntimeInstanceStore::write(&dir, &instance("a")).unwrap();
        let loaded = RuntimeInstanceStore::load(&dir).unwrap().unwrap();
        assert_eq!(loaded.api_endpoint, "127.0.0.1:31702");
        assert_eq!(loaded.binary_version, "0.1.0");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn remove_only_matches_the_owning_instance() {
        let dir = temp_dir();
        RuntimeInstanceStore::write(&dir, &instance("new")).unwrap();
        // A different (older) process must not remove it.
        assert!(!RuntimeInstanceStore::remove_if_matches(&dir, "old"));
        assert!(RuntimeInstanceStore::load(&dir).unwrap().is_some());
        // The owner removes it.
        assert!(RuntimeInstanceStore::remove_if_matches(&dir, "new"));
        assert!(RuntimeInstanceStore::load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_marker_is_an_error_not_panicked_through() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(RuntimeInstanceStore::path(&dir), b"{not json").unwrap();
        assert!(RuntimeInstanceStore::load(&dir).is_err());
        // A malformed marker is never silently removed by a non-owner id.
        assert!(!RuntimeInstanceStore::remove_if_matches(&dir, "a"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
