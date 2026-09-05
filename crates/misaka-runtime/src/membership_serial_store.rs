//! Persistent, monotonic MembershipCertificate serial allocation.
//!
//! Sister revocation is identified by `MembershipKind + membership_serial`, so a
//! serial MUST NEVER be reused — including across Authority process restarts.
//! The enrollment path cannot rely on an in-memory counter seeded from wall
//! clock time (that restarts low and can collide). This store keeps a single
//! high-water mark on disk under the Authority's own config directory.
//!
//! This is deliberately a tiny monotonic counter, not a membership registry: it
//! assigns serials, and nothing more.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SERIAL_FILE: &str = "membership-serial";

/// Filesystem-backed monotonic serial allocator.
///
/// The in-memory value is seeded from the persisted high-water mark on open and
/// written through on every allocation, so a restart never rewinds and a
/// concurrent redemption can never observe the same value twice.
pub struct MembershipSerialStore {
    directory: PathBuf,
    state: Mutex<u64>,
}

impl MembershipSerialStore {
    /// Open the allocator, resuming from the persisted serial (0 when new).
    pub fn open(directory: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(directory)?;
        let current = Self::read(directory)?.unwrap_or(0);
        Ok(Self {
            directory: directory.to_path_buf(),
            state: Mutex::new(current),
        })
    }

    fn path(directory: &Path) -> PathBuf {
        directory.join(SERIAL_FILE)
    }

    fn read(directory: &Path) -> std::io::Result<Option<u64>> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let text = fs::read_to_string(path)?;
        let value = text
            .trim()
            .parse::<u64>()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        Ok(Some(value))
    }

    /// Allocate the next serial. Strictly greater than every previously issued
    /// serial, durable across restart.
    pub fn allocate(&self) -> std::io::Result<u64> {
        let mut current = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("membership serial lock poisoned"))?;
        let next = current.saturating_add(1);
        // Write-through before publishing the serial: the Authority signs and
        // sends the membership only after this returns, so a crash never lets a
        // delivered serial rewind or repeat after restart.
        fs::write(Self::path(&self.directory), next.to_string())?;
        *current = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("misaka-serial-{}", uuid::Uuid::new_v4()));
        dir
    }

    #[test]
    fn serial_is_monotonic_and_survives_reopen() {
        let dir = temp();
        let first = MembershipSerialStore::open(&dir).unwrap();
        let a = first.allocate().unwrap();
        let b = first.allocate().unwrap();
        assert_eq!((a, b), (1, 2));

        // A fresh process-equivalent (reopen) must continue above the last serial.
        drop(first);
        let reopened = MembershipSerialStore::open(&dir).unwrap();
        let c = reopened.allocate().unwrap();
        assert!(c > b, "serial {c} did not exceed persisted {b}");

        // And again across a second restart.
        drop(reopened);
        let again = MembershipSerialStore::open(&dir).unwrap();
        let d = again.allocate().unwrap();
        assert!(d > c);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_allocation_never_repeats_a_serial() {
        let dir = temp();
        let store = std::sync::Arc::new(MembershipSerialStore::open(&dir).unwrap());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            threads.push(std::thread::spawn(move || {
                let mut local = Vec::new();
                for _ in 0..16 {
                    local.push(store.allocate().unwrap());
                }
                local
            }));
        }
        let mut all = Vec::new();
        for t in threads {
            all.extend(t.join().unwrap());
        }
        let unique: std::collections::HashSet<u64> = all.iter().copied().collect();
        assert_eq!(
            unique.len(),
            all.len(),
            "a serial was issued twice concurrently"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
