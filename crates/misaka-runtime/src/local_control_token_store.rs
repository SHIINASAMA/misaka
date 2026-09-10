//! Persistent local-control token for the loopback Sister API.
//!
//! The token is a machine-local secret that authorizes access to the running
//! Sister's local control surface (`/api/v1/*`). It is deliberately
//! independent of every other credential: it is not derived from the Sister
//! key, the Human key, the Network Authority key, the NetworkId, or the
//! SisterId. Loopback is a network boundary, not a local-user authorization
//! boundary; this token is that boundary for local callers.
//!
//! Threat model: it protects against other local OS users/processes that can
//! reach loopback but cannot read this user's private config files. It does
//! NOT protect against malware already running as the same OS user.

use std::path::{Path, PathBuf};
use thiserror::Error;

const TOKEN_FILE: &str = "local-control-token";
/// 256 bits of entropy, hex-encoded ⇒ 64 characters.
const TOKEN_BYTES: usize = 32;
const TOKEN_CHARS: usize = TOKEN_BYTES * 2;

#[derive(Debug, Error)]
pub enum LocalControlTokenError {
    #[error("local control token I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("local control token is malformed (expected {TOKEN_CHARS} hex characters, got {0})")]
    Malformed(usize),
}

/// Filesystem-persisted local control token.
///
/// The token is never derived from other credentials and is never regenerated
/// silently: a malformed existing file is an error, not a cue to overwrite it.
pub struct LocalControlTokenStore;

impl LocalControlTokenStore {
    /// Load the token, generating and persisting one if none exists.
    ///
    /// A present-but-malformed token returns an error; it is never replaced.
    pub fn load_or_init(directory: &Path) -> Result<String, LocalControlTokenError> {
        if let Some(token) = Self::load(directory)? {
            return Ok(token);
        }
        std::fs::create_dir_all(directory)?;
        let token = generate_token();
        write_token(&Self::path(directory), &token)?;
        Ok(token)
    }

    /// Load the token if present. A malformed file is an error.
    pub fn load(directory: &Path) -> Result<Option<String>, LocalControlTokenError> {
        let path = Self::path(directory);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)?;
        let token = raw.trim_end_matches(['\n', '\r']);
        if !is_well_formed(token) {
            return Err(LocalControlTokenError::Malformed(token.len()));
        }
        Ok(Some(token.to_string()))
    }

    pub fn path(directory: &Path) -> PathBuf {
        directory.join(TOKEN_FILE)
    }
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(TOKEN_CHARS);
    for byte in bytes {
        token.push_str(&format!("{byte:02x}"));
    }
    token
}

fn is_well_formed(token: &str) -> bool {
    token.len() == TOKEN_CHARS && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn write_token(path: &Path, token: &str) -> Result<(), LocalControlTokenError> {
    std::fs::write(path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Constant-time equality for two token strings.
///
/// Never short-circuits on the first differing byte. Lengths are compared
/// first (token length is not secret), then all bytes are folded with OR.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{constant_time_eq, LocalControlTokenStore};
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("misaka-lct-{}", uuid::Uuid::new_v4()))
    }

    // LC05: a generated token persists across reloads and is stable.
    #[test]
    fn token_persists_across_reload() {
        let dir = temp_dir();
        let first = LocalControlTokenStore::load_or_init(&dir).unwrap();
        let second = LocalControlTokenStore::load_or_init(&dir).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        let _ = std::fs::remove_dir_all(dir);
    }

    // LC06: a malformed existing token is rejected, never silently replaced.
    #[test]
    fn malformed_token_is_rejected_not_regenerated() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(LocalControlTokenStore::path(&dir), b"not-a-valid-token").unwrap();
        assert!(LocalControlTokenStore::load_or_init(&dir).is_err());
        assert!(LocalControlTokenStore::load(&dir).is_err());
        // The malformed content is untouched.
        let raw = std::fs::read_to_string(LocalControlTokenStore::path(&dir)).unwrap();
        assert_eq!(raw, "not-a-valid-token");
        let _ = std::fs::remove_dir_all(dir);
    }

    // LC07: the token file is owner-only (0600) on Unix.
    #[cfg(unix)]
    #[test]
    fn token_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        LocalControlTokenStore::load_or_init(&dir).unwrap();
        let mode = std::fs::metadata(LocalControlTokenStore::path(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(dir);
    }

    // LC08: different config directories get different tokens.
    #[test]
    fn distinct_directories_get_distinct_tokens() {
        let a = temp_dir();
        let b = temp_dir();
        let ta = LocalControlTokenStore::load_or_init(&a).unwrap();
        let tb = LocalControlTokenStore::load_or_init(&b).unwrap();
        assert_ne!(ta, tb);
        let _ = std::fs::remove_dir_all(a);
        let _ = std::fs::remove_dir_all(b);
    }

    #[test]
    fn constant_time_eq_matches_equality_semantics() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abc", ""));
    }
}
