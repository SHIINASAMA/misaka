//! Filesystem persistence for the Gateways a Sister announces to and
//! discovers through.
//!
//! A Gateway is untrusted infrastructure — this store holds only base URLs, and
//! it is deliberately separate from `peer_record_store` (which holds signed
//! locators). Adding a Gateway confers no trust; it only names a directory the
//! Sister will query. The list is de-duplicated and order-normalised so
//! `add`/`remove` are idempotent.

use std::path::{Path, PathBuf};

const GATEWAYS_FILE: &str = "gateways.json";

pub struct GatewayStore;

impl GatewayStore {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(GATEWAYS_FILE)
    }

    /// Load the configured Gateway base URLs. Missing or malformed files yield
    /// an empty list rather than an error, so a Sister still starts normally
    /// when discovery configuration is absent or corrupt.
    pub fn load(dir: &Path) -> Vec<String> {
        let Ok(json) = std::fs::read_to_string(Self::path(dir)) else {
            return Vec::new();
        };
        serde_json::from_str::<Vec<String>>(&json)
            .unwrap_or_default()
            .into_iter()
            .map(|url| url.trim().trim_end_matches('/').to_string())
            .filter(|url| !url.is_empty())
            .collect()
    }

    pub fn save(dir: &Path, gateways: &[String]) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(gateways)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(Self::path(dir), json)
    }

    /// Add a Gateway if absent. Returns true when the set changed.
    pub fn add(dir: &Path, url: &str) -> std::io::Result<bool> {
        let normalized = url.trim().trim_end_matches('/').to_string();
        if normalized.is_empty() {
            return Ok(false);
        }
        let mut gateways = Self::load(dir);
        if gateways.iter().any(|existing| existing == &normalized) {
            return Ok(false);
        }
        gateways.push(normalized);
        gateways.sort();
        Self::save(dir, &gateways)?;
        Ok(true)
    }

    /// Remove a Gateway if present. Returns true when the set changed.
    pub fn remove(dir: &Path, url: &str) -> std::io::Result<bool> {
        let normalized = url.trim().trim_end_matches('/').to_string();
        let mut gateways = Self::load(dir);
        let before = gateways.len();
        gateways.retain(|existing| existing != &normalized);
        if gateways.len() == before {
            return Ok(false);
        }
        Self::save(dir, &gateways)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::GatewayStore;

    #[test]
    fn add_remove_roundtrip_is_idempotent_and_normalized() {
        let dir = std::env::temp_dir().join(format!("misaka-gateways-{}", uuid::Uuid::new_v4()));
        assert_eq!(GatewayStore::load(&dir), Vec::<String>::new());
        assert!(GatewayStore::add(&dir, "https://gw.example.com/").unwrap());
        // Trailing slash normalized; duplicate add is a no-op.
        assert!(!GatewayStore::add(&dir, "https://gw.example.com").unwrap());
        assert_eq!(
            GatewayStore::load(&dir),
            vec!["https://gw.example.com".to_string()]
        );
        assert!(GatewayStore::remove(&dir, "https://gw.example.com/").unwrap());
        assert!(!GatewayStore::remove(&dir, "https://gw.example.com").unwrap());
        assert!(GatewayStore::load(&dir).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
