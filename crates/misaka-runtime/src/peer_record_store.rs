//! Filesystem persistence for signed transport locators.
//!
//! PeerRecord is a signed wire contract. This store only persists records that
//! already passed signature and network validation; it never manufactures
//! trust from an unsigned endpoint string.

use misaka_core::{NetworkId, PeerRecord};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const RECORDS_FILE: &str = "peer-records.json";

pub struct PeerRecordStore;

impl PeerRecordStore {
    pub fn load_from_dir(dir: &Path, network_id: NetworkId) -> HashMap<u64, PeerRecord> {
        let path = dir.join(RECORDS_FILE);
        let Ok(json) = std::fs::read_to_string(path) else {
            return HashMap::new();
        };
        serde_json::from_str::<Vec<PeerRecord>>(&json)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                record.network_id == network_id && record.verify() && record.sister_id.as_u64() != 0
            })
            .map(|record| (record.sister_id.as_u64(), record))
            .collect()
    }

    pub fn save_to_dir(dir: &Path, records: &HashMap<u64, PeerRecord>) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut records: Vec<_> = records.values().cloned().collect();
        records.sort_by_key(|record| record.sister_id.as_u64());
        let json = serde_json::to_string_pretty(&records)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(dir.join(RECORDS_FILE), json)
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join(RECORDS_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_core::{IrohEndpointId, SisterKeyPair, TransportBinding};

    #[test]
    fn signed_records_roundtrip_and_invalid_records_are_not_loaded() {
        let dir =
            std::env::temp_dir().join(format!("misaka-peer-records-{}", uuid::Uuid::new_v4()));
        let network_id = NetworkId::generate();
        let key = SisterKeyPair::generate();
        let binding = TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([7u8; 32]),
            0,
            &key,
        );
        let record = PeerRecord::issue(network_id, 42, "iroh://endpoint".into(), binding, 1, &key);
        let mut records = HashMap::new();
        records.insert(42, record.clone());
        PeerRecordStore::save_to_dir(&dir, &records).unwrap();
        assert_eq!(PeerRecordStore::load_from_dir(&dir, network_id), records);

        let mut invalid = record;
        invalid.endpoint_addr = "iroh://forged".into();
        PeerRecordStore::save_to_dir(&dir, &HashMap::from([(42, invalid)])).unwrap();
        assert!(PeerRecordStore::load_from_dir(&dir, network_id).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
