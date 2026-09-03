use misaka_core::PeerBlueprint;
use std::path::Path;

/// Peer 持久化层 —— peers.json 读写，供独立 `run` 进程解析地址。
/// 与内存态的 `PeerStateTable` (core) 分离：持久化是 OS 行为，属运行时层。
pub struct PeerStore;

impl PeerStore {
    /// 把所有已知 peers 序列化到指定 data 目录。
    pub fn save_to_dir(table: &misaka_core::PeerStateTable, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("peers.json");
        let blueprints: Vec<PeerBlueprint> = table.all().iter().map(PeerBlueprint::from).collect();
        let json = serde_json::to_string_pretty(&blueprints)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    /// 把所有已知 peers 写入当前配置目录（兼容 CLI 辅助命令）。
    pub fn save_to_file(table: &misaka_core::PeerStateTable) -> std::io::Result<()> {
        let dir = crate::identity_store::IdentityStore::config_dir()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Self::save_to_dir(table, &dir)
    }

    /// 从指定 data 目录加载已知 peers。
    pub fn load_from_dir(dir: &Path) -> Vec<PeerBlueprint> {
        let path = dir.join("peers.json");
        let json = match std::fs::read_to_string(path) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        serde_json::from_str(&json).unwrap_or_default()
    }

    /// 从当前配置目录加载已知 peers（兼容 CLI 辅助命令）。
    pub fn load_from_file() -> Vec<PeerBlueprint> {
        let dir = match crate::identity_store::IdentityStore::config_dir() {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        Self::load_from_dir(&dir)
    }
}
