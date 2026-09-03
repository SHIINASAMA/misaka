use misaka_core::PeerBlueprint;

/// Peer 持久化层 —— peers.json 读写，供独立 `run` 进程解析地址。
/// 与内存态的 `PeerStateTable` (core) 分离：持久化是 OS 行为，属运行时层。
pub struct PeerStore;

impl PeerStore {
    /// 把所有已知 peers 序列化持久化到磁盘 (供独立进程解析地址)
    pub fn save_to_file(table: &misaka_core::PeerStateTable) -> std::io::Result<()> {
        let dir = crate::identity_store::IdentityStore::config_dir()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("peers.json");
        let blues: Vec<PeerBlueprint> = table.all().iter().map(PeerBlueprint::from).collect();
        let json = serde_json::to_string_pretty(&blues)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        std::fs::write(path, json)
    }

    /// 从磁盘加载已知 peers 的地址映射 (供独立进程使用)
    pub fn load_from_file() -> Vec<PeerBlueprint> {
        let dir = if let Ok(d) = crate::identity_store::IdentityStore::config_dir() {
            d
        } else {
            return vec![];
        };
        let path = dir.join("peers.json");
        if !path.exists() {
            return vec![];
        }
        let json = match std::fs::read_to_string(&path) {
            Ok(j) => j,
            Err(_) => return vec![],
        };
        serde_json::from_str(&json).unwrap_or_default()
    }
}
