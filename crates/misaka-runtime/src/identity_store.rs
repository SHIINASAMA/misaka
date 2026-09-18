use misaka_core::{Nickname, SisterIdentity};
use std::path::PathBuf;
use thiserror::Error;

/// 身份存储层 —— 提供 hostname 探测 + 文件系统持久化。
/// 这些是 OS 行为，不属于 core 的领域契约。
#[derive(Error, Debug)]
pub enum IdentityStoreError {
    #[error("Config dir not found")]
    NoConfigDir,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// 身份存储：生成/加载/保存 SisterIdentity 到 config 目录。
pub struct IdentityStore;

impl IdentityStore {
    /// The per-user Misaka product root (default `~/.misaka`).
    pub fn root_dir() -> Result<PathBuf, IdentityStoreError> {
        if let Some(dir) = non_empty_env_path("MISAKA") {
            return Ok(dir);
        }
        Ok(home_dir()?.join(".misaka"))
    }

    /// Persistent state/configuration directory (default `MISAKA`).
    pub fn config_dir() -> Result<PathBuf, IdentityStoreError> {
        if let Some(dir) = non_empty_env_path("MISAKA_CONFIG_DIR") {
            return Ok(dir);
        }
        Self::root_dir()
    }

    /// Service/runtime log directory (default `MISAKA/log`).
    pub fn log_dir() -> Result<PathBuf, IdentityStoreError> {
        if let Some(dir) = non_empty_env_path("MISAKA_LOG_DIR") {
            return Ok(dir);
        }
        Ok(Self::root_dir()?.join("log"))
    }

    /// Versioned and stable installed binary directory (default `MISAKA/bin`).
    pub fn bin_dir() -> Result<PathBuf, IdentityStoreError> {
        if let Some(dir) = non_empty_env_path("MISAKA_BIN_DIR") {
            return Ok(dir);
        }
        Ok(Self::root_dir()?.join("bin"))
    }

    /// Stable executable path used by a managed per-user service.
    pub fn stable_binary() -> Result<PathBuf, IdentityStoreError> {
        if let Some(path) = non_empty_env_path("MISAKA_BIN") {
            return Ok(path);
        }
        Ok(Self::bin_dir()?.join("misaka"))
    }

    /// 尽量探测主机名，失败则回退到 "unknown"
    fn detect_hostname() -> String {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .or_else(|_| std::env::var("UNAME"))
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                // 用 hostname 命令行兜底
                std::process::Command::new("hostname")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// 生成一个全新的稳定身份 (持久化前不落盘)
    pub fn generate(nickname: Option<String>, listen_port: u16) -> SisterIdentity {
        // 从 UUID 派生一个稳定的 u64 ID
        let u = uuid::Uuid::new_v4();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&u.as_bytes()[..8]);
        let id = u64::from_be_bytes(bytes);

        let hostname = Self::detect_hostname();
        let platform = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
        let nickname = nickname
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("misaka-{}", id % 100000));

        SisterIdentity::new(
            id,
            nickname,
            hostname,
            platform,
            env!("CARGO_PKG_VERSION").to_string(),
            listen_port,
        )
    }

    /// 持久化身份到 config_dir/identity.json
    pub fn save(identity: &SisterIdentity) -> Result<(), IdentityStoreError> {
        let dir = Self::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("identity.json");
        let json = serde_json::to_string_pretty(identity)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// 从 config_dir/identity.json 加载
    pub fn load() -> Result<Option<SisterIdentity>, IdentityStoreError> {
        let dir = Self::config_dir()?;
        let path = dir.join("identity.json");
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(path)?;
        let identity = serde_json::from_str(&json)?;
        Ok(Some(identity))
    }

    /// 加载或生成身份，并更新监听端口
    pub fn load_or_init(
        nickname: Option<String>,
        listen_port: u16,
    ) -> Result<SisterIdentity, IdentityStoreError> {
        if let Some(mut existing) = Self::load()? {
            if let Some(nick) = nickname {
                existing.nickname = Nickname(nick);
                Self::save(&existing)?;
            }
            existing.listen_port = listen_port;
            Self::save(&existing)?;
            Ok(existing)
        } else {
            let fresh = Self::generate(nickname, listen_port);
            Self::save(&fresh)?;
            Ok(fresh)
        }
    }

    /// 更新昵称 (不丢弃稳定 ID)
    pub fn update_nickname(nickname: String) -> Result<SisterIdentity, IdentityStoreError> {
        let mut identity = Self::load()?.ok_or(IdentityStoreError::NoConfigDir)?;
        identity.nickname = Nickname(nickname);
        Self::save(&identity)?;
        Ok(identity)
    }
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_dir() -> Result<PathBuf, IdentityStoreError> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or(IdentityStoreError::NoConfigDir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_stable_u64_id() {
        let a = IdentityStore::generate(Some("railgun".into()), 31700);
        let b = IdentityStore::generate(Some("railgun".into()), 31700);
        assert_ne!(a.id, b.id); // 每次不同
        assert_eq!(a.nickname.as_str(), "railgun");
        assert_eq!(a.listen_port, 31700);
    }
}
