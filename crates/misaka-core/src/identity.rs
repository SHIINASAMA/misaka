use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Config dir not found")]
    NoConfigDir,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// 每个 Sister 的稳定身份
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SisterIdentity {
    pub id: u64,          // 稳定身份，重启不变
    pub nickname: String, // 用户可修改显示名
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub listen_port: u16,
    /// 从 ID 生成的稳定临时端口种子；加载后由 Config 计算实际端口
    #[serde(skip, default)]
    pub port_seed: u16,
}

impl SisterIdentity {
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

    /// 生成一个新的稳定身份
    pub fn generate(nickname: Option<String>, listen_port: u16) -> Self {
        // 从 UUID 派生一个稳定的 u64 ID
        let u = Uuid::new_v4();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&u.as_bytes()[..8]);
        let id = u64::from_be_bytes(bytes);

        let hostname = Self::detect_hostname();

        let platform = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

        let nickname = nickname.unwrap_or_else(|| format!("misaka-{}", id % 100000));

        Self {
            id,
            nickname,
            hostname,
            platform,
            version: env!("CARGO_PKG_VERSION").to_string(),
            listen_port,
            port_seed: (id % 10000) as u16,
        }
    }

    pub fn config_dir() -> Result<PathBuf, IdentityError> {
        Self::config_dir_from_env()
    }

    /// 允许通过 misaka_config_dir 环境变量覆盖配置目录 (默认 ~/.misaka)。
    /// 便于本机测试多个节点、以及未来支持自定义数据目录。
    pub fn config_dir_from_env() -> Result<PathBuf, IdentityError> {
        if let Ok(dir) = std::env::var("MISAKA_CONFIG_DIR") {
            if !dir.is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| IdentityError::NoConfigDir)?;
        Ok(PathBuf::from(home).join(".misaka"))
    }

    /// 持久化身份到 ~/.misaka/identity.json
    pub fn save(&self) -> Result<(), IdentityError> {
        let dir = Self::config_dir()?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("identity.json");
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// 从 ~/.misaka/identity.json 加载
    pub fn load() -> Result<Option<Self>, IdentityError> {
        let dir = Self::config_dir()?;
        let path = dir.join("identity.json");
        if !path.exists() {
            return Ok(None);
        }
        let json = std::fs::read_to_string(path)?;
        let identity = serde_json::from_str(&json)?;
        Ok(Some(identity))
    }

    /// 加载或生成身份，并读取最新端口
    pub async fn load_or_init(
        nickname: Option<String>,
        listen_port: u16,
    ) -> Result<Self, IdentityError> {
        if let Some(mut existing) = Self::load()? {
            if let Some(nick) = nickname {
                existing.nickname = nick;
                existing.save()?;
            }
            existing.listen_port = listen_port;
            existing.save()?;
            Ok(existing)
        } else {
            let fresh = Self::generate(nickname, listen_port);
            fresh.save()?;
            Ok(fresh)
        }
    }

    /// 友好的显示名称
    pub fn display_name(&self) -> String {
        format!("#{} \"{}\"", self.id, self.nickname)
    }
}
