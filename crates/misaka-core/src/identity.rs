use serde::{Deserialize, Serialize};

/// 稳定身份，重启不变
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SisterId(pub u64);

impl SisterId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SisterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// 用户可修改的显示名，与稳定 ID 分离
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Nickname(pub String);

impl Nickname {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Nickname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

/// 一个 Sister 的稳定身份。
///
/// 只包含领域数据；hostname 探测、文件系统持久化等 OS 行为在运行时层处理。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SisterIdentity {
    pub id: SisterId,
    pub nickname: Nickname,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub listen_port: u16,
}

impl SisterIdentity {
    pub fn new(
        id: u64,
        nickname: String,
        hostname: String,
        platform: String,
        version: String,
        listen_port: u16,
    ) -> Self {
        Self {
            id: SisterId(id),
            nickname: Nickname(nickname),
            hostname,
            platform,
            version,
            listen_port,
        }
    }

    /// 友好的显示名称
    pub fn display_name(&self) -> String {
        format!("{} {}", self.id, self.nickname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrips_json() {
        let id = SisterIdentity::new(
            10032,
            "Railgun".to_string(),
            "MacBook".to_string(),
            "macos aarch64".to_string(),
            "0.1.0".to_string(),
            31700,
        );
        let json = serde_json::to_string(&id).unwrap();
        let back: SisterIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert_eq!(back.id.as_u64(), 10032);
        assert_eq!(back.nickname.as_str(), "Railgun");
    }

    #[test]
    fn display_name_formats_id_and_nick() {
        let id = SisterIdentity::new(
            10032,
            "Railgun".to_string(),
            "MacBook".to_string(),
            "macos aarch64".to_string(),
            "0.1.0".to_string(),
            31700,
        );
        assert_eq!(id.display_name(), "#10032 \"Railgun\"");
    }
}
