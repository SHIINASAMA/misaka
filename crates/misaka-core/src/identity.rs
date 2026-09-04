use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

/// Stable namespace identifier for one independent Misaka Network.
///
/// This is deliberately separate from both the display-oriented `SisterId`
/// and any backend transport identity such as an Iroh endpoint key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(uuid::Uuid);

impl NetworkId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn parse(value: &str) -> Result<Self, uuid::Error> {
        uuid::Uuid::parse_str(value).map(Self)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for NetworkId {
    fn default() -> Self {
        Self(uuid::Uuid::nil())
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

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
    fn network_id_roundtrips_as_a_stable_uuid_string() {
        let id = NetworkId::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap();
        assert_eq!(id.to_string(), "01234567-89ab-cdef-0123-456789abcdef");

        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"01234567-89ab-cdef-0123-456789abcdef\"");
        let decoded: NetworkId = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn generated_network_ids_are_not_the_same_default_namespace() {
        let first = NetworkId::generate();
        let second = NetworkId::generate();
        assert_ne!(first, NetworkId::default());
        assert_ne!(first, second);
    }

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
