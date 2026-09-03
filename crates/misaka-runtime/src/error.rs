use thiserror::Error;

/// 统一的错误类型
#[derive(Error, Debug)]
pub enum MisakaError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Protocol serialization error: {0}")]
    Serde(String),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Address parse error: {0}")]
    Addr(#[from] std::net::AddrParseError),
    #[error("Frame length {length} exceeds maximum {max}")]
    FrameTooLarge { length: usize, max: usize },
    #[error("Unknown: {0}")]
    Other(String),
}

impl From<bincode::Error> for MisakaError {
    fn from(e: bincode::Error) -> Self {
        MisakaError::Serde(e.to_string())
    }
}

impl From<crate::crypto::CryptoError> for MisakaError {
    fn from(e: crate::crypto::CryptoError) -> Self {
        MisakaError::Crypto(e.to_string())
    }
}
