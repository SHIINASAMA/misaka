use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use rand::Rng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("AES-GCM error: {0}")]
    AesGcm(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Decryption failed")]
    DecryptionFailed,
}

#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    /// 创建新的加密器，key 必须是 32 字节 (256 位)
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CryptoError::AesGcm(format!("Failed to create cipher: {}", e)))?;

        Ok(Self { cipher })
    }

    /// 生成随机 nonce (12 字节 for AES-GCM)
    pub fn generate_nonce() -> [u8; 12] {
        rand::thread_rng().gen()
    }

    /// 加密数据
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Self::generate_nonce();
        let nonce_bytes = nonce.to_vec();

        let ciphertext = self
            .cipher
            .encrypt(&nonce.into(), data)
            .map_err(|e| CryptoError::AesGcm(format!("Encryption failed: {}", e)))?;

        // 返回：[nonce(12 字节)] + [ciphertext]
        let mut result = nonce_bytes;
        result.extend(ciphertext);
        Ok(result)
    }

    /// 解密数据
    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(12);

        // 从 12 字节重建 nonce (GenericArray<u8, U12>)
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(&nonce_arr.into(), ciphertext)
            .map_err(|e| CryptoError::AesGcm(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let crypto = Crypto::new(&key).unwrap();

        let data = b"Hello, World!";
        let encrypted = crypto.encrypt(data).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let result = Crypto::new(&key);
        assert!(result.is_err());
    }
}
