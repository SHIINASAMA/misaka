//! Network transport — TCP framing + encryption for the peer-to-peer wire.
//!
//! This module is responsible ONLY for: TCP connect/accept, framing,
//! encrypt/decrypt, send, receive. No protocol dispatch, no job logic.

use crate::crypto::Crypto;
use misaka_core::Envelope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 封装了一个短连接的收发原语：长度前缀 + AES-GCM 加密 + bincode。
#[derive(Clone)]
pub struct PeerTransport {
    crypto: Crypto,
}

impl PeerTransport {
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    /// 打开一条短连接发送 envelope，等待一条响应
    pub async fn send_to(
        &self,
        addr: std::net::SocketAddr,
        env: &Envelope,
    ) -> crate::Result<Envelope> {
        let mut stream = TcpStream::connect(addr).await?;
        write_envelope(&mut stream, &self.crypto, env).await?;
        let resp = read_envelope(&mut stream, &self.crypto).await?;
        Ok(resp)
    }

    /// 单向发送 (不等待响应)
    pub async fn send_fire(&self, addr: std::net::SocketAddr, env: &Envelope) -> crate::Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        write_envelope(&mut stream, &self.crypto, env).await?;
        Ok(())
    }

    /// 处理一条入站连接：读一个 envelope 并返回 (由调用方 dispatch)
    pub async fn receive(&self, stream: &mut TcpStream) -> crate::Result<Envelope> {
        read_envelope(stream, &self.crypto).await
    }

    /// 在入站连接上回写一个 envelope (例如握手回复)
    pub async fn reply(&self, stream: &mut TcpStream, env: &Envelope) -> crate::Result<()> {
        write_envelope(stream, &self.crypto, env).await
    }
}

/// 绑定监听地址，返回 listener
pub async fn bind(addr: std::net::SocketAddr) -> crate::Result<TcpListener> {
    Ok(TcpListener::bind(addr).await?)
}

/// 序列化 + 加密 + 写入 stream (frame: [len:u32 BE][ciphertext])
pub async fn write_envelope(
    stream: &mut TcpStream,
    crypto: &Crypto,
    env: &Envelope,
) -> crate::Result<()> {
    let plaintext = bincode::serialize(env)?;
    let encrypted = crypto.encrypt(&plaintext)?;
    stream
        .write_all(&(encrypted.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&encrypted).await?;
    Ok(())
}

/// 从 stream 读取 + 解密 + 反序列化 (读取一个 frame)
pub async fn read_envelope(stream: &mut TcpStream, crypto: &Crypto) -> crate::Result<Envelope> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let decrypted = crypto.decrypt(&buf)?;
    let env: Envelope = bincode::deserialize(&decrypted)?;
    Ok(env)
}
