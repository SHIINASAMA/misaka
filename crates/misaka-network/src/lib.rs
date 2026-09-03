//! Direct TCP Network Stream v0 primitives.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const HANDSHAKE_LEN: usize = MAGIC.len() + 1;
pub const MAGIC: &[u8; 13] = b"MISAKA_STREAM";
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("bind failed: {0}")]
    Bind(#[source] io::Error),
    #[error("connect failed: {0}")]
    Connect(#[source] io::Error),
    #[error("handshake failed: {reason}")]
    Handshake { reason: String },
    #[error("unsupported protocol version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },
    #[error("I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("stream closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, NetworkError>;

/// A validated, long-lived bidirectional byte stream.
pub struct NetworkStream {
    inner: TcpStream,
}

impl NetworkStream {
    fn new(inner: TcpStream) -> Self {
        Self { inner }
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl AsyncRead for NetworkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NetworkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A TCP listener that only returns streams after handshake validation.
pub struct NetworkListener {
    inner: TcpListener,
}

impl NetworkListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.inner
            .local_addr()
            .expect("a bound TCP listener has a local address")
    }

    pub async fn accept(&self) -> Result<(NetworkStream, SocketAddr)> {
        let (mut stream, addr) = self.inner.accept().await.map_err(NetworkError::Io)?;
        server_handshake(&mut stream).await?;
        tracing::info!(event = "stream_accepted", peer_addr = %addr, "network stream accepted");
        Ok((NetworkStream::new(stream), addr))
    }
}

pub async fn listen(addr: SocketAddr) -> Result<NetworkListener> {
    let listener = TcpListener::bind(addr).await.map_err(NetworkError::Bind)?;
    let bound = listener.local_addr().map_err(NetworkError::Bind)?;
    tracing::info!(event = "stream_listener_started", address = %bound, "network stream listener started");
    Ok(NetworkListener { inner: listener })
}

pub async fn connect(addr: SocketAddr) -> Result<NetworkStream> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(NetworkError::Connect)?;
    client_handshake(&mut stream).await?;
    tracing::info!(event = "stream_connected", peer_addr = %addr, "network stream connected");
    Ok(NetworkStream::new(stream))
}

async fn client_handshake(stream: &mut TcpStream) -> Result<()> {
    let mut request = [0u8; HANDSHAKE_LEN];
    request[..MAGIC.len()].copy_from_slice(MAGIC);
    request[MAGIC.len()] = PROTOCOL_VERSION;
    stream
        .write_all(&request)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("write request: {error}"),
        })?;

    let response = read_handshake(stream).await?;
    validate_handshake(&response)
}

async fn server_handshake(stream: &mut TcpStream) -> Result<()> {
    let request = read_handshake(stream).await?;
    validate_handshake(&request)?;
    let mut response = [0u8; HANDSHAKE_LEN];
    response[..MAGIC.len()].copy_from_slice(MAGIC);
    response[MAGIC.len()] = PROTOCOL_VERSION;
    stream
        .write_all(&response)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("write response: {error}"),
        })?;
    Ok(())
}

async fn read_handshake(stream: &mut TcpStream) -> Result<[u8; HANDSHAKE_LEN]> {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    stream
        .read_exact(&mut handshake)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("read handshake: {error}"),
        })?;
    Ok(handshake)
}

fn validate_handshake(handshake: &[u8; HANDSHAKE_LEN]) -> Result<()> {
    if &handshake[..MAGIC.len()] != MAGIC {
        tracing::warn!(
            event = "stream_handshake_failed",
            reason = "invalid_magic",
            "network stream handshake failed"
        );
        return Err(NetworkError::Handshake {
            reason: "invalid magic".to_string(),
        });
    }
    let version = handshake[MAGIC.len()];
    if version != PROTOCOL_VERSION {
        tracing::warn!(
            event = "stream_handshake_failed",
            reason = "unsupported_version",
            version,
            "network stream handshake failed"
        );
        return Err(NetworkError::UnsupportedVersion {
            expected: PROTOCOL_VERSION,
            actual: version,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{connect, listen};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn localhost_stream_connects_and_exchanges_bytes() {
        let listener = listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = [0u8; 5];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let mut client = connect(address).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut output = [0u8; 5];
        client.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"world");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_magic_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"NOT_MISAKA!!\x01").await.unwrap();
        });

        let result = connect(address).await;
        assert!(matches!(result, Err(super::NetworkError::Handshake { .. })));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unsupported_version_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"MISAKA_STREAM\x7f").await.unwrap();
        });

        let result = connect(address).await;
        assert!(matches!(
            result,
            Err(super::NetworkError::UnsupportedVersion { .. })
        ));
        server.await.unwrap();
    }
}
