//! Transport-neutral Network Stream v0 primitives with a Direct TCP backend.

use serde::{Deserialize, Serialize};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const HANDSHAKE_LEN: usize = MAGIC.len() + 1;
pub const MAGIC: &[u8; 13] = b"MISAKA_STREAM";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const IROH_ALPN: &[u8] = b"misaka/stream/iroh/0";

pub mod iroh_backend;
pub mod resolver;
pub mod tls;
pub use iroh_backend::{IrohBackend, IrohSession};

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("bind failed: {0}")]
    Bind(#[source] io::Error),
    #[error("connect failed: {0}")]
    Connect(#[source] io::Error),
    #[error("handshake failed: {reason}")]
    Handshake { reason: String },
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("unsupported protocol version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },
    #[error("I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("unsupported network endpoint: {0}")]
    UnsupportedEndpoint(String),
    #[error("Iroh failed: {0}")]
    Iroh(String),
    #[error("stream closed")]
    Closed,
}

pub type Result<T> = std::result::Result<T, NetworkError>;

/// A backend-specific way to reach a Sister.
///
/// Identity is deliberately not part of this value: a `SisterId` identifies
/// a node, while an endpoint is only one connection candidate for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEndpoint {
    Tcp(SocketAddr),
    Iroh(iroh::EndpointAddr),
}

impl From<SocketAddr> for NetworkEndpoint {
    fn from(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }
}

impl std::fmt::Display for NetworkEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(formatter, "tcp://{addr}"),
            Self::Iroh(addr) => {
                let encoded = serde_json::to_string(addr).map_err(|_| std::fmt::Error)?;
                write!(formatter, "iroh://{encoded}")
            }
        }
    }
}

impl std::str::FromStr for NetworkEndpoint {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if let Some(value) = value.strip_prefix("tcp://") {
            let addr = value
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid TCP endpoint {value}: {error}"))?;
            return Ok(Self::Tcp(addr));
        }
        if let Some(value) = value.strip_prefix("iroh://") {
            let endpoint = serde_json::from_str(value)
                .map_err(|error| format!("invalid Iroh endpoint {value}: {error}"))?;
            return Ok(Self::Iroh(endpoint));
        }
        Err(format!("unsupported network endpoint: {value}"))
    }
}

/// The transport boundary for stream establishment.
#[allow(async_fn_in_trait)]
pub trait NetworkBackend: Send + Sync {
    async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener>;
    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream>;
}

/// The v0 backend: direct TCP with the Network Stream handshake.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectTcpBackend;

impl NetworkBackend for DirectTcpBackend {
    async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener> {
        direct_tcp::listen(endpoint).await
    }

    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream> {
        direct_tcp::connect(endpoint).await
    }
}

/// The byte-stream contract shared by all transport backends.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// A validated, long-lived bidirectional byte stream.
pub struct NetworkStream {
    inner: Box<dyn AsyncStream>,
    path: PathInfo,
    stats: StreamStats,
    started_at: Instant,
}

/// Connection metadata captured when a stream is established.
///
/// This describes the selected transport path, not the peer's application
/// identity. Endpoint strings are diagnostic metadata and may be absent for
/// transports whose meaningful address is not a socket address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfo {
    pub backend: String,
    pub route: String,
    pub rtt_ms: Option<u64>,
    pub local_endpoint: Option<String>,
    pub remote_endpoint: Option<String>,
}

impl PathInfo {
    pub fn new(
        backend: impl Into<String>,
        route: impl Into<String>,
        local_endpoint: Option<String>,
        remote_endpoint: Option<String>,
    ) -> Self {
        Self {
            backend: backend.into(),
            route: route.into(),
            rtt_ms: None,
            local_endpoint,
            remote_endpoint,
        }
    }

    pub fn with_rtt_ms(mut self, rtt_ms: Option<u64>) -> Self {
        self.rtt_ms = rtt_ms;
        self
    }

    fn unknown() -> Self {
        Self::new("unknown", "unknown", None, None)
    }
}

/// Counters collected at the transport-neutral stream boundary.
#[derive(Clone, Default)]
pub struct StreamStats {
    tx_bytes: Arc<AtomicU64>,
    rx_bytes: Arc<AtomicU64>,
}

impl std::fmt::Debug for StreamStats {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamStats")
            .field("tx_bytes", &self.tx_bytes())
            .field("rx_bytes", &self.rx_bytes())
            .finish()
    }
}

impl StreamStats {
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }
}

impl NetworkStream {
    /// Wrap a backend-provided bidirectional byte stream.
    pub fn from_stream(stream: impl AsyncStream + 'static) -> Self {
        Self::from_stream_with_path(stream, PathInfo::unknown())
    }

    pub fn from_stream_with_path(stream: impl AsyncStream + 'static, path: PathInfo) -> Self {
        Self {
            inner: Box::new(stream),
            path,
            stats: StreamStats::default(),
            started_at: Instant::now(),
        }
    }

    pub fn path_info(&self) -> PathInfo {
        self.path.clone()
    }

    pub fn stats(&self) -> StreamStats {
        self.stats.clone()
    }

    pub fn connected_for(&self) -> Duration {
        self.started_at.elapsed()
    }
}

impl AsyncRead for NetworkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            this.stats
                .rx_bytes
                .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for NetworkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            this.stats
                .tx_bytes
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A backend-neutral future returned by a listener driver.
pub type ListenerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(NetworkStream, SocketAddr)>> + Send + 'a>>;

/// Backend-specific listener implementation hidden behind `NetworkListener`.
pub trait NetworkListenerDriver: Send + Sync {
    fn local_addr(&self) -> SocketAddr;
    fn accept(&self) -> ListenerFuture<'_>;
}

/// A backend-neutral listener that returns validated streams.
pub struct NetworkListener {
    inner: Box<dyn NetworkListenerDriver>,
}

impl NetworkListener {
    pub fn from_driver(driver: impl NetworkListenerDriver + 'static) -> Self {
        Self {
            inner: Box::new(driver),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    pub async fn accept(&self) -> Result<(NetworkStream, SocketAddr)> {
        self.inner.accept().await
    }
}

pub async fn listen(endpoint: impl Into<NetworkEndpoint>) -> Result<NetworkListener> {
    DirectTcpBackend.listen(endpoint.into()).await
}

pub async fn connect(endpoint: impl Into<NetworkEndpoint>) -> Result<NetworkStream> {
    DirectTcpBackend.connect(endpoint.into()).await
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

mod direct_tcp {
    use super::{
        validate_handshake, AsyncStream, ListenerFuture, NetworkEndpoint, NetworkError,
        NetworkListener, NetworkListenerDriver, NetworkStream, Result, HANDSHAKE_LEN,
        HANDSHAKE_TIMEOUT, MAGIC, PROTOCOL_VERSION,
    };
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    pub(super) async fn listen(endpoint: NetworkEndpoint) -> Result<NetworkListener> {
        let NetworkEndpoint::Tcp(addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "DirectTcpBackend requires tcp:// endpoint".to_string(),
            ));
        };
        let listener = TcpListener::bind(addr).await.map_err(NetworkError::Bind)?;
        let bound = listener.local_addr().map_err(NetworkError::Bind)?;
        tracing::info!(event = "stream_listener_started", address = %bound, "network stream listener started");
        Ok(NetworkListener::from_driver(DirectTcpListener {
            inner: listener,
        }))
    }

    pub(super) async fn connect(endpoint: NetworkEndpoint) -> Result<NetworkStream> {
        let NetworkEndpoint::Tcp(addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "DirectTcpBackend requires tcp:// endpoint".to_string(),
            ));
        };
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(NetworkError::Connect)?;
        client_handshake(&mut stream).await?;
        tracing::info!(event = "stream_connected", peer_addr = %addr, "network stream connected");
        let local_endpoint = stream.local_addr().ok().map(|addr| addr.to_string());
        let remote_endpoint = stream.peer_addr().ok().map(|addr| addr.to_string());
        Ok(NetworkStream::from_stream_with_path(
            stream,
            super::PathInfo::new("direct-tcp", "direct", local_endpoint, remote_endpoint),
        ))
    }

    struct DirectTcpListener {
        inner: TcpListener,
    }

    impl NetworkListenerDriver for DirectTcpListener {
        fn local_addr(&self) -> SocketAddr {
            self.inner
                .local_addr()
                .expect("a bound TCP listener has a local address")
        }

        fn accept(&self) -> ListenerFuture<'_> {
            Box::pin(async move {
                let (mut stream, addr) = self.inner.accept().await.map_err(NetworkError::Io)?;
                tokio::time::timeout(HANDSHAKE_TIMEOUT, server_handshake(&mut stream))
                    .await
                    .map_err(|_| NetworkError::Handshake {
                        reason: format!(
                            "handshake timed out after {} seconds",
                            HANDSHAKE_TIMEOUT.as_secs()
                        ),
                    })??;
                tracing::info!(event = "stream_accepted", peer_addr = %addr, "network stream accepted");
                let local_endpoint = stream.local_addr().ok().map(|addr| addr.to_string());
                Ok((
                    NetworkStream::from_stream_with_path(
                        stream,
                        super::PathInfo::new(
                            "direct-tcp",
                            "direct",
                            local_endpoint,
                            Some(addr.to_string()),
                        ),
                    ),
                    addr,
                ))
            })
        }
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

    // Keep this bound in the module so the compiler verifies the backend's
    // concrete TCP stream continues to satisfy the transport contract.
    fn _assert_async_stream<T: AsyncStream>() {}
}

#[cfg(test)]
mod tests {
    use super::{
        connect, listen, IrohBackend, ListenerFuture, NetworkBackend, NetworkEndpoint,
        NetworkError, NetworkListener, NetworkListenerDriver, NetworkStream, IROH_ALPN,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn localhost_stream_connects_and_exchanges_bytes() {
        let listener = listen("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
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
    async fn stream_stats_count_payload_bytes() {
        let (left, mut right) = tokio::io::duplex(64);
        let mut stream = NetworkStream::from_stream(left);
        stream.write_all(b"hello").await.unwrap();
        let mut received = [0u8; 5];
        right.read_exact(&mut received).await.unwrap();
        assert_eq!(stream.stats().tx_bytes(), 5);

        right.write_all(b"world").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(stream.stats().rx_bytes(), 5);
        assert!(stream.connected_for() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn iroh_backend_roundtrips_a_network_stream() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server = IrohBackend::new(server_endpoint, IROH_ALPN);
        let client = IrohBackend::new(client_endpoint, IROH_ALPN);
        let server_address = iroh::EndpointAddr::new(server.endpoint().id())
            .with_ip_addr(server.endpoint().bound_sockets()[0]);
        let listener = server
            .listen(NetworkEndpoint::Iroh(server_address.clone()))
            .await
            .unwrap();
        let accept_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
        });
        let mut outgoing = client
            .connect(NetworkEndpoint::Iroh(server_address))
            .await
            .unwrap();
        let path = outgoing.path_info();
        assert_eq!(path.backend, "iroh");
        assert_eq!(path.route, "direct");
        assert!(path.rtt_ms.is_some());
        assert!(path.remote_endpoint.is_some());
        let (mut incoming, _) = accept_task.await.unwrap();

        outgoing.write_all(b"iroh-ok").await.unwrap();
        let mut received = [0u8; 7];
        incoming.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"iroh-ok");

        server.close().await;
        client.close().await;
    }

    #[tokio::test]
    async fn iroh_session_reuses_one_connection_for_multiple_streams() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server = IrohBackend::new(server_endpoint, IROH_ALPN);
        let client = IrohBackend::new(client_endpoint, IROH_ALPN);
        let server_address = iroh::EndpointAddr::new(server.endpoint().id())
            .with_ip_addr(server.endpoint().bound_sockets()[0]);
        let server_task = tokio::spawn(async move {
            let session = server.accept_session().await.unwrap();
            let mut first = session.accept_stream().await.unwrap();
            let mut second = session.accept_stream().await.unwrap();
            first.write_all(b"one").await.unwrap();
            second.write_all(b"two").await.unwrap();
            let mut first_ack = [0u8; 3];
            let mut second_ack = [0u8; 3];
            first.read_exact(&mut first_ack).await.unwrap();
            second.read_exact(&mut second_ack).await.unwrap();
            assert_eq!(&first_ack, b"ack");
            assert_eq!(&second_ack, b"ack");
        });

        let session = client
            .connect_session(NetworkEndpoint::Iroh(server_address))
            .await
            .unwrap();
        let mut first = session.open_stream().await.unwrap();
        let mut second = session.open_stream().await.unwrap();
        let mut first_response = [0u8; 3];
        let mut second_response = [0u8; 3];
        first.read_exact(&mut first_response).await.unwrap();
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&first_response, b"one");
        assert_eq!(&second_response, b"two");
        first.write_all(b"ack").await.unwrap();
        second.write_all(b"ack").await.unwrap();
        server_task.await.unwrap();
        client.close().await;
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

    #[tokio::test]
    async fn incomplete_handshake_does_not_block_the_next_connection() {
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration};

        let listener = Arc::new(
            listen("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .await
                .unwrap(),
        );
        let address = listener.local_addr();
        let _stalled = TcpStream::connect(address).await.unwrap();
        let first_listener = Arc::clone(&listener);
        let first = tokio::spawn(async move { first_listener.accept().await });
        let second_listener = Arc::clone(&listener);
        let second = tokio::spawn(async move { connect(second_listener.local_addr()).await });

        let first_result = timeout(Duration::from_secs(6), first)
            .await
            .expect("incomplete handshake should be bounded")
            .unwrap();
        assert!(matches!(first_result, Err(NetworkError::Handshake { .. })));
        timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("next connection should be accepted after timeout")
            .unwrap();
        timeout(Duration::from_secs(2), second)
            .await
            .expect("next connection handshake should complete")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn direct_tcp_backend_implements_network_backend_contract() {
        use super::{DirectTcpBackend, NetworkBackend};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let backend = DirectTcpBackend;
        let listener = backend
            .listen(NetworkEndpoint::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let address = listener.local_addr();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"backend-ok").await.unwrap();
        });
        let mut stream = backend
            .connect(NetworkEndpoint::Tcp(address))
            .await
            .unwrap();
        let mut response = [0u8; 10];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"backend-ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn network_stream_wraps_a_non_tcp_async_stream() {
        let (mut peer, client) = tokio::io::duplex(32);
        let mut stream = NetworkStream::from_stream(client);
        peer.write_all(b"generic").await.unwrap();

        let mut received = [0u8; 7];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"generic");
    }

    #[tokio::test]
    async fn network_listener_accepts_a_non_tcp_stream_driver() {
        struct MemoryListener {
            stream: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
        }

        impl NetworkListenerDriver for MemoryListener {
            fn local_addr(&self) -> SocketAddr {
                "127.0.0.1:1".parse().unwrap()
            }

            fn accept(&self) -> ListenerFuture<'_> {
                Box::pin(async move {
                    let stream = self
                        .stream
                        .lock()
                        .await
                        .take()
                        .ok_or(NetworkError::Closed)?;
                    Ok((NetworkStream::from_stream(stream), self.local_addr()))
                })
            }
        }

        let (mut peer, client) = tokio::io::duplex(32);
        let listener = NetworkListener::from_driver(MemoryListener {
            stream: tokio::sync::Mutex::new(Some(client)),
        });
        let server = tokio::spawn(async move {
            let (mut stream, addr) = listener.accept().await.unwrap();
            assert_eq!(addr, "127.0.0.1:1".parse::<SocketAddr>().unwrap());
            let mut received = [0u8; 7];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"generic");
        });
        peer.write_all(b"generic").await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn tcp_endpoint_roundtrips_and_formats_as_a_tcp_uri() {
        let endpoint = NetworkEndpoint::Tcp("127.0.0.1:31701".parse().unwrap());
        let encoded = serde_json::to_string(&endpoint).unwrap();
        let decoded: NetworkEndpoint = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, endpoint);
        assert_eq!(endpoint.to_string(), "tcp://127.0.0.1:31701");
        assert_eq!(
            NetworkEndpoint::from(SocketAddr::from(([127, 0, 0, 1], 31701))),
            endpoint
        );
    }
}
