//! Iroh QUIC backend for the NetworkStream contract.
//!
//! One Iroh connection can carry one or more bidirectional QUIC streams, and
//! every stream still uses the Network Stream handshake before it is exposed
//! to callers. Runtime routing and candidate selection remain explicit.

use crate::{
    validate_handshake, AsyncStream, ListenerFuture, NetworkEndpoint, NetworkError,
    NetworkListener, NetworkListenerDriver, NetworkStream, PathInfo, Result, HANDSHAKE_LEN,
    HANDSHAKE_TIMEOUT, IROH_ALPN, MAGIC, PROTOCOL_VERSION,
};
use iroh::endpoint::{Connection, IncomingAddr, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A backend backed by one Iroh endpoint.
#[derive(Clone, Debug)]
pub struct IrohBackend {
    endpoint: Endpoint,
    alpn: Vec<u8>,
}

impl IrohBackend {
    /// Create a backend around an already configured Iroh endpoint.
    ///
    /// The endpoint must be configured with the same ALPN before it is bound.
    pub fn new(endpoint: Endpoint, alpn: impl Into<Vec<u8>>) -> Self {
        Self {
            endpoint,
            alpn: alpn.into(),
        }
    }

    /// Bind an endpoint using Iroh's default relay/address-lookup preset.
    pub async fn bind() -> Result<Self> {
        Self::bind_with_secret_key(iroh::SecretKey::generate()).await
    }

    /// Bind an endpoint with a persisted transport identity.
    pub async fn bind_with_secret_key(secret_key: iroh::SecretKey) -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(Self::new(endpoint, IROH_ALPN))
    }

    /// Establish one long-lived Iroh connection without opening a logical
    /// stream yet. Call `IrohSession::open_stream` for each operation.
    pub async fn connect_session(&self, endpoint: NetworkEndpoint) -> Result<IrohSession> {
        let NetworkEndpoint::Iroh(endpoint_addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "IrohBackend requires iroh:// endpoint".to_string(),
            ));
        };
        let connection = self
            .endpoint
            .connect(endpoint_addr, &self.alpn)
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(IrohSession {
            endpoint: self.endpoint.clone(),
            connection,
        })
    }

    /// Accept one long-lived Iroh connection without consuming a logical
    /// stream. The caller can accept multiple streams from the session.
    pub async fn accept_session(&self) -> Result<IrohSession> {
        let incoming = self.endpoint.accept().await.ok_or(NetworkError::Closed)?;
        let accepting = incoming
            .accept()
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting)
            .await
            .map_err(|_| NetworkError::Iroh("Iroh connection handshake timed out".to_string()))?
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(IrohSession {
            endpoint: self.endpoint.clone(),
            connection,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// A long-lived Iroh connection that can carry multiple logical streams.
#[derive(Clone)]
pub struct IrohSession {
    endpoint: Endpoint,
    connection: Connection,
}

impl std::fmt::Debug for IrohSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IrohSession")
            .field("remote_id", &self.connection.remote_id())
            .finish()
    }
}

impl IrohSession {
    pub fn remote_id(&self) -> iroh::EndpointId {
        self.connection.remote_id()
    }

    pub async fn open_stream(&self) -> Result<NetworkStream> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        write_handshake(&mut send).await?;
        read_and_validate_handshake(&mut recv).await?;
        Ok(network_stream(
            send,
            recv,
            self.endpoint.clone(),
            &self.connection,
        ))
    }

    pub async fn accept_stream(&self) -> Result<NetworkStream> {
        let (mut send, mut recv) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, self.connection.accept_bi())
                .await
                .map_err(|_| NetworkError::Handshake {
                    reason: "Iroh logical stream open timed out".to_string(),
                })?
                .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        read_and_validate_handshake(&mut recv).await?;
        write_handshake(&mut send).await?;
        Ok(network_stream(
            send,
            recv,
            self.endpoint.clone(),
            &self.connection,
        ))
    }
}

impl crate::NetworkBackend for IrohBackend {
    async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener> {
        let NetworkEndpoint::Iroh(endpoint_addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "IrohBackend requires iroh:// endpoint".to_string(),
            ));
        };
        if endpoint_addr.id != self.endpoint.id() {
            return Err(NetworkError::Iroh(
                "listener endpoint does not belong to this Iroh endpoint".to_string(),
            ));
        }
        let local_addr = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        tracing::info!(
            event = "iroh_listener_started",
            endpoint_id = %self.endpoint.id(),
            address = %local_addr,
            "Iroh network listener started"
        );
        Ok(NetworkListener::from_driver(IrohListener {
            endpoint: self.endpoint.clone(),
            local_addr,
        }))
    }

    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream> {
        let NetworkEndpoint::Iroh(endpoint_addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "IrohBackend requires iroh:// endpoint".to_string(),
            ));
        };
        let connection = self
            .endpoint
            .connect(endpoint_addr, &self.alpn)
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        write_handshake(&mut send).await?;
        read_and_validate_handshake(&mut recv).await?;
        let remote_endpoint = serde_json::to_string(&EndpointAddr::new(connection.remote_id()))
            .ok()
            .map(|value| format!("iroh://{value}"));
        tracing::info!(
            event = "iroh_stream_connected",
            peer_id = %connection.remote_id(),
            "Iroh network stream connected"
        );
        let (route, rtt_ms) = selected_path_metrics(&connection);
        Ok(network_stream_with_metadata(
            send,
            recv,
            self.endpoint.clone(),
            route,
            rtt_ms,
            remote_endpoint,
        ))
    }
}

struct IrohListener {
    endpoint: Endpoint,
    local_addr: SocketAddr,
}

impl NetworkListenerDriver for IrohListener {
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn accept(&self) -> ListenerFuture<'_> {
        Box::pin(async move {
            let incoming = self.endpoint.accept().await.ok_or(NetworkError::Closed)?;
            let remote_addr = incoming.remote_addr();
            let accepting = incoming
                .accept()
                .map_err(|error| NetworkError::Iroh(error.to_string()))?;
            let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting)
                .await
                .map_err(|_| NetworkError::Handshake {
                    reason: format!(
                        "Iroh handshake timed out after {} seconds",
                        HANDSHAKE_TIMEOUT.as_secs()
                    ),
                })?
                .map_err(|error| NetworkError::Iroh(error.to_string()))?;
            let (mut send, mut recv) =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
                    .await
                    .map_err(|_| NetworkError::Handshake {
                        reason: format!(
                            "Iroh stream open timed out after {} seconds",
                            HANDSHAKE_TIMEOUT.as_secs()
                        ),
                    })?
                    .map_err(|error| NetworkError::Iroh(error.to_string()))?;
            read_and_validate_handshake(&mut recv).await?;
            write_handshake(&mut send).await?;
            let (route, rtt_ms) = selected_path_metrics(&connection);
            let peer_addr = match remote_addr {
                IncomingAddr::Ip(addr) => addr,
                IncomingAddr::Relay { .. } | IncomingAddr::Custom(_) => {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                }
                _ => SocketAddr::from(([0, 0, 0, 0], 0)),
            };
            tracing::info!(
                event = "iroh_stream_accepted",
                peer_id = %connection.remote_id(),
                peer_addr = %peer_addr,
                "Iroh network stream accepted"
            );
            Ok((
                NetworkStream::from_stream_with_path(
                    IrohStream {
                        send,
                        recv,
                        _endpoint: self.endpoint.clone(),
                    },
                    PathInfo::new(
                        "iroh",
                        route,
                        self.endpoint
                            .bound_sockets()
                            .into_iter()
                            .next()
                            .map(|addr| addr.to_string()),
                        Some(format!("iroh://{}", connection.remote_id())),
                    )
                    .with_rtt_ms(rtt_ms),
                ),
                peer_addr,
            ))
        })
    }
}

struct IrohStream {
    send: SendStream,
    recv: RecvStream,
    // Keep the endpoint alive for callers that outlive the listener/backend
    // value which accepted this stream (notably short-lived CLI commands).
    _endpoint: Endpoint,
}

fn network_stream(
    send: SendStream,
    recv: RecvStream,
    endpoint: Endpoint,
    connection: &Connection,
) -> NetworkStream {
    let remote_endpoint = serde_json::to_string(&EndpointAddr::new(connection.remote_id()))
        .ok()
        .map(|value| format!("iroh://{value}"));
    let (route, rtt_ms) = selected_path_metrics(connection);
    network_stream_with_metadata(send, recv, endpoint, route, rtt_ms, remote_endpoint)
}

fn network_stream_with_metadata(
    send: SendStream,
    recv: RecvStream,
    endpoint: Endpoint,
    route: impl Into<String>,
    rtt_ms: Option<u64>,
    remote_endpoint: Option<String>,
) -> NetworkStream {
    NetworkStream::from_stream_with_path(
        IrohStream {
            send,
            recv,
            _endpoint: endpoint.clone(),
        },
        PathInfo::new(
            "iroh",
            route,
            endpoint
                .bound_sockets()
                .into_iter()
                .next()
                .map(|addr| addr.to_string()),
            remote_endpoint,
        )
        .with_rtt_ms(rtt_ms),
    )
}

fn selected_path_metrics(connection: &Connection) -> (&'static str, Option<u64>) {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| {
            let route = if path.is_ip() {
                "direct"
            } else if path.is_relay() {
                "relay"
            } else {
                "custom"
            };
            (route, Some(path.rtt().as_millis() as u64))
        })
        .unwrap_or(("unknown", None))
}

impl AsyncRead for IrohStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().recv).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for IrohStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().send).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn write_handshake(stream: &mut SendStream) -> Result<()> {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    handshake[..MAGIC.len()].copy_from_slice(MAGIC);
    handshake[MAGIC.len()] = PROTOCOL_VERSION;
    stream
        .write_all(&handshake)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("write Iroh handshake: {error}"),
        })?;
    stream
        .flush()
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("flush Iroh handshake: {error}"),
        })
}

async fn read_and_validate_handshake(stream: &mut RecvStream) -> Result<()> {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    stream
        .read_exact(&mut handshake)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("read Iroh handshake: {error}"),
        })?;
    validate_handshake(&handshake)
}

fn _assert_async_stream<T: AsyncStream>() {}
