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
use futures_util::StreamExt;
use iroh::endpoint::{Connection, IncomingAddr, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;
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

    /// Bind an endpoint using one explicitly selected Iroh relay.
    ///
    /// The relay only carries Iroh's encrypted transport traffic; it does not
    /// become a Misaka authority or a separate network backend.
    pub async fn bind_with_secret_key_and_relay(
        secret_key: iroh::SecretKey,
        relay_url: iroh::RelayUrl,
    ) -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![IROH_ALPN.to_vec()])
            .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(relay_url)))
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
        Ok(IrohSession::new(self.endpoint.clone(), connection))
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
        Ok(IrohSession::new(self.endpoint.clone(), connection))
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
    path_telemetry: IrohPathTelemetry,
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
    fn new(endpoint: Endpoint, connection: Connection) -> Self {
        let path_telemetry = IrohPathTelemetry::new(
            connection.clone(),
            connection_path_info(&endpoint, &connection),
        );
        Self {
            endpoint,
            connection,
            path_telemetry,
        }
    }

    pub fn remote_id(&self) -> iroh::EndpointId {
        self.connection.remote_id()
    }

    /// Whether the underlying QUIC connection has observed a close reason.
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Close the logical session and make future stream opens fail promptly.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"Misaka session closed");
    }

    pub async fn open_stream(&self) -> Result<NetworkStream> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            write_handshake(&mut send).await?;
            read_and_validate_handshake(&mut recv).await
        })
        .await
        .map_err(|_| NetworkError::Handshake {
            reason: format!(
                "Iroh logical stream handshake timed out after {} seconds",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        })??;
        Ok(network_stream(
            send,
            recv,
            self.endpoint.clone(),
            &self.connection,
            self.path_telemetry.clone(),
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
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            read_and_validate_handshake(&mut recv).await?;
            write_handshake(&mut send).await
        })
        .await
        .map_err(|_| NetworkError::Handshake {
            reason: format!(
                "Iroh logical stream handshake timed out after {} seconds",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        })??;
        Ok(network_stream(
            send,
            recv,
            self.endpoint.clone(),
            &self.connection,
            self.path_telemetry.clone(),
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
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            write_handshake(&mut send).await?;
            read_and_validate_handshake(&mut recv).await
        })
        .await
        .map_err(|_| NetworkError::Handshake {
            reason: format!(
                "Iroh logical stream handshake timed out after {} seconds",
                HANDSHAKE_TIMEOUT.as_secs()
            ),
        })??;
        let remote_endpoint = serde_json::to_string(&EndpointAddr::new(connection.remote_id()))
            .ok()
            .map(|value| format!("iroh://{value}"));
        tracing::info!(
            event = "iroh_stream_connected",
            peer_id = %connection.remote_id(),
            "Iroh network stream connected"
        );
        Ok(network_stream_with_metadata(
            send,
            recv,
            self.endpoint.clone(),
            &connection,
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
            tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                read_and_validate_handshake(&mut recv).await?;
                write_handshake(&mut send).await
            })
            .await
            .map_err(|_| NetworkError::Handshake {
                reason: format!(
                    "Iroh logical stream handshake timed out after {} seconds",
                    HANDSHAKE_TIMEOUT.as_secs()
                ),
            })??;
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
                network_stream(
                    send,
                    recv,
                    self.endpoint.clone(),
                    &connection,
                    IrohPathTelemetry::new(
                        connection.clone(),
                        connection_path_info(&self.endpoint, &connection),
                    ),
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
    path_telemetry: IrohPathTelemetry,
) -> NetworkStream {
    let remote_endpoint = serde_json::to_string(&EndpointAddr::new(connection.remote_id()))
        .ok()
        .map(|value| format!("iroh://{value}"));
    network_stream_with_telemetry(send, recv, endpoint, path_telemetry, remote_endpoint)
}

fn network_stream_with_metadata(
    send: SendStream,
    recv: RecvStream,
    endpoint: Endpoint,
    connection: &Connection,
    remote_endpoint: Option<String>,
) -> NetworkStream {
    let path = connection_path_info(&endpoint, connection);
    let path_telemetry = IrohPathTelemetry::new(connection.clone(), path);
    network_stream_with_telemetry(send, recv, endpoint, path_telemetry, remote_endpoint)
}

fn network_stream_with_telemetry(
    send: SendStream,
    recv: RecvStream,
    endpoint: Endpoint,
    path_telemetry: IrohPathTelemetry,
    remote_endpoint: Option<String>,
) -> NetworkStream {
    let mut path = path_telemetry.snapshot();
    if remote_endpoint.is_some() {
        path.remote_endpoint = remote_endpoint;
    }
    let provider = path_telemetry.clone();
    NetworkStream::from_stream_with_path_provider(
        IrohStream {
            send,
            recv,
            _endpoint: endpoint,
        },
        path,
        move || provider.snapshot(),
    )
}

#[derive(Clone)]
struct IrohPathTelemetry {
    state: Arc<RwLock<PathInfo>>,
}

impl IrohPathTelemetry {
    fn new(connection: Connection, initial: PathInfo) -> Self {
        let state = Arc::new(RwLock::new(initial));
        let observer_state = Arc::downgrade(&state);
        tokio::spawn(async move {
            let mut events = connection.path_events();
            let mut stop_check = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    event = events.next() => {
                        let Some(event) = event else { break };
                        if matches!(
                            event,
                            iroh::endpoint::PathEvent::Selected { .. }
                                | iroh::endpoint::PathEvent::Lagged { .. }
                        ) {
                            let Some(observer_state) = observer_state.upgrade() else { break };
                            let (route, rtt_ms) = selected_path_metrics(&connection);
                            let mut path = observer_state
                                .write()
                                .expect("Iroh path telemetry lock poisoned");
                            if path.route != route {
                                path.path_switches = path.path_switches.saturating_add(1);
                                tracing::info!(
                                    event = "iroh_path_switched",
                                    peer_id = %connection.remote_id(),
                                    from_route = %path.route,
                                    to_route = %route,
                                    path_switches = path.path_switches,
                                    "Iroh selected path changed"
                                );
                            }
                            path.route = route.to_string();
                            path.rtt_ms = rtt_ms;
                        }
                    }
                    _ = stop_check.tick() => {
                        if observer_state.upgrade().is_none() { break; }
                    }
                }
            }
        });
        Self { state }
    }

    fn snapshot(&self) -> PathInfo {
        self.state
            .read()
            .expect("Iroh path telemetry lock poisoned")
            .clone()
    }
}

fn connection_path_info(endpoint: &Endpoint, connection: &Connection) -> PathInfo {
    let (route, rtt_ms) = selected_path_metrics(connection);
    PathInfo::new(
        "iroh",
        route,
        endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .map(|addr| addr.to_string()),
        Some(format!("iroh://{}", connection.remote_id())),
    )
    .with_rtt_ms(rtt_ms)
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
