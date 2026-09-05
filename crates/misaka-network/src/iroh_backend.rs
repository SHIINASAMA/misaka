//! Iroh QUIC backend for the NetworkStream contract.
//!
//! One Iroh connection can carry one or more bidirectional QUIC streams, and
//! every stream still uses the Network Stream handshake before it is exposed
//! to callers. Runtime routing and candidate selection remain explicit.

use crate::{
    validate_handshake, AsyncStream, ListenerFuture, NetworkEndpoint, NetworkError,
    NetworkListener, NetworkListenerDriver, NetworkStream, PathInfo, Result, ENROLLMENT_ALPN,
    HANDSHAKE_LEN, HANDSHAKE_TIMEOUT, IROH_ALPN, MAGIC, PROTOCOL_VERSION,
};
use futures_util::StreamExt;
use iroh::endpoint::{Connection, IncomingAddr, PathList, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use misaka_core::NetworkId;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// A backend backed by one Iroh endpoint.
#[derive(Clone, Debug)]
pub struct IrohBackend {
    endpoint: Endpoint,
    alpn: Vec<u8>,
}

/// The ALPN set every Misaka Iroh endpoint advertises.
///
/// The member stream protocol and the narrow enrollment protocol share one
/// endpoint and are distinguished by the negotiated ALPN, so enrollment can be
/// served by an ordinary running Sister without a separate networking stack.
pub fn misaka_alpns() -> Vec<Vec<u8>> {
    vec![IROH_ALPN.to_vec(), ENROLLMENT_ALPN.to_vec()]
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
            .alpns(misaka_alpns())
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
            .alpns(misaka_alpns())
            .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(relay_url)))
            .bind()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(Self::new(endpoint, IROH_ALPN))
    }

    /// Bind an endpoint that can reach peers only through one explicitly selected relay.
    ///
    /// This is intended for controlled UDP-restricted measurements. It does not
    /// change the authenticated Iroh transport or introduce a Misaka relay role.
    pub async fn bind_with_secret_key_and_relay_only(
        secret_key: iroh::SecretKey,
        relay_url: iroh::RelayUrl,
    ) -> Result<Self> {
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(misaka_alpns())
            .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from(relay_url)))
            .clear_ip_transports()
            .bind()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(Self::new(endpoint, IROH_ALPN))
    }

    /// Establish one long-lived Iroh connection without opening a logical
    /// stream yet. Call `IrohSession::open_stream` for each operation.
    pub async fn connect_session(&self, endpoint: NetworkEndpoint) -> Result<IrohSession> {
        self.connect_session_for_network(endpoint, NetworkId::default())
            .await
    }

    pub async fn connect_session_for_network(
        &self,
        endpoint: NetworkEndpoint,
        network_id: NetworkId,
    ) -> Result<IrohSession> {
        self.connect_session_with_alpn(endpoint, network_id, &self.alpn)
            .await
    }

    /// Establish one long-lived connection on an explicit ALPN.
    ///
    /// Enrollment clients dial the Authority on [`ENROLLMENT_ALPN`]; the member
    /// control plane keeps dialing on [`IROH_ALPN`]. The endpoint advertises both,
    /// so the choice is per-connection, not per-backend.
    pub async fn connect_session_with_alpn(
        &self,
        endpoint: NetworkEndpoint,
        network_id: NetworkId,
        alpn: &[u8],
    ) -> Result<IrohSession> {
        let NetworkEndpoint::Iroh(endpoint_addr) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "IrohBackend requires iroh:// endpoint".to_string(),
            ));
        };
        let connection = self
            .endpoint
            .connect(endpoint_addr, alpn)
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(IrohSession::new(
            self.endpoint.clone(),
            connection,
            network_id,
            None,
        ))
    }

    /// Accept one long-lived Iroh connection without consuming a logical
    /// stream. The caller can accept multiple streams from the session.
    pub async fn accept_session(&self) -> Result<IrohSession> {
        self.accept_session_for_network(NetworkId::default()).await
    }

    pub async fn accept_session_for_network(&self, network_id: NetworkId) -> Result<IrohSession> {
        let incoming = self.endpoint.accept().await.ok_or(NetworkError::Closed)?;
        let incoming_addr = incoming.remote_addr();
        let accepting = incoming
            .accept()
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting)
            .await
            .map_err(|_| NetworkError::Iroh("Iroh connection handshake timed out".to_string()))?
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(IrohSession::new(
            self.endpoint.clone(),
            connection,
            network_id,
            Some(incoming_addr),
        ))
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
    network_id: NetworkId,
    alpn: Vec<u8>,
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
    fn new(
        endpoint: Endpoint,
        connection: Connection,
        network_id: NetworkId,
        incoming_addr: Option<IncomingAddr>,
    ) -> Self {
        let mut path = connection_path_info(&endpoint, &connection);
        if path.route == "unknown" {
            if let Some(incoming_addr) = incoming_addr.as_ref() {
                path.route = incoming_route(incoming_addr).to_string();
            }
        }
        let alpn = connection.alpn().to_vec();
        let path_telemetry = IrohPathTelemetry::new(connection.clone(), path);
        Self {
            endpoint,
            connection,
            path_telemetry,
            network_id,
            alpn,
        }
    }

    /// The ALPN this connection actually negotiated.
    ///
    /// A single running Sister advertises both the member and enrollment ALPNs;
    /// the accept loop dispatches on this value so enrollment is served ahead of,
    /// and independently from, the authenticated member session.
    pub fn negotiated_alpn(&self) -> &[u8] {
        &self.alpn
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
            write_handshake(&mut send, self.network_id).await?;
            read_and_validate_handshake(&mut recv, self.network_id).await
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
            read_and_validate_handshake(&mut recv, self.network_id).await?;
            write_handshake(&mut send, self.network_id).await
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
        self.listen_for_network(endpoint, NetworkId::default())
            .await
    }

    async fn listen_for_network(
        &self,
        endpoint: NetworkEndpoint,
        network_id: NetworkId,
    ) -> Result<NetworkListener> {
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
            network_id,
        }))
    }

    async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream> {
        self.connect_for_network(endpoint, NetworkId::default())
            .await
    }

    async fn connect_for_network(
        &self,
        endpoint: NetworkEndpoint,
        network_id: NetworkId,
    ) -> Result<NetworkStream> {
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
            write_handshake(&mut send, network_id).await?;
            read_and_validate_handshake(&mut recv, network_id).await
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
    network_id: NetworkId,
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
                read_and_validate_handshake(&mut recv, self.network_id).await?;
                write_handshake(&mut send, self.network_id).await
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
                        connection_path_info_with_incoming(
                            &self.endpoint,
                            &connection,
                            &remote_addr,
                        ),
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
    connection: Connection,
    state: Arc<RwLock<PathInfo>>,
    _selected_path: Arc<RwLock<Option<String>>>,
}

impl IrohPathTelemetry {
    fn new(connection: Connection, initial: PathInfo) -> Self {
        let observer_connection = connection.clone();
        let state = Arc::new(RwLock::new(initial));
        let selected_path = Arc::new(RwLock::new(selected_path_key(&connection)));
        let observer_state = Arc::downgrade(&state);
        let observer_selected_path = Arc::downgrade(&selected_path);
        tokio::spawn(async move {
            let mut paths = observer_connection.paths_stream();
            while let Some(paths) = paths.next().await {
                let Some(observer_state) = observer_state.upgrade() else {
                    break;
                };
                let Some(observer_selected_path) = observer_selected_path.upgrade() else {
                    break;
                };
                let event_path_key = path_list_selected_key(&paths);
                if event_path_key.is_none() {
                    continue;
                }
                let (route, rtt_ms) = path_list_metrics(&paths);
                let mut path = observer_state
                    .write()
                    .expect("Iroh path telemetry lock poisoned");
                let mut selected_path = observer_selected_path
                    .write()
                    .expect("Iroh selected path telemetry lock poisoned");
                let changed = selected_path.is_some()
                    && event_path_key
                        .as_ref()
                        .is_some_and(|key| selected_path.as_ref() != Some(key));
                if changed {
                    path.path_switches = path.path_switches.saturating_add(1);
                    tracing::info!(
                        event = "iroh_path_switched",
                        peer_id = %observer_connection.remote_id(),
                        from_route = %path.route,
                        to_route = %route,
                        path_switches = path.path_switches,
                        "Iroh selected path changed"
                    );
                }
                *selected_path = event_path_key;
                path.route = route.to_string();
                path.rtt_ms = rtt_ms;
            }
        });
        Self {
            connection,
            state,
            _selected_path: selected_path,
        }
    }

    fn snapshot(&self) -> PathInfo {
        let mut path = self
            .state
            .read()
            .expect("Iroh path telemetry lock poisoned")
            .clone();
        // A stream can be registered immediately after the QUIC handshake,
        // before the first path-selection event reaches the watcher. Refresh
        // the current route synchronously so observers do not retain an
        // initial `unknown` value forever.
        let (route, rtt_ms) = selected_path_metrics(&self.connection);
        if route != "unknown" {
            path.route = route.to_string();
            path.rtt_ms = rtt_ms;
        }
        path
    }
}

fn selected_path_key(connection: &Connection) -> Option<String> {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| format!("{:?}", path.id()))
}

fn path_list_selected_key(paths: &PathList<'_>) -> Option<String> {
    paths
        .iter()
        .find(|path| path.is_selected())
        .map(|path| format!("{:?}", path.id()))
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

fn connection_path_info_with_incoming(
    endpoint: &Endpoint,
    connection: &Connection,
    incoming_addr: &IncomingAddr,
) -> PathInfo {
    let mut path = connection_path_info(endpoint, connection);
    if path.route == "unknown" {
        path.route = incoming_route(incoming_addr).to_string();
    }
    path
}

fn incoming_route(incoming_addr: &IncomingAddr) -> &'static str {
    match incoming_addr {
        IncomingAddr::Ip(_) => "direct",
        IncomingAddr::Relay { .. } => "relay",
        IncomingAddr::Custom(_) => "custom",
        _ => "unknown",
    }
}

fn selected_path_metrics(connection: &Connection) -> (&'static str, Option<u64>) {
    path_list_metrics(&connection.paths())
}

fn path_list_metrics(paths: &PathList<'_>) -> (&'static str, Option<u64>) {
    paths
        .iter()
        .find(|path| path.is_selected())
        .or_else(|| paths.iter().next())
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

async fn write_handshake(stream: &mut SendStream, network_id: NetworkId) -> Result<()> {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    handshake[..MAGIC.len()].copy_from_slice(MAGIC);
    handshake[MAGIC.len()] = PROTOCOL_VERSION;
    handshake[MAGIC.len() + 1..].copy_from_slice(network_id.as_bytes());
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

async fn read_and_validate_handshake(stream: &mut RecvStream, network_id: NetworkId) -> Result<()> {
    let mut handshake = [0u8; HANDSHAKE_LEN];
    stream
        .read_exact(&mut handshake)
        .await
        .map_err(|error| NetworkError::Handshake {
            reason: format!("read Iroh handshake: {error}"),
        })?;
    validate_handshake(&handshake)?;
    crate::validate_network_id(&handshake, network_id)
}

fn _assert_async_stream<T: AsyncStream>() {}
