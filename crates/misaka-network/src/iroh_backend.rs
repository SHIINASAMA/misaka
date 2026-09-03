//! Iroh QUIC backend for the NetworkStream contract.
//!
//! This is intentionally a small connectivity spike: one Iroh connection
//! carries one bidirectional QUIC stream, and the stream still uses the
//! Network Stream handshake before it is exposed to callers. Runtime routing
//! and automatic candidate selection remain outside this module for now.

use crate::{
    validate_handshake, AsyncStream, ListenerFuture, NetworkEndpoint, NetworkError,
    NetworkListener, NetworkListenerDriver, NetworkStream, Result, HANDSHAKE_LEN,
    HANDSHAKE_TIMEOUT, IROH_ALPN, MAGIC, PROTOCOL_VERSION,
};
use iroh::endpoint::{IncomingAddr, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        let endpoint = Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![IROH_ALPN.to_vec()])
            .bind()
            .await
            .map_err(|error| NetworkError::Iroh(error.to_string()))?;
        Ok(Self::new(endpoint, IROH_ALPN))
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
        tracing::info!(
            event = "iroh_stream_connected",
            peer_id = %connection.remote_id(),
            "Iroh network stream connected"
        );
        Ok(NetworkStream::from_stream(IrohStream { send, recv }))
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
                NetworkStream::from_stream(IrohStream { send, recv }),
                peer_addr,
            ))
        })
    }
}

struct IrohStream {
    send: SendStream,
    recv: RecvStream,
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
