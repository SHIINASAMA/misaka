//! Transport-neutral control channel framing for authenticated Iroh streams.

use crate::authenticated_session::{authenticate_client, AuthenticatedSessionConfig};
use crate::node::SisterNode;
use misaka_core::{Envelope, NetworkId};
use misaka_network::{IrohBackend, NetworkEndpoint, NetworkError, NetworkStream, Result};
use serde::{Deserialize, Serialize};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const CONTROL_MAGIC: &[u8; 4] = b"MSKC";
const MAX_CONTROL_FRAME_LENGTH: usize = 4 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct ControlRequest {
    envelope: Envelope,
    expect_response: bool,
}

/// Open one authenticated Iroh logical stream and carry a control request.
pub async fn send(
    backend: &IrohBackend,
    endpoint: NetworkEndpoint,
    network_id: NetworkId,
    auth: Option<&AuthenticatedSessionConfig>,
    envelope: &Envelope,
    expect_response: bool,
) -> Result<Option<Envelope>> {
    let session = backend
        .connect_session_for_network(endpoint, network_id)
        .await?;
    let stream = session.open_stream().await?;
    let mut stream = match auth {
        Some(auth) => {
            authenticate_client(stream, auth, (envelope.to != 0).then_some(envelope.to)).await?
        }
        None => stream,
    };
    // Keep the existing Iroh service-stream opening contract: a Sister sends
    // `world` before the client selects a service. Control clients consume
    // that greeting, then select the control channel with its discriminator.
    let mut greeting = [0u8; 5];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(NetworkError::Io)?;
    if greeting != *b"world" {
        return Err(NetworkError::Authentication(
            "unexpected Iroh control greeting".to_string(),
        ));
    }
    stream
        .write_all(CONTROL_MAGIC)
        .await
        .map_err(NetworkError::Io)?;
    write_frame(
        &mut stream,
        &ControlRequest {
            envelope: envelope.clone(),
            expect_response,
        },
    )
    .await?;
    if expect_response {
        Ok(Some(read_frame(&mut stream).await?))
    } else {
        Ok(None)
    }
}

/// Handle the control payload after the Iroh stream handshake and magic have
/// already been consumed.
pub async fn serve(node: &SisterNode, mut stream: NetworkStream) -> Result<()> {
    let request: ControlRequest = read_frame(&mut stream).await?;
    let response = crate::handler::dispatch_envelope(node, request.envelope)
        .await
        .map_err(|error| NetworkError::Authentication(error.to_string()))?;
    if request.expect_response {
        if let Some(response) = response {
            write_frame(&mut stream, &response).await?;
        }
    }
    Ok(())
}

/// Restore a non-control service preamble after the Iroh dispatcher reads the
/// four-byte discriminator.
pub fn prepend(stream: NetworkStream, prefix: [u8; 4]) -> NetworkStream {
    let path = stream.path_info();
    let provider = stream.path_info_provider();
    let stream = PrefixedStream {
        prefix: Some(prefix),
        inner: stream,
    };
    match provider {
        Some(provider) => {
            NetworkStream::from_stream_with_path_provider(stream, path, move || provider())
        }
        None => NetworkStream::from_stream_with_path(stream, path),
    }
}

async fn write_frame<T: Serialize>(stream: &mut NetworkStream, value: &T) -> Result<()> {
    let payload = bincode::serialize(value)
        .map_err(|error| NetworkError::Authentication(error.to_string()))?;
    if payload.len() > MAX_CONTROL_FRAME_LENGTH {
        return Err(NetworkError::Authentication(
            "control frame is too large".to_string(),
        ));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(NetworkError::Io)?;
    stream.write_all(&payload).await.map_err(NetworkError::Io)?;
    stream.flush().await.map_err(NetworkError::Io)?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut NetworkStream) -> Result<T> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(NetworkError::Io)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_CONTROL_FRAME_LENGTH {
        return Err(NetworkError::Authentication(
            "control frame is too large".to_string(),
        ));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(NetworkError::Io)?;
    bincode::deserialize(&payload).map_err(|error| NetworkError::Authentication(error.to_string()))
}

struct PrefixedStream {
    prefix: Option<[u8; 4]>,
    inner: NetworkStream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = self.prefix.take() {
            if buf.remaining() < prefix.len() {
                self.prefix = Some(prefix);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "prefixed stream requires a four-byte read buffer",
                )));
            }
            buf.put_slice(&prefix);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
