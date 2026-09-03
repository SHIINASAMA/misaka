//! Minimal relay: pair two TCP sockets by Sister ID and forward bytes.
//!
//! The relay is deliberately not a Sister. It has no peer store, discovery,
//! scheduler, identity authority, or payload decryption responsibility.

use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};

const MAGIC: &[u8; 8] = b"MSKRELAY";
const REGISTER: u8 = 1;
const DIAL: u8 = 2;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<TcpStream>>>>;

#[derive(Debug, thiserror::Error)]
enum RelayError {
    #[error("relay I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid relay handshake")]
    Handshake,
    #[error("Sister #{0} is not registered")]
    UnknownPeer(u64),
    #[error("Sister #{0} already has a pending registration")]
    DuplicatePeer(u64),
}

#[derive(Parser, Debug)]
#[command(name = "misaka-relay")]
struct Args {
    /// TCP address on which the byte-forwarding relay listens.
    #[arg(long, default_value = "0.0.0.0:443")]
    bind: SocketAddr,
}

struct Relay {
    listener: TcpListener,
    pending: Pending,
}

impl Relay {
    async fn bind(address: SocketAddr) -> Result<Self, RelayError> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn run(self) -> Result<(), RelayError> {
        tracing::info!(address = %self.listener.local_addr()?, "relay listening");
        loop {
            let (stream, address) = self.listener.accept().await?;
            let pending = Arc::clone(&self.pending);
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, pending).await {
                    tracing::debug!(peer = %address, error = %error, "relay connection closed");
                }
            });
        }
    }
}

async fn handle_connection(mut stream: TcpStream, pending: Pending) -> Result<(), RelayError> {
    let mut magic = [0u8; MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    if magic != *MAGIC {
        return Err(RelayError::Handshake);
    }
    let role = stream.read_u8().await?;
    let sister_id = stream.read_u64().await?;
    match role {
        REGISTER => {
            let (sender, receiver) = oneshot::channel();
            if pending.lock().await.insert(sister_id, sender).is_some() {
                return Err(RelayError::DuplicatePeer(sister_id));
            }
            let Ok(mut peer) = receiver.await else {
                pending.lock().await.remove(&sister_id);
                return Err(RelayError::UnknownPeer(sister_id));
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut peer).await?;
            pending.lock().await.remove(&sister_id);
            Ok(())
        }
        DIAL => {
            let sender = pending
                .lock()
                .await
                .remove(&sister_id)
                .ok_or(RelayError::UnknownPeer(sister_id))?;
            sender
                .send(stream)
                .map_err(|_| RelayError::UnknownPeer(sister_id))?;
            Ok(())
        }
        _ => Err(RelayError::Handshake),
    }
}

#[tokio::main]
async fn main() -> Result<(), RelayError> {
    let args = Args::parse();
    tracing_subscriber::fmt().with_target(false).init();
    Relay::bind(args.bind).await?.run().await
}

#[cfg(test)]
mod tests {
    use super::{Relay, DIAL, MAGIC, REGISTER};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn hello(stream: &mut TcpStream, role: u8, id: u64) {
        stream.write_all(MAGIC).await.unwrap();
        stream.write_u8(role).await.unwrap();
        stream.write_u64(id).await.unwrap();
    }

    #[tokio::test]
    async fn relay_pairs_register_and_dial_without_inspecting_payload() {
        let relay = Relay::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let address = relay.listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });

        let mut registered = TcpStream::connect(address).await.unwrap();
        hello(&mut registered, REGISTER, 42).await;
        let mut dialed = TcpStream::connect(address).await.unwrap();
        hello(&mut dialed, DIAL, 42).await;
        dialed.write_all(b"relay-payload").await.unwrap();
        let mut received = [0u8; 13];
        registered.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"relay-payload");
    }
}
