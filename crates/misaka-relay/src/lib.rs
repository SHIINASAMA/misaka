//! Opaque byte-forwarding relay service.
//!
//! The relay is deliberately not a Sister. It has no peer store, discovery,
//! scheduler, identity authority, or payload decryption responsibility.

use misaka_core::NetworkId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};

const MAGIC: &[u8; 8] = b"MSKRELAY";
const REGISTER: u8 = 1;
const DIAL: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RelayTarget {
    network_id: NetworkId,
    sister_id: u64,
}

type Pending = Arc<Mutex<HashMap<RelayTarget, oneshot::Sender<TcpStream>>>>;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("relay I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid relay handshake")]
    Handshake,
    #[error("Sister #{sister_id} is not registered in network {network_id}")]
    UnknownPeer {
        network_id: NetworkId,
        sister_id: u64,
    },
    #[error("Sister #{sister_id} already has a pending registration in network {network_id}")]
    DuplicatePeer {
        network_id: NetworkId,
        sister_id: u64,
    },
}

/// Owns one opaque TCP relay listener. It never becomes a Misaka peer.
pub struct RelayService {
    listener: TcpListener,
    pending: Pending,
}

impl RelayService {
    pub async fn bind(address: SocketAddr) -> Result<Self, RelayError> {
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self) -> Result<(), RelayError> {
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
    let mut network_bytes = [0u8; 16];
    stream.read_exact(&mut network_bytes).await?;
    let network_id = NetworkId::from_bytes(network_bytes);
    let sister_id = stream.read_u64().await?;
    let target = RelayTarget {
        network_id,
        sister_id,
    };
    match role {
        REGISTER => {
            let (sender, receiver) = oneshot::channel();
            if pending.lock().await.insert(target, sender).is_some() {
                return Err(RelayError::DuplicatePeer {
                    network_id,
                    sister_id,
                });
            }
            let Ok(mut peer) = receiver.await else {
                pending.lock().await.remove(&target);
                return Err(RelayError::UnknownPeer {
                    network_id,
                    sister_id,
                });
            };
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut peer).await?;
            pending.lock().await.remove(&target);
            Ok(())
        }
        DIAL => {
            let sender = pending
                .lock()
                .await
                .remove(&target)
                .ok_or(RelayError::UnknownPeer {
                    network_id,
                    sister_id,
                })?;
            sender.send(stream).map_err(|_| RelayError::UnknownPeer {
                network_id,
                sister_id,
            })?;
            Ok(())
        }
        _ => Err(RelayError::Handshake),
    }
}

#[cfg(test)]
mod tests {
    use super::{RelayService, DIAL, MAGIC, REGISTER};
    use misaka_core::NetworkId;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn hello(stream: &mut TcpStream, role: u8, network_id: NetworkId, id: u64) {
        stream.write_all(MAGIC).await.unwrap();
        stream.write_u8(role).await.unwrap();
        stream.write_all(network_id.as_bytes()).await.unwrap();
        stream.write_u64(id).await.unwrap();
    }

    #[tokio::test]
    async fn relay_pairs_register_and_dial_without_inspecting_payload() {
        let relay = RelayService::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let address = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });

        let network_id = NetworkId::generate();
        let mut registered = TcpStream::connect(address).await.unwrap();
        hello(&mut registered, REGISTER, network_id, 42).await;
        let mut dialed = TcpStream::connect(address).await.unwrap();
        hello(&mut dialed, DIAL, network_id, 42).await;
        dialed.write_all(b"relay-payload").await.unwrap();
        let mut received = [0u8; 13];
        registered.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"relay-payload");
    }

    #[tokio::test]
    async fn identical_sister_ids_in_different_networks_do_not_cross_route() {
        let relay = RelayService::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let address = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.run().await;
        });

        let first = NetworkId::generate();
        let second = NetworkId::generate();
        let mut first_registered = TcpStream::connect(address).await.unwrap();
        hello(&mut first_registered, REGISTER, first, 7).await;
        let mut second_registered = TcpStream::connect(address).await.unwrap();
        hello(&mut second_registered, REGISTER, second, 7).await;

        let mut second_dialed = TcpStream::connect(address).await.unwrap();
        hello(&mut second_dialed, DIAL, second, 7).await;
        second_dialed.write_all(b"second").await.unwrap();
        let mut received = [0u8; 6];
        second_registered.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"second");
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            first_registered.read_u8()
        )
        .await
        .is_err());
    }
}
