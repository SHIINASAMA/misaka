use misaka_core::SisterId;
use misaka_network::{
    DirectTcpBackend, NetworkBackend, NetworkEndpoint, NetworkError, NetworkStream,
};
use thiserror::Error;

use crate::peer_service::PeerService;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("unknown Sister {0}")]
    UnknownSister(SisterId),
    #[error("Sister {0} has no stream endpoint candidates")]
    NoStreamEndpoint(SisterId),
    #[error("invalid stream endpoint for Sister {sister}: {endpoint}: {reason}")]
    InvalidEndpoint {
        sister: SisterId,
        endpoint: String,
        reason: String,
    },
    #[error("all stream endpoints for Sister {sister} failed: {source}")]
    Connect {
        sister: SisterId,
        #[source]
        source: NetworkError,
    },
}

#[derive(Clone)]
pub struct SisterConnector {
    peers: PeerService,
    backend: DirectTcpBackend,
}

impl SisterConnector {
    pub fn new(peers: PeerService) -> Self {
        Self {
            peers,
            backend: DirectTcpBackend,
        }
    }

    pub async fn connect_to_sister(
        &self,
        sister: SisterId,
    ) -> Result<NetworkStream, ConnectionError> {
        let peer = self
            .peers
            .get(sister.as_u64())
            .await
            .ok_or_else(|| ConnectionError::UnknownSister(sister.clone()))?;
        if peer.stream_endpoints.is_empty() {
            return Err(ConnectionError::NoStreamEndpoint(sister));
        }

        let mut last_error = None;
        for raw_endpoint in peer.stream_endpoints {
            let endpoint = match raw_endpoint.parse::<NetworkEndpoint>() {
                Ok(endpoint) => endpoint,
                Err(reason) => {
                    last_error = Some(ConnectionError::InvalidEndpoint {
                        sister: sister.clone(),
                        endpoint: raw_endpoint,
                        reason,
                    });
                    continue;
                }
            };
            match self.backend.connect(endpoint).await {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last_error = Some(ConnectionError::Connect {
                        sister: sister.clone(),
                        source: error,
                    })
                }
            }
        }

        Err(last_error.expect("non-empty endpoint candidates produce an error"))
    }
}

#[cfg(test)]
mod tests {
    use misaka_core::{PeerState, SisterId};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connects_to_a_sister_using_its_stream_endpoint() {
        let listener =
            misaka_network::listen("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                .await
                .unwrap();
        let endpoint = listener.local_addr();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"resolved").await.unwrap();
        });

        let peer = PeerState {
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("tcp://{endpoint}")],
            addr: "127.0.0.1:31700".into(),
            cpu_usage: 0.0,
            memory_total: 0,
            memory_used: 0,
            running_jobs: 0,
            queued_jobs: 0,
            uptime_secs: 0,
            capabilities: vec![],
        };
        let service = crate::peer_service::PeerService::new(
            crate::peer_registry::PeerRegistry::new_seeded(vec![peer]),
            std::path::PathBuf::from("."),
        );
        let connector = super::SisterConnector::new(service);
        let mut stream = connector.connect_to_sister(SisterId(42)).await.unwrap();

        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"resolved");
        server.await.unwrap();
    }
}
