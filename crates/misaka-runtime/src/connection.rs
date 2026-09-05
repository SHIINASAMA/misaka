use futures_util::{stream::FuturesUnordered, StreamExt};
use misaka_core::SisterId;
use misaka_network::resolver::{rank_candidates, EndpointCandidate};
use misaka_network::tls::{TlsClient, TlsIdentity};
use misaka_network::{
    DirectTcpBackend, IrohBackend, IrohSession, NetworkBackend, NetworkEndpoint, NetworkError,
    NetworkStream,
};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::peer_service::PeerService;
use crate::{
    authenticated_session::authenticate_client, authenticated_session::AuthenticatedSessionConfig,
};

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
    #[error("connection to Sister {0} is already being established")]
    AlreadyConnecting(SisterId),
    #[error("Sister {0} has no pinned stream certificate")]
    NoPeerCertificate(SisterId),
}

#[derive(Clone)]
pub struct SisterConnector {
    peers: PeerService,
    backend: DirectTcpBackend,
    iroh_backend: Option<IrohBackend>,
    authenticated_session: Option<AuthenticatedSessionConfig>,
}

impl SisterConnector {
    pub fn new(peers: PeerService) -> Self {
        Self {
            peers,
            backend: DirectTcpBackend,
            iroh_backend: None,
            authenticated_session: None,
        }
    }

    pub fn with_iroh_backend(mut self, backend: IrohBackend) -> Self {
        self.iroh_backend = Some(backend);
        self
    }

    pub fn with_authenticated_session(mut self, auth: AuthenticatedSessionConfig) -> Self {
        self.authenticated_session = Some(auth);
        self
    }

    pub async fn connect_to_sister(
        &self,
        sister: SisterId,
    ) -> Result<NetworkStream, ConnectionError> {
        self.connect_to_sister_with_session(sister)
            .await
            .map(|connection| connection.stream)
    }

    async fn connect_to_sister_with_session(
        &self,
        sister: SisterId,
    ) -> Result<ConnectedStream, ConnectionError> {
        let peer = self
            .peers
            .get(sister.as_u64())
            .await
            .ok_or_else(|| ConnectionError::UnknownSister(sister.clone()))?;
        if peer.stream_endpoints.is_empty() {
            return Err(ConnectionError::NoStreamEndpoint(sister));
        }

        let mut invalid_error = None;
        let mut candidates = Vec::new();
        for raw_endpoint in peer.stream_endpoints {
            let endpoint = match raw_endpoint.parse::<NetworkEndpoint>() {
                Ok(endpoint) => endpoint,
                Err(reason) => {
                    invalid_error = Some(ConnectionError::InvalidEndpoint {
                        sister: sister.clone(),
                        endpoint: raw_endpoint,
                        reason,
                    });
                    continue;
                }
            };
            candidates.push(EndpointCandidate::for_endpoint(endpoint));
        }
        if candidates.is_empty() {
            return Err(invalid_error.unwrap_or(ConnectionError::NoStreamEndpoint(sister)));
        }
        let network_id = self.peers.network_id();
        let expected_sister_id = sister.as_u64();
        let mut attempts = FuturesUnordered::new();
        for candidate in rank_candidates(candidates) {
            let direct = self.backend;
            let iroh = self.iroh_backend.clone();
            let auth = self.authenticated_session.clone();
            attempts.push(async move {
                let result = match candidate.endpoint.clone() {
                    NetworkEndpoint::Tcp(_) => direct
                        .connect_for_network(candidate.endpoint.clone(), network_id)
                        .await
                        .map(|stream| ConnectedStream {
                            stream,
                            iroh_session: None,
                        }),
                    NetworkEndpoint::Iroh(endpoint) => match iroh {
                        Some(backend) => match backend
                            .connect_session_for_network(
                                NetworkEndpoint::Iroh(endpoint),
                                network_id,
                            )
                            .await
                        {
                            Ok(session) => match session.open_stream().await {
                                Ok(stream) => match auth.as_ref() {
                                    Some(auth) => authenticate_client(
                                        stream,
                                        auth,
                                        Some(expected_sister_id),
                                        None,
                                    )
                                    .await
                                    .map(|stream| ConnectedStream {
                                        stream,
                                        iroh_session: Some(session),
                                    }),
                                    None => Ok(ConnectedStream {
                                        stream,
                                        iroh_session: Some(session),
                                    }),
                                },
                                Err(error) => Err(error),
                            },
                            Err(error) => Err(error),
                        },
                        None => Err(NetworkError::UnsupportedEndpoint(
                            "Iroh candidate requires an explicitly configured Iroh backend"
                                .to_string(),
                        )),
                    },
                };
                (candidate, result)
            });
        }
        let mut last_error = None;
        while let Some((_, result)) = attempts.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(ConnectionError::Connect {
            sister,
            source: last_error.expect("non-empty candidates produce an attempt"),
        })
    }
}

/// Resolves an explicitly advertised Iroh endpoint for a Sister and opens one
/// stream. This remains available for callers that want Iroh-only behavior;
/// `SisterConnector` can also race stored TCP and Iroh candidates when an Iroh
/// backend is explicitly injected.
#[derive(Clone)]
pub struct IrohSisterConnector {
    peers: PeerService,
    backend: IrohBackend,
}

impl IrohSisterConnector {
    pub fn new(peers: PeerService, backend: IrohBackend) -> Self {
        Self { peers, backend }
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
            let NetworkEndpoint::Iroh(_) = endpoint else {
                continue;
            };
            match self
                .backend
                .connect_for_network(endpoint, self.peers.network_id())
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    last_error = Some(ConnectionError::Connect {
                        sister: sister.clone(),
                        source: error,
                    });
                }
            }
        }
        Err(last_error.unwrap_or(ConnectionError::NoStreamEndpoint(sister)))
    }
}

#[derive(Clone)]
pub struct SecureSisterConnector {
    peers: PeerService,
    identity: TlsIdentity,
}

impl SecureSisterConnector {
    pub fn new(peers: PeerService, identity: TlsIdentity) -> Self {
        Self { peers, identity }
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
        let certificate = peer
            .stream_certificate
            .ok_or_else(|| ConnectionError::NoPeerCertificate(sister.clone()))?;
        if peer.stream_endpoints.is_empty() {
            return Err(ConnectionError::NoStreamEndpoint(sister));
        }
        let client_config = self.identity.client_config(&certificate).map_err(|error| {
            ConnectionError::Connect {
                sister: sister.clone(),
                source: error,
            }
        })?;
        let client = TlsClient::new(client_config, format!("sister-{}", sister.as_u64())).map_err(
            |error| ConnectionError::Connect {
                sister: sister.clone(),
                source: error,
            },
        )?;

        let mut last_error = None;
        let mut candidates = Vec::new();
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
            candidates.push(EndpointCandidate::tcp(endpoint));
        }
        for candidate in rank_candidates(candidates) {
            match client.connect(candidate.endpoint).await {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Tracks the lifecycle of explicitly opened Sister stream connections.
///
/// The manager deliberately does not own or recover a `NetworkStream`. The
/// caller owns each returned stream and reports EOF/I/O failure with
/// `mark_disconnected`; a later `open_stream` reuses a healthy Iroh session or
/// creates a fresh candidate connection.
#[derive(Clone)]
pub struct ConnectionManager {
    connector: SisterConnector,
    states: Arc<Mutex<HashMap<u64, ConnectionState>>>,
    iroh_sessions: Arc<Mutex<HashMap<u64, IrohSession>>>,
}

struct ConnectedStream {
    stream: NetworkStream,
    iroh_session: Option<IrohSession>,
}

impl ConnectionManager {
    pub fn new(connector: SisterConnector) -> Self {
        Self {
            connector,
            states: Arc::new(Mutex::new(HashMap::new())),
            iroh_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn new_with_iroh_backend(peers: PeerService, backend: IrohBackend) -> Self {
        Self::new(SisterConnector::new(peers).with_iroh_backend(backend))
    }

    pub fn new_with_iroh_backend_and_auth(
        peers: PeerService,
        backend: IrohBackend,
        auth: AuthenticatedSessionConfig,
    ) -> Self {
        Self::new(
            SisterConnector::new(peers)
                .with_iroh_backend(backend)
                .with_authenticated_session(auth),
        )
    }

    pub async fn state(&self, sister: &SisterId) -> ConnectionState {
        self.states
            .lock()
            .await
            .get(&sister.as_u64())
            .copied()
            .unwrap_or(ConnectionState::Disconnected)
    }

    pub async fn open_stream(&self, sister: SisterId) -> Result<NetworkStream, ConnectionError> {
        {
            let mut states = self.states.lock().await;
            if states.get(&sister.as_u64()) == Some(&ConnectionState::Connecting) {
                return Err(ConnectionError::AlreadyConnecting(sister));
            }
            states.insert(sister.as_u64(), ConnectionState::Connecting);
        }

        let sister_id = sister.as_u64();
        let cached_session = self.iroh_sessions.lock().await.get(&sister_id).cloned();
        if let Some(session) = cached_session {
            if session.is_closed() {
                self.iroh_sessions.lock().await.remove(&sister_id);
            } else {
                match tokio::time::timeout(misaka_network::HANDSHAKE_TIMEOUT, session.open_stream())
                    .await
                {
                    Ok(Ok(stream)) => {
                        self.states
                            .lock()
                            .await
                            .insert(sister_id, ConnectionState::Connected);
                        return Ok(stream);
                    }
                    _ => {
                        session.close();
                        self.iroh_sessions.lock().await.remove(&sister_id);
                    }
                }
            }
        }

        match self
            .connector
            .connect_to_sister_with_session(sister.clone())
            .await
        {
            Ok(connection) => {
                if let Some(session) = connection.iroh_session {
                    self.iroh_sessions.lock().await.insert(sister_id, session);
                }
                self.states
                    .lock()
                    .await
                    .insert(sister_id, ConnectionState::Connected);
                Ok(connection.stream)
            }
            Err(error) => {
                self.states
                    .lock()
                    .await
                    .insert(sister_id, ConnectionState::Disconnected);
                Err(error)
            }
        }
    }

    pub async fn mark_disconnected(&self, sister: &SisterId) {
        self.states
            .lock()
            .await
            .insert(sister.as_u64(), ConnectionState::Disconnected);
    }
}

#[cfg(test)]
mod tests {
    use misaka_core::{PeerState, SisterId};
    use misaka_network::{IrohBackend, NetworkBackend, NetworkEndpoint};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

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
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("tcp://{endpoint}")],
            stream_certificate: None,
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

    #[tokio::test]
    async fn connection_manager_reconnects_after_explicit_disconnect() {
        let listener = misaka_network::listen(
            "127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .expect("loopback address"),
        )
        .await
        .unwrap();
        let endpoint = listener.local_addr();
        let server = tokio::spawn(async move {
            for response in [b"first".as_slice(), b"second".as_slice()] {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(response).await.unwrap();
            }
        });

        let peer = PeerState {
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("tcp://{endpoint}")],
            stream_certificate: None,
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
        let manager = super::ConnectionManager::new(super::SisterConnector::new(service));
        let sister = SisterId(42);

        assert_eq!(
            manager.state(&sister).await,
            super::ConnectionState::Disconnected
        );

        let mut first = manager.open_stream(sister.clone()).await.unwrap();
        assert_eq!(
            manager.state(&sister).await,
            super::ConnectionState::Connected
        );
        let mut first_response = [0u8; 5];
        first.read_exact(&mut first_response).await.unwrap();
        assert_eq!(&first_response, b"first");

        manager.mark_disconnected(&sister).await;
        assert_eq!(
            manager.state(&sister).await,
            super::ConnectionState::Disconnected
        );

        let mut second = manager.open_stream(sister.clone()).await.unwrap();
        assert_eq!(
            manager.state(&sister).await,
            super::ConnectionState::Connected
        );
        let mut second_response = [0u8; 6];
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&second_response, b"second");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_manager_reuses_an_iroh_session_for_explicit_streams() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend = IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend = IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_endpoint_addr = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let server_task = tokio::spawn(async move {
            let session = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                server_backend.accept_session(),
            )
            .await
            .unwrap()
            .unwrap();
            for response in [b"first".as_slice(), b"second".as_slice()] {
                let mut stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    session.accept_stream(),
                )
                .await
                .unwrap()
                .unwrap();
                stream.write_all(response).await.unwrap();
                let mut ack = [0u8; 3];
                stream.read_exact(&mut ack).await.unwrap();
                assert_eq!(&ack, b"ack");
            }
        });

        let peer = PeerState {
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("{}", NetworkEndpoint::Iroh(server_endpoint_addr))],
            stream_certificate: None,
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
        let manager = super::ConnectionManager::new_with_iroh_backend(service, client_backend);
        let sister = SisterId(42);

        let mut first = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            manager.open_stream(sister.clone()),
        )
        .await
        .expect("first Iroh stream timed out")
        .unwrap();
        let mut first_response = [0u8; 5];
        first.read_exact(&mut first_response).await.unwrap();
        assert_eq!(&first_response, b"first");
        first.write_all(b"ack").await.unwrap();
        drop(first);
        manager.mark_disconnected(&sister).await;

        let mut second = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            manager.open_stream(sister),
        )
        .await
        .expect("second Iroh stream timed out")
        .unwrap();
        let mut second_response = [0u8; 6];
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&second_response, b"second");
        second.write_all(b"ack").await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connection_manager_reconnects_after_an_iroh_session_closes() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend = IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend = IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_endpoint_addr = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let server_task = tokio::spawn(async move {
            let first_session = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                server_backend.accept_session(),
            )
            .await
            .unwrap()
            .unwrap();
            let mut first_stream = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                first_session.accept_stream(),
            )
            .await
            .unwrap()
            .unwrap();
            first_stream.write_all(b"first").await.unwrap();
            first_stream.flush().await.unwrap();
            let mut ack = [0u8; 3];
            first_stream.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"ack");
            drop(first_stream);
            first_session.close();

            let second_session = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                server_backend.accept_session(),
            )
            .await
            .unwrap()
            .unwrap();
            let mut second_stream = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                second_session.accept_stream(),
            )
            .await
            .unwrap()
            .unwrap();
            second_stream.write_all(b"second").await.unwrap();
            second_stream.flush().await.unwrap();
            let mut ack = [0u8; 3];
            second_stream.read_exact(&mut ack).await.unwrap();
            assert_eq!(&ack, b"ack");
        });

        let peer = PeerState {
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("{}", NetworkEndpoint::Iroh(server_endpoint_addr))],
            stream_certificate: None,
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
        let manager = super::ConnectionManager::new_with_iroh_backend(service, client_backend);
        let sister = SisterId(42);

        let mut first = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            manager.open_stream(sister.clone()),
        )
        .await
        .expect("first Iroh stream timed out")
        .unwrap();
        let mut first_response = [0u8; 5];
        first.read_exact(&mut first_response).await.unwrap();
        assert_eq!(&first_response, b"first");
        first.write_all(b"ack").await.unwrap();
        first.flush().await.unwrap();
        drop(first);
        manager.mark_disconnected(&sister).await;

        let mut second = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            manager.open_stream(sister),
        )
        .await
        .expect("second Iroh stream timed out")
        .unwrap();
        let mut second_response = [0u8; 6];
        second.read_exact(&mut second_response).await.unwrap();
        assert_eq!(&second_response, b"second");
        second.write_all(b"ack").await.unwrap();
        second.flush().await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn iroh_connector_resolves_a_sister_by_its_iroh_endpoint() {
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![misaka_network::IROH_ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server_backend = IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client_backend = IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let server_endpoint_addr = iroh::EndpointAddr::new(server_backend.endpoint().id())
            .with_ip_addr(server_backend.endpoint().bound_sockets()[0]);
        let listener = server_backend
            .listen(NetworkEndpoint::Iroh(server_endpoint_addr.clone()))
            .await
            .unwrap();
        let server_task = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap()
        });

        let peer = PeerState {
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("{}", NetworkEndpoint::Iroh(server_endpoint_addr))],
            stream_certificate: None,
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
        let connector =
            super::SisterConnector::new(service).with_iroh_backend(client_backend.clone());
        let mut stream = connector.connect_to_sister(SisterId(42)).await.unwrap();

        let mut response = [0u8; 8];
        let (mut server_stream, _) = server_task.await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut server_stream, b"resolved")
            .await
            .unwrap();
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"resolved");
        client_backend.close().await;
        server_backend.close().await;
    }

    #[tokio::test]
    async fn secure_connector_pins_the_peer_certificate_and_identity_name() {
        install_test_crypto_provider();
        let server_dir =
            std::env::temp_dir().join(format!("misaka-server-{}", uuid::Uuid::new_v4()));
        let client_dir =
            std::env::temp_dir().join(format!("misaka-client-{}", uuid::Uuid::new_v4()));
        let server_identity =
            crate::tls_identity_store::TlsIdentityStore::load_or_init(&server_dir, "sister-42")
                .unwrap();
        let client_identity =
            crate::tls_identity_store::TlsIdentityStore::load_or_init(&client_dir, "sister-1")
                .unwrap();
        let server = misaka_network::tls::TlsServer::new(
            server_identity
                .server_config(client_identity.certificate_der())
                .unwrap(),
        );
        let listener = server
            .listen(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        let endpoint = listener.local_addr();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"secure").await.unwrap();
        });

        let peer = PeerState {
            network_id: misaka_core::NetworkId::default(),
            id: 42,
            nickname: "peer".into(),
            hostname: "host".into(),
            platform: "test".into(),
            version: "0.1".into(),
            stream_endpoints: vec![format!("tcp://{endpoint}")],
            stream_certificate: Some(server_identity.certificate_der().to_vec()),
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
        let connector = super::SecureSisterConnector::new(service, client_identity);
        let mut stream = connector.connect_to_sister(SisterId(42)).await.unwrap();
        let mut response = [0u8; 6];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"secure");
        server_task.await.unwrap();
        let _ = std::fs::remove_dir_all(server_dir);
        let _ = std::fs::remove_dir_all(client_dir);
    }
}
