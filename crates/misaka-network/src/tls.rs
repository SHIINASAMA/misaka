use crate::{
    NetworkEndpoint, NetworkError, NetworkListener, NetworkListenerDriver, NetworkStream, PathInfo,
    Result, HANDSHAKE_TIMEOUT,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// A certificate and private key used for mutual TLS.
///
/// The certificate is intentionally kept as DER bytes so callers can persist
/// it alongside a Sister's identity and pin it as a trust root for a known
/// peer. Certificate issuance and trust policy stay outside the stream
/// transport; the TLS implementation performs the protocol correctly.
#[derive(Clone)]
pub struct TlsIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsIdentity")
            .field("certificate_len", &self.certificate_der.len())
            .field("private_key_len", &self.private_key_der.len())
            .finish()
    }
}

impl TlsIdentity {
    pub fn from_der(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Self {
        Self {
            certificate_der,
            private_key_der,
        }
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn client_config(&self, trusted_peer_certificate: &[u8]) -> Result<Arc<ClientConfig>> {
        self.client_config_with_trusted_peer_certificates(&[trusted_peer_certificate.to_vec()])
    }

    pub fn client_config_with_trusted_peer_certificates(
        &self,
        trusted_peer_certificates: &[Vec<u8>],
    ) -> Result<Arc<ClientConfig>> {
        let roots = root_store(trusted_peer_certificates.iter().map(Vec::as_slice))?;
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_client_auth_cert(self.certificate_chain(), self.private_key())
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        Ok(Arc::new(config))
    }

    pub fn server_config(&self, trusted_client_certificate: &[u8]) -> Result<Arc<ServerConfig>> {
        self.server_config_with_trusted_client_certificates(&[trusted_client_certificate.to_vec()])
    }

    pub fn server_config_with_trusted_client_certificates(
        &self,
        trusted_client_certificates: &[Vec<u8>],
    ) -> Result<Arc<ServerConfig>> {
        let roots = root_store(trusted_client_certificates.iter().map(Vec::as_slice))?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.certificate_chain(), self.private_key())
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        Ok(Arc::new(config))
    }

    fn certificate_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.certificate_der.clone())]
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key_der.clone()))
    }
}

fn root_store<'a>(certificates: impl IntoIterator<Item = &'a [u8]>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for certificate_der in certificates {
        roots
            .add(CertificateDer::from(certificate_der.to_vec()))
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
    }
    Ok(roots)
}

/// A TLS 1.3 client using mutual certificate authentication.
pub struct TlsClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsClient {
    pub fn new(config: Arc<ClientConfig>, server_name: impl Into<String>) -> Result<Self> {
        let server_name = ServerName::try_from(server_name.into())
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        Ok(Self {
            connector: TlsConnector::from(config),
            server_name,
        })
    }

    pub async fn connect(&self, endpoint: NetworkEndpoint) -> Result<NetworkStream> {
        let NetworkEndpoint::Tcp(address) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "TlsClient requires tcp:// endpoint".to_string(),
            ));
        };
        let stream = TcpStream::connect(address)
            .await
            .map_err(NetworkError::Connect)?;
        let local_endpoint = stream.local_addr().ok().map(|addr| addr.to_string());
        let stream = self
            .connector
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        Ok(NetworkStream::from_stream_with_path(
            stream,
            PathInfo::new(
                "direct-tcp",
                "direct",
                local_endpoint,
                Some(address.to_string()),
            ),
        ))
    }
}

/// A TLS 1.3 server requiring a trusted client certificate.
pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config),
        }
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<NetworkStream> {
        let local_endpoint = stream.local_addr().ok().map(|addr| addr.to_string());
        let remote_endpoint = stream.peer_addr().ok().map(|addr| addr.to_string());
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(|error| NetworkError::Tls(error.to_string()))?;
        Ok(NetworkStream::from_stream_with_path(
            stream,
            PathInfo::new("direct-tcp", "direct", local_endpoint, remote_endpoint),
        ))
    }

    pub async fn listen(&self, endpoint: NetworkEndpoint) -> Result<NetworkListener> {
        let NetworkEndpoint::Tcp(address) = endpoint else {
            return Err(NetworkError::UnsupportedEndpoint(
                "TlsServer requires tcp:// endpoint".to_string(),
            ));
        };
        let listener = TcpListener::bind(address)
            .await
            .map_err(NetworkError::Bind)?;
        let bound = listener.local_addr().map_err(NetworkError::Bind)?;
        tracing::info!(
            event = "secure_stream_listener_started",
            address = %bound,
            "secure network stream listener started"
        );
        Ok(NetworkListener::from_driver(TlsListener {
            inner: listener,
            acceptor: self.acceptor.clone(),
        }))
    }
}

struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl NetworkListenerDriver for TlsListener {
    fn local_addr(&self) -> SocketAddr {
        self.inner
            .local_addr()
            .expect("a bound TCP listener has a local address")
    }

    fn accept(&self) -> crate::ListenerFuture<'_> {
        Box::pin(async move {
            let (stream, address) = self.inner.accept().await.map_err(NetworkError::Io)?;
            let local_endpoint = stream.local_addr().ok().map(|addr| addr.to_string());
            let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream))
                .await
                .map_err(|_| NetworkError::Tls("TLS handshake timed out".to_string()))?
                .map_err(|error| NetworkError::Tls(error.to_string()))?;
            Ok((
                NetworkStream::from_stream_with_path(
                    stream,
                    PathInfo::new(
                        "direct-tcp",
                        "direct",
                        local_endpoint,
                        Some(address.to_string()),
                    ),
                ),
                address,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{TlsClient, TlsIdentity, TlsServer};
    use crate::NetworkEndpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::CertificateDer;
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn identity(name: &str) -> TlsIdentity {
        let generated = generate_simple_self_signed(vec![name.to_string()]).unwrap();
        TlsIdentity::from_der(
            generated.cert.der().to_vec(),
            generated.key_pair.serialize_der(),
        )
    }

    fn install_test_crypto_provider() {
        // The Iroh relay test fixture enables both rustls providers. Install
        // one explicitly so rustls builders do not depend on test order.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[tokio::test]
    async fn mutual_tls_authenticates_and_encrypts_a_stream() {
        install_test_crypto_provider();
        let server_identity = identity("sister-server");
        let client_identity = identity("sister-client");
        let server = TlsServer::new(
            server_identity
                .server_config(client_identity.certificate_der())
                .unwrap(),
        );
        let client = TlsClient::new(
            client_identity
                .client_config(server_identity.certificate_der())
                .unwrap(),
            "sister-server",
        )
        .unwrap();

        let listener = server
            .listen(NetworkEndpoint::Tcp("127.0.0.1:0".parse().unwrap()))
            .await
            .unwrap();
        let endpoint = listener.local_addr();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let mut stream = client
            .connect(NetworkEndpoint::Tcp(endpoint))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn mutual_tls_rejects_an_untrusted_client() {
        install_test_crypto_provider();
        let server_identity = identity("sister-server");
        let client_identity = identity("sister-client");
        let server = TlsServer::new(
            server_identity
                .server_config(client_identity.certificate_der())
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                server_identity.certificate_der().to_vec(),
            ))
            .unwrap();
        let client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let client = TlsClient::new(Arc::new(client_config), "sister-server").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            match server.accept(stream).await {
                Ok(mut stream) => {
                    let _ = stream.write_all(b"bad").await;
                    false
                }
                Err(_) => true,
            }
        });

        let client_result = client.connect(NetworkEndpoint::Tcp(endpoint)).await;
        if let Ok(mut stream) = client_result {
            let mut response = [0u8; 3];
            assert!(stream.read_exact(&mut response).await.is_err());
        }
        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn tls_rejects_a_wrong_server_identity_name() {
        install_test_crypto_provider();
        let server_identity = identity("sister-server");
        let client_identity = identity("sister-client");
        let server = TlsServer::new(
            server_identity
                .server_config(client_identity.certificate_der())
                .unwrap(),
        );
        let client = TlsClient::new(
            client_identity
                .client_config(server_identity.certificate_der())
                .unwrap(),
            "another-sister",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server.accept(stream).await.is_err()
        });

        assert!(client
            .connect(NetworkEndpoint::Tcp(endpoint))
            .await
            .is_err());
        assert!(server_task.await.unwrap());
    }
}
