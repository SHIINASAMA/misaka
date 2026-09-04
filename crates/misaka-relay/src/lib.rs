//! Iroh-native relay service.
//!
//! A relay is infrastructure only. It is not a Sister, does not join a
//! Misaka Network, and does not inspect or authorize application payloads.

use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRequest, RelayConfig as IrohRelayConfig, Server,
    ServerConfig, TlsConfig,
};
use rustls::pki_types::CertificateDer;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Configuration for one Iroh relay service.
#[derive(Debug, Clone)]
pub struct RelayOptions {
    /// Public relay address. HTTP in development mode, HTTPS when TLS files
    /// are configured.
    pub bind: SocketAddr,
    /// Plain HTTP address used for the relay captive-portal service when TLS
    /// is enabled. Defaults to port 80 on the bind address.
    pub http_bind: Option<SocketAddr>,
    /// PEM certificate chain for HTTPS mode.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key for HTTPS mode.
    pub tls_key: Option<PathBuf>,
    /// JSON array of admitted Iroh EndpointIds. When absent, relay access is
    /// open for compatibility; when present, changes take effect for new
    /// connections without restarting the relay.
    pub access_allowlist: Option<PathBuf>,
    /// JSON array of temporary enrollment EndpointIds. These are unioned with
    /// the regular allowlist and should be removed after `network join`.
    pub bootstrap_allowlist: Option<PathBuf>,
}

impl RelayOptions {
    pub fn http(bind: SocketAddr) -> Self {
        Self {
            bind,
            http_bind: None,
            tls_cert: None,
            tls_key: None,
            access_allowlist: None,
            bootstrap_allowlist: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("Iroh relay configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("Iroh relay TLS I/O failed: {0}")]
    TlsIo(#[from] std::io::Error),
    #[error("Iroh relay TLS configuration failed: {0}")]
    Tls(String),
    #[error("Iroh relay failed: {0}")]
    Iroh(String),
}

/// Owns one native Iroh relay server. It never becomes a Misaka peer.
pub struct RelayService {
    server: Server,
}

impl RelayService {
    /// Bind an HTTP-only Iroh relay. This is useful for local development;
    /// public deployments should configure TLS with [`Self::bind_with_options`].
    pub async fn bind(address: SocketAddr) -> Result<Self, RelayError> {
        Self::bind_with_options(RelayOptions::http(address)).await
    }

    /// Bind an Iroh relay with either plain HTTP or configured HTTPS.
    pub async fn bind_with_options(options: RelayOptions) -> Result<Self, RelayError> {
        let config = build_server_config(&options)?;
        let server = Server::spawn(config)
            .await
            .map_err(|error| RelayError::Iroh(error.to_string()))?;
        Ok(Self { server })
    }

    /// Return the address used by Iroh clients: HTTPS when TLS is enabled,
    /// otherwise HTTP.
    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        self.server
            .https_addr()
            .or_else(|| self.server.http_addr())
            .ok_or_else(|| RelayError::Iroh("relay server has no bound address".to_string()))
    }

    pub fn is_tls_enabled(&self) -> bool {
        self.server.https_addr().is_some()
    }

    /// Wait until the native Iroh relay server stops.
    pub async fn run(mut self) -> Result<(), RelayError> {
        tracing::info!(
            address = %self.local_addr()?,
            tls = self.is_tls_enabled(),
            "Iroh relay listening"
        );
        let result = self
            .server
            .join()
            .await
            .map_err(|error| RelayError::Iroh(error.to_string()))?;
        result.map_err(|error| RelayError::Iroh(error.to_string()))
    }
}

fn build_server_config(options: &RelayOptions) -> Result<ServerConfig, RelayError> {
    let mut relay = IrohRelayConfig::new(options.bind);
    let allowlist_paths = [
        options.access_allowlist.clone(),
        options.bootstrap_allowlist.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if !allowlist_paths.is_empty() {
        for path in &allowlist_paths {
            validate_allowlist(path)?;
        }
        relay.access = Arc::new(FileAllowlistAccess {
            paths: allowlist_paths,
        });
    }
    match (&options.tls_cert, &options.tls_key) {
        (None, None) => {}
        (Some(cert), Some(key)) => {
            let server_config = load_tls_config(cert, key)?;
            let http_bind = options
                .http_bind
                .unwrap_or_else(|| SocketAddr::new(options.bind.ip(), 80));
            relay.http_bind_addr = http_bind;
            relay.tls = Some(TlsConfig::new(
                options.bind,
                CertConfig::Manual { server_config },
            ));
        }
        _ => {
            return Err(RelayError::InvalidConfig(
                "--relay-tls-cert and --relay-tls-key must be provided together".to_string(),
            ));
        }
    }

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    Ok(config)
}

#[derive(Debug, Clone)]
struct FileAllowlistAccess {
    paths: Vec<PathBuf>,
}

impl AccessControl for FileAllowlistAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        for path in &self.paths {
            match load_allowlist(path) {
                Ok(endpoints) if endpoints.contains(&request.endpoint_id()) => {
                    return Access::Allow;
                }
                Ok(_) => {}
                Err(error) => {
                    return Access::Deny {
                        reason: Some(format!("relay access allowlist unavailable: {error}")),
                    };
                }
            }
        }
        Access::Deny {
            reason: Some("Iroh EndpointId is not admitted by this relay".to_string()),
        }
    }
}

fn validate_allowlist(path: &Path) -> Result<(), RelayError> {
    load_allowlist(path)
        .map(|_| ())
        .map_err(|error| RelayError::InvalidConfig(format!("read relay access allowlist: {error}")))
}

fn load_allowlist(path: &Path) -> Result<Vec<iroh::EndpointId>, std::io::Error> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|error| std::io::Error::other(error.to_string()))
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig, RelayError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| RelayError::Tls(error.to_string()))?;
    if certificates.is_empty() {
        return Err(RelayError::InvalidConfig(format!(
            "TLS certificate file is empty: {}",
            cert_path.display()
        )));
    }

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|error| RelayError::Tls(error.to_string()))?
        .ok_or_else(|| {
            RelayError::InvalidConfig(format!(
                "TLS private key file is empty: {}",
                key_path.display()
            ))
        })?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| RelayError::Tls(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{RelayOptions, RelayService};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn native_iroh_relay_serves_health_endpoint() {
        let relay = RelayService::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let address = relay.local_addr().unwrap();
        let task = tokio::spawn(relay.run());

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");

        task.abort();
    }

    #[test]
    fn tls_files_must_be_configured_as_a_pair() {
        let options = RelayOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            http_bind: None,
            tls_cert: Some("cert.pem".into()),
            tls_key: None,
            access_allowlist: None,
            bootstrap_allowlist: None,
        };
        let error = super::build_server_config(&options).unwrap_err();
        assert!(error.to_string().contains("provided together"));
    }

    #[test]
    fn access_allowlist_must_be_a_json_endpoint_id_array() {
        let directory =
            std::env::temp_dir().join(format!("misaka-relay-access-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("allowlist.json");
        std::fs::write(&path, "not-json").unwrap();
        let options = RelayOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            http_bind: None,
            tls_cert: None,
            tls_key: None,
            access_allowlist: Some(path),
            bootstrap_allowlist: None,
        };
        let error = super::build_server_config(&options).unwrap_err();
        assert!(error.to_string().contains("access allowlist"));
        let _ = std::fs::remove_dir_all(directory);
    }
}
