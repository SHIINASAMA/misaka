//! Authenticated ClientHello/ServerHello for Iroh logical streams.
//!
//! Iroh already encrypts the transport. This layer answers the separate
//! Misaka questions: which Network is this, which Sister key is speaking,
//! whether that key has membership, and whether it owns the transport
//! endpoint that reached us.

use misaka_core::{
    AuthenticatedClientHello, AuthenticatedServerHello, IrohEndpointId, MembershipCertificate,
    MembershipKind, NetworkAuthority, NetworkId, SisterKeyPair, TransportBinding,
    AUTH_SESSION_PROTOCOL_VERSION,
};
use misaka_network::{NetworkError, NetworkStream, Result};
use rand::random;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_AUTH_FRAME_LENGTH: usize = 1024 * 1024;

/// Local material required to authenticate one Iroh session.
#[derive(Clone, Debug)]
pub struct AuthenticatedSessionConfig {
    pub network_id: NetworkId,
    pub sister_id: u64,
    pub sister_key: SisterKeyPair,
    pub authority: NetworkAuthority,
    pub membership_certificate: MembershipCertificate,
    pub transport_binding: TransportBinding,
    /// Local revocation state is read from this directory for every session
    /// decision, so a post-start revoke takes effect without restarting.
    pub revocation_directory: Option<PathBuf>,
}

impl AuthenticatedSessionConfig {
    pub fn new(
        network_id: NetworkId,
        sister_id: u64,
        sister_key: SisterKeyPair,
        authority: NetworkAuthority,
        membership_certificate: MembershipCertificate,
        transport_binding: TransportBinding,
    ) -> Self {
        Self {
            network_id,
            sister_id,
            sister_key,
            authority,
            membership_certificate,
            transport_binding,
            revocation_directory: None,
        }
    }

    pub fn with_revocation_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.revocation_directory = Some(directory.into());
        self
    }
}

#[derive(Debug, Error)]
pub enum AuthenticatedSessionError {
    #[error("authenticated session frame I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid authenticated session frame: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
    #[error("authenticated session rejected: {0}")]
    Rejected(String),
}

impl From<AuthenticatedSessionError> for NetworkError {
    fn from(error: AuthenticatedSessionError) -> Self {
        match error {
            AuthenticatedSessionError::Io(error) => NetworkError::Io(error),
            AuthenticatedSessionError::Codec(error) => NetworkError::Authentication(format!(
                "invalid authenticated session payload: {error}"
            )),
            AuthenticatedSessionError::Rejected(reason) => NetworkError::Authentication(reason),
        }
    }
}

/// Authenticate an outbound Iroh logical stream and return it only after the
/// remote identity and transport binding have been verified.
pub async fn authenticate_client(
    mut stream: NetworkStream,
    local: &AuthenticatedSessionConfig,
    expected_sister_id: Option<u64>,
) -> Result<NetworkStream> {
    validate_local(local)?;
    let client = AuthenticatedClientHello::sign(
        local.network_id,
        local.sister_id,
        local.sister_key.public_key(),
        local.membership_certificate.clone(),
        local.transport_binding.clone(),
        random(),
        &local.sister_key,
    );
    write_frame(&mut stream, &client).await?;
    let server: AuthenticatedServerHello = read_frame(&mut stream).await?;
    validate_server(local, &client, &server, expected_sister_id, &stream)?;
    Ok(stream)
}

/// Authenticate an inbound Iroh logical stream. Failure drops the stream and
/// prevents it from reaching any service handler.
pub async fn authenticate_server(
    mut stream: NetworkStream,
    local: &AuthenticatedSessionConfig,
) -> Result<NetworkStream> {
    validate_local(local)?;
    let client: AuthenticatedClientHello = read_frame(&mut stream).await?;
    validate_client(local, &client, &stream)?;
    let server = AuthenticatedServerHello::sign(
        local.network_id,
        local.sister_id,
        local.sister_key.public_key(),
        local.membership_certificate.clone(),
        local.transport_binding.clone(),
        client.nonce,
        random(),
        &local.sister_key,
    );
    write_frame(&mut stream, &server).await?;
    Ok(stream)
}

fn validate_local(local: &AuthenticatedSessionConfig) -> Result<()> {
    if local.network_id != local.authority.network_id
        || local.membership_certificate.network_id != local.network_id
        || local.membership_certificate.sister_id.as_u64() != local.sister_id
        || local.membership_certificate.sister_public_key != local.sister_key.public_key()
        || local.transport_binding.network_id != local.network_id
        || local.transport_binding.sister_id.as_u64() != local.sister_id
        || local.transport_binding.sister_public_key != local.sister_key.public_key()
        || !local.membership_certificate.verify(&local.authority)
        || !local.membership_certificate.is_valid_at(now_secs())
        || !local.transport_binding.verify()
        || membership_is_revoked(
            local,
            MembershipKind::Sister,
            local.membership_certificate.serial,
        )?
    {
        return Err(rejected("local authentication material is inconsistent"));
    }
    Ok(())
}

fn validate_client(
    local: &AuthenticatedSessionConfig,
    client: &AuthenticatedClientHello,
    stream: &NetworkStream,
) -> Result<()> {
    if client.protocol_version != AUTH_SESSION_PROTOCOL_VERSION
        || client.network_id != local.network_id
        || client.sister_public_key != client.membership_certificate.sister_public_key
        || client.sister_id != client.membership_certificate.sister_id
        || client.membership_certificate.network_id != local.network_id
        || client.transport_binding.network_id != local.network_id
        || client.transport_binding.sister_id != client.sister_id
        || client.transport_binding.sister_public_key != client.sister_public_key
        || !client.verify_signature()
        || !client.membership_certificate.verify(&local.authority)
        || !client.membership_certificate.is_valid_at(now_secs())
        || !client.transport_binding.verify()
        || membership_is_revoked(
            local,
            MembershipKind::Sister,
            client.membership_certificate.serial,
        )?
        || !endpoint_matches_binding(stream, client.transport_binding.iroh_endpoint_id)
    {
        return Err(rejected(
            "ClientHello identity, membership, or endpoint binding is invalid",
        ));
    }
    Ok(())
}

fn validate_server(
    local: &AuthenticatedSessionConfig,
    client: &AuthenticatedClientHello,
    server: &AuthenticatedServerHello,
    expected_sister_id: Option<u64>,
    stream: &NetworkStream,
) -> Result<()> {
    if server.protocol_version != AUTH_SESSION_PROTOCOL_VERSION
        || server.network_id != local.network_id
        || server.client_nonce != client.nonce
        || expected_sister_id.is_some_and(|id| server.sister_id.as_u64() != id)
        || server.sister_public_key != server.membership_certificate.sister_public_key
        || server.sister_id != server.membership_certificate.sister_id
        || server.membership_certificate.network_id != local.network_id
        || server.transport_binding.network_id != local.network_id
        || server.transport_binding.sister_id != server.sister_id
        || server.transport_binding.sister_public_key != server.sister_public_key
        || !server.verify_signature()
        || !server.membership_certificate.verify(&local.authority)
        || !server.membership_certificate.is_valid_at(now_secs())
        || !server.transport_binding.verify()
        || membership_is_revoked(
            local,
            MembershipKind::Sister,
            server.membership_certificate.serial,
        )?
        || !endpoint_matches_binding(stream, server.transport_binding.iroh_endpoint_id)
    {
        return Err(rejected(
            "ServerHello identity, membership, or endpoint binding is invalid",
        ));
    }
    Ok(())
}

fn membership_is_revoked(
    local: &AuthenticatedSessionConfig,
    membership_kind: MembershipKind,
    membership_serial: u64,
) -> Result<bool> {
    let Some(directory) = local.revocation_directory.as_deref() else {
        return Ok(false);
    };
    crate::revocation_store::RevocationStore::is_revoked(
        directory,
        &local.authority,
        local.network_id,
        membership_kind,
        membership_serial,
    )
    .map_err(|error| rejected(format!("cannot load local revocation state: {error}")))
}

fn endpoint_matches_binding(stream: &NetworkStream, binding: IrohEndpointId) -> bool {
    let Some(remote) = stream.path_info().remote_endpoint else {
        return false;
    };
    let Some(remote_id) = remote.strip_prefix("iroh://") else {
        return false;
    };
    let Ok(remote_id) = remote_id.parse::<iroh::EndpointId>() else {
        return false;
    };
    IrohEndpointId::from_bytes(*remote_id.as_bytes()) == binding
}

async fn write_frame<T: serde::Serialize>(stream: &mut NetworkStream, value: &T) -> Result<()> {
    let payload = bincode::serialize(value).map_err(AuthenticatedSessionError::from)?;
    if payload.len() > MAX_AUTH_FRAME_LENGTH {
        return Err(rejected("authenticated session frame is too large"));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .map_err(AuthenticatedSessionError::from)?;
    stream
        .write_all(&payload)
        .await
        .map_err(AuthenticatedSessionError::from)?;
    stream
        .flush()
        .await
        .map_err(AuthenticatedSessionError::from)?;
    Ok(())
}

async fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut NetworkStream) -> Result<T> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(AuthenticatedSessionError::from)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_AUTH_FRAME_LENGTH {
        return Err(rejected("authenticated session frame is too large"));
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(AuthenticatedSessionError::from)?;
    Ok(bincode::deserialize(&payload).map_err(AuthenticatedSessionError::from)?)
}

fn rejected(reason: impl Into<String>) -> NetworkError {
    NetworkError::Authentication(reason.into())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{authenticate_client, authenticate_server, AuthenticatedSessionConfig};
    use misaka_core::{
        IrohEndpointId, MembershipCertificate, NetworkAuthority, NetworkId, SisterKeyPair,
        TransportBinding,
    };
    use misaka_network::{IrohBackend, NetworkEndpoint};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(
        network_id: NetworkId,
        authority: NetworkAuthority,
        authority_key: &misaka_core::AuthorityKeyPair,
        sister_id: u64,
        sister_key: SisterKeyPair,
        endpoint_id: IrohEndpointId,
    ) -> AuthenticatedSessionConfig {
        let certificate = MembershipCertificate::issue(
            &authority,
            authority_key,
            sister_key.public_key(),
            sister_id,
            super::now_secs().saturating_sub(1),
            None,
            sister_id,
        );
        let binding = TransportBinding::sign(network_id, sister_id, endpoint_id, 0, &sister_key);
        AuthenticatedSessionConfig::new(
            network_id,
            sister_id,
            sister_key,
            authority,
            certificate,
            binding,
        )
    }

    #[tokio::test]
    async fn authenticated_iroh_stream_requires_valid_membership_and_binding() {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
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
        let server_addr = NetworkEndpoint::Iroh(
            iroh::EndpointAddr::new(server_backend.endpoint().id())
                .with_ip_addr(server_backend.endpoint().bound_sockets()[0]),
        );
        let server_key = SisterKeyPair::generate();
        let client_key = SisterKeyPair::generate();
        let server_auth = config(
            network_id,
            authority,
            &authority_key,
            2,
            server_key,
            IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes()),
        );
        let client_auth = config(
            network_id,
            authority,
            &authority_key,
            1,
            client_key,
            IrohEndpointId::from_bytes(*client_backend.endpoint().id().as_bytes()),
        );

        let server_task = tokio::spawn(async move {
            let session = server_backend
                .accept_session_for_network(network_id)
                .await
                .unwrap();
            let stream = session.accept_stream().await.unwrap();
            let mut stream = authenticate_server(stream, &server_auth).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let session = client_backend
            .connect_session_for_network(server_addr, network_id)
            .await
            .unwrap();
        let stream = session.open_stream().await.unwrap();
        let mut stream = authenticate_client(stream, &client_auth, Some(2))
            .await
            .unwrap();
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server_task.await.unwrap();
        client_backend.close().await;
    }
}
