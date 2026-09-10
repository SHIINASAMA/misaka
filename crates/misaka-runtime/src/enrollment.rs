//! The narrow enrollment protocol carried over Iroh.
//!
//! A joining Sister has no membership yet, so it cannot use the authenticated
//! member control plane. Enrollment is served on its own ALPN
//! ([`misaka_network::ENROLLMENT_ALPN`]) by any running Sister that holds the
//! Network Authority private key, and exposes exactly one operation: redeem a
//! valid, unexpired [`EnrollmentInvite`] for a normal [`MembershipCertificate`].
//!
//! Nothing else runs here — no jobs, transfers, tunnels, discovery, or RPC. The
//! Authority private key never leaves this host: it signs the issued membership
//! locally and is never encoded into a request, challenge, response, or log.

use misaka_core::{
    AuthorityKeyPair, EnrollmentChallenge, EnrollmentInvite, EnrollmentProof, EnrollmentRequest,
    EnrollmentResponse, IrohEndpointId, MembershipCertificate, NetworkAuthority, NetworkId,
    PeerRecord, SisterId, SisterKeyPair, ENROLLMENT_PROTOCOL_VERSION,
};
use misaka_network::{IrohSession, NetworkError, NetworkStream, ENROLLMENT_ALPN};
use rand::random;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest enrollment frame accepted in either direction. An enrollment invite
/// plus a signed locator is well under this; oversized frames are refused
/// before allocation, matching the authenticated-session bound.
const MAX_ENROLLMENT_FRAME_LENGTH: usize = 512 * 1024;

/// Bounds every read/write on an enrollment stream so a stalled or malicious
/// peer cannot pin an Authority task open.
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(20);

/// Authority-side material for serving enrollment.
///
/// Constructed only when a running Sister holds the Network Authority private
/// key. The key is used solely to sign freshly issued memberships.
#[derive(Clone)]
pub struct EnrollmentServer {
    network_id: NetworkId,
    authority: NetworkAuthority,
    authority_key: AuthorityKeyPair,
    sister_id: u64,
    iroh_endpoint_id: IrohEndpointId,
    /// The Authority Sister's current signed locator, advertised back to the
    /// joiner as its first trusted bootstrap peer.
    locator: PeerRecord,
    /// Additional already-trusted bootstrap records the Authority can share.
    extra_bootstrap: Vec<PeerRecord>,
    /// Persistent monotonic MembershipCertificate serial allocator. Survives
    /// Authority restart and never reuses a serial (revocation is keyed on it).
    serials: std::sync::Arc<crate::membership_serial_store::MembershipSerialStore>,
}

impl std::fmt::Debug for EnrollmentServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollmentServer")
            .field("network_id", &self.network_id)
            .field("sister_id", &self.sister_id)
            .finish_non_exhaustive()
    }
}

impl EnrollmentServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_dir: &std::path::Path,
        network_id: NetworkId,
        authority: NetworkAuthority,
        authority_key: AuthorityKeyPair,
        sister_id: u64,
        iroh_endpoint_id: IrohEndpointId,
        locator: PeerRecord,
        extra_bootstrap: Vec<PeerRecord>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            network_id,
            authority,
            authority_key,
            sister_id,
            iroh_endpoint_id,
            locator,
            extra_bootstrap,
            serials: std::sync::Arc::new(
                crate::membership_serial_store::MembershipSerialStore::open(data_dir)?,
            ),
        })
    }

    /// Whether this session was negotiated for the enrollment protocol.
    pub fn serves(session: &IrohSession) -> bool {
        session.negotiated_alpn() == ENROLLMENT_ALPN
    }

    /// Serve one enrollment connection: accept a single redemption stream, then
    /// stop. Enrollment is one-shot per connection; the joiner disconnects after.
    pub async fn serve_session(&self, session: IrohSession) {
        let stream = match tokio::time::timeout(ENROLLMENT_TIMEOUT, session.accept_stream()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::debug!(
                    event = "enrollment_stream_failed",
                    error = %error,
                    "enrollment stream not opened"
                );
                return;
            }
            Err(_) => {
                tracing::debug!(
                    event = "enrollment_stream_timeout",
                    "enrollment stream timed out"
                );
                return;
            }
        };
        if let Err(error) = self.serve_stream(stream).await {
            tracing::debug!(
                event = "enrollment_rejected",
                error = %error,
                sister_id = self.sister_id,
                "enrollment redemption rejected"
            );
        }
    }

    async fn serve_stream(&self, mut stream: NetworkStream) -> Result<(), EnrollmentFailure> {
        let request: EnrollmentRequest = read_frame(&mut stream).await?;
        if request.protocol_version != ENROLLMENT_PROTOCOL_VERSION {
            return Err(EnrollmentFailure::Protocol);
        }
        let challenge = match self.evaluate(&request) {
            Ok(challenge) => challenge,
            Err(reason) => {
                write_frame(&mut stream, &ServerReply::Rejected(reason.to_core())).await?;
                return Err(EnrollmentFailure::Rejected(reason));
            }
        };
        write_frame(&mut stream, &ServerReply::Challenge(challenge.clone())).await?;

        let proof: EnrollmentProof = read_frame(&mut stream).await?;
        let response = if !challenge.verify(&proof) {
            EnrollmentResponse::rejected(EnrollmentRejectionKind::InvalidProof.to_core())
        } else {
            match self.serials.allocate() {
                Ok(serial) => {
                    tracing::info!(
                        event = "enrollment_redeemed",
                        network_id = %self.network_id,
                        new_sister_id = request.sister_id.as_u64(),
                        membership_serial = serial,
                        "issued enrollment membership"
                    );
                    self.issue_membership(&request, serial)
                }
                Err(error) => {
                    // Never fall back to a non-persisted serial: reuse would
                    // corrupt revocation. Refuse and let the client retry.
                    tracing::warn!(
                        event = "enrollment_serial_alloc_failed",
                        error = %error,
                        sister_id = self.sister_id,
                        "could not allocate a durable membership serial"
                    );
                    EnrollmentResponse::rejected(EnrollmentRejectionKind::IssuanceFailed.to_core())
                }
            }
        };
        let accepted = matches!(
            response.outcome,
            misaka_core::EnrollmentOutcome::Accepted { .. }
        );
        write_frame(&mut stream, &response).await?;
        if accepted {
            Ok(())
        } else {
            Err(EnrollmentFailure::Rejected(
                EnrollmentRejectionKind::IssuanceFailed,
            ))
        }
    }

    /// Verify everything about a request before any membership is issued.
    fn evaluate(
        &self,
        request: &EnrollmentRequest,
    ) -> Result<EnrollmentChallenge, EnrollmentRejectionKind> {
        let now = now_secs();
        let invite = &request.invite;
        if !invite.verify(now) {
            return Err(if invite.is_expired(now) {
                EnrollmentRejectionKind::Expired
            } else {
                EnrollmentRejectionKind::InvalidInvite
            });
        }
        // The invite must name *this* Network and *this* Authority, and its
        // embedded locator must be us. That prevents one Authority from being
        // talked into redeeming another Network's invite.
        if invite.network_id != self.network_id || invite.authority != self.authority {
            return Err(EnrollmentRejectionKind::WrongNetwork);
        }
        if invite.locator.sister_id.as_u64() != self.sister_id
            || invite.locator.transport_binding.iroh_endpoint_id != self.iroh_endpoint_id
        {
            return Err(EnrollmentRejectionKind::InvalidInvite);
        }
        Ok(EnrollmentChallenge::new(
            self.network_id,
            invite.digest(),
            request.sister_id.clone(),
            request.sister_public_key,
            random(),
            request.recipient_nonce,
        ))
    }

    /// Issue a normal, Authority-signed membership indistinguishable from one
    /// provisioned any other way, and return only public recipient material.
    /// `serial` comes from the durable allocator (never reused).
    fn issue_membership(&self, request: &EnrollmentRequest, serial: u64) -> EnrollmentResponse {
        let now = now_secs();
        let membership = MembershipCertificate::issue(
            &self.authority,
            &self.authority_key,
            request.sister_public_key,
            request.sister_id.as_u64(),
            now,
            None,
            serial,
        );
        let mut bootstrap = vec![self.locator.clone()];
        bootstrap.extend(self.extra_bootstrap.iter().cloned());
        bootstrap.sort_by_key(|record| record.sister_id.as_u64());
        bootstrap.dedup_by(|a, b| a.sister_id == b.sister_id);
        EnrollmentResponse::accepted(self.authority, membership, bootstrap)
    }
}

/// Redeem an invite against the Authority Sister named by its locator.
///
/// The caller supplies its freshly generated Sister identity/key and the local
/// NetworkId it expects. This performs the full challenge/proof exchange and
/// returns the raw response; the caller runs
/// [`EnrollmentResponse::validate_received`] and installs transactionally. The
/// response is never trusted until then.
pub async fn redeem(
    session: IrohSession,
    invite: EnrollmentInvite,
    sister_id: SisterId,
    sister_key: &SisterKeyPair,
) -> Result<EnrollmentResponse, EnrollmentFailure> {
    let mut stream = tokio::time::timeout(ENROLLMENT_TIMEOUT, session.open_stream())
        .await
        .map_err(|_| EnrollmentFailure::Transport("enrollment open timed out".into()))?
        .map_err(|error| EnrollmentFailure::Transport(error.to_string()))?;

    let recipient_nonce: [u8; 32] = random();
    let request = EnrollmentRequest::new(
        invite.clone(),
        sister_id.clone(),
        sister_key.public_key(),
        recipient_nonce,
    );
    write_frame(&mut stream, &request).await?;

    let reply: ServerReply = read_frame(&mut stream).await?;
    let challenge = match reply {
        ServerReply::Rejected(reason) => {
            return Err(EnrollmentFailure::Rejected(
                EnrollmentRejectionKind::from_core(reason),
            ))
        }
        ServerReply::Challenge(challenge) => challenge,
    };
    if challenge.protocol_version != ENROLLMENT_PROTOCOL_VERSION
        || challenge.network_id != invite.network_id
        || challenge.invite_digest != invite.digest()
        || challenge.sister_id != sister_id
        || challenge.sister_public_key != sister_key.public_key()
        || challenge.recipient_nonce != recipient_nonce
    {
        return Err(EnrollmentFailure::Rejected(
            EnrollmentRejectionKind::InvalidInvite,
        ));
    }
    let proof = challenge.solve(sister_key);
    write_frame(&mut stream, &proof).await?;

    let response: EnrollmentResponse = read_frame(&mut stream).await?;
    if let misaka_core::EnrollmentOutcome::Rejected { reason } = &response.outcome {
        return Err(EnrollmentFailure::Rejected(
            EnrollmentRejectionKind::from_core(*reason),
        ));
    }
    Ok(response)
}

/// The Authority's first reply to a redemption request: either a challenge to
/// sign, or an immediate rejection (expired / wrong-network / bad-invite).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum ServerReply {
    Challenge(EnrollmentChallenge),
    Rejected(misaka_core::EnrollmentRejection),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRejectionKind {
    InvalidInvite,
    Expired,
    WrongNetwork,
    InvalidProof,
    Protocol,
    IssuanceFailed,
}

impl EnrollmentRejectionKind {
    fn to_core(self) -> misaka_core::EnrollmentRejection {
        use misaka_core::EnrollmentRejection as R;
        match self {
            Self::InvalidInvite => R::InvalidInvite,
            Self::Expired => R::Expired,
            Self::WrongNetwork => R::WrongNetwork,
            Self::InvalidProof => R::InvalidProof,
            Self::Protocol => R::ProtocolVersion,
            Self::IssuanceFailed => R::IssuanceFailed,
        }
    }

    fn from_core(reason: misaka_core::EnrollmentRejection) -> Self {
        use misaka_core::EnrollmentRejection as R;
        match reason {
            R::InvalidInvite => Self::InvalidInvite,
            R::Expired => Self::Expired,
            R::WrongNetwork => Self::WrongNetwork,
            R::InvalidProof => Self::InvalidProof,
            R::ProtocolVersion => Self::Protocol,
            R::IssuanceFailed => Self::IssuanceFailed,
        }
    }
}

impl std::fmt::Display for EnrollmentRejectionKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_core().to_string())
    }
}

#[derive(Debug)]
pub enum EnrollmentFailure {
    Transport(String),
    Protocol,
    Rejected(EnrollmentRejectionKind),
}

impl std::fmt::Display for EnrollmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(reason) => write!(formatter, "enrollment transport failed: {reason}"),
            Self::Protocol => formatter.write_str("unsupported enrollment protocol version"),
            Self::Rejected(reason) => write!(formatter, "enrollment rejected: {reason}"),
        }
    }
}

impl std::error::Error for EnrollmentFailure {}

impl From<EnrollmentFailure> for NetworkError {
    fn from(error: EnrollmentFailure) -> Self {
        NetworkError::Authentication(error.to_string())
    }
}

async fn write_frame<T: serde::Serialize>(
    stream: &mut NetworkStream,
    value: &T,
) -> Result<(), EnrollmentFailure> {
    let payload = bincode::serialize(value)
        .map_err(|error| EnrollmentFailure::Transport(format!("encode: {error}")))?;
    if payload.len() > MAX_ENROLLMENT_FRAME_LENGTH {
        return Err(EnrollmentFailure::Protocol);
    }
    tokio::time::timeout(ENROLLMENT_TIMEOUT, async {
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .map_err(|error| EnrollmentFailure::Transport(format!("write len: {error}")))?;
        stream
            .write_all(&payload)
            .await
            .map_err(|error| EnrollmentFailure::Transport(format!("write body: {error}")))?;
        stream
            .flush()
            .await
            .map_err(|error| EnrollmentFailure::Transport(format!("flush: {error}")))
    })
    .await
    .map_err(|_| EnrollmentFailure::Transport("write timed out".into()))?
}

async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut NetworkStream,
) -> Result<T, EnrollmentFailure> {
    let result = tokio::time::timeout(ENROLLMENT_TIMEOUT, async {
        let mut length = [0u8; 4];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error: io::Error| {
                EnrollmentFailure::Transport(format!("read len: {error}"))
            })?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_ENROLLMENT_FRAME_LENGTH {
            return Err(EnrollmentFailure::Protocol);
        }
        let mut payload = vec![0u8; length];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|error| EnrollmentFailure::Transport(format!("read body: {error}")))?;
        bincode::deserialize(&payload)
            .map_err(|error| EnrollmentFailure::Transport(format!("decode: {error}")))
    })
    .await
    .map_err(|_| EnrollmentFailure::Transport("read timed out".into()))?;
    result
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_core::TransportBinding;
    use misaka_network::{IrohBackend, NetworkEndpoint};

    fn authority_fixture() -> (NetworkId, NetworkAuthority, AuthorityKeyPair, SisterKeyPair) {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let server_key = SisterKeyPair::generate();
        (network_id, authority, authority_key, server_key)
    }

    async fn bind_pair() -> (IrohBackend, IrohBackend, iroh::EndpointAddr) {
        // Bind like the transport's own tests: a minimal, relay-free endpoint on
        // loopback advertising both Misaka ALPNs, so enrollment can be dialed by
        // ALPN over a direct path with no network access.
        let server_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(misaka_network::misaka_alpns())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let client_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(misaka_network::misaka_alpns())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let server = IrohBackend::new(server_endpoint, misaka_network::IROH_ALPN);
        let client = IrohBackend::new(client_endpoint, misaka_network::IROH_ALPN);
        let addr = iroh::EndpointAddr::new(server.endpoint().id())
            .with_ip_addr(server.endpoint().bound_sockets()[0]);
        (server, client, addr)
    }

    /// A fresh temp directory backing the persistent membership serial store
    /// (unique per test so concurrent tests never share a high-water mark).
    fn serial_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("misaka-enroll-serial-{}", uuid::Uuid::new_v4()))
    }

    fn signed_locator(
        network_id: NetworkId,
        sister_key: &SisterKeyPair,
        endpoint_id: IrohEndpointId,
    ) -> PeerRecord {
        let binding = TransportBinding::sign(network_id, 1, endpoint_id, 1, sister_key);
        // The endpoint string is opaque to PeerRecord verification (it binds the
        // signed identity + sequence); tests dial the real address separately.
        PeerRecord::issue(
            network_id,
            1,
            "iroh://authority".into(),
            binding,
            now_secs(),
            sister_key,
        )
    }

    #[tokio::test]
    async fn full_enrollment_handshake_issues_verifiable_membership() {
        let (network_id, authority, authority_key, server_key) = authority_fixture();
        let (server_backend, client_backend, addr) = bind_pair().await;
        let endpoint_id = IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes());
        let locator = signed_locator(network_id, &server_key, endpoint_id);
        let invite = EnrollmentInvite::issue(
            &authority,
            &authority_key,
            now_secs(),
            now_secs() + 3600,
            random(),
            locator.clone(),
        );
        let server = EnrollmentServer::new(
            &serial_dir(),
            network_id,
            authority,
            authority_key.clone(),
            1,
            endpoint_id,
            locator,
            vec![],
        )
        .unwrap();

        // Clone the backend into the serve task so the original endpoint stays
        // alive in this scope until the exchange completes (a running Authority
        // endpoint likewise outlives any single redemption).
        let accept_backend = server_backend.clone();
        let serve = tokio::spawn(async move {
            let session = accept_backend
                .accept_session_for_network(network_id)
                .await
                .unwrap();
            assert_eq!(session.negotiated_alpn(), ENROLLMENT_ALPN);
            server.serve_session(session).await;
        });

        let joiner_key = SisterKeyPair::generate();
        let joiner_id = SisterId(77);
        let session = client_backend
            .connect_session_with_alpn(NetworkEndpoint::Iroh(addr), network_id, ENROLLMENT_ALPN)
            .await
            .unwrap();
        let response = redeem(session, invite.clone(), joiner_id.clone(), &joiner_key)
            .await
            .expect("enrollment succeeds");

        let bundle = response
            .validate_received(
                &invite,
                network_id,
                &joiner_id,
                joiner_key.public_key(),
                now_secs(),
            )
            .expect("response validates");
        assert_eq!(bundle.membership.sister_id, joiner_id);
        assert_eq!(bundle.membership.sister_public_key, joiner_key.public_key());
        assert!(bundle.membership.verify(&authority));
        assert!(bundle
            .bootstrap_records
            .iter()
            .any(|r| r.sister_id.as_u64() == 1));
        // The Authority private key never appears in the wire response.
        let encoded = bincode::serialize(&response).unwrap();
        assert!(!encoded.windows(32).any(|w| w == authority_key.to_bytes()));

        serve.await.unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn one_invite_redeems_two_distinct_sisters() {
        let (network_id, authority, authority_key, server_key) = authority_fixture();
        let (server_backend, client_backend, addr) = bind_pair().await;
        let endpoint_id = IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes());
        let locator = signed_locator(network_id, &server_key, endpoint_id);
        let invite = EnrollmentInvite::issue(
            &authority,
            &authority_key,
            now_secs(),
            now_secs() + 3600,
            random(),
            locator.clone(),
        );
        let server = EnrollmentServer::new(
            &serial_dir(),
            network_id,
            authority,
            authority_key.clone(),
            1,
            endpoint_id,
            locator,
            vec![],
        )
        .unwrap();
        let accept_backend = server_backend.clone();
        let serve = tokio::spawn(async move {
            for _ in 0..2 {
                let session = accept_backend
                    .accept_session_for_network(network_id)
                    .await
                    .unwrap();
                server.serve_session(session).await;
            }
        });

        let mut seen = std::collections::HashSet::new();
        for id in [100u64, 200u64] {
            let joiner_key = SisterKeyPair::generate();
            let session = client_backend
                .connect_session_with_alpn(
                    NetworkEndpoint::Iroh(addr.clone()),
                    network_id,
                    ENROLLMENT_ALPN,
                )
                .await
                .unwrap();
            let response = redeem(session, invite.clone(), SisterId(id), &joiner_key)
                .await
                .expect("redeem");
            let bundle = response
                .validate_received(
                    &invite,
                    network_id,
                    &SisterId(id),
                    joiner_key.public_key(),
                    now_secs(),
                )
                .expect("validate");
            seen.insert(bundle.membership.serial);
        }
        // Two distinct keys yield two distinct, individually revocable serials.
        assert_eq!(seen.len(), 2);
        serve.await.unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn expired_invite_is_rejected_before_membership() {
        let (network_id, authority, authority_key, server_key) = authority_fixture();
        let (server_backend, client_backend, addr) = bind_pair().await;
        let endpoint_id = IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes());
        let locator = signed_locator(network_id, &server_key, endpoint_id);
        let invite = EnrollmentInvite::issue(
            &authority,
            &authority_key,
            now_secs().saturating_sub(120),
            now_secs().saturating_sub(60),
            random(),
            locator.clone(),
        );
        let server = EnrollmentServer::new(
            &serial_dir(),
            network_id,
            authority,
            authority_key,
            1,
            endpoint_id,
            locator,
            vec![],
        )
        .unwrap();
        let accept_backend = server_backend.clone();
        let serve = tokio::spawn(async move {
            let session = accept_backend
                .accept_session_for_network(network_id)
                .await
                .unwrap();
            server.serve_session(session).await;
        });

        let joiner_key = SisterKeyPair::generate();
        let session = client_backend
            .connect_session_with_alpn(NetworkEndpoint::Iroh(addr), network_id, ENROLLMENT_ALPN)
            .await
            .unwrap();
        let error = redeem(session, invite, SisterId(1), &joiner_key)
            .await
            .expect_err("expired invite fails");
        assert!(matches!(
            error,
            EnrollmentFailure::Rejected(EnrollmentRejectionKind::Expired)
        ));
        serve.await.unwrap();
        client_backend.close().await;
    }

    #[tokio::test]
    async fn wrong_network_invite_is_rejected_by_the_authority() {
        let (network_id, authority, authority_key, server_key) = authority_fixture();
        let (server_backend, client_backend, addr) = bind_pair().await;
        let endpoint_id = IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes());
        // An invite minted for a completely different Network/Authority.
        let (foreign_network, foreign_authority, foreign_key, _foreign_sister) =
            authority_fixture();
        let foreign_locator = signed_locator(foreign_network, &server_key, endpoint_id);
        let foreign_invite = EnrollmentInvite::issue(
            &foreign_authority,
            &foreign_key,
            now_secs(),
            now_secs() + 3600,
            random(),
            foreign_locator,
        );
        let locator = signed_locator(network_id, &server_key, endpoint_id);
        let server = EnrollmentServer::new(
            &serial_dir(),
            network_id,
            authority,
            authority_key,
            1,
            endpoint_id,
            locator,
            vec![],
        )
        .unwrap();
        let accept_backend = server_backend.clone();
        let serve = tokio::spawn(async move {
            let session = accept_backend
                .accept_session_for_network(foreign_network)
                .await;
            if let Ok(session) = session {
                server.serve_session(session).await;
            }
        });

        let joiner_key = SisterKeyPair::generate();
        let session = client_backend
            .connect_session_with_alpn(
                NetworkEndpoint::Iroh(addr),
                foreign_network,
                ENROLLMENT_ALPN,
            )
            .await
            .unwrap();
        let error = redeem(session, foreign_invite, SisterId(1), &joiner_key)
            .await
            .expect_err("foreign invite fails");
        assert!(matches!(
            error,
            EnrollmentFailure::Rejected(EnrollmentRejectionKind::WrongNetwork)
        ));
        serve.await.unwrap();
        client_backend.close().await;
    }

    // E06 (black-box equivalent): a redemption whose key-possession proof was
    // not made by the key it presents must be refused, and no membership issued.
    #[tokio::test]
    async fn invalid_key_possession_proof_is_rejected() {
        use misaka_core::{EnrollmentOutcome, EnrollmentRejection};
        let (network_id, authority, authority_key, server_key) = authority_fixture();
        let (server_backend, client_backend, addr) = bind_pair().await;
        let endpoint_id = IrohEndpointId::from_bytes(*server_backend.endpoint().id().as_bytes());
        let locator = signed_locator(network_id, &server_key, endpoint_id);
        let invite = EnrollmentInvite::issue(
            &authority,
            &authority_key,
            now_secs(),
            now_secs() + 3600,
            random(),
            locator.clone(),
        );
        let server = EnrollmentServer::new(
            &serial_dir(),
            network_id,
            authority,
            authority_key,
            1,
            endpoint_id,
            locator,
            vec![],
        )
        .unwrap();
        let accept = server_backend.clone();
        let serve = tokio::spawn(async move {
            let session = accept.accept_session_for_network(network_id).await.unwrap();
            server.serve_session(session).await;
        });

        // Drive the exchange manually so the proof can be deliberately wrong.
        let session = client_backend
            .connect_session_with_alpn(NetworkEndpoint::Iroh(addr), network_id, ENROLLMENT_ALPN)
            .await
            .unwrap();
        let mut stream = session.open_stream().await.unwrap();
        let joiner_key = SisterKeyPair::generate();
        let request = EnrollmentRequest::new(
            invite.clone(),
            SisterId(5),
            joiner_key.public_key(),
            random(),
        );
        write_frame(&mut stream, &request).await.unwrap();
        let reply: ServerReply = read_frame(&mut stream).await.unwrap();
        let challenge = match reply {
            ServerReply::Challenge(challenge) => challenge,
            other => panic!("expected a challenge, got a rejection: {other:?}"),
        };
        // Sign the challenge with a different key than the one presented.
        let attacker_key = SisterKeyPair::generate();
        let bad_proof = EnrollmentProof {
            signature: attacker_key.sign(&challenge.signing_bytes()),
        };
        write_frame(&mut stream, &bad_proof).await.unwrap();
        let response: EnrollmentResponse = read_frame(&mut stream).await.unwrap();
        assert!(matches!(
            response.outcome,
            EnrollmentOutcome::Rejected {
                reason: EnrollmentRejection::InvalidProof
            }
        ));

        serve.await.unwrap();
        client_backend.close().await;
        server_backend.close().await;
    }
}
