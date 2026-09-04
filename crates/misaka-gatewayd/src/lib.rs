//! Native reference implementation of the Misaka Gateway v0 discovery service.
//!
//! Mirrors the Cloudflare Workers reference deployment exactly: same three
//! endpoints, same `misaka_core::gateway` wire contract and stateless
//! [`verify_request`] logic. This host keeps the directory and the nonce-replay
//! set in process memory (the Workers host uses a Durable Object).
//!
//! Trust model invariants enforced here:
//! 1. Only authority-valid, self-verified [`PeerRecord`]s are ever stored.
//! 2. A record's identity must match the presenting membership — a member cannot
//!    publish a locator for a different Sister.
//! 3. A nonce is accepted once within its window — replays are refused.
//!
//! The Gateway never holds the Network Authority private key.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use misaka_core::{
    announce_body_bytes, peers_body_bytes, record_matches_membership, verify_request,
    GatewayAnnounceRequest, GatewayAuth, GatewayAuthError, GatewayInfo, GatewayPeersRequest,
    GatewayPeersResponse, MembershipCertificate, NetworkAuthority, NetworkId, PeerRecord,
    SisterPublicKey,
};
use rand::RngCore;
use thiserror::Error;
use tokio::net::TcpListener;

/// Wall-clock seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Tunables for one Gateway deployment. One deployment serves one Network.
#[derive(Clone)]
pub struct GatewayConfig {
    pub authority: NetworkAuthority,
    /// How long an announced record stays queryable before it must be renewed.
    pub record_ttl_secs: u64,
    /// Accepted skew between an auth timestamp and the current time.
    pub auth_window_secs: u64,
    /// How long a seen nonce blocks a replay. Should cover `auth_window` twice.
    pub nonce_ttl_secs: u64,
    /// Clock injection so tests are deterministic.
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl GatewayConfig {
    pub fn new(authority: NetworkAuthority) -> Self {
        Self {
            authority,
            record_ttl_secs: 600,
            auth_window_secs: 300,
            nonce_ttl_secs: 900,
            now: Arc::new(unix_now),
        }
    }

    /// Override the clock (used by tests).
    pub fn with_now(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }
}

#[derive(Clone)]
struct DirectoryEntry {
    record: PeerRecord,
    membership_serial: u64,
    expires_at: u64,
}

/// Shared, mutable Gateway state.
pub struct Gateway {
    config: GatewayConfig,
    members: Mutex<HashMap<u64, DirectoryEntry>>,
    nonces: Mutex<HashMap<[u8; 16], u64>>,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            members: Mutex::new(HashMap::new()),
            nonces: Mutex::new(HashMap::new()),
        })
    }

    fn now(&self) -> u64 {
        (self.config.now)()
    }

    /// Stateless verification plus the stateful nonce-replay guard. Consumes the
    /// nonce only after every cheap check passes, so junk cannot bloat the set.
    fn authenticate(
        &self,
        auth: &GatewayAuth,
        body: &[u8],
        membership: &MembershipCertificate,
    ) -> Result<SisterPublicKey, GatewayError> {
        let now = self.now();
        let key = verify_request(
            auth,
            body,
            membership,
            &self.config.authority,
            now,
            self.config.auth_window_secs,
        )?;
        let mut nonces = self.nonces.lock().unwrap();
        nonces.retain(|_, expiry| *expiry > now);
        if nonces
            .insert(auth.nonce, now + self.config.nonce_ttl_secs)
            .is_some()
        {
            return Err(GatewayError::Replayed);
        }
        Ok(key)
    }

    /// Insert or refresh a directory entry, refusing to downgrade the sequence.
    fn upsert(&self, record: &PeerRecord, membership: &MembershipCertificate) {
        let now = self.now();
        let mut members = self.members.lock().unwrap();
        let sister_id = record.sister_id.as_u64();
        match members.get_mut(&sister_id) {
            Some(entry) if entry.record.sequence >= record.sequence && entry.expires_at > now => {}
            _ => {
                members.insert(
                    sister_id,
                    DirectoryEntry {
                        record: record.clone(),
                        membership_serial: membership.serial,
                        expires_at: now + self.config.record_ttl_secs,
                    },
                );
            }
        }
    }

    /// Snapshot the live directory (used by `/v1/peers` and by introspection).
    pub fn live_records(&self) -> Vec<PeerRecord> {
        let now = self.now();
        let members = self.members.lock().unwrap();
        members
            .values()
            .filter(|entry| entry.expires_at > now)
            .map(|entry| entry.record.clone())
            .collect()
    }

    /// The stored record and membership serial for one live Sister, if present.
    /// Exposed for diagnostics and to let a host reason about renewal.
    pub fn entry_for(&self, sister_id: u64) -> Option<(PeerRecord, u64)> {
        let now = self.now();
        let members = self.members.lock().unwrap();
        members
            .get(&sister_id)
            .filter(|entry| entry.expires_at > now)
            .map(|entry| (entry.record.clone(), entry.membership_serial))
    }
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("request authentication failed: {0}")]
    Auth(#[from] GatewayAuthError),
    #[error("request has already been processed (replayed nonce)")]
    Replayed,
    #[error("invalid request body")]
    InvalidBody,
    #[error("announced record does not match the presenting membership")]
    IdentityMismatch,
    #[error("announced record failed signature verification")]
    InvalidRecord,
    #[error("internal error")]
    Internal,
}

impl GatewayError {
    fn status(&self) -> StatusCode {
        match self {
            GatewayError::Auth(GatewayAuthError::NetworkMismatch)
            | GatewayError::Auth(GatewayAuthError::IdentityMismatch)
            | GatewayError::Auth(GatewayAuthError::BadSignature) => StatusCode::FORBIDDEN,
            GatewayError::Auth(_) | GatewayError::Replayed => StatusCode::UNAUTHORIZED,
            GatewayError::InvalidBody | GatewayError::InvalidRecord => StatusCode::BAD_REQUEST,
            GatewayError::IdentityMismatch => StatusCode::FORBIDDEN,
            GatewayError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        (self.status(), self.to_string()).into_response()
    }
}

/// Build the Gateway's HTTP router over shared state.
pub fn router(gateway: Arc<Gateway>) -> Router {
    Router::new()
        .route("/.well-known/misaka", get(info))
        .route("/v1/announce", post(announce))
        .route("/v1/peers", post(peers))
        .with_state(gateway)
}

async fn info(State(gateway): State<Arc<Gateway>>) -> Json<GatewayInfo> {
    Json(GatewayInfo::from_authority(&gateway.config.authority))
}

async fn announce(
    State(gateway): State<Arc<Gateway>>,
    body: Bytes,
) -> Result<StatusCode, GatewayError> {
    let request: GatewayAnnounceRequest =
        serde_json::from_slice(&body).map_err(|_| GatewayError::InvalidBody)?;
    let payload = announce_body_bytes(&request.membership, &request.record);
    gateway.authenticate(&request.auth, &payload, &request.membership)?;
    if !record_matches_membership(&request.record, &request.membership) {
        return Err(GatewayError::IdentityMismatch);
    }
    if !request.record.verify() {
        return Err(GatewayError::InvalidRecord);
    }
    gateway.upsert(&request.record, &request.membership);
    Ok(StatusCode::NO_CONTENT)
}

async fn peers(
    State(gateway): State<Arc<Gateway>>,
    body: Bytes,
) -> Result<Json<GatewayPeersResponse>, GatewayError> {
    let request: GatewayPeersRequest =
        serde_json::from_slice(&body).map_err(|_| GatewayError::InvalidBody)?;
    gateway.authenticate(&request.auth, &peers_body_bytes(), &request.membership)?;
    Ok(Json(GatewayPeersResponse {
        records: gateway.live_records(),
    }))
}

/// A bound, runnable Gateway server.
pub struct GatewayServer {
    listener: TcpListener,
    app: Router,
    bound: SocketAddr,
    gateway: Arc<Gateway>,
}

impl GatewayServer {
    pub async fn bind(config: GatewayConfig, address: SocketAddr) -> std::io::Result<Self> {
        let gateway = Gateway::new(config);
        let listener = TcpListener::bind(address).await?;
        let bound = listener.local_addr()?;
        Ok(Self {
            app: router(gateway.clone()),
            listener,
            bound,
            gateway,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.bound
    }

    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }

    pub async fn run(self) -> std::io::Result<()> {
        tracing::info!(event = "gateway_started", address = %self.bound, "Misaka Gateway listening");
        axum::serve(self.listener, self.app).await
    }

    pub async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let _ = axum::serve(self.listener, self.app)
            .with_graceful_shutdown(shutdown)
            .await;
    }
}

/// Generate a fresh 16-byte request nonce.
pub fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Reconstruct a [`NetworkAuthority`] from a Network id plus a hex-encoded
/// Authority public key (both are public, non-secret configuration).
pub fn authority_from_hex(
    network_id: NetworkId,
    authority_public_key_hex: &str,
) -> Result<NetworkAuthority, String> {
    let bytes = decode_hex(authority_public_key_hex)
        .ok_or_else(|| "authority public key must be 64 hex chars".to_string())?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "authority public key must be 32 bytes".to_string())?;
    Ok(NetworkAuthority {
        network_id,
        authority_public_key: misaka_core::AuthorityPublicKey::from_bytes(key),
    })
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use misaka_core::{
        MembershipCertificate, NetworkAuthority, NetworkId, PeerRecord, SisterKeyPair,
        TransportBinding,
    };
    use tower::ServiceExt;

    struct Fixture {
        authority: NetworkAuthority,
        key: SisterKeyPair,
        membership: MembershipCertificate,
        record: PeerRecord,
    }

    fn fixture() -> Fixture {
        let network_id = NetworkId::from_bytes([1u8; 16]);
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let key = SisterKeyPair::from_bytes([9u8; 32]);
        let membership = MembershipCertificate::issue(
            &authority,
            &authority_key,
            key.public_key(),
            42,
            100,
            Some(1_000),
            7,
        );
        let binding = TransportBinding::sign(
            network_id,
            42,
            misaka_core::IrohEndpointId::from_bytes([3u8; 32]),
            1,
            &key,
        );
        let record = PeerRecord::issue(network_id, 42, "iroh://peer".into(), binding, 500, &key);
        Fixture {
            authority,
            key,
            membership,
            record,
        }
    }

    fn gateway(clock: u64) -> (Arc<Gateway>, Fixture) {
        let f = fixture();
        let config = GatewayConfig::new(f.authority).with_now(move || clock);
        (Gateway::new(config), f)
    }

    async fn post_json(app: Router, path: &str, value: &impl serde::Serialize) -> StatusCode {
        let body = Body::from(serde_json::to_vec(value).unwrap());
        let response = app
            .oneshot(Request::post(path).body(body).unwrap())
            .await
            .unwrap();
        response.status()
    }

    fn announce_req(f: &Fixture) -> GatewayAnnounceRequest {
        let auth = GatewayAuth::sign_announce(
            f.authority.network_id,
            42,
            500,
            [1u8; 16],
            &f.membership,
            &f.record,
            &f.key,
        );
        GatewayAnnounceRequest {
            auth,
            membership: f.membership.clone(),
            record: f.record.clone(),
        }
    }

    #[tokio::test]
    async fn valid_announce_accepted_then_peers_returns_it() {
        let (gw, f) = gateway(500);
        let status = post_json(router(gw.clone()), "/v1/announce", &announce_req(&f)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let peers_req = GatewayPeersRequest {
            auth: GatewayAuth::sign_peers(f.authority.network_id, 42, 500, [5u8; 16], &f.key),
            membership: f.membership.clone(),
        };
        let response = router(gw.clone())
            .oneshot(
                Request::post("/v1/peers")
                    .body(Body::from(serde_json::to_vec(&peers_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: GatewayPeersResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.records[0].sister_id.as_u64(), 42);

        let (record, serial) = gw.entry_for(42).expect("entry present");
        assert_eq!(record.sister_id.as_u64(), 42);
        assert_eq!(serial, f.membership.serial);
    }

    #[tokio::test]
    async fn replayed_nonce_is_rejected() {
        let (gw, f) = gateway(500);
        let app = router(gw);
        assert_eq!(
            post_json(app.clone(), "/v1/announce", &announce_req(&f)).await,
            StatusCode::NO_CONTENT
        );
        // Same nonce again -> replay refused.
        assert_eq!(
            post_json(app, "/v1/announce", &announce_req(&f)).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn member_cannot_publish_a_record_for_another_sister() {
        // Sister 42 authenticates with its own valid membership, but announces a
        // *correctly signed* locator belonging to Sister 99. The record digest
        // matches (auth signs over it), so this is caught by the identity-agrees
        // -with-membership check, not the signature check.
        let (gw, f) = gateway(500);
        let other_key = SisterKeyPair::from_bytes([8u8; 32]);
        let binding = TransportBinding::sign(
            f.authority.network_id,
            99,
            misaka_core::IrohEndpointId::from_bytes([3u8; 32]),
            1,
            &other_key,
        );
        let foreign = PeerRecord::issue(
            f.authority.network_id,
            99,
            "iroh://other".into(),
            binding,
            500,
            &other_key,
        );
        let auth = GatewayAuth::sign_announce(
            f.authority.network_id,
            42,
            500,
            [1u8; 16],
            &f.membership,
            &foreign,
            &f.key,
        );
        let request = GatewayAnnounceRequest {
            auth,
            membership: f.membership.clone(),
            record: foreign,
        };
        assert_eq!(
            post_json(router(gw), "/v1/announce", &request).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn tampered_record_breaks_the_body_digest() {
        // Defense in depth: mutating an announced record after signing is caught
        // by the body-digest binding before any directory write.
        let (gw, f) = gateway(500);
        let mut req = announce_req(&f);
        req.record.sister_id = misaka_core::SisterId(99);
        assert_eq!(
            post_json(router(gw), "/v1/announce", &req).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn expired_membership_is_rejected() {
        let (gw, f) = gateway(5_000); // clock far past membership expiry and window
        let status = post_json(router(gw), "/v1/announce", &announce_req(&f)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn info_reports_network_id() {
        let (gw, f) = gateway(500);
        let response = router(gw)
            .oneshot(
                Request::get("/.well-known/misaka")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let info: GatewayInfo = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(info.network_id, f.authority.network_id);
    }

    #[test]
    fn authority_reconstructs_from_hex_and_matches_fingerprint() {
        let f = fixture();
        let hex = f.authority.authority_public_key.to_string();
        let rebuilt = authority_from_hex(f.authority.network_id, &hex).unwrap();
        assert_eq!(rebuilt, f.authority);
    }
}
