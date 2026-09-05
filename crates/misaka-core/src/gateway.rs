//! Gateway v0 wire contract.
//!
//! The Gateway is a discovery service only: it stores signed [`PeerRecord`]s
//! and hands them back to authenticated members so two Sisters that share a
//! Network can bootstrap the existing authenticated Iroh control plane using
//! nothing more than a configured Gateway domain.
//!
//! This module holds the transport-agnostic request/response DTOs and the
//! **stateless** request verification shared by every Gateway host (the
//! Cloudflare Workers reference deployment and the native reference server).
//! Stateful concerns — the nonce-replay set and the directory's expiry clock —
//! belong to each host, not here, keeping `misaka-core` free of infrastructure
//! dependencies exactly as the crate's contract requires.
//!
//! It intentionally does NOT: enroll members, issue [`MembershipCertificate`]s,
//! hold the Network Authority private key, relay traffic, or forward data.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    MembershipCertificate, NetworkAuthority, NetworkId, PeerRecord, SisterId, SisterKeyPair,
    SisterPublicKey, SisterSignature,
};

/// Protocol version advertised by a Gateway. Bumped only on a breaking change
/// to the v0 request/response shapes.
pub const GATEWAY_PROTOCOL_VERSION: u16 = 1;

/// Public self-description served at `GET /.well-known/misaka`.
///
/// Lets a Sister confirm it reached the Gateway of the Network it expects
/// before it announces anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    /// Hex fingerprint of the Network Authority public key. Informational: the
    /// Sister's primary check is `network_id`. Never private key material.
    pub authority_fingerprint: String,
}

impl GatewayInfo {
    /// Build the info payload from a Network Authority (public half only).
    pub fn from_authority(authority: &NetworkAuthority) -> Self {
        Self {
            protocol_version: GATEWAY_PROTOCOL_VERSION,
            network_id: authority.network_id,
            // `AuthorityPublicKey`'s `Display` is the lowercase hex encoding.
            authority_fingerprint: authority.authority_public_key.to_string(),
        }
    }
}

/// A Sister-signed envelope authenticating one Gateway request.
///
/// Signed with the Sister key the membership certificate vouches for. The
/// signature covers a canonical bincode projection of every field EXCEPT the
/// signature itself, matching the `signing_bytes()` convention used across all
/// signed Misaka contracts. `body_digest` binds the auth to the exact HTTP body
/// so the auth cannot be replayed against a different request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayAuth {
    pub network_id: NetworkId,
    pub sister_id: SisterId,
    /// Seconds since the Unix epoch at signing time; validated against a
    /// caller-chosen freshness window.
    pub timestamp: u64,
    /// Per-request random value; the host tracks seen nonces to stop replay.
    pub nonce: [u8; 16],
    /// SHA-256 of the exact request body bytes.
    pub body_digest: [u8; 32],
    pub signature: SisterSignature,
}

#[derive(Serialize)]
struct GatewayAuthUnsigned<'a> {
    network_id: NetworkId,
    sister_id: &'a SisterId,
    timestamp: u64,
    nonce: [u8; 16],
    body_digest: [u8; 32],
}

impl GatewayAuth {
    /// Canonical bytes covered by [`GatewayAuth::signature`].
    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&GatewayAuthUnsigned {
            network_id: self.network_id,
            sister_id: &self.sister_id,
            timestamp: self.timestamp,
            nonce: self.nonce,
            body_digest: self.body_digest,
        })
        .expect("gateway auth fields are serializable")
    }

    /// Sign a new request auth over `body`. The caller supplies `timestamp` and
    /// a fresh `nonce`; the body digest is computed here so client and verifier
    /// agree on exactly what is hashed.
    pub fn sign(
        network_id: NetworkId,
        sister_id: u64,
        timestamp: u64,
        nonce: [u8; 16],
        body: &[u8],
        key: &SisterKeyPair,
    ) -> Self {
        let sister_id = SisterId(sister_id);
        let body_digest = crate::transfer_content_digest(body);
        let mut auth = Self {
            network_id,
            sister_id,
            timestamp,
            nonce,
            body_digest,
            signature: SisterSignature::from_bytes([0; 64]),
        };
        auth.signature = key.sign(&auth.signing_bytes());
        auth
    }

    /// Verify only the self-contained signature against `public_key` (no
    /// network, membership, freshness, or replay checks). Used internally by
    /// [`verify_request`] and directly when a host has already established the
    /// requester's key.
    pub fn verify_signature(&self, public_key: &SisterPublicKey) -> bool {
        public_key.verify(&self.signing_bytes(), &self.signature)
    }

    /// Convenience: build a `/v1/announce` auth over the canonical announce
    /// payload. Guarantees the client and server hash identical bytes.
    pub fn sign_announce(
        network_id: NetworkId,
        sister_id: u64,
        timestamp: u64,
        nonce: [u8; 16],
        membership: &MembershipCertificate,
        record: &PeerRecord,
        key: &SisterKeyPair,
    ) -> Self {
        Self::sign(
            network_id,
            sister_id,
            timestamp,
            nonce,
            &announce_body_bytes(membership, record),
            key,
        )
    }

    /// Convenience: build a `/v1/peers` auth over the peers domain tag.
    pub fn sign_peers(
        network_id: NetworkId,
        sister_id: u64,
        timestamp: u64,
        nonce: [u8; 16],
        key: &SisterKeyPair,
    ) -> Self {
        Self::sign(
            network_id,
            sister_id,
            timestamp,
            nonce,
            &peers_body_bytes(),
            key,
        )
    }
}

/// Body of `POST /v1/announce`: prove membership, then publish a signed locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayAnnounceRequest {
    pub auth: GatewayAuth,
    pub membership: MembershipCertificate,
    pub record: PeerRecord,
}

/// Body of `POST /v1/peers`: member authentication plus the certificate the
/// auth is checked against. Peers queries are NOT public — presenting a valid
/// membership is what gates access to the Network's node directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayPeersRequest {
    pub auth: GatewayAuth,
    pub membership: MembershipCertificate,
}

/// Response to `POST /v1/peers`: the currently-valid signed locators.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GatewayPeersResponse {
    #[serde(default)]
    pub records: Vec<PeerRecord>,
}

/// Domain tag folded into the bytes a `/v1/peers` auth signs over, so a peers
/// auth can never be replayed as an announce auth (and vice-versa).
const PEERS_DOMAIN: &[u8] = b"misaka-gateway/peers/v1";

/// The exact bytes a `/v1/announce` request's [`GatewayAuth::body_digest`] is
/// taken over: a canonical encoding of everything the request carries other
/// than the auth itself. Kept out of `GatewayAuth` so signing never has to hash
/// a structure that contains its own signature.
pub fn announce_body_bytes(membership: &MembershipCertificate, record: &PeerRecord) -> Vec<u8> {
    #[derive(Serialize)]
    struct AnnouncePayload<'a> {
        membership: &'a MembershipCertificate,
        record: &'a PeerRecord,
    }
    bincode::serialize(&AnnouncePayload { membership, record })
        .expect("announce payload is serializable")
}

/// The exact bytes a `/v1/peers` request's [`GatewayAuth::body_digest`] is taken
/// over.
pub fn peers_body_bytes() -> Vec<u8> {
    PEERS_DOMAIN.to_vec()
}

/// Reasons a Gateway request can be rejected during stateless verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GatewayAuthError {
    #[error("auth is for a different Network")]
    NetworkMismatch,
    #[error("request body does not match the signed body digest")]
    BodyDigestMismatch,
    #[error("request timestamp is outside the allowed window")]
    StaleTimestamp,
    #[error("membership certificate is not valid for this Network Authority")]
    InvalidMembership,
    #[error("membership certificate is outside its validity window")]
    ExpiredMembership,
    #[error("auth Sister identity does not match the membership certificate")]
    IdentityMismatch,
    #[error("auth signature does not verify against the membership key")]
    BadSignature,
}

/// Stateless verification of one authenticated Gateway request.
///
/// Returns the verified [`SisterPublicKey`] on success. Does NOT touch a
/// nonce-replay set — callers must reject a repeated `auth.nonce` separately.
///
/// Checks, in order:
/// 1. `auth` and `membership` belong to `authority`'s Network;
/// 2. `auth.body_digest` matches SHA-256 of `body`;
/// 3. `auth.timestamp` is within `window` seconds of `now`;
/// 4. `membership` is authority-signed and live at `now`;
/// 5. `auth.sister_id` equals the membership's Sister;
/// 6. `auth.signature` verifies against the membership's Sister key.
pub fn verify_request(
    auth: &GatewayAuth,
    body: &[u8],
    membership: &MembershipCertificate,
    authority: &NetworkAuthority,
    now: u64,
    window: u64,
) -> Result<SisterPublicKey, GatewayAuthError> {
    if auth.network_id != authority.network_id || membership.network_id != authority.network_id {
        return Err(GatewayAuthError::NetworkMismatch);
    }
    if auth.body_digest != crate::transfer_content_digest(body) {
        return Err(GatewayAuthError::BodyDigestMismatch);
    }
    let delta = now
        .saturating_sub(auth.timestamp)
        .max(auth.timestamp.saturating_sub(now));
    if delta > window {
        return Err(GatewayAuthError::StaleTimestamp);
    }
    if !membership.verify(authority) {
        return Err(GatewayAuthError::InvalidMembership);
    }
    if !membership.is_valid_at(now) {
        return Err(GatewayAuthError::ExpiredMembership);
    }
    if auth.sister_id != membership.sister_id {
        return Err(GatewayAuthError::IdentityMismatch);
    }
    if !auth.verify_signature(&membership.sister_public_key) {
        return Err(GatewayAuthError::BadSignature);
    }
    Ok(membership.sister_public_key)
}

/// Whether a locator's identity agrees with a membership certificate. Used by
/// hosts on `/v1/announce` to stop a member publishing a record for a DIFFERENT
/// Sister than the one its certificate vouches for.
pub fn record_matches_membership(record: &PeerRecord, membership: &MembershipCertificate) -> bool {
    record.network_id == membership.network_id
        && record.sister_id == membership.sister_id
        && record.sister_public_key == membership.sister_public_key
}

// ---------------------------------------------------------------------------
// Shared directory timing constants. These are configuration values, NOT
// policy: the Cloudflare host enforces monotonic sequence, nonce replay, TTL,
// and GC declaratively through Durable Object SQLite (one atomic statement
// each) rather than through a reusable Rust state machine. The native server is
// a self-host/test stand-in with its own equivalent storage.
// ---------------------------------------------------------------------------

/// How long an accepted record stays queryable before it must be renewed.
pub const DEFAULT_RECORD_TTL_SECS: u64 = 600;
/// Accepted skew between a request auth timestamp and the current time.
pub const DEFAULT_AUTH_WINDOW_SECS: u64 = 300;
/// How long a spent nonce keeps blocking replays (covers the window on both
/// sides of a skewed clock).
pub const DEFAULT_NONCE_TTL_SECS: u64 = 900;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityKeyPair, IrohEndpointId, TransportBinding};

    fn fixture() -> (
        NetworkAuthority,
        AuthorityKeyPair,
        SisterKeyPair,
        MembershipCertificate,
        PeerRecord,
    ) {
        let network_id = NetworkId::from_bytes([1u8; 16]);
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyPair::from_bytes([9u8; 32]);
        let membership = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            42,
            100,
            Some(1_000),
            7,
        );
        let binding = TransportBinding::sign(
            network_id,
            42,
            IrohEndpointId::from_bytes([3u8; 32]),
            1,
            &sister_key,
        );
        let record = PeerRecord::issue(
            network_id,
            42,
            "iroh://peer".into(),
            binding,
            500,
            &sister_key,
        );
        (authority, authority_key, sister_key, membership, record)
    }

    #[test]
    fn valid_request_verifies_and_yields_key() {
        let (authority, _, sister_key, membership, _) = fixture();
        let body = b"some-body".to_vec();
        let auth = GatewayAuth::sign(authority.network_id, 42, 500, [7u8; 16], &body, &sister_key);
        let key = verify_request(&auth, &body, &membership, &authority, 500, 60).expect("valid");
        assert_eq!(key, membership.sister_public_key);
    }

    #[test]
    fn tampered_body_is_rejected() {
        let (authority, _, sister_key, membership, _) = fixture();
        let auth = GatewayAuth::sign(authority.network_id, 42, 500, [7u8; 16], b"a", &sister_key);
        let error = verify_request(&auth, b"b", &membership, &authority, 500, 60).unwrap_err();
        assert_eq!(error, GatewayAuthError::BodyDigestMismatch);
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let (authority, _, sister_key, membership, _) = fixture();
        let body = b"x".to_vec();
        let auth = GatewayAuth::sign(authority.network_id, 42, 100, [7u8; 16], &body, &sister_key);
        let error = verify_request(&auth, &body, &membership, &authority, 1_000, 60).unwrap_err();
        assert_eq!(error, GatewayAuthError::StaleTimestamp);
    }

    #[test]
    fn expired_membership_is_rejected() {
        let network_id = NetworkId::from_bytes([1u8; 16]);
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let sister_key = SisterKeyPair::from_bytes([9u8; 32]);
        let expired = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            42,
            1,
            Some(2),
            7,
        );
        let body = b"x".to_vec();
        let auth = GatewayAuth::sign(network_id, 42, 10, [7u8; 16], &body, &sister_key);
        // Timestamp is fresh at `now = 10`, but the certificate lapsed at 2.
        let error = verify_request(&auth, &body, &expired, &authority, 10, 60).unwrap_err();
        assert_eq!(error, GatewayAuthError::ExpiredMembership);
    }

    #[test]
    fn wrong_sister_identity_is_rejected() {
        let (authority, _, sister_key, membership, _) = fixture();
        let body = b"x".to_vec();
        // Sign as Sister 99 but present a certificate for Sister 42.
        let auth = GatewayAuth::sign(authority.network_id, 99, 500, [7u8; 16], &body, &sister_key);
        let error = verify_request(&auth, &body, &membership, &authority, 500, 60).unwrap_err();
        assert_eq!(error, GatewayAuthError::IdentityMismatch);
    }

    #[test]
    fn record_must_match_membership_identity() {
        let (authority, _, sister_key, membership, record) = fixture();
        assert!(record_matches_membership(&record, &membership));
        let mut forged = record;
        forged.sister_id = SisterId(99);
        assert!(!record_matches_membership(&forged, &membership));
        let _ = (&authority, &sister_key);
    }

    #[test]
    fn info_carries_public_fingerprint_and_version() {
        let (authority, _, _, _, _) = fixture();
        let info = GatewayInfo::from_authority(&authority);
        assert_eq!(info.protocol_version, GATEWAY_PROTOCOL_VERSION);
        assert_eq!(info.network_id, authority.network_id);
        assert!(!info.authority_fingerprint.is_empty());
    }

    /// End-to-end contract check mirroring what a real host does: a client
    /// builds an announce request, it crosses a JSON boundary, and the server
    /// re-derives the signed payload bytes from the *parsed* body.
    #[test]
    fn announce_request_crosses_json_and_verifies() {
        let (authority, _, sister_key, membership, record) = fixture();
        let auth = GatewayAuth::sign_announce(
            authority.network_id,
            42,
            500,
            [1u8; 16],
            &membership,
            &record,
            &sister_key,
        );
        let request = GatewayAnnounceRequest {
            auth,
            membership: membership.clone(),
            record: record.clone(),
        };
        let wire = serde_json::to_vec(&request).unwrap();
        let parsed: GatewayAnnounceRequest = serde_json::from_slice(&wire).unwrap();

        let body = announce_body_bytes(&parsed.membership, &parsed.record);
        let key =
            verify_request(&parsed.auth, &body, &parsed.membership, &authority, 500, 60).unwrap();
        assert_eq!(key, sister_key.public_key());
        assert!(record_matches_membership(
            &parsed.record,
            &parsed.membership
        ));
    }

    #[test]
    fn peers_request_crosses_json_and_verifies() {
        let (authority, _, sister_key, membership, _) = fixture();
        let auth = GatewayAuth::sign_peers(authority.network_id, 42, 500, [2u8; 16], &sister_key);
        let request = GatewayPeersRequest {
            auth,
            membership: membership.clone(),
        };
        let wire = serde_json::to_vec(&request).unwrap();
        let parsed: GatewayPeersRequest = serde_json::from_slice(&wire).unwrap();

        let body = peers_body_bytes();
        verify_request(&parsed.auth, &body, &parsed.membership, &authority, 500, 60).unwrap();
    }

    /// An announce auth must not validate as a peers auth: the signed payload
    /// bytes differ, so the body-digest check rejects the cross-use.
    #[test]
    fn announce_and_peers_audiences_are_not_interchangeable() {
        let (authority, _, sister_key, membership, record) = fixture();
        let announce_auth = GatewayAuth::sign_announce(
            authority.network_id,
            42,
            500,
            [3u8; 16],
            &membership,
            &record,
            &sister_key,
        );
        let error = verify_request(
            &announce_auth,
            &peers_body_bytes(),
            &membership,
            &authority,
            500,
            60,
        )
        .unwrap_err();
        assert_eq!(error, GatewayAuthError::BodyDigestMismatch);
    }
}
