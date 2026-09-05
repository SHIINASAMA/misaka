//! Timed, recipient-independent Network enrollment contracts.
//!
//! This module is the *domain* half of the v1 enrollment flow. It defines a
//! signed, time-limited [`EnrollmentInvite`] that is not bound to any
//! recipient Sister, the one-shot [`EnrollmentRequest`] / [`EnrollmentChallenge`]
//! / [`EnrollmentResponse`] exchange that redeems such an invite, and the
//! key-possession proof that binds a freshly generated Sister key to the
//! membership the Authority issues.
//!
//! Nothing here touches the filesystem, sockets, or a networking stack: the
//! transport lives in `misaka-network`/`misaka-runtime`. This crate only owns
//! the authenticated data contracts, mirroring how [`crate::NetworkInvite`] and
//! [`crate::MembershipCertificate`] are defined in [`crate::identity`].
//!
//! Security model preserved from the pre-identified flow:
//! - the [`crate::AuthorityKeyPair`] never leaves the Authority and is never
//!   encoded into an invite or a wire message;
//! - the issued [`crate::MembershipCertificate`] is still Authority-signed and
//!   still bound to NetworkId + SisterId + SisterPublicKey;
//! - the NetworkId is a namespace, and possession of an unexpired Invite Code is
//!   the only capability the code grants.
//!
//! Possession of an unexpired Invite Code grants temporary permission to
//! request membership in that Network. An invite is reusable until it expires.

use crate::{
    AuthorityKeyPair, MembershipCertificate, NetworkAuthority, NetworkId, PeerRecord, SisterId,
    SisterKeyPair, SisterPublicKey, SisterSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version tag carried by every enrollment wire message and inside an
/// [`EnrollmentInvite`]. The Invite Code prefix (`misaka1_`) is the
/// user-visible mirror of this number.
pub const ENROLLMENT_VERSION: u16 = 1;
/// Version tag of the enrollment request/challenge/response exchange.
pub const ENROLLMENT_PROTOCOL_VERSION: u16 = 1;

/// Human-copyable prefix identifying a Misaka enrollment Invite Code and its
/// binary encoding generation. It is the only structure the normal user sees.
pub const INVITE_CODE_PREFIX: &str = "misaka1_";

/// Default invite lifetime (one hour) when the operator does not choose one.
pub const DEFAULT_INVITE_TTL_SECS: u64 = 60 * 60;
/// Hard maximum invite lifetime (seven days). A longer request is rejected.
pub const MAX_INVITE_TTL_SECS: u64 = 7 * 60 * 60 * 24;

/// Errors decoding an [`EnrollmentInvite`] from its user-facing Invite Code.
///
/// A successful decode is *not* authentication: the caller must still run
/// [`EnrollmentInvite::verify`] against the current clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteCodeError {
    /// The code does not begin with the [`INVITE_CODE_PREFIX`] generation tag.
    UnsupportedPrefix,
    /// The body is not well-formed URL-safe base64.
    InvalidEncoding,
    /// The decoded bytes are not a valid serialized invite.
    InvalidPayload,
}

impl std::fmt::Display for InviteCodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::UnsupportedPrefix => "invite code is missing the expected prefix",
            Self::InvalidEncoding => "invite code is not valid URL-safe base64",
            Self::InvalidPayload => "invite code does not decode to a signed invite",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for InviteCodeError {}

/// A time-limited, recipient-independent enrollment capability.
///
/// The invite is Authority-signed and self-validating: it names a Network,
/// identifies the Authority, sets an expiry, carries high-entropy nonce used to
/// bind the key-possession proof, and embeds a signed [`PeerRecord`] locator so
/// a joining Sister can reach the Authority's running enrollment handler without
/// the operator ever copying a raw `iroh://` address. It is deliberately *not*
/// bound to a recipient Sister: any Sister that can prove possession of the key
/// it presents may redeem it while it is unexpired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentInvite {
    pub version: u16,
    pub network_id: NetworkId,
    pub authority: NetworkAuthority,
    pub issued_at: u64,
    pub expires_at: u64,
    /// 32 bytes of Authority-generated entropy. Binds every proof to this
    /// exact invite so a proof can never be replayed onto a different invite.
    pub invite_nonce: [u8; 32],
    /// The signed Authority-Sister enrollment locator captured when the invite
    /// was minted. Reuses the ordinary [`PeerRecord`]/[`crate::TransportBinding`]
    /// trust model rather than inventing a second locator system.
    pub locator: PeerRecord,
    pub authority_signature: crate::AuthoritySignature,
}

#[derive(Serialize)]
struct EnrollmentInviteUnsigned<'a> {
    version: u16,
    network_id: NetworkId,
    authority: NetworkAuthority,
    issued_at: u64,
    expires_at: u64,
    invite_nonce: [u8; 32],
    locator: &'a PeerRecord,
}

impl EnrollmentInvite {
    /// Mint an invite. `locator` must be a current, self-verifying
    /// [`PeerRecord`] for the Authority Sister so a recipient can dial it.
    /// `expires_at` is expected to already reflect the requested lifetime;
    /// this constructor only binds and signs the fields.
    pub fn issue(
        authority: &NetworkAuthority,
        authority_key: &AuthorityKeyPair,
        issued_at: u64,
        expires_at: u64,
        invite_nonce: [u8; 32],
        locator: PeerRecord,
    ) -> Self {
        let mut invite = Self {
            version: ENROLLMENT_VERSION,
            network_id: authority.network_id,
            authority: *authority,
            issued_at,
            expires_at,
            invite_nonce,
            locator,
            authority_signature: crate::AuthoritySignature::from_bytes([0u8; 64]),
        };
        invite.authority_signature = authority_key.sign(&invite.signing_bytes());
        invite
    }

    /// Verify the Authority signature, self-consistency, the locator, and the
    /// validity window against `now`. Returns `false` on any failure.
    pub fn verify(&self, now: u64) -> bool {
        self.version == ENROLLMENT_VERSION
            && self.network_id == self.authority.network_id
            && self.issued_at <= self.expires_at
            && self.issued_at <= now
            && now <= self.expires_at
            && self
                .authority
                .authority_public_key
                .verify(&self.signing_bytes(), &self.authority_signature)
            && self.locator.network_id == self.network_id
            && self.locator.verify()
    }

    /// Whether the invite's time window has closed at `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Whether this invite names `network_id`. The join command supplies the
    /// NetworkId explicitly; this catches a code pasted for a different Network.
    pub fn matches_network(&self, network_id: NetworkId) -> bool {
        self.network_id == network_id
    }

    /// SHA-256 of the canonical Authority-signed bytes. Binds the
    /// key-possession proof to this exact invite without reserializing the
    /// whole structure on the Authority side.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.signing_bytes()).into()
    }

    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&EnrollmentInviteUnsigned {
            version: self.version,
            network_id: self.network_id,
            authority: self.authority,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            invite_nonce: self.invite_nonce,
            locator: &self.locator,
        })
        .expect("enrollment invite fields are serializable")
    }

    /// Encode as a single copy/paste-safe Invite Code string. The signature is
    /// retained inside the payload, so the code is self-validating once decoded
    /// and verified; no companion `invite.json` is required.
    pub fn encode_code(&self) -> Result<String, InviteCodeError> {
        let payload = bincode::serialize(self).map_err(|_| InviteCodeError::InvalidPayload)?;
        Ok(format!(
            "{INVITE_CODE_PREFIX}{}",
            base64url_encode(&payload)
        ))
    }

    /// Decode an Invite Code. Performs no authentication; the result must still
    /// pass [`EnrollmentInvite::verify`] and the join-side checks.
    pub fn decode_code(code: &str) -> Result<Self, InviteCodeError> {
        let body = code
            .trim()
            .strip_prefix(INVITE_CODE_PREFIX)
            .ok_or(InviteCodeError::UnsupportedPrefix)?;
        let payload = base64url_decode(body).ok_or(InviteCodeError::InvalidEncoding)?;
        bincode::deserialize(&payload).map_err(|_| InviteCodeError::InvalidPayload)
    }
}

/// The single enrollment operation: redeem an invite for a membership.
///
/// The joining Sister sends its freshly generated identity and a nonce; the
/// Authority replies with a [`EnrollmentChallenge`] the Sister must sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub protocol_version: u16,
    pub invite: EnrollmentInvite,
    pub sister_id: SisterId,
    pub sister_public_key: SisterPublicKey,
    /// Recipient random echoed into the challenge so the proof is bound to this
    /// exact request/response exchange.
    pub recipient_nonce: [u8; 32],
}

impl EnrollmentRequest {
    pub fn new(
        invite: EnrollmentInvite,
        sister_id: SisterId,
        sister_public_key: SisterPublicKey,
        recipient_nonce: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invite,
            sister_id,
            sister_public_key,
            recipient_nonce,
        }
    }
}

/// Authority challenge binding a key-possession proof to a specific Network,
/// invite, Sister identity, and exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    pub protocol_version: u16,
    pub network_id: NetworkId,
    /// [`EnrollmentInvite::digest`] of the invite being redeemed.
    pub invite_digest: [u8; 32],
    pub sister_id: SisterId,
    pub sister_public_key: SisterPublicKey,
    /// Authority random; guarantees a stale proof cannot be replayed.
    pub authority_nonce: [u8; 32],
    pub recipient_nonce: [u8; 32],
}

impl EnrollmentChallenge {
    pub fn new(
        network_id: NetworkId,
        invite_digest: [u8; 32],
        sister_id: SisterId,
        sister_public_key: SisterPublicKey,
        authority_nonce: [u8; 32],
        recipient_nonce: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            network_id,
            invite_digest,
            sister_id,
            sister_public_key,
            authority_nonce,
            recipient_nonce,
        }
    }

    /// Canonical bytes the recipient signs. Reuses the same Ed25519 signing
    /// convention as every other Misaka contract (bincode of an unsigned view).
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("enrollment challenge fields are serializable")
    }

    /// Produce a key-possession proof using the Sister private key.
    pub fn solve(&self, sister_key: &SisterKeyPair) -> EnrollmentProof {
        EnrollmentProof {
            signature: sister_key.sign(&self.signing_bytes()),
        }
    }

    /// Verify a proof against the challenge's claimed public key.
    pub fn verify(&self, proof: &EnrollmentProof) -> bool {
        self.sister_public_key
            .verify(&self.signing_bytes(), &proof.signature)
    }
}

/// Ed25519 signature over an [`EnrollmentChallenge`] made by the Sister key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentProof {
    pub signature: SisterSignature,
}

/// Authority reply to an enrollment redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub protocol_version: u16,
    pub outcome: EnrollmentOutcome,
}

impl EnrollmentResponse {
    pub fn accepted(
        authority: NetworkAuthority,
        membership: MembershipCertificate,
        bootstrap_records: Vec<PeerRecord>,
    ) -> Self {
        Self {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            outcome: EnrollmentOutcome::Accepted {
                authority,
                membership,
                bootstrap_records,
            },
        }
    }

    pub fn rejected(reason: EnrollmentRejection) -> Self {
        Self {
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            outcome: EnrollmentOutcome::Rejected { reason },
        }
    }

    /// Validate an enrollment response on the recipient side *before* any local
    /// state is written. This is the trust-the-received-data boundary: nothing is
    /// installed until every check below passes. Returns the accepted material,
    /// or a reason the join must abort.
    pub fn validate_received(
        &self,
        invite: &EnrollmentInvite,
        expected_network_id: NetworkId,
        sister_id: &SisterId,
        sister_public_key: SisterPublicKey,
        now: u64,
    ) -> Result<EnrollmentBundle, EnrollmentRejection> {
        if self.protocol_version != ENROLLMENT_PROTOCOL_VERSION {
            return Err(EnrollmentRejection::ProtocolVersion);
        }
        let EnrollmentOutcome::Accepted {
            authority,
            membership,
            bootstrap_records,
        } = &self.outcome
        else {
            // The Authority explicitly refused; surface its reason.
            if let EnrollmentOutcome::Rejected { reason } = &self.outcome {
                return Err(*reason);
            }
            return Err(EnrollmentRejection::IssuanceFailed);
        };

        // The returned descriptor must be the one the signed invite names.
        if authority != &invite.authority || authority.network_id != expected_network_id {
            return Err(EnrollmentRejection::WrongNetwork);
        }
        // Membership binds this Network, this exact Sister, and is Authority-signed.
        if membership.network_id != expected_network_id
            || membership.network_id != authority.network_id
            || membership.sister_id != *sister_id
            || membership.sister_public_key != sister_public_key
            || !membership.verify(authority)
            || !membership.is_valid_at(now)
        {
            return Err(EnrollmentRejection::IssuanceFailed);
        }
        // Every bootstrap record must belong to the Network and self-verify.
        if bootstrap_records
            .iter()
            .any(|record| record.network_id != expected_network_id || !record.verify())
        {
            return Err(EnrollmentRejection::IssuanceFailed);
        }
        Ok(EnrollmentBundle {
            authority: *authority,
            membership: membership.clone(),
            bootstrap_records: bootstrap_records.clone(),
        })
    }
}

/// Fully validated enrollment material ready for atomic local installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentBundle {
    pub authority: NetworkAuthority,
    pub membership: MembershipCertificate,
    pub bootstrap_records: Vec<PeerRecord>,
}

/// The Authority's reply to an enrollment redemption: an issued membership, or
/// a stable rejection reason.
///
/// The `Accepted` variant is intentionally by-value: an `EnrollmentResponse` is
/// a transient, single-ownership wire message deserialized once per redemption,
/// never stored in a long-lived collection, so boxing the payload would add
/// churn at every accessor without shrinking any hot data structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum EnrollmentOutcome {
    Accepted {
        authority: NetworkAuthority,
        membership: MembershipCertificate,
        bootstrap_records: Vec<PeerRecord>,
    },
    Rejected {
        reason: EnrollmentRejection,
    },
}

/// Machine-readable reasons an enrollment redemption is refused. These are
/// stable strings (never a stack trace) so a client can present them and tests
/// can assert on them without matching log text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentRejection {
    /// The invite signature, self-consistency, or locator failed verification.
    InvalidInvite,
    /// The invite expiry window has closed.
    Expired,
    /// The invite or returned membership names a different Network.
    WrongNetwork,
    /// The key-possession proof did not verify against the presented key.
    InvalidProof,
    /// The message version is not this protocol's version.
    ProtocolVersion,
    /// Membership issuance could not complete.
    IssuanceFailed,
}

impl std::fmt::Display for EnrollmentRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::InvalidInvite => "the invite code is not a valid signed invite",
            Self::Expired => "the invite code has expired",
            Self::WrongNetwork => "the invite code is for a different Network",
            Self::InvalidProof => "the Sister key-possession proof is invalid",
            Self::ProtocolVersion => "the enrollment protocol version is unsupported",
            Self::IssuanceFailed => "the Network Authority could not issue membership",
        };
        formatter.write_str(reason)
    }
}

// ---------------------------------------------------------------------------
// URL-safe base64 (RFC 4648 §5), unpadded.
//
// The project keeps `misaka-core` free of new dependencies; this codec is pure
// logic and its integrity guarantee is the Authority signature it wraps, not
// the alphabet. It is unit-tested against RFC 4648 vectors below.
// ---------------------------------------------------------------------------

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn base64url_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let group = (b0 << 16) | (b1 << 8) | b2;
        output.push(BASE64URL_ALPHABET[(group >> 18) as usize & 0x3f] as char);
        output.push(BASE64URL_ALPHABET[(group >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            output.push(BASE64URL_ALPHABET[(group >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            output.push(BASE64URL_ALPHABET[(group & 0x3f) as usize] as char);
        }
    }
    output
}

pub fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 == 1 {
        return None; // A remainder of one character cannot encode any byte.
    }
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut output = Vec::with_capacity(input.len() / 4 * 3 + 3);
    for character in input.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    // Any leftover bits must be zero padding, not hidden payload.
    if accumulator != 0 {
        return None;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IrohEndpointId, TransportBinding};

    fn locator(network_id: NetworkId) -> (PeerRecord, SisterKeyPair) {
        let key = SisterKeyPair::generate();
        let binding = TransportBinding::sign(
            network_id,
            7,
            IrohEndpointId::from_bytes([9u8; 32]),
            1,
            &key,
        );
        let record = PeerRecord::issue(
            network_id,
            7,
            "iroh://authority-endpoint".to_string(),
            binding,
            100,
            &key,
        );
        (record, key)
    }

    fn fixture() -> (
        NetworkId,
        NetworkAuthority,
        AuthorityKeyPair,
        EnrollmentInvite,
    ) {
        let network_id = NetworkId::generate();
        let (authority, authority_key) = NetworkAuthority::generate(network_id);
        let (locator, _sister_key) = locator(network_id);
        let invite =
            EnrollmentInvite::issue(&authority, &authority_key, 100, 200, [7u8; 32], locator);
        (network_id, authority, authority_key, invite)
    }

    #[test]
    fn invite_verifies_only_within_its_window() {
        let (_network_id, _authority, _key, invite) = fixture();
        assert!(invite.verify(100));
        assert!(invite.verify(200));
        assert!(!invite.verify(99));
        assert!(!invite.verify(201));
        assert!(!invite.is_expired(200));
        assert!(invite.is_expired(201));
    }

    #[test]
    fn invite_rejects_tampering_and_foreign_authority_descriptor() {
        let (_network_id, _authority, _key, invite) = fixture();

        // Changing a signed field without re-signing invalidates the signature.
        let mut tampered = invite.clone();
        tampered.expires_at += 1_000;
        assert!(!tampered.verify(100));

        let mut tampered_window = invite.clone();
        tampered_window.invite_nonce = [8u8; 32];
        assert!(!tampered_window.verify(100));

        // Swapping in a different Authority descriptor (leaving the original
        // signature) must fail: the signature covered the original descriptor.
        let (other_authority, _other_key) = NetworkAuthority::generate(NetworkId::generate());
        let mut descriptor_swap = invite.clone();
        descriptor_swap.authority = other_authority;
        assert!(!descriptor_swap.verify(100));
    }

    #[test]
    fn invite_rejects_a_locator_for_a_different_network() {
        let (_network_id, authority, authority_key, _invite) = fixture();
        let sister_key = SisterKeyPair::generate();
        // A locator self-signed for an unrelated Network cannot anchor a valid
        // invite, even though the Authority signature over the invite is fine.
        let foreign_network = NetworkId::generate();
        let binding = TransportBinding::sign(
            foreign_network,
            7,
            IrohEndpointId::from_bytes([1u8; 32]),
            1,
            &sister_key,
        );
        let foreign_locator = PeerRecord::issue(
            foreign_network,
            7,
            "iroh://foreign".to_string(),
            binding,
            100,
            &sister_key,
        );
        let invite = EnrollmentInvite::issue(
            &authority,
            &authority_key,
            100,
            200,
            [7u8; 32],
            foreign_locator,
        );
        assert!(!invite.verify(100));
    }

    #[test]
    fn invite_code_roundtrips_and_rejects_garbage() {
        let (_network_id, _authority, _key, invite) = fixture();
        let code = invite.encode_code().unwrap();
        assert!(code.starts_with(INVITE_CODE_PREFIX));
        assert!(!code.chars().any(|c| c == '+' || c == '/' || c == '='));
        let decoded = EnrollmentInvite::decode_code(&code).unwrap();
        assert_eq!(decoded, invite);
        assert!(decoded.verify(150));

        assert_eq!(
            EnrollmentInvite::decode_code("nope_ABC").unwrap_err(),
            InviteCodeError::UnsupportedPrefix
        );
        assert!(EnrollmentInvite::decode_code("misaka1_!!!not base64!!!").is_err());
        assert!(EnrollmentInvite::decode_code("misaka1_A").is_err());
    }

    #[test]
    fn tampered_code_fails_verification() {
        let (_network_id, _authority, _key, invite) = fixture();
        let mut code = invite.encode_code().unwrap();
        // Flip one character in the payload body to a different valid symbol.
        let bytes: Vec<char> = code.chars().collect();
        let last = bytes.len() - 1;
        code.remove(last);
        let replacement = if bytes[last] == 'A' { 'B' } else { 'A' };
        code.push(replacement);
        if let Ok(decoded) = EnrollmentInvite::decode_code(&code) {
            assert!(!decoded.verify(150));
        }
    }

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"o", "bw"),
            (b"yo", "eW8"),
            (b"your", "eW91cg"),
            (b"your name.", "eW91ciBuYW1lLg"),
            (&[0xfb, 0xff, 0xbf], "-_-_"),
        ];
        for (input, expected) in cases {
            assert_eq!(&base64url_encode(input), expected);
            assert_eq!(&base64url_decode(expected).unwrap(), *input);
        }
    }

    #[test]
    fn base64url_rejects_invalid_padding_and_characters() {
        assert!(base64url_decode("A").is_none()); // 1 leftover char
        assert!(base64url_decode("AAAA!").is_none()); // non-alphabet byte
        assert!(base64url_decode("/").is_none()); // standard alphabet char is not URL-safe
    }

    #[test]
    fn challenge_binds_network_invite_identity_and_both_nonces() {
        let (network_id, _authority, _key, invite) = fixture();
        let sister_key = SisterKeyPair::generate();
        let challenge = EnrollmentChallenge::new(
            network_id,
            invite.digest(),
            SisterId(42),
            sister_key.public_key(),
            [3u8; 32],
            [4u8; 32],
        );
        let proof = challenge.solve(&sister_key);
        assert!(challenge.verify(&proof));

        // A proof must not verify for a different invite, sister key, or nonce.
        let mut other_invite = challenge.clone();
        other_invite.invite_digest = [9u8; 32];
        assert!(!other_invite.verify(&proof));
        let mut other_key = challenge.clone();
        other_key.sister_public_key = SisterKeyPair::generate().public_key();
        assert!(!other_key.verify(&proof));
        assert!(!challenge.verify(&EnrollmentProof {
            signature: SisterKeyPair::generate().sign(&challenge.signing_bytes()),
        }));
    }

    #[test]
    fn accepted_response_validates_only_for_the_matching_sister_and_network() {
        let (network_id, authority, authority_key, invite) = fixture();
        let sister_key = SisterKeyPair::generate();
        let sister_id = SisterId(42);
        let membership = MembershipCertificate::issue(
            &authority,
            &authority_key,
            sister_key.public_key(),
            sister_id.as_u64(),
            150,
            None,
            150,
        );
        let response = EnrollmentResponse::accepted(
            authority,
            membership.clone(),
            vec![invite.locator.clone()],
        );

        let bundle = response
            .validate_received(
                &invite,
                network_id,
                &sister_id,
                sister_key.public_key(),
                150,
            )
            .unwrap();
        assert_eq!(bundle.membership, membership);
        assert_eq!(bundle.authority, authority);

        // Wrong CLI NetworkId.
        assert_eq!(
            response
                .validate_received(
                    &invite,
                    NetworkId::generate(),
                    &sister_id,
                    sister_key.public_key(),
                    150
                )
                .unwrap_err(),
            EnrollmentRejection::WrongNetwork
        );
        // Membership for a different Sister.
        assert_eq!(
            response
                .validate_received(
                    &invite,
                    network_id,
                    &SisterId(99),
                    sister_key.public_key(),
                    150
                )
                .unwrap_err(),
            EnrollmentRejection::IssuanceFailed
        );
        // A different local key than the membership was issued for.
        assert_eq!(
            response
                .validate_received(
                    &invite,
                    network_id,
                    &sister_id,
                    SisterKeyPair::generate().public_key(),
                    150
                )
                .unwrap_err(),
            EnrollmentRejection::IssuanceFailed
        );
    }

    #[test]
    fn rejected_response_surfaces_its_reason() {
        let (network_id, _authority, _key, invite) = fixture();
        let response = EnrollmentResponse::rejected(EnrollmentRejection::Expired);
        assert_eq!(
            response
                .validate_received(
                    &invite,
                    network_id,
                    &SisterId(1),
                    SisterKeyPair::generate().public_key(),
                    150
                )
                .unwrap_err(),
            EnrollmentRejection::Expired
        );
    }

    #[test]
    fn request_and_response_roundtrip_bincode() {
        let (_network_id, _authority, _key, invite) = fixture();
        let request = EnrollmentRequest::new(
            invite.clone(),
            SisterId(7),
            SisterKeyPair::generate().public_key(),
            [1u8; 32],
        );
        let encoded = bincode::serialize(&request).unwrap();
        let decoded: EnrollmentRequest = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, request);

        let response = EnrollmentResponse::rejected(EnrollmentRejection::InvalidProof);
        let encoded = bincode::serialize(&response).unwrap();
        let decoded: EnrollmentResponse = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, response);
    }
}
