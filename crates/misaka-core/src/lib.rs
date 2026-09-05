//! Misaka Network domain contracts.
//!
//! This crate defines the stable vocabulary of Misaka Network. It contains
//! domain types and cross-package contracts ONLY — no OS/infrastructure deps,
//! no tokio, no sockets, no filesystem layout, no process spawning.
//!
//! `serde` is acceptable because these types are exchanged between packages
//! and exposed through machine-readable introspection.

pub mod gateway;
pub mod identity;
pub mod introspection;
pub mod job;
pub mod peer;
pub mod protocol;

pub use gateway::{
    announce_body_bytes, peers_body_bytes, record_matches_membership, verify_request,
    GatewayAnnounceRequest, GatewayAuth, GatewayAuthError, GatewayInfo, GatewayPeersRequest,
    GatewayPeersResponse, DEFAULT_AUTH_WINDOW_SECS, DEFAULT_NONCE_TTL_SECS,
    DEFAULT_RECORD_TTL_SECS, GATEWAY_PROTOCOL_VERSION,
};

pub use identity::{
    AuthorityKeyPair, AuthorityPublicKey, AuthoritySignature, CommandAuthorization, HumanId,
    HumanIdentity, HumanKeyPair, HumanMembershipCertificate, HumanPublicKey, HumanSignature,
    IrohEndpointId, KeyPossessionChallenge, MembershipCertificate, MembershipKind,
    NetworkAuthority, NetworkId, NetworkInvite, Nickname, PeerRecord, Permission, Principal,
    RevocationRecord, Role, SisterId, SisterIdentity, SisterKeyPair, SisterPublicKey,
    SisterSignature, TransportBinding,
};
pub use introspection::{
    ActiveStreamSnapshot, IntrospectionSnapshot, JobSnapshot, PeerSnapshot, ResourceSnapshot,
};
pub use job::{JobId, JobStatus};
pub use peer::{PeerBlueprint, PeerState, PeerStateTable};
pub use protocol::*;
