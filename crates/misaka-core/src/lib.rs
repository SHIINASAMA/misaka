//! Misaka Network domain contracts.
//!
//! This crate defines the stable vocabulary of Misaka Network. It contains
//! domain types and cross-package contracts ONLY — no OS/infrastructure deps,
//! no tokio, no sockets, no filesystem layout, no process spawning.
//!
//! `serde` is acceptable because these types are exchanged between packages
//! and exposed through machine-readable introspection.

pub mod identity;
pub mod introspection;
pub mod job;
pub mod peer;
pub mod protocol;

pub use identity::{
    AuthorityKeyPair, AuthorityPublicKey, AuthoritySignature, IrohEndpointId,
    KeyPossessionChallenge, MembershipCertificate, NetworkAuthority, NetworkId, NetworkInvite,
    Nickname, PeerRecord, RevocationRecord, SisterId, SisterIdentity, SisterKeyPair,
    SisterPublicKey, SisterSignature, TransportBinding,
};
pub use introspection::{
    ActiveStreamSnapshot, IntrospectionSnapshot, JobSnapshot, PeerSnapshot, ResourceSnapshot,
};
pub use job::{JobId, JobStatus};
pub use peer::{PeerBlueprint, PeerState, PeerStateTable};
pub use protocol::*;
