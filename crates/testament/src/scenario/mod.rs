//! Scenario engine: runs Rust scenario functions against real Sister
//! processes. Split by suite so each file stays focused:
//!   - `context`  the shared `Context` (launch/observe/teardown of real Sisters)
//!   - `helpers`  free helpers shared across suites
//!   - `core`     T01–T13 baseline        - `network` N01–N21 Network Stream
//!   - `relay`    R01–R07 Iroh relay      - `security` S01–S03 auth/revocation
//!   - `gateway`  G01–G10 Gateway discovery
//!   - `live`     opt-in LIVE smoke against a real external Gateway (never in CI)

mod context;
mod core;
mod enrollment;
mod gateway;
pub(crate) mod helpers;
mod live;
mod network;
mod relay;
mod security;
mod types;

// Re-exported so sibling modules can pull the common imports with
// `use super::*;` while each stays free of unused-import warnings.
pub(crate) use crate::assertion as assert;
pub(crate) use crate::observer;
pub(crate) use crate::run_manager::{alloc_port, misaka_binary};
pub(crate) use crate::supervisor::{
    build_spawn, build_spawn_secure, CliProcess, SisterProcess, SpawnConfig,
};
pub(crate) use crate::types::{Artifacts, Manifest, Report, RunLayout, ScenarioError, SisterEntry};
pub(crate) use misaka_core::identity::{
    MembershipCertificate, MembershipKind, NetworkAuthority, NetworkId, RevocationRecord,
    SisterIdentity, SisterKeyPair,
};
pub(crate) use misaka_core::introspection::IntrospectionSnapshot;
pub(crate) use std::collections::HashMap;
pub(crate) use std::fs::OpenOptions;
pub(crate) use std::io::{Read, Write};
pub(crate) use std::net::SocketAddr;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::time::Duration;

pub use context::Context;
pub use types::{ScenarioDef, ScenarioFn};

pub use core::scenarios;
pub use enrollment::enrollment_scenarios;
pub use gateway::gateway_scenarios;
pub use live::run_gateway_live;
pub use network::network_scenarios;
pub use relay::relay_scenarios;
pub use security::security_scenarios;
