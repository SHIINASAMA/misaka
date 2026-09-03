//! Misaka Network runtime — the life of one Sister.
//!
//! Implements the peer-to-peer node: listening, connecting, discovery,
//! state sharing, job orchestration, work stealing. Everything here is one
//! Sister's behavior; no master/slave roles exist.

pub mod commands;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod node;
pub mod queue;
pub mod scheduler;
pub mod state;

pub use error::MisakaError as Error;

pub type Result<T> = std::result::Result<T, Error>;
pub mod identity_store;
pub mod peer_store;
