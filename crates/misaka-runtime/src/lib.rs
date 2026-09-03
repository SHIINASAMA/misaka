//! Misaka Network runtime — the life of one Sister.
//!
//! Implements the peer-to-peer node: listening, connecting, discovery,
//! state sharing, job orchestration, work stealing. Everything here is one
//! Sister's behavior; no master/slave roles exist.

pub mod commands;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod error;
mod executor;
mod handler;
pub mod identity_store;
pub mod node;
pub mod peer_store;
pub mod queue;
pub mod resources;
pub mod runtime;
pub mod scheduler;
pub mod state;
mod stealing;

pub use error::MisakaError as Error;

pub type Result<T> = std::result::Result<T, Error>;
pub mod introspection;
pub mod network;
