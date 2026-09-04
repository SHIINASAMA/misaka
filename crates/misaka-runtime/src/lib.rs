//! Misaka Network runtime — the life of one Sister.
//!
//! Implements the peer-to-peer node: listening, connecting, discovery,
//! state sharing, job orchestration, work stealing. Everything here is one
//! Sister's behavior; no master/slave roles exist.

pub mod commands;
pub mod config;
pub mod connection;
pub mod content_store;
pub mod crypto;
pub mod discovery;
pub mod error;
pub mod executor;
pub mod handler;
pub mod identity_store;
pub mod introspection;
pub mod iroh_endpoint_store;
pub mod iroh_identity_store;
pub mod job_manager;
pub mod network;
pub mod network_id_store;
pub mod node;
pub mod peer_registry;
pub mod peer_service;
pub mod peer_store;
pub mod queue;
pub mod resources;
pub mod runtime;
pub mod scheduler;
pub mod shutdown;
pub mod sister_key_store;
pub mod state;
pub mod stealing;
pub(crate) mod stream_registry;
pub mod tls_identity_store;
pub mod transport_binding_store;

pub use error::MisakaError as Error;
pub use shutdown::{Shutdown, ShutdownToken};

pub type Result<T> = std::result::Result<T, Error>;
