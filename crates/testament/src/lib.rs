//! Testament — external experiment harness for Misaka Network.
//!
//! Never part of Misaka Network (§14):
//! 1. never executes Misaka jobs in-process
//! 2. never participates in Sister discovery
//! 3. never acts as a peer
//! 4. Sisters never know Testament exists
//! 5. killing Testament must not break a running network
//!
//! It only ever spawns real `misaka` OS processes and observes them through
//! the read-only introspection endpoint. It depends on misaka-core for data
//! contracts only — never on misaka-runtime.

pub mod assertion;
pub mod observer;
pub mod operator;
pub mod reporter;
pub mod run_manager;
pub mod scenario;
pub mod service_verify;
pub mod smoke;
pub mod supervisor;
pub mod types;
