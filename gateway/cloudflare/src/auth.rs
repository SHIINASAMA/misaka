//! Shared Gateway configuration parsing and constants for the Cloudflare host.
//!
//! Both the top-level worker (which serves `/.well-known/misaka`) and the
//! Durable Object (which authenticates + stores) need the Network Authority's
//! PUBLIC half and a clock. The Authority private key is never present here.

use js_sys::Date;
use misaka_core::{AuthorityPublicKey, NetworkAuthority, NetworkId};
use worker::{Env, Error, Result};

/// Seconds an announced `PeerRecord` stays queryable before it must be renewed.
pub const RECORD_TTL_SECS: u64 = 600;
/// Accepted skew between a request auth timestamp and the current time.
pub const AUTH_WINDOW_SECS: u64 = 300;
/// How long a seen nonce blocks a replay. Covers the auth window on both sides.
pub const NONCE_TTL_SECS: u64 = 900;

/// Parse the configured Network Authority (public half only) from Worker env
/// vars. Both values are public configuration, not secrets:
/// - `NETWORK_ID`: the Network UUID this Gateway serves (one Gateway, one Network).
/// - `NETWORK_AUTHORITY_PUBLIC_KEY`: hex-encoded 32-byte Authority public key.
pub fn authority_from_env(env: &Env) -> Result<NetworkAuthority> {
    let network_id = NetworkId::parse(&env.var("NETWORK_ID")?.to_string())
        .map_err(|_| Error::from("NETWORK_ID is not a valid UUID"))?;
    let hex = env.var("NETWORK_AUTHORITY_PUBLIC_KEY")?.to_string();
    let bytes = decode_hex(&hex).ok_or_else(|| Error::from("authority public key must be 64 hex chars"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::from("authority public key must be 32 bytes"))?;
    Ok(NetworkAuthority {
        network_id,
        authority_public_key: AuthorityPublicKey::from_bytes(key),
    })
}

/// Current wall-clock seconds (Workers time via the JS `Date` epoch).
pub fn now_secs() -> u64 {
    (Date::now() / 1000.0) as u64
}

/// Record lifetime in seconds. Defaults to [`RECORD_TTL_SECS`]; overridable via
/// the `GATEWAY_RECORD_TTL_SECS` env var (used by the Durable Object SQL tests to
/// exercise TTL expiry and renewal without a 10-minute wait).
pub fn record_ttl_secs(env: &Env) -> u64 {
    env.var("GATEWAY_RECORD_TTL_SECS")
        .ok()
        .and_then(|value| value.to_string().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(RECORD_TTL_SECS)
}

/// Minimal lowercase/uppercase hex decoder. `misaka-core` intentionally has no
/// hex crate dependency; only this Gateway host needs to read a hex public key
/// from configuration, so the helper lives here rather than in the shared crate.
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect()
}
