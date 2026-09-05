//! Cloudflare Workers entry point for the Misaka Gateway v0.
//!
//! Request shape:
//!   GET  /.well-known/misaka   served inline from the configured Network id.
//!   POST /v1/announce          forwarded to this Network's Durable Object.
//!   POST /v1/peers             forwarded to this Network's Durable Object.
//!
//! Plus two build guards kept from the original packaging spike:
//!   GET  /                     liveness string.
//!   GET  /verify               runs the real misaka-core crypto path so the
//!                              linker can never strip serde/sha2/ed25519 from
//!                              the bundle even if the gateway routes change.

mod auth;
mod directory;

use misaka_core::{GatewayInfo, PeerRecord};
use worker::*;

/// A fixed, validly-signed `PeerRecord`, compiled into the Wasm and verified at
/// request time. Proves the Gateway core dependency chain is genuinely linked.
const PEER_RECORD_FIXTURE: &str = include_str!("peer-record-fixture.json");

fn verify_fixture() -> bool {
    let record: PeerRecord =
        serde_json::from_str(PEER_RECORD_FIXTURE).expect("fixture must parse");
    // Force sha2 into the live call graph as well.
    let _digest = misaka_core::transfer_content_digest(PEER_RECORD_FIXTURE.as_bytes());
    record.verify()
}

/// Resolve the Durable Object stub for the Network this Gateway is configured
/// for. One Gateway deployment serves exactly one Network.
fn directory_stub(env: &Env) -> Result<Stub> {
    let authority = auth::authority_from_env(env)?;
    env.durable_object("GATEWAY_DIRECTORY")?
        .get_by_name(&authority.network_id.to_string())
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get("/", |_, _| Response::ok("misaka gateway"))
        .get("/verify", |_, _| {
            Response::from_json(&serde_json::json!({ "valid": verify_fixture() }))
        })
        .get("/.well-known/misaka", |_, ctx| {
            let authority = auth::authority_from_env(&ctx.env)?;
            Response::from_json(&GatewayInfo::from_authority(&authority))
        })
        .post_async("/v1/announce", |req, ctx| async move {
            directory_stub(&ctx.env)?.fetch_with_request(req).await
        })
        .post_async("/v1/peers", |req, ctx| async move {
            directory_stub(&ctx.env)?.fetch_with_request(req).await
        })
        .run(req, env)
        .await
}
