use worker::*;

/// A fixed, validly-signed `PeerRecord`. It is compiled into the Wasm module
/// and parsed + verified at request time, so the linker must retain the real
/// `serde + sha2 + ed25519-dalek + misaka-core` code path rather than
/// dead-code-eliminating an unused import.
const PEER_RECORD_FIXTURE: &str = include_str!("peer-record-fixture.json");

/// Execute the Gateway core chain: deserialize the record, verify the
/// transport binding and the Ed25519 signatures, and run the SHA-256 domain
/// helper over the fixture bytes. Returns whether the record verifies.
fn verify_fixture() -> bool {
    let record: misaka_core::PeerRecord =
        serde_json::from_str(PEER_RECORD_FIXTURE).expect("fixture must parse");

    // Force `sha2` (via misaka-core's protocol domain code) into the live
    // call graph so it cannot be stripped from the bundle.
    let digest = misaka_core::transfer_content_digest(PEER_RECORD_FIXTURE.as_bytes());
    debug_assert_eq!(digest.len(), 32);

    record.verify()
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get("/", |_, _| Response::ok("misaka gateway spike"))
        .get("/verify", |_, _| {
            Response::from_json(&serde_json::json!({ "valid": verify_fixture() }))
        })
        .run(req, env)
        .await
}
