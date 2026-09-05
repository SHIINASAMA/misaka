//! Test/dev helper: emit a signed Gateway request body (announce or peers) as
//! JSON on stdout, so the Cloudflare Worker's Durable Object SQL behavior can be
//! driven end-to-end from a shell/CI (e.g. under `wrangler dev --local`),
//! without a native HTTP client that could produce valid signatures.
//!
//! This is NOT part of the Gateway service — it only exercises the same
//! `misaka-core` crypto the real Sister client uses.
//!
//! Usage:
//!   cargo run -p misaka-gatewayd --example sign_request -- <args>
//!
//!   authority-pub  <auth_secret_hex>                       -> hex pubkey
//!   announce <network_id> <auth_secret_hex> <sister_secret_hex> <sister_id> <nonce_hex> <expires_in_secs> <record_sequence>
//!   peers    <network_id> <auth_secret_hex> <sister_secret_hex> <sister_id> <nonce_hex> [expires_in_secs]
//!
//! `record_sequence` fixes the announced `PeerRecord` sequence so a test can
//! re-announce the SAME sequence (renewal) rather than accidentally bumping it.
//! The record's `updated_at` is pinned to that sequence, so two calls with the
//! same `record_sequence` produce byte-identical `PeerRecord`s.

use std::time::{SystemTime, UNIX_EPOCH};

use misaka_core::{
    AuthorityKeyPair, GatewayAnnounceRequest, GatewayAuth, GatewayPeersRequest, IrohEndpointId,
    MembershipCertificate, NetworkAuthority, NetworkId, PeerRecord, SisterKeyPair,
    TransportBinding,
};

fn hex32(s: &str) -> [u8; 32] {
    let bytes = decode_hex(s);
    bytes.try_into().expect("expected 32-byte hex")
}

fn hex16(s: &str) -> [u8; 16] {
    decode_hex(s).try_into().expect("expected 16-byte hex")
}

fn decode_hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = argv.first().map(String::as_str) else {
        eprintln!("missing mode");
        std::process::exit(2);
    };

    if mode == "authority-pub" {
        let key = AuthorityKeyPair::from_bytes(hex32(&argv[1]));
        print!("{}", encode_hex(&key.public_key().to_bytes()));
        return;
    }

    let network_id = NetworkId::parse(&argv[1]).expect("network id");
    let authority_key = AuthorityKeyPair::from_bytes(hex32(&argv[2]));
    let sister_key = SisterKeyPair::from_bytes(hex32(&argv[3]));
    let sister_id: u64 = argv[4].parse().expect("sister id");
    let nonce = hex16(&argv[5]);
    let expires_in: i64 = argv.get(6).and_then(|s| s.parse().ok()).unwrap_or(3600);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let authority = NetworkAuthority {
        network_id,
        authority_public_key: authority_key.public_key(),
    };
    let membership = MembershipCertificate::issue(
        &authority,
        &authority_key,
        sister_key.public_key(),
        sister_id,
        now.saturating_sub(10),
        Some((now as i64 + expires_in).max(0) as u64),
        sister_id,
    );

    let body = if mode == "announce" {
        let sequence: u64 = argv[7].parse().expect("record sequence");
        let binding = TransportBinding::sign(
            network_id,
            sister_id,
            IrohEndpointId::from_bytes([7u8; 32]),
            sequence,
            &sister_key,
        );
        // updated_at pinned to the sequence: same sequence => byte-identical
        // record, so a re-announce is a genuine same-record renewal, not a new
        // locator that merely happens to carry a higher sequence.
        let record = PeerRecord::issue(
            network_id,
            sister_id,
            "iroh://peer".to_string(),
            binding,
            sequence,
            &sister_key,
        );
        let auth = GatewayAuth::sign_announce(
            network_id,
            sister_id,
            now,
            nonce,
            &membership,
            &record,
            &sister_key,
        );
        serde_json::to_string(&GatewayAnnounceRequest {
            auth,
            membership,
            record,
        })
        .unwrap()
    } else if mode == "peers" {
        let auth = GatewayAuth::sign_peers(network_id, sister_id, now, nonce, &sister_key);
        serde_json::to_string(&GatewayPeersRequest { auth, membership }).unwrap()
    } else {
        eprintln!("unknown mode {mode}");
        std::process::exit(2);
    };
    print!("{body}");
}
