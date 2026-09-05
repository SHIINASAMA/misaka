//! The Gateway directory: a single Durable Object per Network, backed by DO
//! SQLite storage.
//!
//! One DO instance per Network (`get_by_name(network_id)`) means the object is
//! a strongly-consistent single-writer actor. That makes the two genuinely
//! racy parts of the v0 contract fall out of the platform for free, with no
//! hand-written locking:
//!   * "only a higher `sequence` may replace a record"  -> an upsert guarded by
//!     `WHERE excluded.sequence > peers.sequence`;
//!   * "a nonce may be spent only once"                  -> a UNIQUE row whose
//!     prior existence is checked in the same actor turn.
//!
//! All *trust* validation (`verify_request`, `PeerRecord::verify`) still runs in
//! Rust here — the platform replaces the state store, never the cryptography.

use worker::{
    durable_object, DurableObject, Env, Request, Response, Result, SqlStorageValue, State, Storage,
};

use misaka_core::{
    announce_body_bytes, peers_body_bytes, record_matches_membership, verify_request,
    GatewayAnnounceRequest, GatewayPeersRequest, GatewayPeersResponse,
};

use crate::auth::{
    authority_from_env, now_secs, AUTH_WINDOW_SECS, NONCE_TTL_SECS, RECORD_TTL_SECS,
};

/// A row of the `peers` table. `record` is the JSON-encoded signed locator.
#[derive(serde::Deserialize)]
struct PeerRow {
    record: String,
}

/// `SELECT min(expires_at) AS n ...`
#[derive(serde::Deserialize)]
struct MinRow {
    n: Option<i64>,
}

/// Whether a DO SQL error is a uniqueness (PRIMARY KEY) violation, which the
/// replay guard reads as "this nonce was already spent".
fn is_unique_conflict(error: &worker::Error) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("unique") || text.contains("constraint")
}

#[durable_object]
pub struct GatewayDirectory {
    state: State,
    env: Env,
}

impl GatewayDirectory {
    /// Create tables if absent. DO SQL is synchronous and idempotent, and there
    /// is no `block_concurrency_while` in this binding, so we run it inline.
    fn ensure_schema(storage: &Storage) -> Result<()> {
        let sql = storage.sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS peers (
                sister_id INTEGER PRIMARY KEY,
                record TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                membership_serial INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )",
            None,
        )?;
        sql.exec(
            "CREATE TABLE IF NOT EXISTS nonces (
                nonce BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL
            )",
            None,
        )?;
        Ok(())
    }

    async fn handle_announce(&self, mut request: Request) -> Result<Response> {
        let body = request.bytes().await?;
        let parsed: GatewayAnnounceRequest = serde_json::from_slice(&body)
            .map_err(|_| worker::Error::from("invalid announce body"))?;
        let authority = authority_from_env(&self.env)?;
        let now = now_secs();

        // 1. Stateless authentication (network, digest, window, membership, sig).
        verify_request(
            &parsed.auth,
            &announce_body_bytes(&parsed.membership, &parsed.record),
            &parsed.membership,
            &authority,
            now,
            AUTH_WINDOW_SECS,
        )
        .map_err(|e| worker::Error::from(format!("auth failed: {e}")))?;

        // 2. A member may not announce a record for a different Sister...
        if !record_matches_membership(&parsed.record, &parsed.membership) {
            return Response::error("record identity does not match membership", 403);
        }
        // ...and the record must be self-valid regardless of who sent it.
        if !parsed.record.verify() {
            return Response::error("record signature verification failed", 400);
        }

        let storage = self.state.storage();
        Self::ensure_schema(&storage)?;
        let sql = storage.sql();

        // Nonce replay: a single atomic INSERT. The PRIMARY KEY on `nonce` makes
        // a second insert of the same (still-blocking) nonce fail in one round
        // trip — the platform, not Rust, enforces "spent once".
        let spent = sql.exec(
            "INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
            Some(vec![
                SqlStorageValue::from(parsed.auth.nonce.to_vec()),
                SqlStorageValue::from((now + NONCE_TTL_SECS) as i64),
            ]),
        );
        if let Err(error) = spent {
            if is_unique_conflict(&error) {
                return Response::error("replayed nonce", 401);
            }
            return Err(error);
        }

        // 4. Upsert, refusing to downgrade the sequence.
        sql.exec(
            "INSERT INTO peers (sister_id, record, sequence, membership_serial, last_seen, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(sister_id) DO UPDATE SET
                record = excluded.record,
                sequence = excluded.sequence,
                membership_serial = excluded.membership_serial,
                last_seen = excluded.last_seen,
                expires_at = excluded.expires_at
             WHERE excluded.sequence > peers.sequence",
            Some(vec![
                worker::SqlStorageValue::from(parsed.record.sister_id.as_u64() as i64),
                worker::SqlStorageValue::from(serde_json::to_string(&parsed.record).unwrap()),
                worker::SqlStorageValue::from(parsed.record.sequence as i64),
                worker::SqlStorageValue::from(parsed.membership.serial as i64),
                worker::SqlStorageValue::from(now as i64),
                worker::SqlStorageValue::from((now + RECORD_TTL_SECS) as i64),
            ]),
        )?;

        self.schedule_alarm(&storage);
        Response::empty()
    }

    async fn handle_peers(&self, mut request: Request) -> Result<Response> {
        let body = request.bytes().await?;
        let parsed: GatewayPeersRequest = serde_json::from_slice(&body)
            .map_err(|_| worker::Error::from("invalid peers body"))?;
        let authority = authority_from_env(&self.env)?;
        let now = now_secs();

        verify_request(
            &parsed.auth,
            &peers_body_bytes(),
            &parsed.membership,
            &authority,
            now,
            AUTH_WINDOW_SECS,
        )
        .map_err(|e| worker::Error::from(format!("auth failed: {e}")))?;

        let storage = self.state.storage();
        Self::ensure_schema(&storage)?;
        let rows = storage
            .sql()
            .exec(
                "SELECT record FROM peers WHERE expires_at > ?",
                Some(vec![worker::SqlStorageValue::from(now as i64)]),
            )?
            .to_array::<PeerRow>()?;

        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            // Directory entries were verified on write; a store/tamper fault
            // would only yield a record we then drop here, never a forged one.
            if let Ok(record) = serde_json::from_str(&row.record) {
                records.push(record);
            }
        }
        Response::from_json(&GatewayPeersResponse { records })
    }

    fn schedule_alarm(&self, storage: &Storage) {
        // Best-effort GC scheduling; correctness never depends on it because
        // reads filter on `expires_at > now`. Ignore failures.
        if let Ok(min) = storage
            .sql()
            .exec("SELECT min(expires_at) AS n FROM peers", None)
            .and_then(|c| c.one::<MinRow>())
        {
            if let Some(expires_at_secs) = min.n {
                let offset_ms = expires_at_secs.saturating_mul(1000) - (now_secs() as i64) * 1000;
                let _ = storage.set_alarm(offset_ms.max(0));
            }
        }
    }
}

impl DurableObject for GatewayDirectory {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match req.path().as_str() {
            "/v1/announce" => self.handle_announce(req).await,
            "/v1/peers" => self.handle_peers(req).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let now = now_secs() as i64;
        storage.sql().exec(
            "DELETE FROM peers WHERE expires_at <= ?",
            Some(vec![worker::SqlStorageValue::from(now)]),
        )?;
        storage.sql().exec(
            "DELETE FROM nonces WHERE expires_at <= ?",
            Some(vec![worker::SqlStorageValue::from(now)]),
        )?;
        self.schedule_alarm(&storage);
        Response::ok("gc")
    }
}
