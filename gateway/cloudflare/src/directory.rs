//! The Gateway directory: a single Durable Object per Network, backed by DO
//! SQLite storage.
//!
//! One DO instance per Network (`get_by_name(network_id)`) makes the object a
//! strongly-consistent single-writer actor. The genuinely racy parts of the v0
//! contract fall out of the platform for free, with no hand-written locking:
//!   * monotonic sequence — a conditional upsert that replaces the record only
//!     for a higher `sequence`, and merely refreshes the expiry for an equal one;
//!   * "a nonce may be spent only once" — a UNIQUE row, consumed on BOTH the
//!     announce and peers routes so they behave identically.
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
    authority_from_env, nonce_ttl_secs, now_secs, record_ttl_secs, AUTH_WINDOW_SECS,
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

/// Outcome of consuming a request nonce.
enum Nonce {
    Fresh,
    Replayed,
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

    /// Atomically spend a request nonce. A second use of a still-blocking nonce
    /// fails on the PRIMARY KEY and is reported as replayed. Shared by both the
    /// announce and peers routes so replay protection is uniform.
    fn spend_nonce(
        storage: &Storage,
        nonce: &[u8; 16],
        now: u64,
        nonce_ttl: u64,
    ) -> Result<Nonce> {
        match storage.sql().exec(
            "INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
            Some(vec![
                SqlStorageValue::from(nonce.to_vec()),
                SqlStorageValue::from((now + nonce_ttl) as i64),
            ]),
        ) {
            Ok(_) => Ok(Nonce::Fresh),
            Err(error) if is_unique_conflict(&error) => Ok(Nonce::Replayed),
            Err(error) => Err(error),
        }
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

        let storage = self.state.storage();
        Self::ensure_schema(&storage)?;
        let record_ttl = record_ttl_secs(&self.env);
        let nonce_ttl = nonce_ttl_secs(&self.env);

        // 2. Spend the nonce (shared with /v1/peers).
        if matches!(
            Self::spend_nonce(&storage, &parsed.auth.nonce, now, nonce_ttl)?,
            Nonce::Replayed
        ) {
            return Response::error("replayed nonce", 401);
        }

        // 3. A member may not announce a record for a different Sister...
        if !record_matches_membership(&parsed.record, &parsed.membership) {
            return Response::error("record identity does not match membership", 403);
        }
        // ...and the record must be self-valid regardless of who sent it.
        if !parsed.record.verify() {
            return Response::error("record signature verification failed", 400);
        }

        // 4. Conditional upsert:
        //    * higher sequence -> replace the record and refresh the expiry;
        //    * equal sequence  -> keep the record, refresh last_seen/expires_at
        //      (this is what lets a Sister's periodic re-announce renew a
        //      still-valid locator whose sequence has not changed);
        //    * lower sequence  -> ignore (WHERE is false).
        storage.sql().exec(
            "INSERT INTO peers (sister_id, record, sequence, membership_serial, last_seen, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(sister_id) DO UPDATE SET
                last_seen = excluded.last_seen,
                expires_at = excluded.expires_at,
                record = CASE WHEN excluded.sequence > peers.sequence THEN excluded.record ELSE peers.record END,
                sequence = CASE WHEN excluded.sequence > peers.sequence THEN excluded.sequence ELSE peers.sequence END,
                membership_serial = CASE WHEN excluded.sequence > peers.sequence THEN excluded.membership_serial ELSE peers.membership_serial END
             WHERE excluded.sequence >= peers.sequence",
            Some(vec![
                SqlStorageValue::from(parsed.record.sister_id.as_u64() as i64),
                SqlStorageValue::from(serde_json::to_string(&parsed.record).unwrap()),
                SqlStorageValue::from(parsed.record.sequence as i64),
                SqlStorageValue::from(parsed.membership.serial as i64),
                SqlStorageValue::from(now as i64),
                SqlStorageValue::from((now + record_ttl) as i64),
            ]),
        )?;

        self.schedule_alarm(&storage).await;
        // 204 No Content — parity with the native gatewayd announce response.
        Ok(Response::builder().with_status(204).empty())
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

        // Peers queries are authenticated member requests too: spend the nonce so
        // a captured peers request cannot be replayed (parity with announce).
        if matches!(
            Self::spend_nonce(
                &storage,
                &parsed.auth.nonce,
                now,
                nonce_ttl_secs(&self.env)
            )?,
            Nonce::Replayed
        ) {
            return Response::error("replayed nonce", 401);
        }
        // Re-arm GC: a peers call can be the only thing that ever wrote a row
        // (empty directory), so schedule the alarm off the nonce expiry too.
        self.schedule_alarm(&storage).await;

        let rows = storage
            .sql()
            .exec(
                "SELECT record FROM peers WHERE expires_at > ?",
                Some(vec![SqlStorageValue::from(now as i64)]),
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

    /// Schedule the GC alarm for the soonest expiry across BOTH tables. A peers
    /// call with an empty directory still leaves a nonce row, so the alarm must
    /// not be driven by `peers` alone or spent nonces would never be collected.
    async fn schedule_alarm(&self, storage: &Storage) {
        if let Ok(min) = storage
            .sql()
            .exec(
                "SELECT min(expires_at) AS n FROM (
                     SELECT expires_at FROM peers
                     UNION ALL
                     SELECT expires_at FROM nonces
                 )",
                None,
            )
            .and_then(|c| c.one::<MinRow>())
        {
            if let Some(expires_at_secs) = min.n {
                let offset_ms = expires_at_secs.saturating_mul(1000) - (now_secs() as i64) * 1000;
                let _ = storage.set_alarm(offset_ms.max(0)).await;
            }
        }
    }
}

/// Whether a DO SQL error is a uniqueness (PRIMARY KEY) violation, which the
/// replay guard reads as "this nonce was already spent".
fn is_unique_conflict(error: &worker::Error) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("unique") || text.contains("constraint")
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
            Some(vec![SqlStorageValue::from(now)]),
        )?;
        storage.sql().exec(
            "DELETE FROM nonces WHERE expires_at <= ?",
            Some(vec![SqlStorageValue::from(now)]),
        )?;
        self.schedule_alarm(&storage).await;
        Response::ok("gc")
    }
}
