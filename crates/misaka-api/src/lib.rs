//! Misaka Network local Sister HTTP API (loopback-only, authenticated).
//!
//! Every `/api/v1/*` route requires the local control token issued by the
//! running Sister (`misaka-runtime::local_control_token_store`). Loopback is a
//! network boundary, not a local-user authorization boundary: the token is the
//! local authorization boundary. A single unauthenticated `GET /healthz` exists
//! for liveness and exposes no state.
//!
//! Authentication does NOT justify binding this API to a LAN/public address;
//! the API remains loopback-only.

use axum::extract::{Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use misaka_core::introspection::{IntrospectionSnapshot, PeerSnapshot};
use misaka_core::protocol::JobResultData;
use misaka_runtime::local_control_token_store::constant_time_eq;
use misaka_runtime::{ShutdownToken, SisterHandle};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(error: impl Display) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
    }
}

impl Display for ApiError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

/// The single generic local-control failure. Missing, malformed, and incorrect
/// tokens all produce exactly this response, so a caller cannot tell which.
fn unauthorized() -> Response {
    ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized").into_response()
}

#[derive(Debug, Clone, Serialize)]
pub struct OverviewResponse {
    pub network_id: String,
    pub this_sister: String,
    pub this_nickname: String,
    pub online_sisters: usize,
    pub known_sisters: usize,
    pub active_streams: usize,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SisterResponse {
    pub id: String,
    pub nickname: String,
    pub hostname: String,
    pub platform: String,
    pub version: String,
    pub status: String,
    pub control_endpoint: String,
    pub stream_endpoints: Vec<String>,
    pub cpu_usage: f32,
    pub memory_total: u64,
    pub memory_used: u64,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub uptime_secs: u64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamResponse {
    pub stream_id: u64,
    pub backend: String,
    pub route: String,
    pub rtt_ms: Option<u64>,
    pub path_switches: u64,
    pub local_endpoint: Option<String>,
    pub remote_endpoint: Option<String>,
    pub connected_for_ms: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PingResponse {
    pub sister_id: String,
    pub status: &'static str,
}

/// Minimal unauthenticated liveness response. Exposes no Sister identity,
/// NetworkId, peers, keys, service state, or job data.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub struct ApiServer {
    listener: TcpListener,
    app: Router,
    bound: SocketAddr,
}

/// Build the API router. `token` is the local control token minted by the
/// running Sister; every `/api/v1/*` route requires it.
pub fn router(handle: SisterHandle, token: String) -> Router {
    // Loopback authorization guard for every `/api/v1/*` route. One invariant:
    // `/api/v1 = authenticated local control surface`. Missing, malformed, and
    // incorrect tokens all yield the same generic 401.
    let guard = middleware::from_fn(move |request: Request, next: Next| {
        let token = token.clone();
        async move {
            let presented = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "));
            match presented {
                Some(presented) if constant_time_eq(presented, &token) => next.run(request).await,
                _ => unauthorized(),
            }
        }
    });
    Router::new()
        .route("/healthz", get(healthz))
        .merge(
            Router::new()
                .route("/api/v1/overview", get(overview))
                .route("/api/v1/sisters", get(sisters))
                .route("/api/v1/sisters/{id}", get(sister))
                .route("/api/v1/streams", get(streams))
                .route("/api/v1/jobs", post(submit_job))
                .route("/api/v1/sisters/{id}/ping", post(ping))
                .route_layer(guard),
        )
        .with_state(handle)
}

pub fn validate_bind(bind: SocketAddr) -> Result<(), ApiError> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "the Misaka API is loopback-only",
        ))
    }
}

pub async fn serve(
    handle: SisterHandle,
    token: String,
    address: SocketAddr,
    shutdown: ShutdownToken,
) -> Result<SocketAddr, ApiError> {
    let server = bind(handle, token, address).await?;
    let bound = server.bound;
    server.run(shutdown).await?;
    Ok(bound)
}

pub async fn bind(
    handle: SisterHandle,
    token: String,
    bind: SocketAddr,
) -> Result<ApiServer, ApiError> {
    validate_bind(bind)?;
    let listener = TcpListener::bind(bind).await.map_err(ApiError::internal)?;
    let bound = listener.local_addr().map_err(ApiError::internal)?;
    tracing::info!(event = "api_started", address = %bound, "local Sister API started");
    Ok(ApiServer {
        listener,
        app: router(handle, token),
        bound,
    })
}

impl ApiServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.bound
    }

    pub async fn run(self, shutdown: ShutdownToken) -> Result<(), ApiError> {
        let graceful_shutdown = async move { shutdown.cancelled().await };
        axum::serve(self.listener, self.app)
            .with_graceful_shutdown(graceful_shutdown)
            .await
            .map_err(ApiError::internal)?;
        Ok(())
    }
}

async fn overview(State(handle): State<SisterHandle>) -> Result<Json<OverviewResponse>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    let online_sisters = snapshot.peers.len() + 1;
    Ok(Json(OverviewResponse {
        network_id: snapshot.network_id.to_string(),
        this_sister: snapshot.identity.id.as_u64().to_string(),
        this_nickname: snapshot.identity.nickname.as_str().to_string(),
        online_sisters,
        known_sisters: online_sisters,
        active_streams: snapshot.stream_summary.streams,
        version: snapshot.identity.version,
    }))
}

async fn sisters(
    State(handle): State<SisterHandle>,
) -> Result<Json<Vec<SisterResponse>>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    Ok(Json(all_sisters(&snapshot)))
}

async fn sister(
    State(handle): State<SisterHandle>,
    Path(id): Path<u64>,
) -> Result<Json<SisterResponse>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    all_sisters(&snapshot)
        .into_iter()
        .find(|sister| sister.id == id.to_string())
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, format!("Sister #{id} was not found")))
}

async fn streams(
    State(handle): State<SisterHandle>,
) -> Result<Json<Vec<StreamResponse>>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    Ok(Json(
        snapshot
            .active_streams
            .into_iter()
            .map(StreamResponse::from)
            .collect(),
    ))
}

/// Body of `POST /api/v1/jobs`: submit a Job through the running Sister over the
/// authenticated Iroh control plane. `sister` selects a directed executor; omit
/// it for scheduler-chosen execution.
#[derive(Debug, Deserialize)]
pub struct JobSubmitRequest {
    pub command: String,
    #[serde(default)]
    pub sister: Option<u64>,
}

async fn submit_job(
    State(handle): State<SisterHandle>,
    Json(request): Json<JobSubmitRequest>,
) -> Result<Json<JobResultData>, ApiError> {
    let result = handle
        .submit_job(&request.command, request.sister)
        .await
        .map_err(|error| {
            // A submission/routing failure is reported distinctly from a
            // successful-but-no-result timeout (whose message says "timed out").
            ApiError::new(StatusCode::BAD_GATEWAY, error.to_string())
        })?;
    Ok(Json(result))
}

async fn ping(
    State(handle): State<SisterHandle>,
    Path(id): Path<u64>,
) -> Result<Json<PingResponse>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    if !all_sisters(&snapshot)
        .iter()
        .any(|sister| sister.id == id.to_string())
    {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("Sister #{id} was not found"),
        ));
    }
    handle.ping(id).await.map_err(ApiError::internal)?;
    Ok(Json(PingResponse {
        sister_id: id.to_string(),
        status: "reachable",
    }))
}

fn all_sisters(snapshot: &IntrospectionSnapshot) -> Vec<SisterResponse> {
    let mut sisters = Vec::with_capacity(snapshot.peers.len() + 1);
    sisters.push(SisterResponse {
        id: snapshot.identity.id.as_u64().to_string(),
        nickname: snapshot.identity.nickname.as_str().to_string(),
        hostname: snapshot.identity.hostname.clone(),
        platform: snapshot.identity.platform.clone(),
        version: snapshot.identity.version.clone(),
        status: "online".to_string(),
        control_endpoint: format!("127.0.0.1:{}", snapshot.identity.listen_port),
        stream_endpoints: vec![],
        cpu_usage: snapshot.resources.cpu_usage,
        memory_total: snapshot.resources.memory_total,
        memory_used: snapshot.resources.memory_used,
        running_jobs: snapshot.resources.running_jobs,
        queued_jobs: snapshot.resources.queued_jobs,
        uptime_secs: snapshot.resources.uptime_secs,
        capabilities: snapshot.resources.capabilities.clone(),
    });
    sisters.extend(snapshot.peers.iter().map(SisterResponse::from));
    sisters.sort_by(|left, right| left.id.cmp(&right.id));
    sisters
}

impl From<&PeerSnapshot> for SisterResponse {
    fn from(peer: &PeerSnapshot) -> Self {
        Self {
            id: peer.id.to_string(),
            nickname: peer.nickname.clone(),
            hostname: peer.hostname.clone(),
            platform: peer.platform.clone(),
            version: peer.version.clone(),
            status: if peer.online { "online" } else { "offline" }.to_string(),
            control_endpoint: peer.addr.clone(),
            stream_endpoints: peer.stream_endpoints.clone(),
            cpu_usage: peer.cpu_usage,
            memory_total: peer.memory_total,
            memory_used: peer.memory_used,
            running_jobs: peer.running_jobs,
            queued_jobs: peer.queued_jobs,
            uptime_secs: peer.uptime_secs,
            capabilities: vec![],
        }
    }
}

impl From<misaka_core::introspection::ActiveStreamSnapshot> for StreamResponse {
    fn from(stream: misaka_core::introspection::ActiveStreamSnapshot) -> Self {
        Self {
            stream_id: stream.stream_id,
            backend: stream.backend,
            route: stream.route,
            rtt_ms: stream.rtt_ms,
            path_switches: stream.path_switches,
            local_endpoint: stream.local_endpoint,
            remote_endpoint: stream.remote_endpoint,
            connected_for_ms: stream.connected_for_ms,
            tx_bytes: stream.tx_bytes,
            rx_bytes: stream.rx_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{router, validate_bind, ErrorResponse};
    use crate::test_support::test_handle;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn authed_get(uri: &str) -> Request<Body> {
        Request::get(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap()
    }

    fn authed_post(uri: &str, body: impl Into<Body>) -> Request<Body> {
        Request::post(uri)
            .header("authorization", format!("Bearer {TOKEN}"))
            .header("content-type", "application/json")
            .body(body.into())
            .unwrap()
    }

    #[tokio::test]
    async fn all_v1_read_routes_are_registered() {
        let app = router(test_handle().await, TOKEN.to_string());

        let overview = app
            .clone()
            .oneshot(authed_get("/api/v1/overview"))
            .await
            .unwrap();
        assert_eq!(overview.status(), StatusCode::OK);
        let overview_body = to_bytes(overview.into_body(), 4096).await.unwrap();
        let overview_json: serde_json::Value = serde_json::from_slice(&overview_body).unwrap();
        assert_eq!(overview_json["this_nickname"], "api");

        let sisters = app
            .clone()
            .oneshot(authed_get("/api/v1/sisters"))
            .await
            .unwrap();
        assert_eq!(sisters.status(), StatusCode::OK);

        let detail = app
            .clone()
            .oneshot(authed_get("/api/v1/sisters/1"))
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);

        let streams = app
            .clone()
            .oneshot(authed_get("/api/v1/streams"))
            .await
            .unwrap();
        assert_eq!(streams.status(), StatusCode::OK);

        let job = app
            .clone()
            .oneshot(authed_post(
                "/api/v1/jobs",
                Body::from(serde_json::json!({ "command": "printf j", "sister": 999 }).to_string()),
            ))
            .await
            .unwrap();
        // The route is registered (it attempts the job; #999 is unknown so it is
        // reported as a submit/routing failure, not a 404 method-not-allowed).
        assert_ne!(job.status(), StatusCode::NOT_FOUND);
        let _ = to_bytes(job.into_body(), 4096).await.unwrap();

        let ping = app
            .oneshot(authed_post("/api/v1/sisters/1/ping", Body::empty()))
            .await
            .unwrap();
        assert_eq!(ping.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_sister_returns_a_small_json_error() {
        let app = router(test_handle().await, TOKEN.to_string());
        let response = app.oneshot(authed_get("/api/v1/sisters/99")).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(error.error, "Sister #99 was not found");
    }

    #[test]
    fn non_loopback_bind_is_rejected() {
        let result = validate_bind("0.0.0.0:31702".parse().unwrap());
        assert!(result.is_err());
    }

    // LC01: a missing token is rejected with 401.
    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let app = router(test_handle().await, TOKEN.to_string());
        let response = app
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // LC02: an incorrect token is rejected with 401.
    #[tokio::test]
    async fn wrong_token_is_unauthorized() {
        let app = router(test_handle().await, TOKEN.to_string());
        let response = app
            .oneshot(
                Request::get("/api/v1/overview")
                    .header("authorization", "Bearer deadbeef")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // LC03: the correct token is accepted.
    #[tokio::test]
    async fn correct_token_is_accepted() {
        let app = router(test_handle().await, TOKEN.to_string());
        let response = app.oneshot(authed_get("/api/v1/overview")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // LC04: a malformed Authorization header is rejected with 401, with the
    // same generic body as the other failures (no oracle).
    #[tokio::test]
    async fn malformed_authorization_header_is_unauthorized() {
        let app = router(test_handle().await, TOKEN.to_string());
        let cases = [
            "Token abc",
            "Bearer",
            "Bearer ",
            "bearer 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        for value in cases {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/api/v1/overview")
                        .header("authorization", value)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "header {value:?}"
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            let error: ErrorResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(error.error, "unauthorized");
            assert!(!error.error.contains(TOKEN));
        }
    }

    // The unauthenticated liveness endpoint works and reveals nothing.
    #[tokio::test]
    async fn healthz_is_public_and_minimal() {
        let app = router(test_handle().await, TOKEN.to_string());
        let response = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({ "status": "ok" }));
    }
}

#[cfg(test)]
mod test_support {
    use misaka_core::{NetworkId, SisterIdentity};
    use misaka_runtime::config::{DiscoveryMode, RuntimeConfig};
    use misaka_runtime::runtime::{default_encryption_key, SisterRuntime};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub async fn test_handle() -> misaka_runtime::SisterHandle {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir: PathBuf = std::env::temp_dir().join(format!("misaka-api-test-{suffix}"));
        SisterRuntime::new(
            SisterIdentity::new(
                42,
                "api".into(),
                "host".into(),
                "test".into(),
                "0.1".into(),
                0,
            ),
            default_encryption_key(),
            RuntimeConfig {
                data_dir,
                network_id: NetworkId::generate(),
                listen_port: 0,
                discovery: DiscoveryMode::Off,
                ..Default::default()
            },
            vec![],
        )
        .await
        .unwrap()
        .handle()
    }
}
