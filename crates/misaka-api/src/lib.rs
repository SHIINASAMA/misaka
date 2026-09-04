use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use misaka_core::introspection::{IntrospectionSnapshot, PeerSnapshot};
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

#[derive(Debug, Clone, Serialize)]
pub struct OverviewResponse {
    pub network_id: String,
    pub this_sister: u64,
    pub this_nickname: String,
    pub online_sisters: usize,
    pub known_sisters: usize,
    pub active_streams: usize,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SisterResponse {
    pub id: u64,
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
    pub sister_id: u64,
    pub status: &'static str,
}

pub fn router(handle: SisterHandle) -> Router {
    Router::new()
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/sisters", get(sisters))
        .route("/api/v1/sisters/{id}", get(sister))
        .route("/api/v1/streams", get(streams))
        .route("/api/v1/sisters/{id}/ping", post(ping))
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
    bind: SocketAddr,
    shutdown: ShutdownToken,
) -> Result<SocketAddr, ApiError> {
    validate_bind(bind)?;
    let listener = TcpListener::bind(bind).await.map_err(ApiError::internal)?;
    let bound = listener.local_addr().map_err(ApiError::internal)?;
    tracing::info!(event = "api_started", address = %bound, "local Sister API started");
    let graceful_shutdown = async move { shutdown.cancelled().await };
    axum::serve(listener, router(handle))
        .with_graceful_shutdown(graceful_shutdown)
        .await
        .map_err(ApiError::internal)?;
    Ok(bound)
}

async fn overview(State(handle): State<SisterHandle>) -> Result<Json<OverviewResponse>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    let online_sisters = snapshot.peers.len() + 1;
    Ok(Json(OverviewResponse {
        network_id: snapshot.network_id.to_string(),
        this_sister: snapshot.identity.id.as_u64(),
        this_nickname: snapshot.identity.nickname.to_string(),
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
        .find(|sister| sister.id == id)
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

async fn ping(
    State(handle): State<SisterHandle>,
    Path(id): Path<u64>,
) -> Result<Json<PingResponse>, ApiError> {
    let snapshot = handle.snapshot().await.map_err(ApiError::internal)?;
    if !all_sisters(&snapshot).iter().any(|sister| sister.id == id) {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("Sister #{id} was not found"),
        ));
    }
    handle.ping(id).await.map_err(ApiError::internal)?;
    Ok(Json(PingResponse {
        sister_id: id,
        status: "reachable",
    }))
}

fn all_sisters(snapshot: &IntrospectionSnapshot) -> Vec<SisterResponse> {
    let mut sisters = Vec::with_capacity(snapshot.peers.len() + 1);
    sisters.push(SisterResponse {
        id: snapshot.identity.id.as_u64(),
        nickname: snapshot.identity.nickname.to_string(),
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
    sisters.sort_by_key(|sister| sister.id);
    sisters
}

impl From<&PeerSnapshot> for SisterResponse {
    fn from(peer: &PeerSnapshot) -> Self {
        Self {
            id: peer.id,
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

    #[tokio::test]
    async fn all_v1_read_routes_are_registered() {
        let handle = test_handle().await;
        let app = router(handle);

        let overview = app
            .clone()
            .oneshot(
                Request::get("/api/v1/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(overview.status(), StatusCode::OK);

        let sisters = app
            .clone()
            .oneshot(Request::get("/api/v1/sisters").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(sisters.status(), StatusCode::OK);

        let detail = app
            .clone()
            .oneshot(
                Request::get("/api/v1/sisters/1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(detail.status(), StatusCode::NOT_FOUND);

        let streams = app
            .clone()
            .oneshot(Request::get("/api/v1/streams").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(streams.status(), StatusCode::OK);

        let ping = app
            .oneshot(
                Request::post("/api/v1/sisters/1/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ping.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_sister_returns_a_small_json_error() {
        let app = router(test_handle().await);
        let response = app
            .oneshot(
                Request::get("/api/v1/sisters/99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

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
