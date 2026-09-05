//! Thin HTTPS client for a Misaka Gateway v0.
//!
//! A Sister holds one `GatewayClient` per configured Gateway. The client owns
//! all HTTP and request-signing detail so `SisterNode` only ever sees
//! `info / announce / peers` returning domain types. Authentication reuses the
//! Sister's existing key and membership — the Gateway needs only the Network
//! Authority PUBLIC key, never the private half, and this client never sends
//! private key material.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use misaka_core::{
    GatewayAnnounceRequest, GatewayAuth, GatewayInfo, GatewayPeersRequest, GatewayPeersResponse,
    MembershipCertificate, NetworkId, PeerRecord, SisterKeyPair,
};
use rand::{rngs::OsRng, RngCore};

use crate::error::MisakaError;

/// A configured Gateway endpoint plus the local identity used to authenticate
/// to it.
#[derive(Clone)]
pub struct GatewayClient {
    base: String,
    http: reqwest::Client,
    network_id: NetworkId,
    sister_id: u64,
    sister_key: SisterKeyPair,
    membership: MembershipCertificate,
}

impl GatewayClient {
    pub fn new(
        base: &str,
        network_id: NetworkId,
        sister_id: u64,
        sister_key: SisterKeyPair,
        membership: MembershipCertificate,
    ) -> Result<Self, MisakaError> {
        let http = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| MisakaError::Other(format!("gateway http client: {error}")))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http,
            network_id,
            sister_id,
            sister_key,
            membership,
        })
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    }

    fn nonce() -> [u8; 16] {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// `GET /.well-known/misaka`: the Gateway's self-description.
    pub async fn info(&self) -> Result<GatewayInfo, MisakaError> {
        let url = format!("{}/.well-known/misaka", self.base);
        self.http
            .get(url)
            .send()
            .await
            .map_err(|error| MisakaError::Other(format!("gateway info: {error}")))?
            .error_for_status()
            .map_err(|error| MisakaError::Other(format!("gateway info status: {error}")))?
            .json::<GatewayInfo>()
            .await
            .map_err(|error| MisakaError::Other(format!("gateway info decode: {error}")))
    }

    /// `POST /v1/announce`: publish the Sister's signed `PeerRecord`.
    pub async fn announce(&self, record: &PeerRecord) -> Result<(), MisakaError> {
        let auth = GatewayAuth::sign_announce(
            self.network_id,
            self.sister_id,
            Self::now_secs(),
            Self::nonce(),
            &self.membership,
            record,
            &self.sister_key,
        );
        let request = GatewayAnnounceRequest {
            auth,
            membership: self.membership.clone(),
            record: record.clone(),
        };
        let url = format!("{}/v1/announce", self.base);
        self.http
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(|error| MisakaError::Other(format!("gateway announce: {error}")))?
            .error_for_status()
            .map_err(|error| MisakaError::Other(format!("gateway announce status: {error}")))?;
        Ok(())
    }

    /// `POST /v1/peers`: fetch the Network's currently-valid signed locators.
    pub async fn peers(&self) -> Result<Vec<PeerRecord>, MisakaError> {
        let auth = GatewayAuth::sign_peers(
            self.network_id,
            self.sister_id,
            Self::now_secs(),
            Self::nonce(),
            &self.sister_key,
        );
        let request = GatewayPeersRequest {
            auth,
            membership: self.membership.clone(),
        };
        let url = format!("{}/v1/peers", self.base);
        let response = self
            .http
            .post(url)
            .json(&request)
            .send()
            .await
            .map_err(|error| MisakaError::Other(format!("gateway peers: {error}")))?
            .error_for_status()
            .map_err(|error| MisakaError::Other(format!("gateway peers status: {error}")))?
            .json::<GatewayPeersResponse>()
            .await
            .map_err(|error| MisakaError::Other(format!("gateway peers decode: {error}")))?;
        Ok(response.records)
    }
}
