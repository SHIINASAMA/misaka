//! Candidate ranking for multi-path Sister connectivity.
//!
//! The first implementation only understands TCP endpoints. Keeping the
//! ranking here lets future relay/P2P backends add candidates without making
//! callers parse transport-specific addresses.

use crate::NetworkEndpoint;
use crate::{NetworkBackend, NetworkError, NetworkStream, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PathKind {
    Lan,
    Direct,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointCandidate {
    pub endpoint: NetworkEndpoint,
    pub kind: PathKind,
    pub priority: u8,
}

impl EndpointCandidate {
    pub fn tcp(endpoint: NetworkEndpoint) -> Self {
        let NetworkEndpoint::Tcp(address) = endpoint.clone() else {
            panic!("EndpointCandidate::tcp requires a TCP endpoint");
        };
        let kind = if address.ip().is_loopback() || is_private(address.ip()) {
            PathKind::Lan
        } else {
            PathKind::Direct
        };
        let priority = match kind {
            PathKind::Lan => 10,
            PathKind::Direct => 20,
            PathKind::Relay => 30,
        };
        Self {
            endpoint,
            kind,
            priority,
        }
    }
}

/// Return candidates in the roadmap's initial order: LAN, direct, relay.
pub fn rank_candidates(mut candidates: Vec<EndpointCandidate>) -> Vec<EndpointCandidate> {
    candidates.sort_by_key(|candidate| candidate.priority);
    candidates
}

/// Race all ranked candidates and return the first successful stream.
///
/// The backend owns transport establishment; the resolver only coordinates
/// candidate futures and drops losing attempts once a winner is available.
pub async fn race_connect<B: NetworkBackend>(
    backend: &B,
    candidates: Vec<EndpointCandidate>,
) -> Result<(NetworkStream, EndpointCandidate)> {
    let candidates = rank_candidates(candidates);
    if candidates.is_empty() {
        return Err(NetworkError::Handshake {
            reason: "no endpoint candidates".to_string(),
        });
    }
    let mut attempts = FuturesUnordered::new();
    for candidate in candidates {
        attempts.push(async move {
            let result = backend.connect(candidate.endpoint.clone()).await;
            (candidate, result)
        });
    }
    let mut last_error = None;
    while let Some((candidate, result)) = attempts.next().await {
        match result {
            Ok(stream) => return Ok((stream, candidate)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.expect("non-empty candidate set produces an attempt"))
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::{race_connect, rank_candidates, EndpointCandidate, PathKind};
    use crate::{DirectTcpBackend, NetworkEndpoint};
    use std::net::SocketAddr;

    #[test]
    fn tcp_candidates_prefer_lan_before_public_direct() {
        let public = EndpointCandidate::tcp(NetworkEndpoint::Tcp(
            "198.51.100.20:31701".parse::<SocketAddr>().unwrap(),
        ));
        let lan = EndpointCandidate::tcp(NetworkEndpoint::Tcp(
            "192.168.1.20:31701".parse::<SocketAddr>().unwrap(),
        ));
        let ranked = rank_candidates(vec![public, lan]);
        assert_eq!(ranked[0].kind, PathKind::Lan);
        assert_eq!(
            ranked[0].endpoint,
            NetworkEndpoint::Tcp("192.168.1.20:31701".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn racing_candidates_returns_the_first_successful_stream() {
        let listener = crate::listen("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .await
            .unwrap();
        let good = listener.local_addr();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"race-ok")
                .await
                .unwrap();
        });
        let bad = "127.0.0.1:9".parse().unwrap();
        let (mut stream, candidate) = race_connect(
            &DirectTcpBackend,
            vec![
                EndpointCandidate::tcp(NetworkEndpoint::Tcp(bad)),
                EndpointCandidate::tcp(NetworkEndpoint::Tcp(good)),
            ],
        )
        .await
        .unwrap();
        let mut response = [0u8; 7];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"race-ok");
        assert_eq!(candidate.endpoint, NetworkEndpoint::Tcp(good));
    }
}
