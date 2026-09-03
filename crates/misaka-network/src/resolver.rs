//! Candidate ranking for multi-path Sister connectivity.
//!
//! The first implementation only understands TCP endpoints. Keeping the
//! ranking here lets future relay/P2P backends add candidates without making
//! callers parse transport-specific addresses.

use crate::NetworkEndpoint;
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
        let NetworkEndpoint::Tcp(address) = endpoint;
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

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::{rank_candidates, EndpointCandidate, PathKind};
    use crate::NetworkEndpoint;
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
}
