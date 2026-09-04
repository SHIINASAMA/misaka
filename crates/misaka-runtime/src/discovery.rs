use misaka_core::NetworkId;
use misaka_network::NetworkEndpoint;
use simple_mdns::async_discovery::ServiceDiscovery;
use simple_mdns::InstanceInformation;
use std::net::SocketAddr;

pub const MISAKA_SERVICE: &str = "_misaka._tcp.local";

/// mDNS 会携带的 TXT 属性键
pub const TXT_ID: &str = "id";
pub const TXT_NICK: &str = "nick";
pub const TXT_HOST: &str = "host";
pub const TXT_PLATFORM: &str = "platform";
pub const TXT_STREAM_PORT: &str = "stream_port";
pub const TXT_NETWORK_ID: &str = "network_id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub network_id: NetworkId,
    pub id: u64,
    pub nickname: String,
    pub control_addr: SocketAddr,
    pub stream_endpoint: Option<NetworkEndpoint>,
}

/// 通过 mDNS 广播本 Sister 服务。
///
/// 返回持有 guard —— 把它保持存活即可持续广播；退出时可调用
/// `remove_service_from_discovery` 优雅下线。
pub fn advertise(
    nickname: &str,
    sister_id: u64,
    network_id: NetworkId,
    hostname: &str,
    platform: &str,
    addr: SocketAddr,
    stream_port: Option<u16>,
    report: tokio::sync::mpsc::Sender<InstanceInformation>,
) -> Result<ServiceDiscovery, simple_mdns::SimpleMdnsError> {
    let mut info = InstanceInformation::new(nickname.to_string())
        .with_socket_address(addr)
        .with_attribute(TXT_ID.to_string(), Some(sister_id.to_string()))
        .with_attribute(TXT_NETWORK_ID.to_string(), Some(network_id.to_string()))
        .with_attribute(TXT_NICK.to_string(), Some(nickname.to_string()))
        .with_attribute(TXT_HOST.to_string(), Some(hostname.to_string()))
        .with_attribute(TXT_PLATFORM.to_string(), Some(platform.to_string()));
    if let Some(stream_port) = stream_port {
        info = info.with_attribute(TXT_STREAM_PORT.to_string(), Some(stream_port.to_string()));
    }

    ServiceDiscovery::new_with_scope(
        info,
        MISAKA_SERVICE,
        60,
        Some(report),
        simple_mdns::NetworkScope::V4,
    )
}

/// 把 mDNS 发现的 InstanceInformation 解析成本节点可用的 (id, nickname, socket_addr)。
pub fn instance_to_peer(instance: &InstanceInformation) -> Option<DiscoveredPeer> {
    let mut id = None;
    let mut nick = None;
    let mut addr = None;
    let mut stream_port = None;
    let mut network_id = None;

    // TXT 属性
    for (k, v) in &instance.attributes {
        let v = v.as_deref().unwrap_or("");
        match k.as_str() {
            TXT_ID => id = v.parse::<u64>().ok(),
            TXT_NICK => nick = Some(v.to_string()),
            TXT_STREAM_PORT => stream_port = v.parse::<u16>().ok(),
            TXT_NETWORK_ID => network_id = NetworkId::parse(v).ok(),
            _ => {}
        }
    }
    let id = id?;
    let nick = nick.unwrap_or_else(|| format!("misaka-{}", id));

    // socket 地址 (取最后一个 ip+port 组合即可)
    for ip in &instance.ip_addresses {
        for port in &instance.ports {
            addr = Some(SocketAddr::new(*ip, *port));
        }
    }
    let addr = addr?;

    Some(DiscoveredPeer {
        network_id: network_id.unwrap_or_default(),
        id,
        nickname: nick,
        control_addr: addr,
        stream_endpoint: stream_port
            .map(|port| NetworkEndpoint::Tcp(SocketAddr::new(addr.ip(), port))),
    })
}

#[cfg(test)]
mod tests {
    use super::{instance_to_peer, TXT_ID, TXT_NETWORK_ID, TXT_NICK, TXT_STREAM_PORT};
    use simple_mdns::InstanceInformation;

    #[test]
    fn discovery_metadata_contains_a_separate_stream_endpoint() {
        let instance = InstanceInformation::new("alpha".into())
            .with_socket_address("127.0.0.1:31700".parse().unwrap())
            .with_attribute(TXT_ID.into(), Some("42".into()))
            .with_attribute(TXT_NICK.into(), Some("alpha".into()))
            .with_attribute(
                TXT_NETWORK_ID.into(),
                Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            )
            .with_attribute(TXT_STREAM_PORT.into(), Some("31701".into()));

        let peer = instance_to_peer(&instance).unwrap();
        assert_eq!(peer.id, 42);
        assert_eq!(
            peer.network_id.to_string(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        assert_eq!(peer.control_addr, "127.0.0.1:31700".parse().unwrap());
        assert_eq!(
            peer.stream_endpoint,
            Some("tcp://127.0.0.1:31701".parse().unwrap())
        );
    }
}
