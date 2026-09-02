use simple_mdns::async_discovery::ServiceDiscovery;
use simple_mdns::InstanceInformation;
use std::net::SocketAddr;

pub const MISAKA_SERVICE: &str = "_misaka._tcp.local";

/// mDNS 会携带的 TXT 属性键
pub const TXT_ID: &str = "id";
pub const TXT_NICK: &str = "nick";
pub const TXT_HOST: &str = "host";
pub const TXT_PLATFORM: &str = "platform";

/// 通过 mDNS 广播本 Sister 服务。
///
/// 返回持有 guard —— 把它保持存活即可持续广播；退出时可调用
/// `remove_service_from_discovery` 优雅下线。
pub fn advertise(
    nickname: &str,
    sister_id: u64,
    hostname: &str,
    platform: &str,
    port: u16,
    report: tokio::sync::mpsc::Sender<InstanceInformation>,
) -> Result<ServiceDiscovery, simple_mdns::SimpleMdnsError> {
    let info = InstanceInformation::new(nickname.to_string())
        // 单机测试用 127.0.0.1；真实局域网应使用机器 IP (见 ADVERTISE_HOST 说明)
        .with_socket_address(format!("127.0.0.1:{}", port).parse().unwrap())
        .with_attribute(TXT_ID.to_string(), Some(sister_id.to_string()))
        .with_attribute(TXT_NICK.to_string(), Some(nickname.to_string()))
        .with_attribute(TXT_HOST.to_string(), Some(hostname.to_string()))
        .with_attribute(TXT_PLATFORM.to_string(), Some(platform.to_string()));

    ServiceDiscovery::new_with_scope(
        info,
        MISAKA_SERVICE,
        60,
        Some(report),
        simple_mdns::NetworkScope::V4,
    )
}

/// 把 mDNS 发现的 InstanceInformation 解析成本节点可用的 (id, nickname, socket_addr)。
pub fn instance_to_peer(instance: &InstanceInformation) -> Option<(u64, String, SocketAddr)> {
    let mut id = None;
    let mut nick = None;
    let mut addr = None;

    // TXT 属性
    for (k, v) in &instance.attributes {
        let v = v.as_deref().unwrap_or("");
        match k.as_str() {
            TXT_ID => id = v.parse::<u64>().ok(),
            TXT_NICK => nick = Some(v.to_string()),
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

    Some((id, nick, addr))
}
