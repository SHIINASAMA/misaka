//! Observer: poll a Sister's read-only introspection endpoint and deserialize
//! the snapshot. This is the ONLY observation surface Testament trusts —
//! logs are diagnostic evidence, never the assertion source (§12).

use misaka_core::introspection::IntrospectionSnapshot;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// 读取一次 snapshot (len-prefixed to stdout? No: server writes raw JSON then closes).
/// 这里用阻塞式 TCP 读一整段 (服务端写完即 flush + 关连接)。
pub fn fetch(addr: SocketAddr, timeout: Duration) -> std::io::Result<IntrospectionSnapshot> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let snap: IntrospectionSnapshot =
        serde_json::from_slice(&buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(snap)
}

/// 轮询直到 predicate 为真或超时。返回是否达成。
pub fn wait_until(
    addr: SocketAddr,
    timeout: Duration,
    mut predicate: impl FnMut(&IntrospectionSnapshot) -> bool,
) -> Option<IntrospectionSnapshot> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(snap) = fetch(addr, Duration::from_millis(500)) {
            if predicate(&snap) {
                return Some(snap);
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
