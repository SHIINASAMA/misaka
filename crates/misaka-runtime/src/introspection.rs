//! Read-only introspection endpoint for debugging/testing.
//!
//! NOT part of the Misaka peer protocol. Binds loopback only, never
//! advertised via mDNS, never used by Sisters. Exposes a stable JSON
//! snapshot so external harnesses (Testament) can observe behavior.
//!
//! Hard rules (§13):
//! - disabled by default
//! - explicitly enabled via config
//! - binds to loopback only
//! - read-only
//! - not advertised through mDNS
//! - not used by Sisters
//!
//! The snapshot data types live in misaka-core so external harnesses can
//! deserialize them without depending on this crate.

use misaka_core::introspection::IntrospectionSnapshot;
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// 是否属于 loopback 地址 (127.0.0.0/8 或 ::1)。
pub fn is_loopback(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// 在 loopback 上起一个极简 TCP 服务器：每次连接读取一行，返回一行 JSON snapshot。
/// 返回实际绑定的地址。
///
/// 绑定地址必须是 loopback (§13)。若非 loopback 则拒绝启动，防止配置错误
/// 把只读观测面暴露到局域网/公网。调用方传入 `SocketAddr`，此处强制校验。
pub async fn spawn_server(
    bind: SocketAddr,
    snapshot: impl Fn() -> BoxFuture<IntrospectionSnapshot> + Send + Sync + 'static,
) -> std::io::Result<SocketAddr> {
    if !is_loopback(bind) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("introspection must bind loopback only, got {bind}"),
        ));
    }
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let snapshot = std::sync::Arc::new(snapshot);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let snapshot = snapshot.clone();
            tokio::spawn(async move {
                let _ = handle(stream, snapshot).await;
            });
        }
    });
    Ok(addr)
}

async fn handle(
    mut stream: TcpStream,
    snapshot: std::sync::Arc<impl Fn() -> BoxFuture<IntrospectionSnapshot>>,
) -> std::io::Result<()> {
    let snap = snapshot().await;
    let json = serde_json::to_vec(&snap).map_err(|e| std::io::Error::other(e.to_string()))?;
    stream.write_all(&json).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback("127.0.0.1:8080".parse().unwrap()));
        assert!(is_loopback("[::1]:8080".parse().unwrap()));
        assert!(!is_loopback("0.0.0.0:8080".parse().unwrap()));
        assert!(!is_loopback("192.168.1.10:8080".parse().unwrap()));
        assert!(!is_loopback("[::]:8080".parse().unwrap()));
    }
}
