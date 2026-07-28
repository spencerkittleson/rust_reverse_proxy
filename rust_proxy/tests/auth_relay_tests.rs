use rust_proxy::auth::{Cidr, Credentials};
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, ProxyStats, RuntimeConfig};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a proxy that serves exactly one connection. Returns its address and
/// the stats it will record into.
async fn one_shot_proxy(config: Arc<RuntimeConfig>) -> (std::net::SocketAddr, Arc<ProxyStats>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, config).await;
    });
    (addr, stats)
}

fn build_config(auth: Option<Credentials>, allow_from: &[&str]) -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: auth.map(Arc::new),
        allow_from: allow_from.iter().map(|s| Cidr::parse(s).unwrap()).collect(),
    })
}

fn config_with_allowlist(specs: &[&str]) -> Arc<RuntimeConfig> {
    build_config(None, specs)
}

fn socks_auth_config() -> Arc<RuntimeConfig> {
    build_config(
        Some(Credentials::parse_file_contents("user:secret").unwrap()),
        &[],
    )
}

/// RFC 1929 sub-negotiation request: VER(0x01) ULEN uname PLEN passwd.
fn rfc1929(user: &str, pass: &str) -> Vec<u8> {
    let mut out = vec![0x01, user.len() as u8];
    out.extend_from_slice(user.as_bytes());
    out.push(pass.len() as u8);
    out.extend_from_slice(pass.as_bytes());
    out
}

#[tokio::test]
async fn a_disallowed_source_gets_no_response_at_all() {
    // Silence, not an error page: a scanner should not learn a proxy is here.
    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["10.0.0.0/8"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET http://e.example/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        response.is_empty(),
        "responded to a disallowed source: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_rejected_connection_is_not_counted_as_a_connection() {
    // Rejecting before the counters run keeps the traffic numbers honest and
    // avoids needing a matching decrement.
    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["10.0.0.0/8"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.write_all(b"x").await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_disallowed_source_sending_socks5_gets_no_response_at_all() {
    // The allowlist gate sits before protocol detection, so it must cover
    // SOCKS5 sources exactly as it covers HTTP ones.
    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["10.0.0.0/8"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        response.is_empty(),
        "responded to a disallowed SOCKS5 source: {:?}",
        response
    );
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_allowed_source_proceeds_normally() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        buf
    });

    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["127.0.0.1"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!("GET http://{origin_addr}/ok HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), origin_task)
        .await
        .expect("origin should have been reached")
        .unwrap();
    let text = String::from_utf8_lossy(&received);
    assert!(text.starts_with("GET /ok HTTP/1.1\r\n"), "{text:?}");
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_empty_allowlist_allows_loopback() {
    let (addr, stats) = one_shot_proxy(Arc::new(RuntimeConfig::anonymous(
        RewritePolicy::FailClosed,
    )))
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client
        .write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\n\r\n")
        .await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn socks5_offers_username_password_when_a_credential_is_configured() {
    // 0x00 must not be offered at all, or the gate is decorative.
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // VER=5, NMETHODS=2, METHODS=[0x00, 0x02]
    client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x02], "expected method 0x02 to be selected");
}

#[tokio::test]
async fn socks5_rejects_a_client_that_cannot_do_username_password() {
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // Offers only 0x00.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0xFF], "expected NO ACCEPTABLE METHODS");
}

#[tokio::test]
async fn socks5_accepts_the_configured_credential() {
    let (addr, stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x02]);

    client.write_all(&rfc1929("user", "secret")).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    // RFC 1929 replies with VER=0x01, not 0x05 — a frequent implementation bug.
    assert_eq!(auth_reply, [0x01, 0x00]);
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn socks5_rejects_a_wrong_password() {
    let (addr, stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();

    client.write_all(&rfc1929("user", "wrong")).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x01], "expected an auth failure reply");

    // And the connection must be closed, not left waiting for a request.
    let mut trailing = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut trailing),
    )
    .await;
    assert!(trailing.is_empty());
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn socks5_rejects_a_bad_subnegotiation_version() {
    // Sending 0x05 here instead of 0x01 is the classic client-side bug; it must
    // be refused rather than silently accepted.
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();

    let mut bad = rfc1929("user", "secret");
    bad[0] = 0x05;
    client.write_all(&bad).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x01]);
}

#[tokio::test]
async fn socks5_under_allow_anonymous_is_unchanged() {
    let (addr, _stats) = one_shot_proxy(Arc::new(RuntimeConfig::anonymous(
        RewritePolicy::FailClosed,
    )))
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00], "anonymous SOCKS5 must be unchanged");
}
