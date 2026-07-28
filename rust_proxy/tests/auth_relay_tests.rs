use rust_proxy::auth::Cidr;
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

fn config_with_allowlist(specs: &[&str]) -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: None,
        allow_from: specs.iter().map(|s| Cidr::parse(s).unwrap()).collect(),
    })
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
