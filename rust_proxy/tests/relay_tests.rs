use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, Ordering, ProxyStats};

/// Origin that records the exact bytes it receives, then replies.
async fn recording_origin(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        received.extend_from_slice(&buf[..n]);
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        if received.windows(4).any(|w| w == b"\r\n\r\n") {
            // Give a pipelined second request a chance to arrive.
            let mut extra = [0u8; 4096];
            if let Ok(Ok(m)) = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                socket.read(&mut extra),
            )
            .await
            {
                if m > 0 {
                    received.extend_from_slice(&extra[..m]);
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            }
            break;
        }
    }
    received
}

/// Run one client byte-stream through a real proxy connection and return what
/// the origin actually received.
async fn proxy_roundtrip(client_bytes: &[u8], policy: RewritePolicy) -> (Vec<u8>, Arc<ProxyStats>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(recording_origin(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();

    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, policy).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = String::from_utf8_lossy(client_bytes)
        .replace("ORIGIN", &origin_addr.to_string())
        .into_bytes();
    client.write_all(&request).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;

    let received = origin_task.await.unwrap();
    (received, stats)
}

#[tokio::test]
async fn origin_never_sees_absolute_form() {
    let (received, stats) = proxy_roundtrip(
        b"GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
        "origin got: {text:?}"
    );
    assert!(!text.contains("http://"), "absolute form leaked: {text:?}");
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn origin_never_sees_proxy_headers() {
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\n\
          Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic zzz\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let lowered = String::from_utf8_lossy(&received).to_lowercase();
    assert!(!lowered.contains("proxy-connection"), "{lowered:?}");
    assert!(!lowered.contains("proxy-authorization"), "{lowered:?}");
    assert!(lowered.contains("connection: keep-alive"), "{lowered:?}");
}

#[tokio::test]
async fn second_pipelined_request_is_also_rewritten() {
    // The whole reason for a streaming rewriter rather than a one-shot.
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\r\n\
          GET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("GET /one HTTP/1.1"), "{text:?}");
    assert!(text.contains("GET /two HTTP/1.1"), "{text:?}");
    assert!(!text.contains("http://"), "absolute form leaked: {text:?}");
}

#[tokio::test]
async fn proxy_never_injects_identifying_headers() {
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let lowered = String::from_utf8_lossy(&received).to_lowercase();
    for banned in ["via:", "x-forwarded-for", "forwarded:", "x-real-ip"] {
        assert!(!lowered.contains(banned), "{banned} present in {lowered:?}");
    }
}
