//! The origin must not be able to distinguish a proxied request from a direct
//! one. Each case sends the *same logical request* twice — once straight to a
//! recording origin, once through the proxy — and requires the recorded bytes to
//! match exactly.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, ProxyStats, RuntimeConfig};

const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

/// Accept one connection, record everything received until the peer stops
/// sending for 250ms, then return the exact bytes.
async fn record_one(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            socket.read(&mut buf),
        )
        .await;

        match read {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                received.extend_from_slice(&buf[..n]);
                let _ = socket.write_all(RESPONSE).await;
            }
            Ok(Err(_)) => break,
        }
    }
    received
}

/// Bytes the origin sees when the client connects directly.
async fn direct_bytes(request: &str, origin_placeholder: &str) -> Vec<u8> {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = origin.local_addr().unwrap();
    let task = tokio::spawn(record_one(origin));

    let wire = request.replace(origin_placeholder, &addr.to_string());
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(wire.as_bytes()).await.unwrap();

    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(600),
        client.read_to_end(&mut sink),
    )
    .await;
    drop(client);
    task.await.unwrap()
}

/// Bytes the origin sees when the same request goes through the proxy.
async fn proxied_bytes(request: &str, origin_placeholder: &str) -> Vec<u8> {
    proxied_bytes_with(
        request,
        origin_placeholder,
        Arc::new(RuntimeConfig::anonymous(RewritePolicy::FailClosed)),
    )
    .await
}

/// Same, with an explicit runtime configuration.
async fn proxied_bytes_with(
    request: &str,
    origin_placeholder: &str,
    config: Arc<RuntimeConfig>,
) -> Vec<u8> {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let task = tokio::spawn(record_one(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats, config).await;
    });

    let wire = request.replace(origin_placeholder, &origin_addr.to_string());
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(wire.as_bytes()).await.unwrap();

    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(600),
        client.read_to_end(&mut sink),
    )
    .await;
    drop(client);
    task.await.unwrap()
}

/// A runtime configuration requiring `user:secret`.
fn authenticating_config() -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: Some(Arc::new(
            rust_proxy::auth::Credentials::parse_file_contents("user:secret").unwrap(),
        )),
        allow_from: Vec::new(),
    })
}

/// `direct` is what the client would send on its own; `proxied` is what it sends
/// to a proxy for the same resource. The origin must see identical bytes.
async fn assert_indistinguishable(direct: &str, proxied: &str) {
    let from_direct = direct_bytes(direct, "ORIGIN").await;
    let from_proxy = proxied_bytes(proxied, "ORIGIN").await;

    // Normalize only the origin's own address, which legitimately differs
    // between the two listeners.
    let strip = |bytes: &[u8]| {
        let text = String::from_utf8_lossy(bytes).to_string();
        let re_host = text
            .lines()
            .map(|l| {
                if l.to_lowercase().starts_with("host:") {
                    "Host: NORMALIZED".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        re_host
    };

    assert_eq!(
        strip(&from_direct),
        strip(&from_proxy),
        "origin can distinguish proxied traffic\n direct: {:?}\nproxied: {:?}",
        String::from_utf8_lossy(&from_direct),
        String::from_utf8_lossy(&from_proxy)
    );
}

#[tokio::test]
async fn simple_get_is_indistinguishable() {
    assert_indistinguishable(
        "GET /path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
        "GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn keep_alive_intent_survives_as_connection_not_proxy_connection() {
    // A direct client sends `Connection: keep-alive`. A client talking to a proxy
    // sends `Proxy-Connection: keep-alive`. The origin must see the former.
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nHost: ORIGIN\r\nConnection: keep-alive\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\nProxy-Connection: keep-alive\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn post_with_body_is_indistinguishable() {
    assert_indistinguishable(
        "POST /submit HTTP/1.1\r\nHost: ORIGIN\r\nContent-Length: 9\r\n\r\nkey=value",
        "POST http://ORIGIN/submit HTTP/1.1\r\nHost: ORIGIN\r\nContent-Length: 9\r\n\r\nkey=value",
    )
    .await;
}

#[tokio::test]
async fn chunked_post_is_indistinguishable() {
    assert_indistinguishable(
        "POST /submit HTTP/1.1\r\nHost: ORIGIN\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "POST http://ORIGIN/submit HTTP/1.1\r\nHost: ORIGIN\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn unusual_header_casing_and_spacing_survive() {
    // Canonicalizing these would swap one fingerprint for another.
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nHost: ORIGIN\r\nx-WeIrD:   spaced   \r\nUser-Agent: curl/8.5.0\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\nx-WeIrD:   spaced   \r\nUser-Agent: curl/8.5.0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn header_order_survives() {
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nAccept: */*\r\nHost: ORIGIN\r\nUser-Agent: x\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nAccept: */*\r\nHost: ORIGIN\r\nUser-Agent: x\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn two_requests_on_one_connection_are_indistinguishable() {
    assert_indistinguishable(
        "GET /one HTTP/1.1\r\nHost: ORIGIN\r\n\r\nGET /two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        "GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\r\nGET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn an_authenticated_request_is_indistinguishable_from_direct() {
    // Rule 4 already drops Proxy-Authorization, so adding a credential must
    // change nothing the origin can observe. If this ever fails, the feature
    // has turned a privacy proxy into a fingerprint.
    let direct = "GET /path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n";
    // base64("user:secret")
    let proxied = "GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";

    let from_direct = direct_bytes(direct, "ORIGIN").await;
    let from_proxy = proxied_bytes_with(proxied, "ORIGIN", authenticating_config()).await;

    // Byte-exact after normalizing only the origin's own address, which
    // legitimately differs between the two listeners.
    let normalize = |bytes: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for line in bytes.split_inclusive(|&b| b == b'\n') {
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
                out.extend_from_slice(b"Host: NORMALIZED\r\n");
            } else {
                out.extend_from_slice(line);
            }
        }
        out
    };

    assert_eq!(
        normalize(&from_direct),
        normalize(&from_proxy),
        "origin can distinguish an authenticated proxied request\n direct: {:?}\nproxied: {:?}",
        String::from_utf8_lossy(&from_direct),
        String::from_utf8_lossy(&from_proxy)
    );
}
