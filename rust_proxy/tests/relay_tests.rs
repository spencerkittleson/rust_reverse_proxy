use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rust_proxy::auth::Credentials;
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, Ordering, ProxyStats, RuntimeConfig};

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
    proxy_roundtrip_with(client_bytes, Arc::new(RuntimeConfig::anonymous(policy))).await
}

/// Same, with an explicit runtime configuration, for the auth cases.
async fn proxy_roundtrip_with(
    client_bytes: &[u8],
    config: Arc<RuntimeConfig>,
) -> (Vec<u8>, Arc<ProxyStats>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(recording_origin_or_nothing(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();

    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, config).await;
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

/// Origin that records bytes but gives up if it is never dialed.
///
/// A refused request means the proxy never connects, so a bare
/// `recording_origin` would block on `accept` forever. Returning an empty
/// recording is exactly the observation the auth tests need.
async fn recording_origin_or_nothing(listener: TcpListener) -> Vec<u8> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        recording_origin(listener),
    )
    .await
    {
        Ok(received) => received,
        Err(_) => Vec::new(),
    }
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

fn auth_config(file_contents: &str) -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: Some(Arc::new(
            Credentials::parse_file_contents(file_contents).unwrap(),
        )),
        allow_from: Vec::new(),
    })
}

#[tokio::test]
async fn unauthenticated_request_never_reaches_the_origin() {
    // The check has to happen before the origin dial, so the origin must see
    // nothing at all — not even a connection's worth of zero bytes.
    let request = b"GET http://ORIGIN/secret HTTP/1.1\r\nHost: ORIGIN\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    assert!(
        received.is_empty(),
        "origin saw bytes from an unauthenticated client: {:?}",
        String::from_utf8_lossy(&received)
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_wrong_password_never_reaches_the_origin() {
    // base64("user:wrong")
    let request = b"GET http://ORIGIN/secret HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    assert!(received.is_empty(), "{:?}", String::from_utf8_lossy(&received));
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_authenticated_request_reaches_the_origin_without_the_credential() {
    // base64("user:secret"). Rule 4 already drops Proxy-Authorization, so the
    // credential must not appear upstream and the request must be rewritten to
    // origin form as usual.
    let request = b"GET http://ORIGIN/ok HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    let text = String::from_utf8(received.clone()).expect("origin bytes must be UTF-8 here");
    assert!(text.starts_with("GET /ok HTTP/1.1\r\n"), "{text:?}");
    assert!(
        !text.to_lowercase().contains("proxy-authorization"),
        "credential leaked upstream: {text:?}"
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 1);
}

/// Send `request` (with `ORIGIN` replaced by a listener that never accepts) to
/// an authenticating proxy and return the client-visible response bytes plus
/// the proxy's stats. Used by the tests that need to inspect the 407 itself,
/// which `proxy_roundtrip_with` cannot show because it reports origin bytes.
async fn challenge_for(request_template: &str) -> (Vec<u8>, Arc<ProxyStats>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();
    let config = auth_config("user:secret");
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, config).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let wire = request_template.replace("ORIGIN", &origin_addr.to_string());
    client.write_all(wire.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    drop(origin);
    (response, stats)
}

#[tokio::test]
async fn an_unauthenticated_client_is_told_how_to_authenticate() {
    // A bare close would leave a client guessing. The 407 must name the scheme
    // and must not carry Server or Date.
    let (response, _stats) =
        challenge_for("GET http://ORIGIN/x HTTP/1.1\r\nHost: ORIGIN\r\n\r\n").await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 407 "), "{text:?}");
    assert!(text.contains("Proxy-Authenticate: Basic"), "{text:?}");
    let lowered = text.to_lowercase();
    assert!(!lowered.contains("\r\nserver:"), "{text:?}");
    assert!(!lowered.contains("\r\ndate:"), "{text:?}");
}

#[tokio::test]
async fn unauthenticated_connect_is_refused_before_the_tunnel_opens() {
    let (response, stats) =
        challenge_for("CONNECT ORIGIN HTTP/1.1\r\nHost: ORIGIN\r\n\r\n").await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 407 "), "{text:?}");
    assert!(
        !text.contains("200 Connection Established"),
        "a tunnel was acknowledged to an unauthenticated client: {text:?}"
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn allow_anonymous_leaves_http_behavior_unchanged() {
    let request = b"GET http://ORIGIN/plain HTTP/1.1\r\nHost: ORIGIN\r\n\r\n";
    let (received, stats) = proxy_roundtrip(request, RewritePolicy::FailClosed).await;
    let text = String::from_utf8(received).unwrap();
    assert!(text.starts_with("GET /plain HTTP/1.1\r\n"), "{text:?}");
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_refused_request_with_a_body_still_receives_the_challenge() {
    // Dropping the socket with the body still unread sends an RST that can
    // discard the 407 we just wrote, so the client sees a connection reset
    // instead of being told it needs to authenticate.
    let (response, stats) = challenge_for(
        "POST http://ORIGIN/submit HTTP/1.1\r\n\
         Host: ORIGIN\r\n\
         Content-Length: 11\r\n\
         \r\n\
         hello world",
    )
    .await;
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 407 "), "{text:?}");
    assert!(text.contains("Proxy-Authenticate: Basic"), "{text:?}");
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_later_request_without_the_credential_never_reaches_the_origin() {
    // The bypass Task 7 closes, observed at the socket: one authenticated
    // request must not unlock the connection for the ones behind it. This is
    // also the only test that proves `connect_and_tunnel` actually hands the
    // credential set to the `RequestStream`; a wiring regression there would
    // pass every unit test in `http_rewrite_tests`.
    let request = b"GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n\
                    GET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;

    let text = String::from_utf8_lossy(&received);
    assert!(
        !text.contains("/two"),
        "an unauthenticated second request reached the origin: {text:?}"
    );
    assert!(
        stats.auth_failures.load(Ordering::Relaxed) >= 1,
        "the second request was not recorded as an auth failure"
    );
}

#[tokio::test]
async fn both_authenticated_pipelined_requests_reach_the_origin() {
    // The false-reject control for
    // `a_later_request_without_the_credential_never_reaches_the_origin`: that
    // test's assertions also pass if the per-head check refuses everything, so
    // this one proves a valid credential on head 2 is still honored.
    let request = b"GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n\
                    GET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;

    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("GET /one HTTP/1.1"), "{text:?}");
    assert!(text.contains("GET /two HTTP/1.1"), "{text:?}");
    assert!(
        !text.to_lowercase().contains("proxy-authorization"),
        "credential leaked upstream: {text:?}"
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
}

