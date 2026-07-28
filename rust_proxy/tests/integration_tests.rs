use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn test_proxy_integration() {
    // Start proxy server in background
    // --allow-anonymous conflicts with a configured credential, and the
    // subprocess inherits our environment. Without this, a developer with
    // RUST_PROXY_AUTH exported sees all of these tests hang rather than fail.
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3130", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    // Give the server time to start
    thread::sleep(Duration::from_secs(2));

    // Test that proxy is accepting connections
    let result = TcpStream::connect("127.0.0.1:3130").await;
    
    // Clean up
    let _ = child.kill();
    let _ = child.wait();
    
    assert!(result.is_ok(), "Proxy server should be accepting connections");
}

#[tokio::test]
async fn test_http_proxy_request() {
    // Start a simple echo server to act as target
    let echo_server = tokio::net::TcpListener::bind("127.0.0.1:3131").await.unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = echo_server.accept().await {
            let mut buffer = [0; 1024];
            if let Ok(_n) = socket.read(&mut buffer).await {
                // Echo back a simple HTTP response
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                let _ = socket.write_all(response).await;
            }
        }
    });

    // Start proxy
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3132", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Test HTTP request through proxy
    let result = TcpStream::connect("127.0.0.1:3132").await;
    
    if let Ok(mut proxy_stream) = result {
        let http_request = b"GET http://127.0.0.1:3131 HTTP/1.1\r\nHost: 127.0.0.1:3131\r\n\r\n";
        let _ = proxy_stream.write_all(http_request).await;
        
        let mut response = [0; 1024];
        if let Ok(n) = proxy_stream.read(&mut response).await {
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.contains("200 OK") || response_str.contains("502"));
        }
    }

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
}

#[tokio::test]
async fn test_connect_proxy_request() {
    // Start a simple server to accept connections
    let simple_server = tokio::net::TcpListener::bind("127.0.0.1:3133").await.unwrap();
    
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = simple_server.accept().await {
            // Just accept the connection and close it
            let _ = socket.shutdown().await;
        }
    });

    // Start proxy
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3134", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Test CONNECT request through proxy
    let result = TcpStream::connect("127.0.0.1:3134").await;
    
    if let Ok(mut proxy_stream) = result {
        let connect_request = b"CONNECT 127.0.0.1:3133 HTTP/1.1\r\nHost: 127.0.0.1:3133\r\n\r\n";
        let _ = proxy_stream.write_all(connect_request).await;
        
        let mut response = [0; 1024];
        if let Ok(n) = proxy_stream.read(&mut response).await {
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.contains("200") || response_str.contains("502"));
        }
    }

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
}

/// End-to-end SOCKS5 test: negotiate no-auth, CONNECT to a local target via
/// IPv4 ATYP, then exchange bytes through the tunnel. Verifies RFC 1928 reply
/// framing.
#[tokio::test]
async fn test_socks5_connect_ipv4() {
    // Target echo-ish server: read up to N bytes, write a known reply, close.
    let target = tokio::net::TcpListener::bind("127.0.0.1:3158").await.unwrap();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = target.accept().await {
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"PONG").await;
            let _ = socket.shutdown().await;
        }
    });

    // Proxy on port 3159 (per user instruction)
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3159", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    let connect_result = timeout(
        Duration::from_secs(5),
        TcpStream::connect("127.0.0.1:3159"),
    )
    .await;

    let mut sock = match connect_result {
        Ok(Ok(s)) => s,
        other => {
            let _ = proxy_child.kill();
            let _ = proxy_child.wait();
            panic!("Could not connect to SOCKS5 proxy on 3159: {:?}", other);
        }
    };

    // --- Method negotiation: VER=5, NMETHODS=1, METHOD=0x00 (no auth) ---
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_reply = [0u8; 2];
    timeout(Duration::from_secs(2), sock.read_exact(&mut method_reply))
        .await
        .expect("method reply timeout")
        .expect("method reply read");
    assert_eq!(method_reply[0], 0x05, "SOCKS version in method reply");
    assert_eq!(method_reply[1], 0x00, "no-auth method must be selected");

    // --- CONNECT request to 127.0.0.1:3158 (IPv4) ---
    // VER | CMD=CONNECT | RSV | ATYP=IPv4 | 127.0.0.1 | port 3158 BE
    let port: u16 = 3158;
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).await.unwrap();

    // Reply: VER | REP | RSV | ATYP=IPv4 | BND.ADDR(4) | BND.PORT(2) = 10 bytes
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(5), sock.read_exact(&mut reply))
        .await
        .expect("connect reply timeout")
        .expect("connect reply read");
    assert_eq!(reply[0], 0x05, "SOCKS version in CONNECT reply");
    assert_eq!(reply[1], 0x00, "REP=succeeded, got 0x{:02x}", reply[1]);
    assert_eq!(reply[2], 0x00, "RSV must be 0");
    assert_eq!(reply[3], 0x01, "ATYP must be IPv4 in our reply");

    // --- Tunnel data: send something, receive PONG ---
    sock.write_all(b"PING").await.unwrap();
    let mut payload = [0u8; 4];
    timeout(Duration::from_secs(5), sock.read_exact(&mut payload))
        .await
        .expect("tunnel read timeout")
        .expect("tunnel read");
    assert_eq!(&payload, b"PONG", "tunneled bytes should round-trip");

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
}

/// SOCKS5 with ATYP=0x03 (domain name). Sends "localhost" as the destination
/// host so the proxy must parse the variable-length domain field and resolve
/// it before connecting. This is the path real clients (curl --socks5-hostname,
/// `nc -X 5`, `ssh -o ProxyCommand`, browsers) take.
#[tokio::test]
async fn test_socks5_connect_domain() {
    // Target server on a fixed port that "localhost" will resolve to.
    let target = tokio::net::TcpListener::bind("127.0.0.1:3162").await.unwrap();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = target.accept().await {
            let mut buf = [0u8; 16];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"DOMAIN_OK").await;
            let _ = socket.shutdown().await;
        }
    });

    // Distinct proxy port to avoid colliding with parallel tests.
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3161", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    let mut sock = match timeout(Duration::from_secs(5), TcpStream::connect("127.0.0.1:3161")).await {
        Ok(Ok(s)) => s,
        other => {
            let _ = proxy_child.kill();
            let _ = proxy_child.wait();
            panic!("Could not connect to SOCKS5 proxy on 3161: {:?}", other);
        }
    };

    // Method negotiation: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method_reply = [0u8; 2];
    timeout(Duration::from_secs(2), sock.read_exact(&mut method_reply))
        .await
        .expect("method reply timeout")
        .expect("method reply read");
    assert_eq!(method_reply, [0x05, 0x00]);

    // CONNECT with ATYP=0x03 (domain), host="localhost", port=3162
    let host = b"localhost";
    let port: u16 = 3162;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    sock.write_all(&req).await.unwrap();

    // Reply: VER | REP | RSV | ATYP=IPv4 | BND.ADDR(4) | BND.PORT(2) = 10 bytes
    // Our proxy always replies with IPv4 0.0.0.0:0 BND regardless of request ATYP.
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(5), sock.read_exact(&mut reply))
        .await
        .expect("connect reply timeout")
        .expect("connect reply read");
    assert_eq!(reply[0], 0x05, "SOCKS version");
    assert_eq!(
        reply[1], 0x00,
        "REP=succeeded for domain ATYP, got 0x{:02x}",
        reply[1]
    );
    assert_eq!(reply[3], 0x01, "BND ATYP must be IPv4");

    // Tunnel
    sock.write_all(b"HELLO").await.unwrap();
    let mut payload = [0u8; 9];
    timeout(Duration::from_secs(5), sock.read_exact(&mut payload))
        .await
        .expect("tunnel read timeout")
        .expect("tunnel read");
    assert_eq!(&payload, b"DOMAIN_OK");

    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
}

/// Regression: catches a refactor that drops the startup credential gate
/// entirely, letting the proxy come up wide open when the operator supplied
/// neither a credential nor an explicit --allow-anonymous opt-out. The gate
/// runs before the listener binds, so the process exits immediately and there
/// is no port to pick. `env_remove` is load-bearing: without it, a developer
/// with the variable exported would satisfy the gate and this test would pass
/// for the wrong reason.
#[test]
fn test_missing_credential_exits_two() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--log-level", "error"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .output()
        .expect("Failed to run proxy binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "no credential and no --allow-anonymous must exit 2, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Configuration error"),
        "stderr should report the configuration error, got: {stderr}"
    );
}

/// Regression: catches removal of the `.filter(|v| !v.trim().is_empty())` on
/// the environment read in `main`. A set-but-blank variable means "no
/// credential", not "a credential named nothing". The distinguishing evidence
/// is the message: filtering to `None` produces "no credential configured",
/// whereas parsing the blank value as a credential file would produce
/// "no credentials found".
#[test]
fn test_whitespace_only_auth_env_is_no_credential() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--log-level", "error"])
        .env(rust_proxy::AUTH_ENV_VAR, "   ")
        .output()
        .expect("Failed to run proxy binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "whitespace-only credential must be rejected, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no credential configured"),
        "blank value must be filtered to None, not parsed as a credential; got: {stderr}"
    );
}

/// Regression: catches a change that resolves contradictory intent silently
/// (for example by letting --allow-anonymous quietly win over a configured
/// credential, which would disable authentication the operator asked for).
#[test]
fn test_credential_plus_allow_anonymous_exits_two() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--host",
            "127.0.0.1",
            "--log-level",
            "error",
            "--allow-anonymous",
        ])
        .env(rust_proxy::AUTH_ENV_VAR, "user:secret")
        .output()
        .expect("Failed to run proxy binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "credential + --allow-anonymous must exit 2, got {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be combined"),
        "stderr should name the conflict, got: {stderr}"
    );
}

/// Regression: catches a gate that rejects every configuration. Without this
/// test the three exit-2 tests above would all still pass even if the
/// environment-variable credential path were broken and no valid setup could
/// ever start. A successful start runs forever, so spawn and probe instead of
/// waiting.
#[test]
fn test_valid_auth_env_starts_proxy() {
    let mut child = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--host",
            "127.0.0.1",
            "--port",
            "3170",
            "--log-level",
            "error",
        ])
        .env(rust_proxy::AUTH_ENV_VAR, "user:secret")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // try_wait() observes the cargo process, not the proxy: if cargo is still
    // compiling or blocked on the build lock at this point, the child is alive
    // and the test would pass without a proxy ever having started. Connecting
    // proves the listener actually bound.
    let connected = std::net::TcpStream::connect("127.0.0.1:3170").is_ok();

    let exited = child.try_wait().expect("try_wait failed");
    let still_running = exited.is_none();

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        connected,
        "a valid {} alone must start the proxy, but nothing accepted a connection on 127.0.0.1:3170",
        rust_proxy::AUTH_ENV_VAR
    );
    assert!(
        still_running,
        "a valid {} alone must start the proxy, but it exited: {:?}",
        rust_proxy::AUTH_ENV_VAR, exited
    );
}

#[tokio::test]
async fn test_proxy_handles_invalid_requests() {
    // Start proxy
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3135", "--log-level", "error", "--allow-anonymous"])
        .env_remove(rust_proxy::AUTH_ENV_VAR)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Test invalid HTTP request
    let result = TcpStream::connect("127.0.0.1:3135").await;
    
    if let Ok(mut proxy_stream) = result {
        let invalid_request = b"Invalid request\r\n\r\n";
        let _ = proxy_stream.write_all(invalid_request).await;
        
        // The proxy should handle this gracefully (either ignore or return error)
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(1), proxy_stream.read(&mut response)).await;
    }

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
}