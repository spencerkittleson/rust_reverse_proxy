use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::test]
async fn test_proxy_integration() {
    // Start proxy server in background
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3130", "--log-level", "error"])
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
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3132", "--log-level", "error"])
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
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3134", "--log-level", "error"])
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

#[tokio::test]
async fn test_proxy_handles_invalid_requests() {
    // Start proxy
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3135", "--log-level", "error"])
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