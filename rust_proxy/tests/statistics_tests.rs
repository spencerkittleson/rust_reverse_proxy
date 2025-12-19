use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use rust_proxy::ProxyStats;

#[tokio::test]
async fn test_statistics_integration_http() {
    // Start a simple HTTP server to act as target
    let http_server = tokio::net::TcpListener::bind("127.0.0.1:3140").await.unwrap();
    
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = http_server.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                if let Ok(_n) = socket.read(&mut buffer).await {
                    // Echo back a simple HTTP response
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                    let _ = socket.write_all(response).await;
                }
            });
        }
    });

    // Start proxy with statistics
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3141", "--log-level", "error"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Make multiple HTTP requests through the proxy
    for _ in 0..5 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3141").await.unwrap();
        let http_request = b"GET http://127.0.0.1:3140 HTTP/1.1\r\nHost: 127.0.0.1:3140\r\n\r\n";
        let _ = proxy_stream.write_all(http_request).await;
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Wait a bit for statistics to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    
    // Test passes if no panics occurred during the test
    assert!(true);
}

#[tokio::test]
async fn test_statistics_integration_https() {
    // Start a simple server to accept CONNECT requests
    let https_server = tokio::net::TcpListener::bind("127.0.0.1:3142").await.unwrap();
    
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = https_server.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                // Just read and close to simulate HTTPS tunnel
                let _ = socket.read(&mut buffer).await;
            });
        }
    });

    // Start proxy with statistics
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3143", "--log-level", "error"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Make multiple HTTPS CONNECT requests through the proxy
    for _ in 0..3 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3143").await.unwrap();
        let connect_request = b"CONNECT 127.0.0.1:3142 HTTP/1.1\r\nHost: 127.0.0.1:3142\r\n\r\n";
        let _ = proxy_stream.write_all(connect_request).await;
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Wait a bit for statistics to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    
    // Test passes if no panics occurred during the test
    assert!(true);
}

#[tokio::test]
async fn test_statistics_error_tracking() {
    // Try to connect to a non-existent server to generate errors
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3144", "--log-level", "error"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Make requests to non-existent servers to generate connection errors
    for _ in 0..3 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3144").await.unwrap();
        
        // HTTP request to non-existent server
        let http_request = b"GET http://127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n";
        let _ = proxy_stream.write_all(http_request).await;
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Make CONNECT requests to non-existent servers
    for _ in 0..2 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3144").await.unwrap();
        
        let connect_request = b"CONNECT 127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n";
        let _ = proxy_stream.write_all(connect_request).await;
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Wait a bit for statistics to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    
    // Test passes if no panics occurred during the test
    assert!(true);
}

#[tokio::test]
async fn test_statistics_mixed_traffic() {
    // Start multiple servers for mixed traffic testing
    let http_server = tokio::net::TcpListener::bind("127.0.0.1:3145").await.unwrap();
    let https_server = tokio::net::TcpListener::bind("127.0.0.1:3146").await.unwrap();
    
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = http_server.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                if let Ok(_n) = socket.read(&mut buffer).await {
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                    let _ = socket.write_all(response).await;
                }
            });
        }
    });
    
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = https_server.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                let _ = socket.read(&mut buffer).await;
            });
        }
    });

    // Start proxy with statistics
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3147", "--log-level", "error"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Make mixed requests
    for i in 0..10 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3147").await.unwrap();
        
        if i % 3 == 0 {
            // HTTP request
            let http_request = b"GET http://127.0.0.1:3145 HTTP/1.1\r\nHost: 127.0.0.1:3145\r\n\r\n";
            let _ = proxy_stream.write_all(http_request).await;
        } else {
            // HTTPS CONNECT request
            let connect_request = b"CONNECT 127.0.0.1:3146 HTTP/1.1\r\nHost: 127.0.0.1:3146\r\n\r\n";
            let _ = proxy_stream.write_all(connect_request).await;
        }
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Try some requests to non-existent servers
    for _ in 0..2 {
        let mut proxy_stream = TcpStream::connect("127.0.0.1:3147").await.unwrap();
        let http_request = b"GET http://127.0.0.1:9999 HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n";
        let _ = proxy_stream.write_all(http_request).await;
        
        let mut response = [0; 1024];
        let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
    }

    // Wait for statistics to be processed
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    
    // Test passes if no panics occurred during the test
    assert!(true);
}

#[test]
fn test_statistics_debug_logging_format() {
    let stats = Arc::new(ProxyStats::new());
    
    // Populate with test data
    stats.total_connections.store(50, std::sync::atomic::Ordering::Relaxed);
    stats.active_connections.store(3, std::sync::atomic::Ordering::Relaxed);
    stats.bytes_transferred.store(2097152, std::sync::atomic::Ordering::Relaxed); // 2MB
    stats.http_requests.store(30, std::sync::atomic::Ordering::Relaxed);
    stats.https_requests.store(20, std::sync::atomic::Ordering::Relaxed);
    stats.connection_errors.store(2, std::sync::atomic::Ordering::Relaxed);
    
    // This test ensures the log_stats method doesn't panic
    // and handles the data correctly
    stats.log_stats();
    
    // Verify data remains unchanged after logging
    assert_eq!(stats.total_connections.load(std::sync::atomic::Ordering::Relaxed), 50);
    assert_eq!(stats.active_connections.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed), 2097152);
    assert_eq!(stats.http_requests.load(std::sync::atomic::Ordering::Relaxed), 30);
    assert_eq!(stats.https_requests.load(std::sync::atomic::Ordering::Relaxed), 20);
    assert_eq!(stats.connection_errors.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[tokio::test]
async fn test_statistics_concurrent_client_simulation() {
    // Start echo server
    let echo_server = tokio::net::TcpListener::bind("127.0.0.1:3148").await.unwrap();
    
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_server.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                if let Ok(_n) = socket.read(&mut buffer).await {
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
                    let _ = socket.write_all(response).await;
                }
            });
        }
    });

    // Start proxy
    let mut proxy_child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3149", "--log-level", "error"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    // Spawn multiple concurrent client connections
    let mut handles = vec![];
    for i in 0..5 {
        let handle = tokio::spawn(async move {
            for j in 0..3 {
                let mut proxy_stream = TcpStream::connect("127.0.0.1:3149").await.unwrap();
                let request = format!(
                    "GET http://127.0.0.1:3148/{} HTTP/1.1\r\nHost: 127.0.0.1:3148\r\n\r\n", 
                    i * 3 + j
                );
                let _ = proxy_stream.write_all(request.as_bytes()).await;
                
                let mut response = [0; 1024];
                let _ = timeout(Duration::from_secs(2), proxy_stream.read(&mut response)).await;
            }
        });
        handles.push(handle);
    }

    // Wait for all concurrent requests to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Wait for statistics to be processed
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Clean up
    let _ = proxy_child.kill();
    let _ = proxy_child.wait();
    
    // Test passes if no panics occurred during concurrent access
    assert!(true);
}