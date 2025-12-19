use rust_proxy::{find_request_end, parse_host_port, bounded_copy, ProxyStats, ProxyError, Args};
use std::sync::Arc;
use std::time::Duration;
use clap::Parser;
use tokio::io::AsyncWriteExt;

#[test]
fn test_find_request_end() {
    // Test with proper CRLFCRLF ending
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = find_request_end(data);
    assert_eq!(result, data.len());

    // Test with more content after headers
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nBody content";
    let result = find_request_end(data);
    assert_eq!(result, data.len() - "Body content".len()); // Position after \r\n\r\n

    // Test with no proper ending
    let data = b"GET / HTTP/1.1\r\nHost: example.com";
    let result = find_request_end(data);
    assert_eq!(result, data.len());

    // Test with mixed newlines
    let data = b"GET / HTTP/1.1\r\nHost: example.com\n\r\n";
    let result = find_request_end(data);
    assert_eq!(result, data.len());
}

#[test]
fn test_parse_host_port() {
    // Test with port
    let (host, port) = parse_host_port("example.com:8080", 80);
    assert_eq!(host, "example.com");
    assert_eq!(port, 8080);

    // Test without port (uses default)
    let (host, port) = parse_host_port("example.com", 80);
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);

    // Test with invalid port (uses default)
    let (host, port) = parse_host_port("example.com:invalid", 80);
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);

    // Test with empty port
    let (host, port) = parse_host_port("example.com:", 80);
    assert_eq!(host, "example.com");
    assert_eq!(port, 80);
}

#[tokio::test]
async fn test_bounded_copy_basic() {
    // Create a pipe to test bounded_copy
    let (mut reader, mut writer) = tokio::io::duplex(64);
    
    // Write some test data
    let test_data = b"Hello, world!";
    writer.write_all(test_data).await.unwrap();
    drop(writer); // Close writer to signal EOF

    // Read back using bounded_copy
    let mut output = Vec::new();
    let result: Result<(), ProxyError> = bounded_copy(&mut reader, &mut output, 1024, Duration::from_secs(1)).await;
    assert!(result.is_ok());
    assert_eq!(output, test_data);
}

#[tokio::test]
async fn test_bounded_copy_size_limit() {
    // Create a pipe
    let (mut reader, mut writer) = tokio::io::duplex(64);
    
    // Write data that exceeds limit
    let test_data = b"This is a very long string that exceeds the limit";
    writer.write_all(test_data).await.unwrap();
    drop(writer);

    // Read with small limit
    let mut output = Vec::new();
    let result: Result<(), ProxyError> = bounded_copy(&mut reader, &mut output, 10, Duration::from_secs(1)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("size limit exceeded"));
}

#[tokio::test]
async fn test_bounded_copy_timeout() {
    // This test would require a more complex setup to simulate timeout
    // For now, we'll just test that it doesn't timeout with valid data
    let (mut reader, mut writer) = tokio::io::duplex(64);
    
    let test_data = b"Quick test";
    writer.write_all(test_data).await.unwrap();
    drop(writer);

    let mut output = Vec::new();
    let result: Result<(), ProxyError> = bounded_copy(&mut reader, &mut output, 1024, Duration::from_millis(100)).await;
    assert!(result.is_ok());
    assert_eq!(output, test_data);
}

#[tokio::test]
async fn test_http_request_parsing() {
    // Test HTTP request parsing with a mock request
    let http_request = b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    let request = String::from_utf8_lossy(http_request);
    let first_line = request.lines().next().unwrap();
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "GET");
    assert_eq!(parts[1], "http://example.com");
    assert_eq!(parts[2], "HTTP/1.1");
}

#[tokio::test]
async fn test_connect_request_parsing() {
    // Test CONNECT request parsing
    let connect_request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    
    let request = String::from_utf8_lossy(connect_request);
    let first_line = request.lines().next().unwrap();
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "CONNECT");
    assert_eq!(parts[1], "example.com:443");
    assert_eq!(parts[2], "HTTP/1.1");
}

#[test]
fn test_args_parsing() {
    // Test default arguments
    let args = Args::try_parse_from(&["rust_proxy"]).unwrap();
    assert_eq!(args.host, "0.0.0.0");
    assert_eq!(args.port, 3129);
    assert_eq!(args.log_level, "info");

    // Test custom arguments
    let args = Args::try_parse_from(&[
        "rust_proxy",
        "--host", "127.0.0.1",
        "--port", "8080",
        "--log-level", "debug"
    ]).unwrap();
    assert_eq!(args.host, "127.0.0.1");
    assert_eq!(args.port, 8080);
    assert_eq!(args.log_level, "debug");

    // Test long arguments only for host (no short for host due to conflict with help)
    let args = Args::try_parse_from(&[
        "rust_proxy",
        "--host", "192.168.1.1",
        "-p", "9000",
        "-l", "warn"
    ]).unwrap();
    assert_eq!(args.host, "192.168.1.1");
    assert_eq!(args.port, 9000);
    assert_eq!(args.log_level, "warn");
}

#[test]
fn test_log_level_parsing() {
    // Test valid log levels
    for level in ["debug", "info", "warn", "error"] {
        let args = Args::try_parse_from(&[
            "rust_proxy",
            "--log-level", level
        ]).unwrap();
        assert_eq!(args.log_level, level);
    }

    // Test custom host with default log level
    let args = Args::try_parse_from(&[
        "rust_proxy",
        "--host", "localhost"
    ]).unwrap();
    assert_eq!(args.host, "localhost");
    assert_eq!(args.log_level, "info");

    // Test custom port with default log level
    let args = Args::try_parse_from(&[
        "rust_proxy",
        "--port", "1234"
    ]).unwrap();
    assert_eq!(args.port, 1234);
    assert_eq!(args.log_level, "info");
}

// ===== Statistics Tests =====

#[test]
fn test_proxy_stats_creation() {
    let stats = ProxyStats::new();
    
    // Test initial values
    assert_eq!(stats.total_connections.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.active_connections.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.http_requests.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.https_requests.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.connection_errors.load(std::sync::atomic::Ordering::Relaxed), 0);
    
    // Test that start time is reasonable (within last second)
    let uptime = stats.start_time.elapsed();
    assert!(uptime < Duration::from_secs(1));
}

#[test]
fn test_proxy_stats_counters() {
    let stats = ProxyStats::new();
    
    // Test connection counters
    stats.total_connections.fetch_add(5, std::sync::atomic::Ordering::Relaxed);
    stats.active_connections.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    
    assert_eq!(stats.total_connections.load(std::sync::atomic::Ordering::Relaxed), 5);
    assert_eq!(stats.active_connections.load(std::sync::atomic::Ordering::Relaxed), 2);
    
    // Test request counters
    stats.http_requests.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    stats.https_requests.fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    
    assert_eq!(stats.http_requests.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(stats.https_requests.load(std::sync::atomic::Ordering::Relaxed), 7);
    
    // Test bytes counter
    stats.bytes_transferred.fetch_add(1024, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed), 1024);
    
    // Test error counter
    stats.connection_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stats.connection_errors.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn test_proxy_stats_log_format() {
    let stats = ProxyStats::new();
    
    // Add some test data
    stats.total_connections.store(100, std::sync::atomic::Ordering::Relaxed);
    stats.active_connections.store(5, std::sync::atomic::Ordering::Relaxed);
    stats.bytes_transferred.store(1048576, std::sync::atomic::Ordering::Relaxed); // 1MB
    stats.http_requests.store(60, std::sync::atomic::Ordering::Relaxed);
    stats.https_requests.store(40, std::sync::atomic::Ordering::Relaxed);
    stats.connection_errors.store(2, std::sync::atomic::Ordering::Relaxed);
    
    // Test that log_stats doesn't panic and produces expected output format
    // We can't easily capture log output in unit tests, but we can ensure it doesn't panic
    stats.log_stats();
    
    // Verify the data is still correct after logging
    assert_eq!(stats.total_connections.load(std::sync::atomic::Ordering::Relaxed), 100);
    assert_eq!(stats.active_connections.load(std::sync::atomic::Ordering::Relaxed), 5);
    assert_eq!(stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed), 1048576);
}

#[tokio::test]
async fn test_bounded_copy_with_stats() {
    use rust_proxy::bounded_copy_with_stats;
    
    // Create a pipe to test the function
    let (mut reader, mut writer) = tokio::io::duplex(64);
    
    // Write test data
    let test_data = b"Hello, world! This is test data for statistics.";
    writer.write_all(test_data).await.unwrap();
    drop(writer);
    
    // Create stats tracker
    let stats = Arc::new(ProxyStats::new());
    
    // Read back using bounded_copy_with_stats
    let mut output = Vec::new();
    let result: Result<(), ProxyError> = bounded_copy_with_stats(
        &mut reader, 
        &mut output, 
        1024, 
        Duration::from_secs(1),
        Some("src"),
        Some("dst"),
        "test",
        stats.clone()
    ).await;
    
    // Verify success
    assert!(result.is_ok());
    assert_eq!(output, test_data);
    
    // Verify statistics were updated
    let bytes_transferred = stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(bytes_transferred, test_data.len() as u64);
}

#[tokio::test]
async fn test_bounded_copy_with_stats_size_limit() {
    use rust_proxy::bounded_copy_with_stats;
    
    let (mut reader, mut writer) = tokio::io::duplex(64);
    
    // Write data that exceeds limit
    let test_data = b"This is a very long string that exceeds the size limit for testing purposes";
    writer.write_all(test_data).await.unwrap();
    drop(writer);
    
    let stats = Arc::new(ProxyStats::new());
    
    // Read with small limit
    let mut output = Vec::new();
    let result: Result<(), ProxyError> = bounded_copy_with_stats(
        &mut reader, 
        &mut output, 
        10, 
        Duration::from_secs(1),
        None,
        None,
        "test",
        stats.clone()
    ).await;
    
    // Should fail due to size limit
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("size limit exceeded"));
    
    // Some bytes should have been tracked before hitting limit
    let bytes_transferred = stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed);
    assert!(bytes_transferred > 0);
    assert!(bytes_transferred <= 10);
}

#[tokio::test]
async fn test_bounded_copy_with_stats_timeout() {
    use rust_proxy::bounded_copy_with_stats;
    
    let (reader, writer) = tokio::io::duplex(64);
    let mut output = Vec::new();
    
    let stats = Arc::new(ProxyStats::new());
    
    // Don't write anything to simulate timeout scenario
    drop(writer);
    
    let result: Result<(), ProxyError> = bounded_copy_with_stats(
        reader, 
        &mut output, 
        1024, 
        Duration::from_millis(10), // Very short timeout
        None,
        None,
        "timeout_test",
        stats.clone()
    ).await;
    
    // Should not fail due to timeout since we dropped the writer (EOF)
    assert!(result.is_ok());
    
    // No bytes should have been transferred
    let bytes_transferred = stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(bytes_transferred, 0);
}

#[test]
fn test_stats_concurrent_access() {
    use std::thread;
    
    let stats = Arc::new(ProxyStats::new());
    let mut handles = vec![];
    
    // Spawn multiple threads to update statistics concurrently
    for i in 0..10 {
        let stats_clone = stats.clone();
        let handle = thread::spawn(move || {
            for j in 0..100 {
                stats_clone.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats_clone.bytes_transferred.fetch_add((i * 100 + j) as u64, std::sync::atomic::Ordering::Relaxed);
                stats_clone.http_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                stats_clone.https_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Verify final counts
    assert_eq!(stats.total_connections.load(std::sync::atomic::Ordering::Relaxed), 1000);
    assert_eq!(stats.http_requests.load(std::sync::atomic::Ordering::Relaxed), 1000);
    assert_eq!(stats.https_requests.load(std::sync::atomic::Ordering::Relaxed), 1000);
    
    // Bytes should be sum of all additions
    let expected_bytes: u64 = (0..10).flat_map(|i| (0..100).map(move |j| (i * 100 + j) as u64)).sum();
    assert_eq!(stats.bytes_transferred.load(std::sync::atomic::Ordering::Relaxed), expected_bytes);
}