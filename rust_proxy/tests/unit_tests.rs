use rust_proxy::{find_request_end, parse_host_port, bounded_copy, ProxyError, Args};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

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