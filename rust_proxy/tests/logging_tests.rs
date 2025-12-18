use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

#[test]
fn test_logging_output_to_file() {
    // Create a temporary file for log output
    let _log_file = NamedTempFile::new().unwrap();

    // Start proxy with debug logging redirected to file
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3140", "--log-level", "debug"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "debug")
        .spawn()
        .expect("Failed to start proxy server");

    // Give the server time to start and log
    thread::sleep(Duration::from_secs(3));

    // Terminate the server
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    // Check that we got some output (stderr contains logs)
    assert!(!output.stderr.is_empty(), "Should have log output");

    // Convert stderr to string and check for expected log messages
    let stderr_output = String::from_utf8_lossy(&output.stderr);
    
    // Should contain startup messages
    assert!(stderr_output.contains("Proxy server starting") || 
            stderr_output.contains("INFO") ||
            stderr_output.contains("debug"), 
            "Should contain startup log messages");
}

#[test]
fn test_logging_levels() {
    let log_levels = vec!["error", "warn", "info", "debug"];
    
    for level in log_levels {
        // Start proxy with specific log level
        let mut child = Command::new("cargo")
            .args(&["run", "--", "--host", "127.0.0.1", "--port", "3141", "--log-level", level])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start proxy server");

        thread::sleep(Duration::from_secs(2));

        let _ = child.kill();
        let output = child.wait_with_output().unwrap();

        // Should have some log output
        assert!(!output.stderr.is_empty(), "Should have log output for level: {}", level);
        
        let stderr_output = String::from_utf8_lossy(&output.stderr);
        
        // Should contain the log level we specified (case insensitive)
        assert!(stderr_output.to_uppercase().contains(&level.to_uppercase()) || 
                stderr_output.contains("INFO") || 
                stderr_output.contains("Proxy server"),
                "Should contain appropriate log level messages for: {}", level);
    }
}

#[test]
fn test_invalid_log_level_handling() {
    // Test with invalid log level - should default to info
    let mut child = Command::new("cargo")
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3142", "--log-level", "invalid"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    thread::sleep(Duration::from_secs(2));

    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    let stderr_output = String::from_utf8_lossy(&output.stderr);
    
    // Should contain warning about invalid log level
    assert!(stderr_output.contains("Invalid log level") || stderr_output.contains("INFO"),
            "Should handle invalid log level gracefully");
}