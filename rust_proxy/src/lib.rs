pub use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
pub use std::sync::Arc;
pub use std::time::{Duration, Instant};
pub use clap::Parser;
pub use log::{debug, error, info, warn};
pub use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub use tokio::net::{TcpListener, TcpStream};
pub use tokio::sync::Semaphore;
pub use tokio::time::{interval, timeout};
pub use url::Url;

#[cfg(windows)]
pub mod windows;

pub type ProxyError = Box<dyn std::error::Error + Send + Sync>;

pub const BUFFER_SIZE: usize = 65536; // Larger buffer for better throughput
pub const MAX_CONNECTIONS: usize = 10000; // Connection limit
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes idle timeout
pub const MAX_DOWNLOAD_SIZE: u64 = 1024 * 1024 * 1024; // 1GB max download

// Statistics tracking
#[derive(Debug)]
pub struct ProxyStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicUsize,
    pub bytes_transferred: AtomicU64,
    pub http_requests: AtomicU64,
    pub https_requests: AtomicU64,
    pub connection_errors: AtomicU64,
    pub start_time: Instant,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            bytes_transferred: AtomicU64::new(0),
            http_requests: AtomicU64::new(0),
            https_requests: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    pub fn log_stats(&self) {
        let uptime = self.start_time.elapsed();
        let total_conn = self.total_connections.load(Ordering::Relaxed);
        let active_conn = self.active_connections.load(Ordering::Relaxed);
        let bytes = self.bytes_transferred.load(Ordering::Relaxed);
        let http = self.http_requests.load(Ordering::Relaxed);
        let https = self.https_requests.load(Ordering::Relaxed);
        let errors = self.connection_errors.load(Ordering::Relaxed);
        
        info!("📊 Proxy Statistics:");
        info!("   Uptime: {:?}", uptime);
        info!("   Total Connections: {}", total_conn);
        info!("   Active Connections: {}", active_conn);
        info!("   Bytes Transferred: {} ({:.2} MB)", bytes, bytes as f64 / 1_048_576.0);
        info!("   HTTP Requests: {}", http);
        info!("   HTTPS Requests: {}", https);
        info!("   Connection Errors: {}", errors);
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Host to listen on (default: 0.0.0.0)
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    
    /// Port to listen on (default: 3129)
    #[arg(short, long, default_value = "3129")]
    pub port: u16,
    
    /// Log level: debug, info, warn, error (default: info)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
}

// Optimized function to find end of HTTP headers
pub fn find_request_end(data: &[u8]) -> usize {
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == b'\r' && data[i + 1] == b'\n' && 
           data[i + 2] == b'\r' && data[i + 3] == b'\n' {
            return i + 4;
        }
        i += 1;
    }
    data.len()
}

// Optimized host:port parsing
pub fn parse_host_port(url: &str, default_port: u16) -> (&str, u16) {
    match url.split_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().unwrap_or(default_port);
            (host, port)
        }
        None => (url, default_port)
    }
}

// Function to analyze connection errors for SSL/TLS certificate issues
fn analyze_ssl_error(host: &str, port: u16, error: &std::io::Error) {
    let error_str = error.to_string().to_lowercase();
    let error_display = error.to_string();
    
    // Common SSL/TLS certificate error patterns
    let ssl_cert_indicators = [
        "certificate",
        "cert",
        "tls",
        "ssl",
        "handshake",
        "verification",
        "expired",
        "self-signed",
        "untrusted",
        "certificate chain",
        "certificate verify",
        "certificate has expired",
        "certificate not yet valid",
        "certificate revoked",
        "certificate signature",
        "certificate authority",
        "ca",
        "unknown ca",
        "unable to get local issuer",
        "issuer certificate",
        "root certificate",
    ];
    
    let is_ssl_related = ssl_cert_indicators.iter().any(|indicator| error_str.contains(indicator));
    
    if is_ssl_related {
        warn!("🔒 SSL/TLS Certificate Issue Detected");
        warn!("   Target: {}:{}", host, port);
        warn!("   Error: {}", error_display);
        
        // Provide specific guidance based on error type
        if error_str.contains("expired") {
            warn!("   Cause: Certificate has expired");
            warn!("   Action: Update certificate on target server");
        } else if error_str.contains("self-signed") || error_str.contains("untrusted") {
            warn!("   Cause: Certificate is self-signed or untrusted");
            warn!("   Action: Add certificate to trust store or use valid certificate");
        } else if error_str.contains("handshake") {
            warn!("   Cause: TLS handshake failed");
            warn!("   Action: Check certificate compatibility and TLS version");
        } else if error_str.contains("verify") {
            warn!("   Cause: Certificate verification failed");
            warn!("   Action: Check certificate chain and CA trust");
        } else if error_str.contains("revoked") {
            warn!("   Cause: Certificate has been revoked");
            warn!("   Action: Renew certificate with new signing");
        } else {
            warn!("   Cause: Unknown SSL/TLS certificate issue");
            warn!("   Action: Investigate certificate validity and trust");
        }
        
        // Additional context for VPN scenarios
        if cfg!(windows) {
            info!("   Note: VPN routing may affect certificate validation");
            info!("   Consider: Certificate might be valid but blocked by VPN policy");
        }
    }
}

pub async fn handle_client(mut client_socket: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    // Configure socket options for better performance
    client_socket.set_nodelay(true)?;
    
    let client_addr = client_socket.peer_addr()?;
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    debug!("Handling client connection from: {}", client_addr);
    
    let mut buffer = vec![0; BUFFER_SIZE];
    let bytes_read = timeout(CONNECT_TIMEOUT, client_socket.read(&mut buffer)).await??;
    
    if bytes_read == 0 {
        return Ok(());
    }

    // Find end of headers more efficiently
    let request_end = find_request_end(&buffer[..bytes_read]);
    if request_end == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..request_end]);
    let first_line = request.lines().next().ok_or("Empty request")?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    if parts.len() < 3 {
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS request
        let (host, port) = parse_host_port(url, 443);
        stats.https_requests.fetch_add(1, Ordering::Relaxed);
        info!("HTTPS CONNECT request to {}:{}", host, port);

        match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
            Ok(Ok(remote)) => {
                info!("Connected to {}:{}", host, port);
                client_socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                tunnel_fast(client_socket, remote, stats.clone()).await?;
            }
            Ok(Err(e)) => {
                // Analyze for SSL certificate issues
                analyze_ssl_error(host, port, &e);
                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                warn!("Failed to connect to {}:{} - {}", host, port, e);
                client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            }
            Err(_) => {
                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                warn!("Timeout connecting to {}:{}", host, port);
                client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            }
        }
    } else {
        // HTTP request
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().ok_or("No host found")?;
        let port = parsed_url.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
        stats.http_requests.fetch_add(1, Ordering::Relaxed);
        info!("HTTP {} request to {}://{}:{}", method, scheme, host, port);

        match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
            Ok(Ok(mut remote)) => {
                remote.set_nodelay(true)?;
                debug!("Connected to {}://{}:{}", scheme, host, port);
                
                // Send the original request
                remote.write_all(&buffer[..bytes_read]).await?;
                tunnel_fast(client_socket, remote, stats.clone()).await?;
            }
            Ok(Err(e)) => {
                // Analyze for SSL certificate issues for HTTPS URLs
                if scheme == "https" {
                    analyze_ssl_error(host, port, &e);
                }
                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                warn!("Failed to connect to {}://{}:{} - {}", scheme, host, port, e);
                client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            }
            Err(_) => {
                stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                warn!("Timeout connecting to {}://{}:{}", scheme, host, port);
                client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            }
        }
    }

    // Cleanup: decrement active connections counter
    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

async fn tunnel_fast(mut src: TcpStream, mut dst: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    // Configure both sockets for better performance
    src.set_nodelay(true)?;
    dst.set_nodelay(true)?;
    
    // Get addresses for error reporting before splitting
    let src_addr = src.peer_addr().map(|a| a.to_string()).ok();
    let dst_addr = dst.peer_addr().map(|a| a.to_string()).ok();
    
    let (mut src_reader, mut src_writer) = src.split();
    let (mut dst_reader, mut dst_writer) = dst.split();

    // Stream data with size limits and idle timeout
    let stats_clone = stats.clone();
    let client_to_server = bounded_copy_with_stats(
        &mut src_reader, &mut dst_writer, MAX_DOWNLOAD_SIZE, IDLE_TIMEOUT,
        src_addr.as_deref(), dst_addr.as_deref(), "client->server", stats_clone
    );
    let stats_clone = stats.clone();
    let server_to_client = bounded_copy_with_stats(
        &mut dst_reader, &mut src_writer, MAX_DOWNLOAD_SIZE, IDLE_TIMEOUT,
        dst_addr.as_deref(), src_addr.as_deref(), "server->client", stats_clone
    );

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

// Copy with size limits and statistics tracking
pub async fn bounded_copy_with_stats<R, W>(
    mut reader: R,
    mut writer: W,
    max_size: u64,
    idle_timeout: Duration,
    _src_addr: Option<&str>,
    _dst_addr: Option<&str>,
    direction: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = vec![0; BUFFER_SIZE];
    
    loop {
        let read_result = timeout(idle_timeout, reader.read(&mut buffer)).await;
        
        match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                transferred += n as u64;
                stats.bytes_transferred.fetch_add(n as u64, Ordering::Relaxed);
                
                if transferred > max_size {
                    warn!("Download size limit exceeded: {} bytes", transferred);
                    return Err("Download size limit exceeded".into());
                }
                
                let write_result = timeout(idle_timeout, writer.write_all(&buffer[..n])).await;
                match write_result {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        debug!("Write error in {}: {}", direction, e);
                        return Err("Write error".into());
                    }
                    Err(_) => {
                        warn!("Write timeout in {}", direction);
                        return Err("Write timeout".into());
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("Read error in {}: {}", direction, e);
                return Err(e.into());
            }
            Err(_) => {
                warn!("Connection idle timeout in {}", direction);
                return Err("Idle timeout".into());
            }
        }
    }
    
    Ok(())
}

// Copy with size limits and SSL error detection
pub async fn bounded_copy_with_ssl_detection<R, W>(
    mut reader: R,
    mut writer: W,
    max_size: u64,
    idle_timeout: Duration,
    src_addr: Option<&str>,
    dst_addr: Option<&str>,
    direction: &str,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = vec![0; BUFFER_SIZE];
    
    loop {
        let read_result = timeout(idle_timeout, reader.read(&mut buffer)).await;
        
        match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                transferred += n as u64;
                if transferred > max_size {
                    warn!("Download size limit exceeded: {} bytes", transferred);
                    return Err("Download size limit exceeded".into());
                }
                
                let write_result = timeout(idle_timeout, writer.write_all(&buffer[..n])).await;
                match write_result {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        debug!("Write error in {}: {}", direction, e);
                        return Err("Write error".into());
                    }
                    Err(_) => {
                        warn!("Write timeout in {}", direction);
                        return Err("Write timeout".into());
                    }
                }
            }
            Ok(Err(e)) => {
                let error_str = e.to_string().to_lowercase();
                
                // Check for SSL/TLS related errors that might indicate certificate issues
                if error_str.contains("tls") || error_str.contains("ssl") || 
                   error_str.contains("handshake") || error_str.contains("certificate") {
                    warn!("🔒 SSL/TLS Error During Data Transfer");
                    if let Some(src) = src_addr {
                        warn!("   Source: {}", src);
                    }
                    if let Some(dst) = dst_addr {
                        warn!("   Destination: {}", dst);
                    }
                    warn!("   Direction: {}", direction);
                    warn!("   Error: {}", e);
                    warn!("   Note: This may indicate certificate validation issues during TLS handshake");
                } else {
                    debug!("Read error in {}: {}", direction, e);
                }
                return Err(e.into());
            }
            Err(_) => {
                warn!("Connection idle timeout in {}", direction);
                return Err("Idle timeout".into());
            }
        }
    }
    
    Ok(())
}

// Copy with size limits and idle timeout (legacy version)
pub async fn bounded_copy<R, W>(
    mut reader: R,
    mut writer: W,
    max_size: u64,
    idle_timeout: Duration,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = vec![0; BUFFER_SIZE];
    
    loop {
        let read_result = timeout(idle_timeout, reader.read(&mut buffer)).await;
        
        match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                transferred += n as u64;
                if transferred > max_size {
                    warn!("Download size limit exceeded: {} bytes", transferred);
                    return Err("Download size limit exceeded".into());
                }
                
                let write_result = timeout(idle_timeout, writer.write_all(&buffer[..n])).await;
                match write_result {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        debug!("Write error: {}", e);
                        return Err("Write error".into());
                    }
                    Err(_) => {
                        warn!("Write timeout");
                        return Err("Write timeout".into());
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("Read error: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                warn!("Connection idle timeout");
                return Err("Idle timeout".into());
            }
        }
    }
    
    Ok(())
}