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

pub mod http_rewrite;

pub type ProxyError = Box<dyn std::error::Error + Send + Sync>;

pub const BUFFER_SIZE: usize = 16384; // 16KB — low-latency forwarding
pub const MAX_CONNECTIONS: usize = 1000; // Connection limit
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_DOWNLOAD_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64GB per-direction transfer cap (tunnel-friendly: scp/rsync over SSH)
pub const STATS_FLUSH_THRESHOLD: u64 = 65536;

// Statistics tracking
#[derive(Debug)]
pub struct ProxyStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicUsize,
    pub bytes_transferred: AtomicU64,
    pub http_requests: AtomicU64,
    pub https_requests: AtomicU64,
    pub socks_requests: AtomicU64,
    pub connection_errors: AtomicU64,
    pub start_time: Instant,
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            bytes_transferred: AtomicU64::new(0),
            http_requests: AtomicU64::new(0),
            https_requests: AtomicU64::new(0),
            socks_requests: AtomicU64::new(0),
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
        let socks = self.socks_requests.load(Ordering::Relaxed);
        let errors = self.connection_errors.load(Ordering::Relaxed);

        info!("📊 Proxy Statistics:");
        info!("   Uptime: {:?}", uptime);
        info!("   Total Connections: {}", total_conn);
        info!("   Active Connections: {}", active_conn);
        info!("   Bytes Transferred: {} ({:.2} MB)", bytes, bytes as f64 / 1_048_576.0);
        info!("   HTTP Requests: {}", http);
        info!("   HTTPS Requests: {}", https);
        info!("   SOCKS5 Requests: {}", socks);
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
pub fn parse_host_port(url: &str, default_port: u16) -> Result<(&str, u16), ProxyError> {
    match url.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>()
                .map_err(|_| format!("Invalid port in '{}'", url))?;
            Ok((host, port))
        }
        None => Ok((url, default_port))
    }
}

fn match_ssl_cause(error_str: &str) -> (&'static str, &'static str) {
    match error_str {
        s if s.contains("expired") => ("Certificate has expired", "Update certificate on target server"),
        s if s.contains("self-signed") || s.contains("untrusted") => ("Certificate is self-signed or untrusted", "Add certificate to trust store or use valid certificate"),
        s if s.contains("handshake") => ("TLS handshake failed", "Check certificate compatibility and TLS version"),
        s if s.contains("verify") => ("Certificate verification failed", "Check certificate chain and CA trust"),
        s if s.contains("revoked") => ("Certificate has been revoked", "Renew certificate with new signing"),
        _ => ("Unknown SSL/TLS certificate issue", "Investigate certificate validity and trust"),
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

        let (cause, action) = match_ssl_cause(&error_str);
        warn!("   Cause: {}", cause);
        warn!("   Action: {}", action);

        // Additional context for VPN scenarios
        if cfg!(windows) {
            info!("   Note: VPN routing may affect certificate validation");
            info!("   Consider: Certificate might be valid but blocked by VPN policy");
        }
    }
}

pub async fn handle_client(client_socket: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    // Configure socket options for better performance
    client_socket.set_nodelay(true)?;

    let client_addr = client_socket.peer_addr()?;
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    debug!("Handling client connection from: {}", client_addr);

    // Peek the first byte to detect SOCKS5 (0x05) vs HTTP
    let mut peek_buf = [0u8; 1];
    let peeked = timeout(CONNECT_TIMEOUT, client_socket.peek(&mut peek_buf)).await??;
    if peeked == 0 {
        stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        return Ok(());
    }

    let result = if peek_buf[0] == 0x05 {
        handle_socks5(client_socket, stats.clone()).await
    } else {
        handle_http(client_socket, stats.clone()).await
    };

    // Cleanup: decrement active connections counter
    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    result
}

async fn connect_and_tunnel(
    mut client_socket: TcpStream,
    host: &str,
    port: u16,
    forward_headers: bool,
    raw_headers: &[u8],
    on_error: impl FnOnce(&std::io::Error),
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError> {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(mut remote)) => {
            debug!("Connected to {}:{}", host, port);
            if forward_headers {
                remote.set_nodelay(true)?;
                remote.write_all(raw_headers).await?;
            } else {
                client_socket.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            }
            tunnel_fast(client_socket, remote, stats).await
        }
        Ok(Err(e)) => {
            on_error(&e);
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to connect to {}:{} - {}", host, port, e);
            client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            Ok(())
        }
        Err(_) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("Timeout connecting to {}:{}", host, port);
            client_socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            Ok(())
        }
    }
}

async fn handle_http(mut client_socket: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    // Read headers incrementally — no large upfront buffer
    let mut raw_headers = Vec::new();
    let mut small_buf = [0u8; 1024];
    let max_header_size = 8192;

    loop {
        let n = timeout(CONNECT_TIMEOUT, client_socket.read(&mut small_buf))
            .await
            .map_err(|_| ProxyError::from("Timeout reading request headers"))??;
        if n == 0 {
            return Ok(());
        }
        raw_headers.extend_from_slice(&small_buf[..n]);

        if raw_headers.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }

        if raw_headers.len() > max_header_size {
            return Err("Headers too large".into());
        }
    }

    let request = String::from_utf8_lossy(&raw_headers);
    let first_line = request.lines().next().ok_or("Empty request")?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(url, 443)?;
        stats.https_requests.fetch_add(1, Ordering::Relaxed);
        info!("HTTPS CONNECT request to {}:{}", host, port);
        connect_and_tunnel(client_socket, host, port, false, &raw_headers, |e| analyze_ssl_error(host, port, e), stats).await?;
    } else {
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().ok_or("No host found")?;
        let port = parsed_url.port().unwrap_or(if scheme == "https" { 443 } else { 80 });
        stats.http_requests.fetch_add(1, Ordering::Relaxed);
        info!("HTTP {} request to {}://{}:{}", method, scheme, host, port);
        connect_and_tunnel(client_socket, host, port, scheme == "http", &raw_headers, |e| {
            if scheme == "https" {
                analyze_ssl_error(host, port, e);
            }
        }, stats).await?;
    }

    Ok(())
}

// SOCKS5 server implementation (RFC 1928) — no-auth, CONNECT only.
async fn handle_socks5(mut client_socket: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    // --- Method negotiation ---
    // Client: VER | NMETHODS | METHODS...
    let mut header = [0u8; 2];
    timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut header)).await??;
    if header[0] != 0x05 {
        return Err("Invalid SOCKS version".into());
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut methods)).await??;
    }

    // We only support "no authentication" (0x00).
    if !methods.contains(&0x00) {
        // 0xFF = NO ACCEPTABLE METHODS
        client_socket.write_all(&[0x05, 0xFF]).await?;
        warn!("SOCKS5 client offered no acceptable auth methods");
        return Ok(());
    }
    client_socket.write_all(&[0x05, 0x00]).await?;

    // --- Request ---
    // VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
    let mut req_head = [0u8; 4];
    timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut req_head)).await??;
    if req_head[0] != 0x05 {
        return Err("Invalid SOCKS version in request".into());
    }
    let cmd = req_head[1];
    let atyp = req_head[3];

    // Reply helper: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    // We always reply with IPv4 0.0.0.0:0 for BND.
    async fn send_reply(sock: &mut TcpStream, rep: u8) -> Result<(), ProxyError> {
        let buf = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        sock.write_all(&buf).await?;
        Ok(())
    }

    if cmd != 0x01 {
        // 0x07 = Command not supported
        send_reply(&mut client_socket, 0x07).await?;
        warn!("SOCKS5 unsupported command: {}", cmd);
        return Ok(());
    }

    // Parse destination address
    let host: String = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut addr)).await??;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name: 1-byte length, then name
            let mut len_buf = [0u8; 1];
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut len_buf)).await??;
            let len = len_buf[0] as usize;
            let mut name = vec![0u8; len];
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut name)).await??;
            String::from_utf8(name).map_err(|_| "Invalid SOCKS5 domain name")?
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut addr)).await??;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        other => {
            // 0x08 = Address type not supported
            send_reply(&mut client_socket, 0x08).await?;
            warn!("SOCKS5 unsupported address type: {}", other);
            return Ok(());
        }
    };

    let mut port_buf = [0u8; 2];
    timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut port_buf)).await??;
    let port = u16::from_be_bytes(port_buf);

    stats.socks_requests.fetch_add(1, Ordering::Relaxed);
    info!("SOCKS5 CONNECT request to {}:{}", host, port);

    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(remote)) => {
            debug!("SOCKS5 connected to {}:{}", host, port);
            // 0x00 = succeeded
            send_reply(&mut client_socket, 0x00).await?;
            tunnel_fast(client_socket, remote, stats.clone()).await?;
        }
        Ok(Err(e)) => {
            analyze_ssl_error(&host, port, &e);
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("SOCKS5 failed to connect to {}:{} - {}", host, port, e);
            // Map common errors to SOCKS5 reply codes.
            let rep = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => 0x05, // Connection refused
                std::io::ErrorKind::TimedOut => 0x06,           // TTL expired
                std::io::ErrorKind::HostUnreachable => 0x04,
                std::io::ErrorKind::NetworkUnreachable => 0x03,
                _ => 0x01, // general SOCKS server failure
            };
            let _ = send_reply(&mut client_socket, rep).await;
        }
        Err(_) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("SOCKS5 timeout connecting to {}:{}", host, port);
            let _ = send_reply(&mut client_socket, 0x06).await; // TTL expired
        }
    }

    Ok(())
}

#[cfg(unix)]
const TCP_QUICKACK: i32 = 12;
#[cfg(unix)]
const TCP_USER_TIMEOUT: i32 = 18;

#[cfg(unix)]
fn configure_keepalive(src: &TcpStream, dst: &TcpStream) {
    use std::os::unix::io::AsRawFd;

    fn set_sock(fd: i32, level: i32, opt: i32, val: i32) {
        let _ = unsafe {
            libc::setsockopt(fd, level, opt,
                &val as *const _ as *const _,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
    }

    let one = 1i32;
    set_sock(src.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE, one);
    set_sock(dst.as_raw_fd(), libc::SOL_SOCKET, libc::SO_KEEPALIVE, one);
    set_sock(src.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60);
    set_sock(dst.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60);
    set_sock(src.as_raw_fd(), libc::IPPROTO_TCP, TCP_QUICKACK, one);
    set_sock(dst.as_raw_fd(), libc::IPPROTO_TCP, TCP_QUICKACK, one);
    set_sock(src.as_raw_fd(), libc::IPPROTO_TCP, TCP_USER_TIMEOUT, 10_000);
    set_sock(dst.as_raw_fd(), libc::IPPROTO_TCP, TCP_USER_TIMEOUT, 10_000);
}

#[cfg(windows)]
fn configure_keepalive(src: &TcpStream, dst: &TcpStream) {
    use std::os::windows::io::AsRawSocket;

    #[repr(C)]
    struct TcpKeepalive {
        onoff: u32,
        keepalivetime: u32,
        keepaliveinterval: u32,
    }

    const SIO_KEEPALIVE_VALS: u32 = 0xFC000006;

    let ka = TcpKeepalive {
        onoff: 1,
        keepalivetime: 60000,
        keepaliveinterval: 1000,
    };

    fn set_keepalive(socket: winapi::um::winsock2::SOCKET, ka: &TcpKeepalive) {
        let _ = unsafe {
            let mut ret = 0;
            winapi::um::winsock2::WSAIoctl(
                socket, SIO_KEEPALIVE_VALS,
                ka as *const _ as *mut _,
                std::mem::size_of::<TcpKeepalive>() as _,
                std::ptr::null_mut(), 0,
                &mut ret, std::ptr::null_mut(), None,
            )
        };
    }

    set_keepalive(src.as_raw_socket() as _, &ka);
    set_keepalive(dst.as_raw_socket() as _, &ka);
}

async fn tunnel_fast(mut src: TcpStream, mut dst: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
    src.set_nodelay(true)?;
    dst.set_nodelay(true)?;
    configure_keepalive(&src, &dst);

    let (mut src_reader, mut src_writer) = src.split();
    let (mut dst_reader, mut dst_writer) = dst.split();

    // Stream data with size limits and idle timeout
    let stats_clone = stats.clone();
    let client_to_server = bounded_copy_with_stats(
        &mut src_reader, &mut dst_writer, MAX_DOWNLOAD_SIZE, IDLE_TIMEOUT,
        "client->server", stats_clone
    );
    let stats_clone = stats.clone();
    let server_to_client = bounded_copy_with_stats(
        &mut dst_reader, &mut src_writer, MAX_DOWNLOAD_SIZE, IDLE_TIMEOUT,
        "server->client", stats_clone
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
    direction: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut bytes_read = 0u64;
    let mut last_flushed = 0u64;
    let mut buffer = vec![0; BUFFER_SIZE];

    loop {
        let read_result = timeout(idle_timeout, reader.read(&mut buffer)).await;

        match read_result {
            Ok(Ok(0)) => {
                writer.shutdown().await.ok();
                break;
            }
            Ok(Ok(n)) => {
                bytes_read += n as u64;
                if (bytes_read - last_flushed) >= STATS_FLUSH_THRESHOLD {
                    stats.bytes_transferred.fetch_add(bytes_read - last_flushed, Ordering::Relaxed);
                    last_flushed = bytes_read;
                }

                if bytes_read > max_size {
                    warn!("Download size limit exceeded: {} bytes", bytes_read);
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

    if bytes_read > last_flushed {
        stats.bytes_transferred.fetch_add(bytes_read - last_flushed, Ordering::Relaxed);
    }

    Ok(())
}

