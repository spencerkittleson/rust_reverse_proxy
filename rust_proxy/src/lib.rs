pub use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
pub use std::sync::Arc;
pub use std::sync::Mutex;
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
pub mod auth;

use crate::http_rewrite::RewriteAnomaly;

pub type ProxyError = Box<dyn std::error::Error + Send + Sync>;

pub const BUFFER_SIZE: usize = 16384; // 16KB — low-latency forwarding
pub const MAX_CONNECTIONS: usize = 1000; // Connection limit
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_DOWNLOAD_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64GB per-direction transfer cap (tunnel-friendly: scp/rsync over SSH)
pub const STATS_FLUSH_THRESHOLD: u64 = 65536;

/// Max request head. Raised from the original 8KB: browsers with large cookie
/// jars and `Authorization: Bearer` tokens exceed 8KB routinely, and that was the
/// likeliest source of spurious rewrite anomalies.
pub const MAX_REQUEST_HEAD_SIZE: usize = 65536;

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
    /// Requests successfully rewritten into direct-client form.
    pub requests_sanitized: AtomicU64,
    /// Per-reason anomaly counts, indexed by `RewriteAnomaly::index()`.
    pub rewrite_anomalies: [AtomicU64; RewriteAnomaly::COUNT],
    /// Last offending host per reason. Written only on anomaly, so this lock is
    /// never contended on the hot path.
    pub rewrite_anomaly_last_host: [Mutex<Option<String>>; RewriteAnomaly::COUNT],
    /// Requests actually forwarded unrewritten, i.e. actual leaks.
    pub rewrite_fallback_forwarded: AtomicU64,
    /// Whether `--rewrite-fallback` is enabled, for the report banner.
    pub rewrite_fallback_active: AtomicBool,
    /// Requests refused for a missing, malformed, or unrecognized credential.
    pub auth_failures: AtomicU64,
    /// Connections refused because the source address is outside --allow-from.
    pub acl_rejections: AtomicU64,
    /// Whether `--allow-anonymous` is enabled, for the report banner.
    pub allow_anonymous_active: AtomicBool,
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
            requests_sanitized: AtomicU64::new(0),
            rewrite_anomalies: Default::default(),
            rewrite_anomaly_last_host: Default::default(),
            rewrite_fallback_forwarded: AtomicU64::new(0),
            rewrite_fallback_active: AtomicBool::new(false),
            auth_failures: AtomicU64::new(0),
            acl_rejections: AtomicU64::new(0),
            allow_anonymous_active: AtomicBool::new(false),
            start_time: Instant::now(),
        }
    }

    pub fn record_sanitized(&self, n: u64) {
        if n > 0 {
            self.requests_sanitized.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Record one anomaly. `forwarded` is true only when the bytes actually went
    /// upstream unrewritten, which is what the leak banner reports.
    pub fn record_anomaly(&self, anomaly: RewriteAnomaly, host: &str, forwarded: bool) {
        self.rewrite_anomalies[anomaly.index()].fetch_add(1, Ordering::Relaxed);
        if forwarded {
            self.rewrite_fallback_forwarded
                .fetch_add(1, Ordering::Relaxed);
        }
        if let Ok(mut slot) = self.rewrite_anomaly_last_host[anomaly.index()].lock() {
            *slot = Some(host.to_string());
        }
    }

    pub fn last_anomaly_host(&self, anomaly: RewriteAnomaly) -> Option<String> {
        self.rewrite_anomaly_last_host[anomaly.index()]
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub fn set_fallback_active(&self, active: bool) {
        self.rewrite_fallback_active
            .store(active, Ordering::Relaxed);
    }

    pub fn set_anonymous_active(&self, active: bool) {
        self.allow_anonymous_active
            .store(active, Ordering::Relaxed);
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

        let sanitized = self.requests_sanitized.load(Ordering::Relaxed);
        let total_anomalies: u64 = RewriteAnomaly::ALL
            .iter()
            .map(|a| self.rewrite_anomalies[a.index()].load(Ordering::Relaxed))
            .sum();
        info!("   Rewrite: {} sanitized, {} anomalies", sanitized, total_anomalies);

        if self.rewrite_fallback_active.load(Ordering::Relaxed) {
            let leaked = self.rewrite_fallback_forwarded.load(Ordering::Relaxed);
            warn!(
                "      ⚠ --rewrite-fallback ACTIVE — {} requests forwarded unrewritten (proxy visible to origin)",
                leaked
            );
        }

        // Only non-zero access-control counters print, so a clean run stays quiet.
        let auth_failures = self.auth_failures.load(Ordering::Relaxed);
        if auth_failures > 0 {
            info!("   Auth Failures: {}", auth_failures);
        }
        let acl_rejections = self.acl_rejections.load(Ordering::Relaxed);
        if acl_rejections > 0 {
            info!("   Source Rejections: {}", acl_rejections);
        }
        if self.allow_anonymous_active.load(Ordering::Relaxed) {
            warn!(
                "      ⚠ --allow-anonymous ACTIVE — this proxy relays for unauthenticated clients"
            );
        }

        // Only non-zero reasons print, so a clean run stays one line.
        for anomaly in RewriteAnomaly::ALL {
            let count = self.rewrite_anomalies[anomaly.index()].load(Ordering::Relaxed);
            if count == 0 {
                continue;
            }
            match self.last_anomaly_host(anomaly) {
                Some(host) => info!("      {}: {} (last: {})", anomaly.name(), count, host),
                None => info!("      {}: {}", anomaly.name(), count),
            }
        }
    }
}

#[derive(Parser, Debug)]
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

    /// Forward requests verbatim when rewriting fails instead of closing the
    /// connection. Leaks proxy presence to the origin for each affected request.
    #[arg(long, default_value_t = false)]
    pub rewrite_fallback: bool,

    /// Path to a credentials file: one `user:password` per line, `#` comments
    /// allowed. Takes precedence over RUST_PROXY_AUTH.
    #[arg(long, value_name = "PATH")]
    pub auth_file: Option<String>,

    /// Run without any credential. This makes the proxy an open relay to
    /// anything that can reach the port.
    #[arg(long, default_value_t = false)]
    pub allow_anonymous: bool,

    /// Only accept connections from this address or CIDR range. Repeatable.
    /// Omitted means every source address is accepted.
    #[arg(long, value_name = "CIDR")]
    pub allow_from: Vec<String>,
}

impl Args {
    pub fn rewrite_policy(&self) -> crate::http_rewrite::RewritePolicy {
        if self.rewrite_fallback {
            crate::http_rewrite::RewritePolicy::Fallback
        } else {
            crate::http_rewrite::RewritePolicy::FailClosed
        }
    }
}

/// Environment variable holding a single `user:password` credential.
pub const AUTH_ENV_VAR: &str = "RUST_PROXY_AUTH";

/// Per-connection policy: what to rewrite, who may connect, who is trusted.
///
/// Replaces the bare `RewritePolicy` that used to be threaded through the
/// handlers, so later flags land in one place instead of growing the parameter
/// list again.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub policy: crate::http_rewrite::RewritePolicy,
    /// `None` means `--allow-anonymous`. Inner `Arc` so `RequestStream` holds a
    /// cheap clone rather than copying the credential set per connection.
    pub auth: Option<Arc<crate::auth::Credentials>>,
    /// Empty means no source filtering at all, not deny-all.
    pub allow_from: Vec<crate::auth::Cidr>,
}

impl RuntimeConfig {
    /// No credential, no allowlist. For `--allow-anonymous` and for tests.
    pub fn anonymous(policy: crate::http_rewrite::RewritePolicy) -> Self {
        Self {
            policy,
            auth: None,
            allow_from: Vec::new(),
        }
    }
}

/// Read and parse a credentials file.
///
/// Warns about loose permissions rather than refusing: on a router the file may
/// legitimately be root-owned with a group that needs it, and refusing to start
/// over a mode bit would be worse than a warning the operator can act on.
pub fn load_credentials_file(path: &str) -> Result<crate::auth::Credentials, ProxyError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ProxyError::from(format!("cannot read --auth-file {path}: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                warn!(
                    "--auth-file {} is readable beyond its owner (mode {:o}); chmod 600 it",
                    path, mode
                );
            }
        }
    }

    crate::auth::Credentials::parse_file_contents(&text)
        .map_err(|e| ProxyError::from(format!("--auth-file {path}: {e}")))
}

/// Build the runtime configuration, refusing to start on a contradictory or
/// dangerously incomplete combination of flags.
///
/// `env_auth` is passed in rather than read from the process environment so
/// tests never race on a global.
pub fn build_runtime_config(
    args: &Args,
    env_auth: Option<String>,
) -> Result<RuntimeConfig, ProxyError> {
    let creds = match (&args.auth_file, env_auth) {
        (Some(path), env) => {
            if env.is_some() {
                warn!(
                    "{} is set but --auth-file takes precedence; ignoring the environment variable",
                    AUTH_ENV_VAR
                );
            }
            Some(load_credentials_file(path)?)
        }
        (None, Some(value)) => Some(
            crate::auth::Credentials::parse_file_contents(&value)
                .map_err(|e| ProxyError::from(format!("{AUTH_ENV_VAR}: {e}")))?,
        ),
        (None, None) => None,
    };

    if creds.is_some() && args.allow_anonymous {
        return Err(
            "--allow-anonymous cannot be combined with a configured credential; pick one".into(),
        );
    }
    if creds.is_none() && !args.allow_anonymous {
        return Err(format!(
            "no credential configured. Pass --auth-file <path>, set {AUTH_ENV_VAR}=user:password, \
             or pass --allow-anonymous to run an open relay on purpose"
        )
        .into());
    }

    let mut allow_from = Vec::with_capacity(args.allow_from.len());
    for spec in &args.allow_from {
        allow_from.push(
            crate::auth::Cidr::parse(spec)
                .map_err(|e| ProxyError::from(format!("--allow-from: {e}")))?,
        );
    }

    Ok(RuntimeConfig {
        policy: args.rewrite_policy(),
        auth: creds.map(Arc::new),
        allow_from,
    })
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

pub async fn handle_client(
    client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
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
        // SOCKS5 is a blind byte relay after the handshake: nothing to rewrite.
        handle_socks5(client_socket, stats.clone(), config).await
    } else {
        handle_http(client_socket, stats.clone(), config).await
    };

    // Cleanup: decrement active connections counter
    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    result
}

/// Move counters out of a `RequestStream` and into `ProxyStats`.
///
/// `forwarded` marks a real leak: only fallback-eligible anomalies under
/// `--rewrite-fallback` actually put unrewritten bytes on the wire.
pub fn flush_rewrite_stats(
    stream: &mut crate::http_rewrite::RequestStream,
    stats: &ProxyStats,
    host: &str,
    fallback: bool,
) {
    stats.record_sanitized(stream.take_sanitized());
    for anomaly in stream.take_anomalies() {
        stats.record_anomaly(anomaly, host, fallback && anomaly.fallback_eligible());
    }
}

/// What to do with an established upstream connection.
///
/// Replaces the old `forward_headers: bool` + `raw_headers: &[u8]` pair. That
/// flag let a non-CONNECT request take the tunnel branch and receive a
/// "200 Connection Established" it never asked for; as two variants the bug is
/// unrepresentable.
pub enum Upstream {
    /// CONNECT: acknowledge to the client, then relay bytes blind both ways.
    Tunnel,
    /// Plain HTTP: rewrite this head, then every later head on the connection.
    Http {
        first_head: Vec<u8>,
        config: Arc<RuntimeConfig>,
    },
}

async fn connect_and_tunnel(
    mut client_socket: TcpStream,
    host: &str,
    port: u16,
    upstream: Upstream,
    on_error: impl FnOnce(&std::io::Error),
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError> {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(mut remote)) => {
            debug!("Connected to {}:{}", host, port);

            match upstream {
                Upstream::Tunnel => {
                    client_socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    tunnel_fast(client_socket, remote, None, host, stats).await
                }
                Upstream::Http { first_head, config } => {
                    remote.set_nodelay(true)?;

                    let mut stream = crate::http_rewrite::RequestStream::new(
                        config.policy,
                        MAX_REQUEST_HEAD_SIZE,
                    );
                    let mut rewritten = Vec::with_capacity(first_head.len() + 64);
                    let push_result = stream.push(&first_head, &mut rewritten);

                    let fallback = config.policy == crate::http_rewrite::RewritePolicy::Fallback;
                    flush_rewrite_stats(&mut stream, &stats, host, fallback);

                    if let Err(anomaly) = push_result {
                        // Nothing has gone upstream yet, so the client can still
                        // be told. Mid-stream failures cannot be, which is why
                        // the relay path just closes.
                        warn!(
                            "Rewrite anomaly '{}' on first request to {}:{} — refusing",
                            anomaly.name(),
                            host,
                            port
                        );
                        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                        client_socket
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await?;
                        return Ok(());
                    }

                    remote.write_all(&rewritten).await?;
                    tunnel_fast(client_socket, remote, Some(stream), host, stats).await
                }
            }
        }
        Ok(Err(e)) => {
            on_error(&e);
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to connect to {}:{} - {}", host, port, e);
            client_socket
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            Ok(())
        }
        Err(_) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!("Timeout connecting to {}:{}", host, port);
            client_socket
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            Ok(())
        }
    }
}

async fn handle_http(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
    // Read headers incrementally — no large upfront buffer
    let mut raw_headers = Vec::new();
    let mut small_buf = [0u8; 1024];
    let max_header_size = MAX_REQUEST_HEAD_SIZE;

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
        connect_and_tunnel(
            client_socket,
            host,
            port,
            Upstream::Tunnel,
            |e| analyze_ssl_error(host, port, e),
            stats,
        )
        .await?;
    } else {
        let parsed_url = Url::parse(url)?;
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().ok_or("No host found")?;
        let port = parsed_url
            .port()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        if scheme != "http" {
            // The old code passed forward_headers=false here, which sent the
            // client a "200 Connection Established" it never requested. This
            // proxy cannot originate TLS, so absolute-form https is unsupported;
            // clients wanting TLS must use CONNECT. 502 rather than a new status
            // string, to avoid adding a client-facing response shape.
            warn!(
                "Unsupported absolute-form scheme '{}' for {}:{}",
                scheme, host, port
            );
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            client_socket
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        }

        stats.http_requests.fetch_add(1, Ordering::Relaxed);
        info!("HTTP {} request to {}://{}:{}", method, scheme, host, port);
        connect_and_tunnel(
            client_socket,
            host,
            port,
            Upstream::Http {
                first_head: raw_headers.clone(),
                config: config.clone(),
            },
            |_e| {},
            stats,
        )
        .await?;
    }

    Ok(())
}

// SOCKS5 server implementation (RFC 1928) — no-auth, CONNECT only.
async fn handle_socks5(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
    // Unused until the RFC 1929 handshake lands; keeps the migration warning-free.
    let _ = &config;
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
            tunnel_fast(client_socket, remote, None, host.as_str(), stats.clone()).await?;
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

/// Tune the **client-facing** socket only.
///
/// The origin-facing socket deliberately inherits OS defaults: these values are
/// far from default and are observable from the origin side. Accepted cost is
/// slower dead-origin detection — establishment is still bounded by
/// `CONNECT_TIMEOUT` and stalls by `IDLE_TIMEOUT`. Waiting minutes on a stalled
/// peer is what a normal client does, so the fingerprint fix and the correct
/// behavior coincide.
#[cfg(unix)]
fn configure_client_socket(client: &TcpStream) {
    use std::os::unix::io::AsRawFd;

    fn set_sock(fd: i32, level: i32, opt: i32, val: i32) {
        let _ = unsafe {
            libc::setsockopt(
                fd,
                level,
                opt,
                &val as *const _ as *const _,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
    }

    let fd = client.as_raw_fd();
    let one = 1i32;
    set_sock(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, one);
    set_sock(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60);
    set_sock(fd, libc::IPPROTO_TCP, TCP_QUICKACK, one);
    set_sock(fd, libc::IPPROTO_TCP, TCP_USER_TIMEOUT, 10_000);
}

/// Tune the **client-facing** socket only. See the Unix variant for rationale.
#[cfg(windows)]
fn configure_client_socket(client: &TcpStream) {
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
                socket,
                SIO_KEEPALIVE_VALS,
                ka as *const _ as *mut _,
                std::mem::size_of::<TcpKeepalive>() as _,
                std::ptr::null_mut(),
                0,
                &mut ret,
                std::ptr::null_mut(),
                None,
            )
        };
    }

    set_keepalive(client.as_raw_socket() as _, &ka);
}

/// Rewriter state shared by the two halves of a plain-HTTP relay.
///
/// A `std::sync::Mutex` is correct here: it is only ever held for a synchronous
/// state-machine step, never across an await. `upgrade_watch` lets the response
/// half skip locking entirely, which keeps it a blind relay for all normal
/// traffic — the lock is touched only while an upgrade offer is outstanding.
struct RewriteShared {
    stream: Mutex<crate::http_rewrite::RequestStream>,
    upgrade_watch: AtomicBool,
}

async fn tunnel_fast(
    mut src: TcpStream,
    mut dst: TcpStream,
    rewrite: Option<crate::http_rewrite::RequestStream>,
    host: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError> {
    src.set_nodelay(true)?;
    dst.set_nodelay(true)?;
    // `src` is the client; `dst` is the origin and keeps OS defaults.
    configure_client_socket(&src);

    let (mut src_reader, mut src_writer) = src.split();
    let (mut dst_reader, mut dst_writer) = dst.split();

    match rewrite {
        // CONNECT and SOCKS5: opaque both ways, zero parsing cost.
        None => {
            let client_to_server = bounded_copy_with_stats(
                &mut src_reader,
                &mut dst_writer,
                MAX_DOWNLOAD_SIZE,
                IDLE_TIMEOUT,
                "client->server",
                stats.clone(),
            );
            let server_to_client = bounded_copy_with_stats(
                &mut dst_reader,
                &mut src_writer,
                MAX_DOWNLOAD_SIZE,
                IDLE_TIMEOUT,
                "server->client",
                stats.clone(),
            );
            tokio::try_join!(client_to_server, server_to_client)?;
        }
        Some(stream) => {
            let fallback = stream.is_fallback();
            let shared = Arc::new(RewriteShared {
                stream: Mutex::new(stream),
                upgrade_watch: AtomicBool::new(false),
            });

            let out_shared = shared.clone();
            let out_stats = stats.clone();
            let out_host = host.to_string();
            let client_to_server = copy_loop(
                &mut src_reader,
                &mut dst_writer,
                MAX_DOWNLOAD_SIZE,
                IDLE_TIMEOUT,
                "client->server",
                stats.clone(),
                move |chunk| {
                    let mut rewritten = Vec::with_capacity(chunk.len() + 64);
                    let mut guard = out_shared
                        .stream
                        .lock()
                        .map_err(|_| ProxyError::from("rewriter lock poisoned"))?;
                    let result = guard.push(chunk, &mut rewritten);
                    flush_rewrite_stats(&mut guard, &out_stats, &out_host, fallback);
                    out_shared
                        .upgrade_watch
                        .store(guard.upgrade_offered(), Ordering::Relaxed);
                    drop(guard);

                    if let Err(anomaly) = result {
                        // Mid-stream, so no status line can be injected; closing
                        // is the only option that does not leak.
                        warn!(
                            "Rewrite anomaly '{}' for {} — closing connection",
                            anomaly.name(),
                            out_host
                        );
                        return Err(ProxyError::from("rewrite anomaly"));
                    }
                    Ok(Transformed::Replaced(rewritten))
                },
            );

            let in_shared = shared.clone();
            let server_to_client = copy_loop(
                &mut dst_reader,
                &mut src_writer,
                MAX_DOWNLOAD_SIZE,
                IDLE_TIMEOUT,
                "server->client",
                stats.clone(),
                move |chunk| {
                    // One atomic load in the common case; no lock, no copy.
                    if in_shared.upgrade_watch.load(Ordering::Relaxed) {
                        if let Ok(mut guard) = in_shared.stream.lock() {
                            guard.observe_response(chunk);
                            if !guard.upgrade_offered() {
                                in_shared.upgrade_watch.store(false, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(Transformed::Verbatim)
                },
            );

            tokio::try_join!(client_to_server, server_to_client)?;
        }
    }

    Ok(())
}

/// What a copy hook decided to do with a chunk.
pub enum Transformed {
    /// Write the input bytes through unchanged.
    Verbatim,
    /// Write these bytes instead (possibly empty).
    Replaced(Vec<u8>),
}

/// Shared copy loop: idle timeout, byte cap, stats flushing, FIN propagation.
async fn copy_loop<R, W, F>(
    mut reader: R,
    mut writer: W,
    max_size: u64,
    idle_timeout: Duration,
    direction: &str,
    stats: Arc<ProxyStats>,
    mut hook: F,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
    F: FnMut(&[u8]) -> Result<Transformed, ProxyError>,
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
                    stats
                        .bytes_transferred
                        .fetch_add(bytes_read - last_flushed, Ordering::Relaxed);
                    last_flushed = bytes_read;
                }

                if bytes_read > max_size {
                    warn!("Download size limit exceeded: {} bytes", bytes_read);
                    return Err("Download size limit exceeded".into());
                }

                let transformed = hook(&buffer[..n])?;
                let payload: &[u8] = match &transformed {
                    Transformed::Verbatim => &buffer[..n],
                    Transformed::Replaced(bytes) => bytes,
                };
                if payload.is_empty() {
                    // Intended: an empty `Transformed::Replaced(vec![])` means
                    // "swallow this chunk" (no write, no FIN). Not a lost flush.
                    continue;
                }

                let write_result = timeout(idle_timeout, writer.write_all(payload)).await;
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
        stats
            .bytes_transferred
            .fetch_add(bytes_read - last_flushed, Ordering::Relaxed);
    }

    Ok(())
}

// Copy with size limits and statistics tracking
pub async fn bounded_copy_with_stats<R, W>(
    reader: R,
    writer: W,
    max_size: u64,
    idle_timeout: Duration,
    direction: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    copy_loop(
        reader,
        writer,
        max_size,
        idle_timeout,
        direction,
        stats,
        |_| Ok(Transformed::Verbatim),
    )
    .await
}

