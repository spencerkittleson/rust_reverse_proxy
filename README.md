# Rust Forward Transparent Proxy Server

A high-performance, configurable HTTP/HTTPS proxy server written in Rust with advanced SSL/TLS intelligence and Windows integration.

## Features

- **HTTP and HTTPS Proxy Support**: Handles both HTTP requests and HTTPS CONNECT tunnels
- **Advanced SSL/TLS Intelligence**: Sophisticated certificate error detection with 25+ error patterns and VPN-aware context
- **Windows Integration**: Automatic firewall configuration, network profile management, and power optimization
- **Cross-Platform Binaries**: Pre-built releases for Windows x64, Linux x64, macOS x64/arm64
- **Configurable Network Settings**: Customizable host and port with connection limiting
- **Comprehensive Logging**: Configurable log levels (debug, info, warn, error) with detailed diagnostics
- **Performance Optimized**: 64KB buffers, connection limits (10,000), timeouts, and size restrictions (1GB)
- **Robust Error Handling**: Intelligent SSL error analysis with actionable recommendations
- **Async Architecture**: Built on tokio for high-performance concurrent connections
- **Automated Releases**: GitHub Actions workflow for automated cross-platform builds and releases

## Quick Start

### Option 1: Download Pre-built Binary (Recommended)

Download the latest release from GitHub for your platform:

**Windows x64**: `rust_proxy-windows-x64.exe`
**Linux x64**: `rust_proxy-linux-x64`  
**macOS x64**: `rust_proxy-macos-x64`
**macOS ARM64**: `rust_proxy-macos-arm64`

```bash
# Download and run (Windows example)
wget https://github.com/spencerkittleson/rust_reverse_proxy/releases/latest/download/rust_proxy-windows-x64.exe
./rust_proxy-windows-x64.exe

# Default settings (0.0.0.0:3129, info level logging)
rust_proxy-windows-x64.exe

# Custom configuration
rust_proxy-windows-x64.exe --host 127.0.0.1 --port 8080 --log-level debug

# Short flags
rust_proxy-windows-x64.exe -h 127.0.0.1 -p 8080 -l debug
```

### Option 2: Build from Source

```bash
cd rust_proxy
cargo build --release

# Run binary
./target/release/rust_proxy
```

### Options

- `--host, -h`: Host to listen on (default: 0.0.0.0)
- `--port, -p`: Port to listen on (default: 3129)
- `--log-level, -l`: Logging level (default: info)
  - Available levels: debug, info, warn, error

### Logging

Logs can be output to stderr or redirected to a file:

```bash
# Log to stderr (default)
./target/release/rust_proxy --log-level debug

# Log to file
./target/release/rust_proxy --log-level info 2> proxy.log

# Combined logs with environment variables
RUST_LOG=info ./target/release/rust_proxy --log-level debug 2> proxy.log
```

## Usage Examples

### Basic HTTP Proxy

```bash
# Start proxy
./target/release/rust_proxy --host 127.0.0.1 --port 3128

# Use with curl
curl -x http://127.0.0.1:3128 http://example.com
```

### HTTPS Proxy

```bash
# Start proxy
./target/release/rust_proxy --port 3129

# Use with curl for HTTPS
curl -x http://127.0.0.1:3129 https://example.com
```

## Testing

This project includes a comprehensive test suite covering unit tests, integration tests, and logging validation.

### Run All Tests

```bash
cargo test
```

### Run Specific Test Categories

```bash
# Unit tests (in tests/unit_tests.rs)
cargo test --test unit_tests

# Integration tests
cargo test --test integration_tests

# Logging tests
cargo test --test logging_tests

# All tests
cargo test
```

### Individual Test Examples

```bash
# Run specific unit test
cargo test test_find_request_end

# Run specific integration test
cargo test test_proxy_integration

# Run with verbose output
cargo test -- --nocapture

# Run tests in parallel
cargo test --release
```

### Test Coverage

The test suite includes:

**Unit Tests (9 tests in `tests/unit_tests.rs`):**
- HTTP header parsing (`test_find_request_end`)
- Host/port extraction (`test_parse_host_port`)
- Data copying with limits (`test_bounded_copy_*`)
- Request format parsing (`test_*_request_parsing`)
- Command line argument parsing (`test_args_parsing`)
- Log level configuration (`test_log_level_parsing`)

**Integration Tests (4 tests in `tests/integration_tests.rs`):**
- Proxy server startup and connectivity (`test_proxy_integration`)
- HTTP proxy functionality (`test_http_proxy_request`)
- HTTPS CONNECT tunneling (`test_connect_proxy_request`)
- Error handling for invalid requests (`test_proxy_handles_invalid_requests`)

**Logging Tests (3 tests in `tests/logging_tests.rs`):**
- Log output verification (`test_logging_output_to_file`)
- All log level configurations (`test_logging_levels`)
- Invalid log level handling (`test_invalid_log_level_handling`)

### Test Environment

Tests use temporary network configurations:
- Various ports (3130-3142) to avoid conflicts
- Mock servers for integration testing
- Temporary files for log testing
- Automatic cleanup after test completion

### Performance Testing

For performance testing, you can use tools like:

```bash
# Using curl with timing
curl -x http://127.0.0.1:3129 -w "@curl-format.txt" http://example.com

# Using Apache Bench
ab -n 1000 -c 10 -x 127.0.0.1:3129 http://example.com/

# Using wrk (if installed)
wrk -t4 -c100 -d30s --timeout 10s http://127.0.0.1:3129/
```

## Configuration

### Environment Variables

- `RUST_LOG`: Set global logging level (overrides default if more verbose)
- `RUST_LOG_STYLE`: Log output style (always, auto, never)

### Windows-Specific Features

**Automatic Network Configuration:**
- Firewall rule creation for proxy ports
- Network profile management (private network detection)
- Power management (disable lid close action for server stability)

**VPN Integration:**
- Detects VPN connection contexts in SSL errors
- Provides VPN-specific troubleshooting guidance
- Handles corporate network SSL certificate scenarios

### Runtime Limits

- **Max Connections**: 10,000 concurrent connections (configurable via `MAX_CONNECTIONS`)
- **Connection Timeout**: 10 seconds for initial connection establishment
- **Idle Timeout**: 5 minutes for inactive connections (300 seconds)
- **Max Download Size**: 1GB per connection to prevent resource exhaustion
- **Buffer Size**: 64KB for optimal throughput with `TCP_NODELAY`

### SSL/TLS Intelligence

The proxy includes advanced SSL certificate error detection:

**Error Pattern Recognition:**
- Certificate validation failures (expired, wrong host, self-signed)
- Certificate chain issues (incomplete chain, untrusted root)
- Protocol and cipher suite mismatches
- Network-level SSL/TLS failures
- Windows-specific SSL errors and VPN contexts

**Diagnostic Features:**
- 25+ specific error pattern matching
- VPN-aware error context analysis
- Actionable recommendations for each error type
- Two-phase detection (connection establishment + data transfer)

## Development

### Code Structure

- `src/main.rs`: Binary entry point with Windows-specific integration and server startup
- `src/lib.rs`: Core library with proxy logic, SSL intelligence, and connection handling
- `tests/unit_tests.rs`: Unit tests for individual functions (9 tests)
- `tests/integration_tests.rs`: Integration tests for proxy functionality (4 tests)
- `tests/logging_tests.rs`: Tests for logging system (3 tests)

### Dependencies

**Core Runtime:**
- `tokio`: Async runtime with full features
- `tokio-util`: Codec utilities for efficient data processing
- `bytes`: High-performance byte buffer handling

**HTTP/URL Processing:**
- `url`: URL parsing for HTTP request routing
- `clap`: Command-line argument parsing with derive macros

**Logging:**
- `log`: Logging framework
- `env_logger`: Environment-based logger configuration

**Windows Integration:**
- `winapi`: Windows API for firewall, network, and power management

**Testing:**
- `tokio-test`: Async testing utilities
- `tempfile`: Temporary file handling for tests

### Build Modes

```bash
# Debug build (with test symbols)
cargo build

# Release build (optimized)
cargo build --release

# Test build
cargo test --no-run
```

### Linting and Formatting

```bash
# Format code
cargo fmt

# Run clippy lints
cargo clippy -- -D warnings
```

## Troubleshooting

### Common Issues

1. **Port already in use**: Change port with `--port` flag
2. **Permission denied**: Use port > 1024 or run with sudo
3. **High memory usage**: Reduce `MAX_CONNECTIONS` constant in src/lib.rs
4. **Connection timeouts**: Check firewall settings and network connectivity
5. **SSL Certificate Errors**: Use debug logging to see specific error patterns and recommendations

### SSL/TLS Troubleshooting

The proxy provides detailed SSL error diagnostics:

```bash
# Enable debug logging for SSL error analysis
./target/release/rust_proxy --log-level debug

# Monitor SSL-specific errors
RUST_LOG=debug ./target/release/rust_proxy 2>&1 | grep -E "(SSL|TLS|certificate)"
```

**Common SSL Error Categories:**
- **Certificate Issues**: Expired, wrong host, self-signed certificates
- **Chain Problems**: Incomplete certificate chains, untrusted roots
- **Protocol Mismatches**: TLS version or cipher suite incompatibilities
- **Network Failures**: Connection timeouts during SSL handshake

### Windows-Specific Issues

**Firewall Configuration:**
- Proxy automatically creates firewall rules for configured ports
- Manual firewall rules may interfere with automatic configuration

**Network Profile:**
- Requires network profile detection for proper operation
- Corporate networks may restrict automatic configuration

**Power Management:**
- Lid close action is automatically disabled to prevent interruptions
- Server stability optimized for continuous operation

### Debug Mode

```bash
# Enable debug logging for detailed troubleshooting
./target/release/rust_proxy --log-level debug

# Monitor specific operations
RUST_LOG=debug ./target/release/rust_proxy 2>&1 | grep -E "(INFO|WARN|ERROR)"

# Monitor connection lifecycle
RUST_LOG=debug ./target/release/rust_proxy 2>&1 | grep -E "(connection|tunnel|proxy)"
```

## Releases

### Automated Binary Releases

This project uses GitHub Actions to automatically build and release cross-platform binaries when version tags are pushed.

**Supported Platforms:**
- Windows x64 (`rust_proxy-windows-x64.exe`)
- Linux x64 (`rust_proxy-linux-x64`)
- macOS x64 (`rust_proxy-macos-x64`)
- macOS ARM64 (`rust_proxy-macos-arm64`)

**Creating a Release:**
```bash
# Tag and push to trigger automated release
git tag v1.0.0
git push origin v1.0.0
```

This will:
1. Build binaries for all supported platforms
2. Create a GitHub release with all binary attachments
3. Generate release notes automatically

### Downloading Releases

Visit the [Releases page](https://github.com/spencerkittleson/rust_reverse_proxy/releases) to download the latest binary for your platform.

## License

This project is licensed under the MIT License.