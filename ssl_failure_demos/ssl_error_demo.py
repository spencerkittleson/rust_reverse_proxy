#!/usr/bin/env python3
"""
Demonstration script showing SSL certificate error detection in rust_proxy.

This script shows how the enhanced proxy detects and reports SSL/TLS certificate issues.
"""

import socket
import ssl
import threading
import time
import subprocess
import sys
import os


def create_ssl_server_with_invalid_cert(port=8443):
    """Create a simple SSL server with an invalid self-signed certificate for testing."""

    def server_thread():
        # Create a self-signed certificate (this will be invalid for most clients)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_default_certs()

        # For demo purposes, we'll use a simple socket that fails SSL handshake
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("localhost", port))
        server_socket.listen(1)

        print(f"🔧 Test SSL server listening on port {port}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Connection from {addr}")

                # Try to establish SSL but it will fail with certificate errors
                try:
                    ssl_socket = context.wrap_socket(client_socket, server_side=True)
                    ssl_socket.send(b"Hello SSL")
                except ssl.SSLError as e:
                    print(f"Expected SSL error: {e}")
                    client_socket.close()
                except Exception as e:
                    print(f"Other error: {e}")
                    client_socket.close()

        except KeyboardInterrupt:
            print("\nShutting down test server")
        finally:
            server_socket.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    return thread


def test_ssl_detection():
    """Test the proxy's SSL certificate error detection."""

    print("🚀 Testing SSL Certificate Error Detection")
    print("=" * 50)

    # Start the problematic SSL server
    ssl_server = create_ssl_server_with_invalid_cert()
    time.sleep(1)

    # Start the proxy
    print("\n📡 Starting rust_proxy...")
    proxy_process = subprocess.Popen(
        ["cargo", "run", "--", "--port", "3129", "--log-level", "debug"],
        cwd="/home/spencerkittleson/Repos/d40b69b39274f733343c2c9bb4adaf86/rust_proxy",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    time.sleep(2)  # Let proxy start

    print("🌐 Attempting to connect through proxy to invalid SSL server...")

    try:
        # Try to connect through proxy to our problematic SSL server
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect(("localhost", 3129))

        # Send CONNECT request
        connect_request = (
            f"CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\n\r\n"
        )
        proxy_socket.send(connect_request.encode())

        # Read response
        response = proxy_socket.recv(1024).decode()
        print(f"Proxy response: {response.strip()}")

        # Try SSL handshake through proxy (this should fail)
        try:
            ssl_context = ssl.create_default_context()
            ssl_socket = ssl_context.wrap_socket(
                proxy_socket, server_hostname="localhost"
            )
            ssl_socket.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        except ssl.SSLError as e:
            print(f"SSL handshake failed as expected: {e}")

        proxy_socket.close()

    except Exception as e:
        print(f"Connection error: {e}")

    # Wait a bit to see proxy logs
    print("\n📋 Proxy logs (showing SSL error detection):")
    print("-" * 50)

    try:
        # Read some output from proxy
        if proxy_process.stdout:
            for _ in range(10):
                line = proxy_process.stdout.readline()
                if line:
                    print(line.strip())
                else:
                    time.sleep(0.1)
    except:
        pass

    # Clean up
    proxy_process.terminate()
    print("\n✅ SSL certificate error detection test completed!")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python3 ssl_error_demo.py")
        print("This demonstrates how rust_proxy detects SSL certificate errors")
        sys.exit(0)

    # Check if we're in the right directory
    if not os.path.exists("rust_proxy"):
        print("Error: Run this script from the repository root directory")
        sys.exit(1)

    test_ssl_detection()
