#!/usr/bin/env python3
"""
Simple demonstration of SSL certificate error detection patterns.

This script shows examples of SSL/TLS errors that the enhanced rust_proxy can detect.
"""

import re


def simulate_ssl_error_detection():
    """Simulate how the proxy detects SSL certificate errors."""

    print("🔒 SSL Certificate Error Detection Demo")
    print("=" * 50)

    # Sample error messages that the proxy can detect
    ssl_errors = [
        "certificate has expired",
        "unable to verify the first certificate",
        "self signed certificate in certificate chain",
        "certificate is not yet valid",
        "certificate has been revoked",
        "SSL handshake failed",
        "TLS verification failed",
        "unknown certificate authority",
        "certificate signature verification failed",
        "cannot get local issuer certificate",
    ]

    # SSL indicator patterns from the proxy
    ssl_cert_indicators = [
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
    ]

    print("📋 Testing SSL/TLS Error Pattern Detection:")
    print("-" * 50)

    for error in ssl_errors:
        error_lower = error.lower()
        is_ssl_related = any(
            indicator in error_lower for indicator in ssl_cert_indicators
        )

        if is_ssl_related:
            print(f"✅ DETECTED: {error}")

            # Show specific analysis
            if "expired" in error_lower:
                print("   → Cause: Certificate has expired")
                print("   → Action: Update certificate on target server")
            elif "self-signed" in error_lower or "untrusted" in error_lower:
                print("   → Cause: Certificate is self-signed or untrusted")
                print(
                    "   → Action: Add certificate to trust store or use valid certificate"
                )
            elif "handshake" in error_lower:
                print("   → Cause: TLS handshake failed")
                print("   → Action: Check certificate compatibility and TLS version")
            elif "verify" in error_lower:
                print("   → Cause: Certificate verification failed")
                print("   → Action: Check certificate chain and CA trust")
            elif "revoked" in error_lower:
                print("   → Cause: Certificate has been revoked")
                print("   → Action: Renew certificate with new signing")
            else:
                print("   → Cause: Unknown SSL/TLS certificate issue")
                print("   → Action: Investigate certificate validity and trust")
        else:
            print(f"❌ MISSED: {error}")
        print()

    print("🌐 VPN Context:")
    print("   When using VPN on Windows devices:")
    print("   • VPN routing may affect certificate validation")
    print("   • Certificate might be valid but blocked by VPN policy")
    print("   • Proxy will now detect and report these issues clearly")

    print("\n✨ Enhanced Features Added to rust_proxy:")
    print("   • SSL certificate error pattern detection")
    print("   • Detailed error analysis with specific guidance")
    print("   • VPN-aware error context for Windows")
    print("   • Clear logging with 🔒 emoji for SSL issues")
    print("   • Detection during both connection and data transfer phases")


if __name__ == "__main__":
    simulate_ssl_error_detection()
