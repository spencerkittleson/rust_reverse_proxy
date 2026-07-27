use rust_proxy::http_rewrite::{sanitize_request_head, RewriteAnomaly};

/// Assert byte-exact output. Renders as text on failure, which matters because
/// the whole point of this module is exact bytes.
fn assert_sanitized(input: &[u8], expected: &[u8]) {
    let got = sanitize_request_head(input).expect("should sanitize");
    assert_eq!(
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(expected),
        "byte mismatch"
    );
}

#[test]
fn rewrites_absolute_form_to_origin_form() {
    assert_sanitized(
        b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn empty_path_becomes_slash() {
    assert_sanitized(
        b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn query_only_target_gets_slash_prefix() {
    assert_sanitized(
        b"GET http://example.com?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET /?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn method_and_version_are_preserved_verbatim() {
    assert_sanitized(
        b"PROPFIND http://example.com/x HTTP/1.0\r\nHost: example.com\r\n\r\n",
        b"PROPFIND /x HTTP/1.0\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn unrelated_headers_pass_through_byte_for_byte() {
    // Odd spacing and casing must survive: normalizing it would be a new fingerprint.
    assert_sanitized(
        b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nx-WeIrD:   spaced   \r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\nx-WeIrD:   spaced   \r\n\r\n",
    );
}

#[test]
fn garbage_is_unparseable() {
    assert_eq!(
        sanitize_request_head(b"not a request\r\n\r\n"),
        Err(RewriteAnomaly::Unparseable)
    );
}

#[test]
fn head_without_terminator_is_unparseable() {
    assert_eq!(
        sanitize_request_head(b"GET http://e/ HTTP/1.1\r\n"),
        Err(RewriteAnomaly::Unparseable)
    );
}

#[test]
fn anomaly_names_and_indices_are_stable_and_unique() {
    let mut seen = std::collections::HashSet::new();
    for a in RewriteAnomaly::ALL {
        assert!(seen.insert(a.index()), "duplicate index for {}", a.name());
        assert!(a.index() < RewriteAnomaly::COUNT);
        assert!(!a.name().is_empty());
    }
}

#[test]
fn framing_conflict_is_never_fallback_eligible() {
    assert!(!RewriteAnomaly::FramingConflict.fallback_eligible());
    assert!(RewriteAnomaly::HeadTooLarge.fallback_eligible());
    assert!(RewriteAnomaly::Unparseable.fallback_eligible());
    assert!(RewriteAnomaly::ObsFoldInRewrittenHeader.fallback_eligible());
}
