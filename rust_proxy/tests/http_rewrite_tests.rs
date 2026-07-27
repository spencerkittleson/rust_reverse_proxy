use rust_proxy::http_rewrite::{sanitize_request_head, RewriteAnomaly};

/// Assert byte-exact output.
///
/// Compares the raw slices — NOT lossy strings, which would collapse any
/// non-UTF-8 divergence to U+FFFD on both sides and compare equal. Byte identity
/// is this module's entire contract, so the guard for it must be byte-exact.
/// Lossy rendering appears only in the failure message, for readability.
fn assert_sanitized(input: &[u8], expected: &[u8]) {
    let got = sanitize_request_head(input).expect("should sanitize");
    assert_eq!(
        got,
        expected.to_vec(),
        "byte mismatch\n     got: {:?}\nexpected: {:?}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(expected)
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

#[test]
fn host_header_takes_authority_from_request_target() {
    // The request-target authority wins over a disagreeing Host header.
    assert_sanitized(
        b"GET http://real.example/ HTTP/1.1\r\nHost: stale.example\r\nAccept: */*\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: real.example\r\nAccept: */*\r\n\r\n",
    );
}

#[test]
fn matching_host_header_is_a_zero_byte_change() {
    let head = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    let got = sanitize_request_head(head).unwrap();
    assert_eq!(
        got,
        b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n".to_vec()
    );
}

#[test]
fn absent_host_header_is_inserted_first() {
    // Browsers and curl put Host first; inserting it elsewhere would be a tell.
    assert_sanitized(
        b"GET http://example.com/ HTTP/1.1\r\nAccept: */*\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
    );
}

#[test]
fn default_http_port_is_stripped_from_host() {
    assert_sanitized(
        b"GET http://example.com:80/ HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn non_default_port_is_kept_in_host() {
    assert_sanitized(
        b"GET http://example.com:8080/ HTTP/1.1\r\nHost: nope\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
    );
}

#[test]
fn port_lookalike_is_not_mistaken_for_default_port() {
    // "h:8080" ends in "080", not ":80" — must not be truncated.
    assert_sanitized(
        b"GET http://h:8080/x HTTP/1.1\r\nHost: h:8080\r\n\r\n",
        b"GET /x HTTP/1.1\r\nHost: h:8080\r\n\r\n",
    );
}

#[test]
fn host_field_name_casing_and_spacing_are_preserved() {
    // Only the value changes; the field name's odd casing and the original
    // whitespace after the colon survive.
    assert_sanitized(
        b"GET http://real.example/ HTTP/1.1\r\nhOsT:   stale.example\r\n\r\n",
        b"GET / HTTP/1.1\r\nhOsT:   real.example\r\n\r\n",
    );
}

#[test]
fn userinfo_is_stripped_from_host() {
    assert_sanitized(
        b"GET http://user:pw@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn ipv6_literal_keeps_brackets_and_loses_default_port() {
    assert_sanitized(
        b"GET http://[::1]:80/x HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
        b"GET /x HTTP/1.1\r\nHost: [::1]\r\n\r\n",
    );
}

#[test]
fn origin_form_request_keeps_its_existing_host() {
    // No authority in the target, so there is nothing to correct.
    assert_sanitized(
        b"GET /already HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET /already HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
}

#[test]
fn non_utf8_header_value_survives_byte_for_byte() {
    // A latin-1 byte (0xE9 = 'é') in an untouched header must pass through
    // unchanged. This is the case a lossy comparison would silently accept.
    let input: &[u8] = b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nX-Note: caf\xe9\r\n\r\n";
    let expected: &[u8] = b"GET / HTTP/1.1\r\nHost: e.example\r\nX-Note: caf\xe9\r\n\r\n";
    assert_sanitized(input, expected);
}

#[test]
fn proxy_connection_is_renamed_in_place_not_deleted() {
    // Deleting it would strip the client's stated intent and leave a header set
    // no real client emits. The line keeps its position.
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
    );
}

#[test]
fn proxy_connection_is_dropped_when_connection_already_present() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: close\r\nProxy-Connection: keep-alive\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nConnection: close\r\n\r\n",
    );
}

#[test]
fn proxy_authorization_is_always_dropped() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nProxy-Authorization: Basic zzz\r\nAccept: */*\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nAccept: */*\r\n\r\n",
    );
}

#[test]
fn headers_named_by_connection_tokens_are_dropped() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive, X-Hop\r\nX-Hop: secret\r\nAccept: */*\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
    );
}

#[test]
fn connection_line_is_dropped_when_no_forwardable_token_survives() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: X-Hop\r\nX-Hop: secret\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\n\r\n",
    );
}

#[test]
fn upgrade_token_and_upgrade_header_both_survive() {
    // RFC 7230 calls `upgrade` hop-by-hop, but dropping it would make upgrade
    // passthrough unreachable.
    assert_sanitized(
        b"GET http://e.example/ws HTTP/1.1\r\nHost: e.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        b"GET /ws HTTP/1.1\r\nHost: e.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    );
}

#[test]
fn renamed_proxy_connection_still_drives_hop_by_hop_removal() {
    // Rule 5 operates on the Connection header as rule 3 leaves it.
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nProxy-Connection: keep-alive, X-Hop\r\nX-Hop: secret\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive\r\n\r\n",
    );
}

#[test]
fn connection_token_matching_is_case_insensitive() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: KEEP-ALIVE, x-hop\r\nX-HoP: secret\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nConnection: KEEP-ALIVE\r\n\r\n",
    );
}

#[test]
fn obs_fold_in_untouched_header_passes_through() {
    assert_sanitized(
        b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nX-Long: a\r\n\tb\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: e.example\r\nX-Long: a\r\n\tb\r\n\r\n",
    );
}

#[test]
fn obs_fold_in_rewritten_header_is_an_anomaly() {
    assert_eq!(
        sanitize_request_head(
            b"GET http://e.example/ HTTP/1.1\r\nHost: stale\r\n\texample\r\n\r\n"
        ),
        Err(RewriteAnomaly::ObsFoldInRewrittenHeader)
    );
    assert_eq!(
        sanitize_request_head(
            b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive\r\n\tfoo\r\n\r\n"
        ),
        Err(RewriteAnomaly::ObsFoldInRewrittenHeader)
    );
}
