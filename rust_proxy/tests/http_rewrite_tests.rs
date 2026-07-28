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

#[test]
fn obs_fold_on_a_dropped_hop_by_hop_header_fails_closed() {
    // X-Hop is named by a Connection token, so rule 5 drops it. A fold
    // continuing X-Hop must not be orphaned onto the wire — fail closed.
    assert_eq!(
        sanitize_request_head(
            b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\nConnection: keep-alive, X-Hop\r\nX-Hop: a\r\n\tb\r\n\r\n"
        ),
        Err(RewriteAnomaly::ObsFoldInRewrittenHeader)
    );
}

use rust_proxy::http_rewrite::{RequestStream, RewritePolicy};

/// Feed `input` through a stream in `chunk`-sized pieces. Small chunk sizes
/// exercise the split-read paths that blind relays never hit.
fn drive(policy: RewritePolicy, input: &[u8], chunk: usize) -> Result<Vec<u8>, PushError> {
    let mut stream = RequestStream::new(policy, 65536, None);
    let mut out = Vec::new();
    for piece in input.chunks(chunk) {
        stream.push(piece, &mut out)?;
    }
    Ok(out)
}

#[test]
fn every_request_on_a_reused_connection_is_rewritten() {
    // The regression this architecture exists to prevent: requests 2 and 3 must
    // not reach the origin in absolute form.
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                  GET http://e.example/two HTTP/1.1\r\nHost: e.example\r\n\r\n\
                  GET http://e.example/three HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let expected = b"GET /one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                     GET /two HTTP/1.1\r\nHost: e.example\r\n\r\n\
                     GET /three HTTP/1.1\r\nHost: e.example\r\n\r\n";

    for chunk in [1usize, 7, 64, 4096] {
        let got = drive(RewritePolicy::FailClosed, input, chunk).unwrap();
        assert_eq!(
            got,
            expected.to_vec(),
            "failed at chunk size {chunk}\n     got: {:?}\nexpected: {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        );
        assert!(
            !got.windows(7).any(|w| w == b"http://"),
            "absolute form leaked at chunk size {chunk}"
        );
    }
}

#[test]
fn mid_stream_origin_form_request_is_supported_not_an_anomaly() {
    // Forwarding origin form leaks nothing, because it is exactly what rule 1
    // produces. Rules 2-5 still apply, so the proxy header is still stripped.
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                  GET /two HTTP/1.1\r\nHost: e.example\r\nProxy-Connection: close\r\n\r\n";
    let expected = b"GET /one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                     GET /two HTTP/1.1\r\nHost: e.example\r\nConnection: close\r\n\r\n";
    let got = drive(RewritePolicy::FailClosed, input, 1).unwrap();
    assert_eq!(
        got,
        expected.to_vec(),
        "byte mismatch\n     got: {:?}\nexpected: {:?}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(expected)
    );
}

#[test]
fn content_length_body_is_relayed_verbatim() {
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\nContent-Length: 5\r\n\r\nab=cd\
                  GET http://e.example/y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let expected = b"POST /x HTTP/1.1\r\nHost: e.example\r\nContent-Length: 5\r\n\r\nab=cd\
                     GET /y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    for chunk in [1usize, 3, 4096] {
        let got = drive(RewritePolicy::FailClosed, input, chunk).unwrap();
        assert_eq!(
            got,
            expected.to_vec(),
            "failed at chunk size {chunk}\n     got: {:?}\nexpected: {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        );
    }
}

#[test]
fn chunked_body_is_relayed_verbatim_and_next_request_is_rewritten() {
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n\
                  5\r\nhello\r\n0\r\n\r\n\
                  GET http://e.example/y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let expected = b"POST /x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n\
                     5\r\nhello\r\n0\r\n\r\n\
                     GET /y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    for chunk in [1usize, 5, 4096] {
        let got = drive(RewritePolicy::FailClosed, input, chunk).unwrap();
        assert_eq!(
            got,
            expected.to_vec(),
            "failed at chunk size {chunk}\n     got: {:?}\nexpected: {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        );
    }
}

#[test]
fn chunked_trailers_are_relayed_and_end_the_body() {
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n\
                  0\r\nX-Trailer: v\r\n\r\n\
                  GET http://e.example/y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let expected = b"POST /x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n\
                     0\r\nX-Trailer: v\r\n\r\n\
                     GET /y HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let got = drive(RewritePolicy::FailClosed, input, 1).unwrap();
    assert_eq!(
        got,
        expected.to_vec(),
        "byte mismatch\n     got: {:?}\nexpected: {:?}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(expected)
    );
}

#[test]
fn transfer_encoding_plus_content_length_always_fails_closed() {
    // The most important assertion in this file. Forwarding this verbatim would
    // make the proxy a request-smuggling gadget aimed at the origin, so the
    // fallback flag must not reach it.
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                  Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n";
    for policy in [RewritePolicy::FailClosed, RewritePolicy::Fallback] {
        assert_eq!(
            drive(policy, input, 4096),
            Err(PushError::Anomaly(RewriteAnomaly::FramingConflict)),
            "framing conflict must fail closed under {policy:?}"
        );
    }
}

#[test]
fn duplicate_conflicting_content_length_is_a_framing_conflict() {
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                  Content-Length: 5\r\nContent-Length: 6\r\n\r\n";
    assert_eq!(
        drive(RewritePolicy::FailClosed, input, 4096),
        Err(PushError::Anomaly(RewriteAnomaly::FramingConflict))
    );
}

#[test]
fn duplicate_agreeing_content_length_is_accepted() {
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                  Content-Length: 2\r\nContent-Length: 2\r\n\r\nhi";
    assert!(drive(RewritePolicy::FailClosed, input, 4096).is_ok());
}

#[test]
fn oversized_head_fails_closed_by_default() {
    let mut input = b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\n".to_vec();
    input.extend_from_slice(b"X-Pad: ");
    input.extend(std::iter::repeat_n(b'a', 70_000));
    input.extend_from_slice(b"\r\n\r\n");

    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    let mut result = Ok(());
    for piece in input.chunks(4096) {
        result = stream.push(piece, &mut out);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(
        result,
        Err(PushError::Anomaly(RewriteAnomaly::HeadTooLarge))
    );
}

#[test]
fn fallback_forwards_verbatim_and_switches_to_passthrough() {
    // Unparseable is fallback-eligible. With the flag on, the bytes go through
    // untouched — that is the leak the flag buys — and parsing stops, because
    // the failed parse is the same parse that would find the next boundary.
    let input = b"!!! not http !!!\r\n\r\nany trailing bytes at all";
    let mut stream = RequestStream::new(RewritePolicy::Fallback, 65536, None);
    let mut out = Vec::new();
    stream.push(input, &mut out).expect("fallback should not error");

    assert_eq!(out, input.to_vec());
    assert!(stream.is_passthrough());
    assert_eq!(stream.take_anomalies(), vec![RewriteAnomaly::Unparseable]);
    // Draining is destructive so the caller cannot double-count.
    assert!(stream.take_anomalies().is_empty());
}

#[test]
fn unparseable_fails_closed_by_default() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    assert_eq!(
        stream.push(b"!!! not http !!!\r\n\r\n", &mut out),
        Err(PushError::Anomaly(RewriteAnomaly::Unparseable))
    );
    assert_eq!(stream.take_anomalies(), vec![RewriteAnomaly::Unparseable]);
}

#[test]
fn sanitized_request_count_tracks_successful_rewrites() {
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                  GET http://e.example/two HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(input, &mut out).unwrap();
    assert_eq!(stream.requests_sanitized(), 2);
    assert!(stream.take_anomalies().is_empty());
}

const WS_REQUEST: &[u8] = b"GET http://e.example/ws HTTP/1.1\r\nHost: e.example\r\n\
                            Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[test]
fn upgrade_request_arms_the_response_check_but_does_not_switch_yet() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();

    assert!(stream.upgrade_offered());
    assert!(
        !stream.is_passthrough(),
        "must not assume the upgrade succeeded"
    );
}

#[test]
fn accepted_upgrade_switches_to_passthrough() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    stream.observe_response(b"HTTP/1.1 101 Switching Protocols\r\n");
    assert!(stream.is_passthrough());

    // Post-upgrade bytes are not HTTP and must survive untouched.
    let mut frames = Vec::new();
    stream.push(b"\x81\x03abc", &mut frames).unwrap();
    assert_eq!(frames, b"\x81\x03abc".to_vec());
}

#[test]
fn declined_upgrade_keeps_parsing_and_still_rewrites_later_requests() {
    // This is why the response is consulted at all. Assuming success here would
    // leak absolute form on every later request on this connection.
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    stream.observe_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert!(!stream.is_passthrough());

    out.clear();
    stream
        .push(
            b"GET http://e.example/after HTTP/1.1\r\nHost: e.example\r\n\r\n",
            &mut out,
        )
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "GET /after HTTP/1.1\r\nHost: e.example\r\n\r\n"
    );
}

#[test]
fn response_observation_is_inert_without_an_upgrade_offer() {
    // The response path stays a blind relay for all normal traffic.
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream
        .push(
            b"GET http://e.example/ HTTP/1.1\r\nHost: e.example\r\n\r\n",
            &mut out,
        )
        .unwrap();
    assert!(!stream.upgrade_offered());

    stream.observe_response(b"HTTP/1.1 101 Switching Protocols\r\n");
    assert!(
        !stream.is_passthrough(),
        "a stray 101 must not disarm request rewriting"
    );
}

#[test]
fn split_status_line_is_still_detected() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    for piece in b"HTTP/1.1 101 Switching Protocols\r\n".chunks(1) {
        stream.observe_response(piece);
    }
    assert!(stream.is_passthrough());
}

#[test]
fn unbounded_chunk_size_line_fails_closed() {
    // A chunk-size line with endless extension octets and no CRLF must be
    // capped, not buffered without bound.
    let mut input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n5;".to_vec();
    input.extend(std::iter::repeat_n(b'a', 70_000));
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    let mut result = Ok(());
    for piece in input.chunks(4096) {
        result = stream.push(piece, &mut out);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(
        result,
        Err(PushError::Anomaly(RewriteAnomaly::HeadTooLarge))
    );
}

#[test]
fn unbounded_trailer_block_fails_closed() {
    // A trailer section that never terminates must be capped.
    let mut input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: ".to_vec();
    input.extend(std::iter::repeat_n(b'a', 70_000));
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    let mut result = Ok(());
    for piece in input.chunks(4096) {
        result = stream.push(piece, &mut out);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(
        result,
        Err(PushError::Anomaly(RewriteAnomaly::HeadTooLarge))
    );
}

#[test]
fn reason_phrase_containing_101_does_not_switch_to_passthrough() {
    // A non-101 status whose reason phrase contains "101" must NOT flip to
    // passthrough — that would silently disable rewriting and leak.
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    stream.observe_response(b"HTTP/1.1 500 Error 101 things\r\n");
    assert!(!stream.is_passthrough());

    // and a later request is still rewritten to origin-form
    out.clear();
    stream
        .push(
            b"GET http://e.example/after HTTP/1.1\r\nHost: e.example\r\n\r\n",
            &mut out,
        )
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out),
        "GET /after HTTP/1.1\r\nHost: e.example\r\n\r\n"
    );
}

#[test]
fn genuine_101_still_switches_to_passthrough() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, None);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    stream.observe_response(b"HTTP/1.1 101 Switching Protocols\r\n");
    assert!(stream.is_passthrough());
}

use rust_proxy::auth::Credentials;
use rust_proxy::http_rewrite::PushError;
use std::sync::Arc;

fn creds_for(text: &str) -> Option<Arc<Credentials>> {
    Some(Arc::new(Credentials::parse_file_contents(text).unwrap()))
}

/// Feed `input` through an authenticating stream in `chunk`-sized pieces.
fn drive_auth(
    policy: RewritePolicy,
    auth: Option<Arc<Credentials>>,
    input: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, PushError> {
    let mut stream = RequestStream::new(policy, 65536, auth);
    let mut out = Vec::new();
    for piece in input.chunks(chunk) {
        stream.push(piece, &mut out)?;
    }
    Ok(out)
}

#[test]
fn a_reused_connection_is_reauthenticated_on_every_request() {
    // The bypass this exists to prevent: request 1 carries a credential,
    // request 2 does not, and must not reach the origin.
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\
                  Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n\
                  GET http://e.example/two HTTP/1.1\r\nHost: e.example\r\n\r\n";

    for chunk in [1usize, 7, 64, 4096] {
        let result = drive_auth(
            RewritePolicy::FailClosed,
            creds_for("user:secret"),
            input,
            chunk,
        );
        assert_eq!(
            result,
            Err(PushError::Unauthorized),
            "request 2 slipped through at chunk size {chunk}"
        );
    }
}

#[test]
fn every_request_carrying_the_credential_is_forwarded() {
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\
                  Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n\
                  GET http://e.example/two HTTP/1.1\r\nHost: e.example\r\n\
                  Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    let expected = b"GET /one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                     GET /two HTTP/1.1\r\nHost: e.example\r\n\r\n";

    for chunk in [1usize, 7, 64, 4096] {
        let got = drive_auth(
            RewritePolicy::FailClosed,
            creds_for("user:secret"),
            input,
            chunk,
        )
        .unwrap();
        assert_eq!(got, expected.to_vec(), "failed at chunk size {chunk}");
    }
}

#[test]
fn unauthorized_is_never_eligible_for_rewrite_fallback() {
    // --rewrite-fallback buys a rewrite leak, never an access-control bypass.
    // This is the test that matters if anyone touches the error plumbing.
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n";
    for policy in [RewritePolicy::FailClosed, RewritePolicy::Fallback] {
        assert_eq!(
            drive_auth(policy, creds_for("user:secret"), input, 4096),
            Err(PushError::Unauthorized),
            "policy {policy:?} must not forward an unauthenticated request"
        );
    }
}

#[test]
fn an_unauthorized_head_produces_no_output_bytes() {
    // Nothing may be appended to `out` before the credential is accepted,
    // otherwise a partial head would already have gone upstream.
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536, creds_for("user:secret"));
    let mut out = Vec::new();
    let err = stream
        .push(
            b"GET http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\r\n",
            &mut out,
        )
        .unwrap_err();
    assert_eq!(err, PushError::Unauthorized);
    assert!(out.is_empty(), "leaked {:?}", String::from_utf8_lossy(&out));
    assert_eq!(stream.requests_sanitized(), 0);
}

#[test]
fn no_credential_configured_means_no_check() {
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let got = drive_auth(RewritePolicy::FailClosed, None, input, 4096).unwrap();
    assert_eq!(got, b"GET /one HTTP/1.1\r\nHost: e.example\r\n\r\n".to_vec());
}

#[test]
fn an_authenticated_body_still_streams() {
    // The check runs on heads only; a POST body must pass through untouched.
    let input = b"POST http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                  Content-Length: 5\r\n\
                  Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\nhello";
    let expected = b"POST /x HTTP/1.1\r\nHost: e.example\r\nContent-Length: 5\r\n\r\nhello";
    for chunk in [1usize, 7, 4096] {
        let got = drive_auth(
            RewritePolicy::FailClosed,
            creds_for("user:secret"),
            input,
            chunk,
        )
        .unwrap();
        assert_eq!(got, expected.to_vec(), "failed at chunk size {chunk}");
    }
}
