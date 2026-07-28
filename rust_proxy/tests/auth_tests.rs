use rust_proxy::auth::{AuthResult, Credentials};

fn creds(text: &str) -> Credentials {
    Credentials::parse_file_contents(text).expect("should parse")
}

/// Build a request head with the given `Proxy-Authorization` value.
fn head_with_auth(value: &str) -> Vec<u8> {
    format!(
        "GET http://e.example/x HTTP/1.1\r\nHost: e.example\r\nProxy-Authorization: {value}\r\n\r\n"
    )
    .into_bytes()
}

#[test]
fn valid_basic_credential_is_granted() {
    // base64("user:secret")
    let head = head_with_auth("Basic dXNlcjpzZWNyZXQ=");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Granted);
}

#[test]
fn scheme_match_is_case_insensitive() {
    // RFC 7235 makes the auth-scheme token case-insensitive; a client that
    // sends "basic" is not a client we should reject.
    let head = head_with_auth("basic dXNlcjpzZWNyZXQ=");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Granted);
}

#[test]
fn wrong_password_is_a_mismatch() {
    // base64("user:wrong")
    let head = head_with_auth("Basic dXNlcjp3cm9uZw==");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Mismatch);
}

#[test]
fn missing_header_is_missing_not_malformed() {
    // The distinction matters: the caller logs a reason code, and "no header"
    // is the ordinary first request from any client.
    let head = b"GET http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\r\n";
    assert_eq!(creds("user:secret").check_head(head), AuthResult::Missing);
}

#[test]
fn non_basic_scheme_is_malformed() {
    let head = head_with_auth("Bearer dXNlcjpzZWNyZXQ=");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Malformed);
}

#[test]
fn invalid_base64_is_malformed() {
    let head = head_with_auth("Basic !!!not-base64!!!");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Malformed);
}

#[test]
fn bare_scheme_with_no_token_is_malformed() {
    let head = head_with_auth("Basic");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Malformed);
}

#[test]
fn decoded_value_without_a_colon_never_matches() {
    // base64("nocolon"). Comparing the whole joined string means this cannot
    // match any entry, without a parse step on attacker bytes.
    let head = head_with_auth("Basic bm9jb2xvbg==");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Mismatch);
}

#[test]
fn duplicate_headers_are_rejected_rather_than_resolved() {
    // Two conflicting credentials in one head is the same class of ambiguity
    // as conflicting Content-Length. This project fails closed on ambiguity.
    let head = b"GET http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                 Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\
                 Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n";
    assert_eq!(creds("user:secret").check_head(head), AuthResult::Duplicate);
}

#[test]
fn password_may_contain_colons() {
    // base64("alice:p@ss:word") — the file splits on the first colon only.
    let head = head_with_auth("Basic YWxpY2U6cEBzczp3b3Jk");
    assert_eq!(
        creds("alice:p@ss:word").check_head(&head),
        AuthResult::Granted
    );
}

#[test]
fn any_configured_entry_may_match() {
    let head = head_with_auth("Basic dXNlcjpzZWNyZXQ=");
    let c = creds("alice:one\nuser:secret\nbob:three\n");
    assert_eq!(c.len(), 3);
    assert_eq!(c.check_head(&head), AuthResult::Granted);
}

#[test]
fn surrounding_whitespace_in_the_value_is_tolerated() {
    let head = head_with_auth("  Basic   dXNlcjpzZWNyZXQ=  ");
    assert_eq!(creds("user:secret").check_head(&head), AuthResult::Granted);
}

#[test]
fn obs_fold_continuation_is_not_read_as_a_header() {
    // A folded credential must not be assembled here. The rewrite layer
    // rejects obs-fold on a touched header separately; auth just fails to
    // find a value.
    let head = b"GET http://e.example/x HTTP/1.1\r\nHost: e.example\r\n\
                 Proxy-Authorization: Basic\r\n dXNlcjpzZWNyZXQ=\r\n\r\n";
    assert_eq!(creds("user:secret").check_head(head), AuthResult::Malformed);
}

#[test]
fn file_parsing_tolerates_crlf_comments_and_blank_lines() {
    // The credentials file will be edited on Windows. CRLF must work.
    let c = creds("# proxy users\r\n\r\nalice:one\r\nbob:two\r\n");
    assert_eq!(c.len(), 2);
}

#[test]
fn file_parsing_preserves_trailing_spaces_in_a_password() {
    // "pass " with a real trailing space is a legal password.
    let c = creds("alice:pass \r\n");
    assert!(c.verify_pair(b"alice", b"pass "));
    assert!(!c.verify_pair(b"alice", b"pass"));
}

#[test]
fn file_parsing_rejects_a_line_without_a_colon() {
    let err = Credentials::parse_file_contents("alice\n").unwrap_err();
    assert!(err.to_string().contains("line 1"), "{err}");
}

#[test]
fn file_parsing_rejects_an_empty_username() {
    assert!(Credentials::parse_file_contents(":secret\n").is_err());
}

#[test]
fn file_parsing_rejects_an_empty_password() {
    assert!(Credentials::parse_file_contents("alice:\n").is_err());
}

#[test]
fn file_parsing_rejects_a_file_with_no_entries() {
    // A comments-only file must be a hard error, never a silent no-auth.
    assert!(Credentials::parse_file_contents("# nothing here\n").is_err());
    assert!(Credentials::parse_file_contents("").is_err());
}

#[test]
fn verify_pair_accepts_the_configured_credential() {
    assert!(creds("alice:one").verify_pair(b"alice", b"one"));
    assert!(!creds("alice:one").verify_pair(b"alice", b"two"));
    assert!(!creds("alice:one").verify_pair(b"bob", b"one"));
}

#[test]
fn verify_pair_rejects_a_username_containing_a_colon() {
    // Guards the joined comparison: user="a", pass="b:c" and user="a:b",
    // pass="c" both join to "a:b:c". Stored usernames cannot contain a colon,
    // so refusing a presented one removes the ambiguity.
    let c = creds("a:b:c");
    assert!(c.verify_pair(b"a", b"b:c"));
    assert!(!c.verify_pair(b"a:b", b"c"));
}

#[test]
fn reason_codes_never_contain_credential_material() {
    for r in [
        AuthResult::Granted,
        AuthResult::Missing,
        AuthResult::Malformed,
        AuthResult::Mismatch,
        AuthResult::Duplicate,
    ] {
        let reason = r.reason();
        assert!(!reason.is_empty());
    }
    assert!(AuthResult::Granted.is_granted());
    assert!(!AuthResult::Missing.is_granted());
}

#[test]
fn debug_output_never_reveals_a_credential() {
    // This type ends up inside a Debug-deriving config; a derived Debug would
    // put the password in any log line or panic message that formats it.
    let rendered = format!("{:?}", creds("alice:supersecret\nbob:hunter2\n"));
    assert!(!rendered.contains("supersecret"), "{rendered}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("alice"), "{rendered}");
    assert!(rendered.contains("entries: 2"), "entry count should be visible: {rendered}");
}

#[test]
fn a_credential_in_the_body_is_not_a_credential() {
    // Scanning must stop at the blank line ending the head. Without that stop,
    // any client could put a credential in a request body it fully controls.
    // Nothing else in this file would catch that regression.
    let head_and_body = b"POST http://e.example/x HTTP/1.1\r\n\
                          Host: e.example\r\n\
                          Content-Length: 46\r\n\
                          \r\n\
                          Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n";
    assert_eq!(
        creds("user:secret").check_head(head_and_body),
        AuthResult::Missing
    );
}

use rust_proxy::auth::{addr_allowed, Cidr};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test address must parse")
}

#[test]
fn v4_prefix_matches_inside_and_rejects_outside() {
    let net = Cidr::parse("192.168.1.0/24").unwrap();
    assert!(net.contains(ip("192.168.1.1")));
    assert!(net.contains(ip("192.168.1.255")));
    assert!(!net.contains(ip("192.168.2.1")));
}

#[test]
fn a_bare_v4_address_is_a_host_route() {
    let host = Cidr::parse("10.0.0.7").unwrap();
    assert!(host.contains(ip("10.0.0.7")));
    assert!(!host.contains(ip("10.0.0.8")));
}

#[test]
fn slash_zero_matches_every_address_of_its_family() {
    let all4 = Cidr::parse("0.0.0.0/0").unwrap();
    assert!(all4.contains(ip("8.8.8.8")));
    assert!(all4.contains(ip("127.0.0.1")));
    // Shifting by the full width is undefined in Rust; /0 must be special-cased.
    assert!(!all4.contains(ip("2001:db8::1")));
}

#[test]
fn v4_prefix_boundaries_are_exact() {
    let net = Cidr::parse("10.1.2.0/23").unwrap();
    assert!(net.contains(ip("10.1.2.0")));
    assert!(net.contains(ip("10.1.3.255")));
    assert!(!net.contains(ip("10.1.4.0")));
    assert!(!net.contains(ip("10.1.1.255")));
}

#[test]
fn v6_prefix_matches() {
    let net = Cidr::parse("2001:db8::/32").unwrap();
    assert!(net.contains(ip("2001:db8::1")));
    assert!(net.contains(ip("2001:db8:ffff::1")));
    assert!(!net.contains(ip("2001:db9::1")));
    let host = Cidr::parse("::1").unwrap();
    assert!(host.contains(ip("::1")));
    assert!(!host.contains(ip("::2")));
}

#[test]
fn families_do_not_cross_match() {
    let net = Cidr::parse("192.168.1.0/24").unwrap();
    assert!(!net.contains(ip("2001:db8::1")));
}

#[test]
fn v4_mapped_v6_source_matches_a_v4_rule() {
    // A v4 client arriving on a dual-stack listener appears as ::ffff:a.b.c.d.
    // Without normalization a 192.168.1.0/24 rule would silently never match.
    let net = Cidr::parse("192.168.1.0/24").unwrap();
    assert!(net.contains(ip("::ffff:192.168.1.5")));
    // And a rule written in mapped form must match a plain v4 source.
    let mapped_rule = Cidr::parse("::ffff:192.168.1.0/24").unwrap();
    assert!(mapped_rule.contains(ip("192.168.1.5")));
}

#[test]
fn malformed_specs_are_rejected() {
    for bad in [
        "",
        "not-an-ip",
        "192.168.1.0/",
        "192.168.1.0/abc",
        "192.168.1.0/33",
        "2001:db8::/129",
        "192.168.1.0/-1",
    ] {
        assert!(Cidr::parse(bad).is_err(), "should reject {bad:?}");
    }
}

#[test]
fn surrounding_whitespace_in_a_spec_is_tolerated() {
    assert!(Cidr::parse("  10.0.0.0/8  ")
        .unwrap()
        .contains(ip("10.1.1.1")));
}

#[test]
fn an_empty_allowlist_permits_everything() {
    // No --allow-from means no filtering, not deny-all.
    assert!(addr_allowed(&[], ip("8.8.8.8")));
    assert!(addr_allowed(&[], ip("2001:db8::1")));
}

#[test]
fn a_populated_allowlist_is_a_union() {
    let list = [
        Cidr::parse("127.0.0.1").unwrap(),
        Cidr::parse("10.0.0.0/8").unwrap(),
    ];
    assert!(addr_allowed(&list, ip("127.0.0.1")));
    assert!(addr_allowed(&list, ip("10.9.9.9")));
    assert!(!addr_allowed(&list, ip("192.168.1.1")));
}

use clap::Parser;
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{build_runtime_config, load_credentials_file, Args, RuntimeConfig};
use std::io::Write;

fn args_from(extra: &[&str]) -> Args {
    let mut argv = vec!["rust_proxy"];
    argv.extend_from_slice(extra);
    Args::try_parse_from(argv).expect("args should parse")
}

fn write_temp(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn starting_with_no_credential_and_no_optout_is_refused() {
    // Fail closed: an unauthenticated proxy must be an explicit choice.
    let err = build_runtime_config(&args_from(&[]), None).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("--auth-file"), "{msg}");
    assert!(msg.contains("RUST_PROXY_AUTH"), "{msg}");
    assert!(msg.contains("--allow-anonymous"), "{msg}");
}

#[test]
fn allow_anonymous_alone_is_accepted_and_has_no_credential() {
    let cfg = build_runtime_config(&args_from(&["--allow-anonymous"]), None).unwrap();
    assert!(cfg.auth.is_none());
    assert!(cfg.allow_from.is_empty());
    assert_eq!(cfg.policy, RewritePolicy::FailClosed);
}

#[test]
fn a_credential_and_allow_anonymous_together_is_refused() {
    // Contradictory intent must not resolve silently in either direction.
    let err =
        build_runtime_config(&args_from(&["--allow-anonymous"]), Some("a:b".into())).unwrap_err();
    assert!(err.to_string().contains("cannot be combined"), "{err}");
}

#[test]
fn the_env_var_supplies_a_credential() {
    let cfg = build_runtime_config(&args_from(&[]), Some("alice:one".into())).unwrap();
    assert_eq!(cfg.auth.as_ref().unwrap().len(), 1);
    assert!(cfg.auth.as_ref().unwrap().verify_pair(b"alice", b"one"));
}

#[test]
fn a_malformed_env_value_is_refused() {
    assert!(build_runtime_config(&args_from(&[]), Some("no-colon".into())).is_err());
}

#[test]
fn the_auth_file_supplies_credentials() {
    let f = write_temp("alice:one\nbob:two\n");
    let path = f.path().to_str().unwrap();
    let cfg = build_runtime_config(&args_from(&["--auth-file", path]), None).unwrap();
    assert_eq!(cfg.auth.as_ref().unwrap().len(), 2);
}

#[test]
fn the_auth_file_wins_over_the_env_var() {
    // A stale environment variable must never override the file the operator
    // just edited.
    let f = write_temp("fromfile:one\n");
    let path = f.path().to_str().unwrap();
    let cfg = build_runtime_config(
        &args_from(&["--auth-file", path]),
        Some("fromenv:two".into()),
    )
    .unwrap();
    let creds = cfg.auth.as_ref().unwrap();
    assert!(creds.verify_pair(b"fromfile", b"one"));
    assert!(!creds.verify_pair(b"fromenv", b"two"));
}

#[test]
fn a_missing_auth_file_is_refused_with_the_path_named() {
    let err = build_runtime_config(
        &args_from(&["--auth-file", "/nonexistent/rust_proxy_auth"]),
        None,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("/nonexistent/rust_proxy_auth"),
        "{err}"
    );
}

#[test]
fn a_comments_only_auth_file_is_refused() {
    let f = write_temp("# no users yet\n");
    assert!(load_credentials_file(f.path().to_str().unwrap()).is_err());
}

#[test]
fn allow_from_specs_are_parsed_and_bad_ones_refused() {
    let cfg = build_runtime_config(
        &args_from(&[
            "--allow-anonymous",
            "--allow-from",
            "127.0.0.1",
            "--allow-from",
            "10.0.0.0/8",
        ]),
        None,
    )
    .unwrap();
    assert_eq!(cfg.allow_from.len(), 2);

    let err = build_runtime_config(
        &args_from(&["--allow-anonymous", "--allow-from", "nope"]),
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("nope"), "{err}");
}

#[test]
fn an_allowlist_is_not_a_substitute_for_a_credential() {
    // Address filtering is not authentication. Without --allow-anonymous this
    // must still refuse to start.
    assert!(build_runtime_config(&args_from(&["--allow-from", "10.0.0.0/8"]), None).is_err());
}

#[test]
fn auth_flags_compose_with_the_existing_ones() {
    let cfg = build_runtime_config(
        &args_from(&[
            "--host",
            "127.0.0.1",
            "--port",
            "9999",
            "--rewrite-fallback",
            "--allow-anonymous",
        ]),
        None,
    )
    .unwrap();
    assert_eq!(cfg.policy, RewritePolicy::Fallback);
}

#[test]
fn help_text_states_the_open_relay_cost_of_allow_anonymous() {
    // A flag whose downside is discoverable only by reading the design doc is
    // a trap. Same standard already applied to --rewrite-fallback.
    let help = Args::try_parse_from(["rust_proxy", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("--allow-anonymous"), "{help}");
    assert!(help.contains("--auth-file"), "{help}");
    assert!(help.contains("--allow-from"), "{help}");
    assert!(
        help.to_lowercase().contains("open relay"),
        "help must state the cost: {help}"
    );
}

#[test]
fn anonymous_constructor_is_credential_free() {
    let cfg = RuntimeConfig::anonymous(RewritePolicy::FailClosed);
    assert!(cfg.auth.is_none());
    assert!(cfg.allow_from.is_empty());
}

use rust_proxy::ProxyStats;
use std::sync::atomic::Ordering;

#[test]
fn auth_counters_start_at_zero_and_increment() {
    let stats = ProxyStats::new();
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 0);
    assert!(!stats.allow_anonymous_active.load(Ordering::Relaxed));

    stats.auth_failures.fetch_add(2, Ordering::Relaxed);
    stats.acl_rejections.fetch_add(3, Ordering::Relaxed);
    stats.set_anonymous_active(true);

    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 2);
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 3);
    assert!(stats.allow_anonymous_active.load(Ordering::Relaxed));

    // Exercises the new report branches. This asserts nothing: a format-argument
    // mismatch is a compile error in Rust, not a panic, so the only thing this
    // could catch is a future `unwrap()` introduced into log_stats. A real
    // assertion on the emitted text would need a log-capture harness.
    stats.log_stats();
}
