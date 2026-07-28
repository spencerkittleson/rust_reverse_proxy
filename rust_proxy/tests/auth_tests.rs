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
        assert!(!reason.contains("secret"), "{reason}");
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
    assert!(rendered.contains('2'), "entry count should be visible: {rendered}");
}
