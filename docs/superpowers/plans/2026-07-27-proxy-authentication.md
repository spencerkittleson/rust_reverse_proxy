# Proxy Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require a credential before this forward proxy will relay anything, over both HTTP/CONNECT and SOCKS5, with an optional source-address allowlist.

**Architecture:** A new pure module `src/auth.rs` holds credential and CIDR logic. A new `RuntimeConfig` replaces the bare `RewritePolicy` parameter threaded through the I/O layer. Enforcement happens at three points, each matching its protocol's natural granularity: `handle_client` (address allowlist), `handle_http` (HTTP 407 before any origin dial), `RequestStream::handle_head` (per-request on reused keep-alive connections), and `handle_socks5` (RFC 1929).

**Tech Stack:** Rust 2021, tokio, clap 4 derive, `base64` 0.22 (new dependency). No TLS library, no crypto library, no hashing.

Design spec: `docs/superpowers/specs/2026-07-27-proxy-authentication-design.md`

## Global Constraints

- **Run all cargo commands from `rust_proxy/`.** The package is in that subdirectory; there is no workspace.
- **Byte-exactness to the origin is the project invariant.** The bytes an origin receives must be identical to what the client would have sent connecting directly. Never emit `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Proxy-Agent`, `Server`, or `Date`.
- **Do not add a TLS library.** No `rustls`, no `native-tls`, no `openssl`.
- **`src/http_rewrite.rs` stays free of I/O, logging, and `ProxyStats`.** It may depend on `src/auth.rs` because that module is also pure.
- **Never log any part of a credential**, at any level, including the username. Log the source address and a fixed reason code only.
- **Auth must never be bypassable by `--rewrite-fallback`.** `PushError::Unauthorized` must not route through `on_anomaly`.
- **`cargo clippy --all-targets -- -D warnings` fails on ~25 pre-existing errors** in the test files and 4 in `src/windows.rs`. Those are out of scope. The gate for this work is `cargo clippy -p rust_proxy --lib -- -D warnings`.
- Verification after every task, from `rust_proxy/`: `cargo test` then `cargo clippy -p rust_proxy --lib -- -D warnings`.

## File Structure

| File | Status | Responsibility |
| --- | --- | --- |
| `rust_proxy/src/auth.rs` | Create | Pure credential logic (`Credentials`, `AuthResult`, Basic parsing, constant-time compare) and pure address logic (`Cidr`, `addr_allowed`). No I/O, no logging. |
| `rust_proxy/src/lib.rs` | Modify | New `Args` flags, `RuntimeConfig`, credential file/env loading, the 407 constant, two new `ProxyStats` counters, and all three I/O-layer enforcement points. |
| `rust_proxy/src/http_rewrite.rs` | Modify | `PushError` enum; `RequestStream` gains an optional credential set and checks every head. |
| `rust_proxy/src/main.rs` | Modify | Build and validate `RuntimeConfig` before binding; thread it through the accept loop; anonymous-mode warning. |
| `rust_proxy/Cargo.toml` | Modify | Add `base64 = "0.22"`. |
| `rust_proxy/tests/auth_tests.rs` | Create | Pure unit tests: Basic parsing, file parsing, CIDR, constant-time compare, startup validation. |
| `rust_proxy/tests/auth_relay_tests.rs` | Create | In-process behavior tests for SOCKS5 RFC 1929 and the address allowlist. |
| `rust_proxy/tests/relay_tests.rs` | Modify | New helper overload; origin-visibility tests for authenticated and unauthenticated requests. |
| `rust_proxy/tests/golden_equality_tests.rs` | Modify | Authenticated request must stay byte-identical to direct. |
| `rust_proxy/tests/http_rewrite_tests.rs` | Modify | `PushError` migration; per-head auth on reused connections under both policies. |
| `rust_proxy/tests/integration_tests.rs`, `statistics_tests.rs`, `logging_tests.rs` | Modify | Add `--allow-anonymous` to the 14 subprocess launch argument vectors. |
| `README.md`, `AGENTS.md` | Modify | Document the feature and correct the now-false "SOCKS5 with no authentication" claim. |

---

### Task 1: Pure credential logic

**Files:**
- Create: `rust_proxy/src/auth.rs`
- Modify: `rust_proxy/src/lib.rs` (add `pub mod auth;`)
- Modify: `rust_proxy/Cargo.toml` (add `base64`)
- Test: `rust_proxy/tests/auth_tests.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub struct ConfigError(pub String)` implementing `Display` and `std::error::Error`
  - `pub enum AuthResult { Granted, Missing, Malformed, Mismatch, Duplicate }` with `pub fn is_granted(self) -> bool` and `pub fn reason(self) -> &'static str`
  - `pub struct Credentials` with `pub fn parse_file_contents(text: &str) -> Result<Credentials, ConfigError>`, `pub fn check_head(&self, head: &[u8]) -> AuthResult`, `pub fn verify_pair(&self, user: &[u8], pass: &[u8]) -> bool`, `pub fn len(&self) -> usize`, `pub fn is_empty(&self) -> bool`

- [ ] **Step 1: Add the base64 dependency**

In `rust_proxy/Cargo.toml`, in the `[dependencies]` section, after the `httparse = "1.8"` line, add:

```toml
base64 = "0.22"
```

- [ ] **Step 2: Write the failing tests**

Create `rust_proxy/tests/auth_tests.rs`:

```rust
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --test auth_tests`
Expected: FAIL to compile with `unresolved import rust_proxy::auth`.

- [ ] **Step 4: Create the module**

Create `rust_proxy/src/auth.rs`:

```rust
//! Credential and source-address checks.
//!
//! Pure logic only: no I/O, no logging, no `ProxyStats`. That is what lets
//! `http_rewrite` depend on this module without breaking its own purity rule.
//! Reading a credentials file is I/O and therefore lives in `lib.rs` beside
//! `Args`, mirroring `Args::rewrite_policy()`.

use base64::Engine as _;

/// A configuration problem worth refusing to start over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Outcome of checking one request head. The variants exist so the caller can
/// log a fixed reason code; none of them carries credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Granted,
    /// No `Proxy-Authorization` header at all — the ordinary first request.
    Missing,
    /// Present but not a decodable `Basic` credential.
    Malformed,
    /// Well-formed and decoded, but not a configured credential.
    Mismatch,
    /// More than one `Proxy-Authorization` header. Ambiguity fails closed.
    Duplicate,
}

impl AuthResult {
    pub fn is_granted(self) -> bool {
        matches!(self, AuthResult::Granted)
    }

    /// Log-safe reason code. Never contains any part of a credential.
    pub fn reason(self) -> &'static str {
        match self {
            AuthResult::Granted => "granted",
            AuthResult::Missing => "no Proxy-Authorization header",
            AuthResult::Malformed => "malformed Basic credential",
            AuthResult::Mismatch => "credential not recognized",
            AuthResult::Duplicate => "multiple Proxy-Authorization headers",
        }
    }
}

/// The set of `user:password` pairs this proxy accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Stored pre-joined as `user:password` bytes, which is exactly the form
    /// both the HTTP and SOCKS5 paths compare against.
    joined: Vec<Vec<u8>>,
}

impl Credentials {
    /// Parse credentials-file contents. Also used for the single-line value of
    /// the environment variable, since the rules are identical.
    ///
    /// One `user:password` per line. `#` comments and blank lines are skipped.
    /// A single trailing `\r` is stripped so a file edited on Windows works.
    /// Split on the *first* colon only, so passwords may contain colons.
    /// Trailing whitespace in the password is preserved, because a password
    /// may legitimately end in a space.
    pub fn parse_file_contents(text: &str) -> Result<Credentials, ConfigError> {
        let mut joined = Vec::new();
        for (i, raw) in text.split('\n').enumerate() {
            let line = raw.strip_suffix('\r').unwrap_or(raw).trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((user, pass)) = line.split_once(':') else {
                return Err(ConfigError(format!(
                    "line {}: expected user:password",
                    i + 1
                )));
            };
            if user.is_empty() {
                return Err(ConfigError(format!("line {}: empty username", i + 1)));
            }
            if pass.is_empty() {
                return Err(ConfigError(format!("line {}: empty password", i + 1)));
            }
            let mut bytes = Vec::with_capacity(line.len());
            bytes.extend_from_slice(user.as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(pass.as_bytes());
            joined.push(bytes);
        }
        if joined.is_empty() {
            return Err(ConfigError(
                "no credentials found; expected at least one user:password line".into(),
            ));
        }
        Ok(Credentials { joined })
    }

    pub fn len(&self) -> usize {
        self.joined.len()
    }

    pub fn is_empty(&self) -> bool {
        self.joined.is_empty()
    }

    /// Check the `Proxy-Authorization` header of one request head.
    pub fn check_head(&self, head: &[u8]) -> AuthResult {
        let values = proxy_authorization_values(head);
        match values.len() {
            0 => return AuthResult::Missing,
            1 => {}
            _ => return AuthResult::Duplicate,
        }
        let Some(token) = basic_token(values[0]) else {
            return AuthResult::Malformed;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
            return AuthResult::Malformed;
        };
        if self.matches_joined(&decoded) {
            AuthResult::Granted
        } else {
            AuthResult::Mismatch
        }
    }

    /// Check a SOCKS5 RFC 1929 username/password pair.
    ///
    /// A presented username containing a colon is refused: stored usernames
    /// cannot contain one, so allowing it would let `user="a:b", pass="c"`
    /// satisfy a stored `("a", "b:c")`.
    pub fn verify_pair(&self, user: &[u8], pass: &[u8]) -> bool {
        if user.contains(&b':') {
            return false;
        }
        let mut presented = Vec::with_capacity(user.len() + pass.len() + 1);
        presented.extend_from_slice(user);
        presented.push(b':');
        presented.extend_from_slice(pass);
        self.matches_joined(&presented)
    }

    /// Compare against every entry without short-circuiting on the first
    /// non-match, so the number of comparisons does not depend on which entry
    /// (if any) matched.
    fn matches_joined(&self, presented: &[u8]) -> bool {
        let mut matched = false;
        for entry in &self.joined {
            matched |= ct_eq(presented, entry);
        }
        matched
    }
}

/// Constant-time byte comparison.
///
/// Returns early on a length mismatch, so the length of a password is in
/// principle observable through timing. Behind a TCP round trip and a full
/// head parse that is not a practically exploitable channel; it is stated here
/// rather than hidden.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Every `Proxy-Authorization` value in a CRLF-delimited request head.
///
/// Obs-fold continuation lines (leading SP or HTAB) are skipped rather than
/// appended: a folded credential therefore fails to match here, and the
/// rewrite layer rejects the head separately as
/// `ObsFoldInRewrittenHeader`.
fn proxy_authorization_values(head: &[u8]) -> Vec<&[u8]> {
    let mut found = Vec::new();
    let Some(p) = find_crlf(head) else {
        return found;
    };
    let mut rest = &head[p + 2..];
    while let Some(p) = find_crlf(rest) {
        let line = &rest[..p];
        rest = &rest[p + 2..];
        if line.is_empty() {
            break;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"Proxy-Authorization") {
            found.push(trim_ows(&line[colon + 1..]));
        }
    }
    found
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', tail @ ..] = v {
        v = tail;
    }
    while let [head @ .., b' ' | b'\t'] = v {
        v = head;
    }
    v
}

/// The base64 token of a `Basic <token>` credential.
fn basic_token(value: &[u8]) -> Option<&[u8]> {
    let sp = value.iter().position(|&b| b == b' ' || b == b'\t')?;
    if !value[..sp].eq_ignore_ascii_case(b"Basic") {
        return None;
    }
    let token = trim_ows(&value[sp..]);
    if token.is_empty() || token.iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some(token)
}
```

- [ ] **Step 5: Declare the module**

In `rust_proxy/src/lib.rs`, immediately after the existing `pub mod http_rewrite;` line, add:

```rust
pub mod auth;
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test auth_tests`
Expected: PASS, 22 tests.

Then run: `cargo test`
Expected: PASS. No existing test touches `auth`, so nothing else should change.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add rust_proxy/Cargo.toml rust_proxy/Cargo.lock rust_proxy/src/auth.rs rust_proxy/src/lib.rs rust_proxy/tests/auth_tests.rs
git commit -m "feat(auth): add pure Basic credential checking"
```

---

### Task 2: Source-address matching

**Files:**
- Modify: `rust_proxy/src/auth.rs` (append)
- Test: `rust_proxy/tests/auth_tests.rs` (append)

**Interfaces:**
- Consumes: `ConfigError` from Task 1.
- Produces:
  - `pub struct Cidr` (`Debug, Clone, Copy, PartialEq, Eq`) with `pub fn parse(s: &str) -> Result<Cidr, ConfigError>` and `pub fn contains(&self, addr: IpAddr) -> bool`
  - `pub fn addr_allowed(list: &[Cidr], addr: IpAddr) -> bool` — an empty list allows everything

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/auth_tests.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test auth_tests`
Expected: FAIL to compile, `no Cidr in rust_proxy::auth`.

- [ ] **Step 3: Implement**

Append to `rust_proxy/src/auth.rs`:

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address or prefix that may open a connection to this proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `addr` or `addr/prefix`. A bare address is a host route.
    pub fn parse(s: &str) -> Result<Cidr, ConfigError> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let parsed: IpAddr = addr_part
            .parse()
            .map_err(|_| ConfigError(format!("not an IP address: {addr_part:?}")))?;
        let base = normalize(parsed);
        let max = if base.is_ipv4() { 32u8 } else { 128u8 };
        let prefix = match prefix_part {
            None => max,
            Some(p) => {
                let n: u8 = p
                    .parse()
                    .map_err(|_| ConfigError(format!("not a prefix length: {p:?}")))?;
                if n > max {
                    return Err(ConfigError(format!(
                        "prefix /{n} is too large for {base}"
                    )));
                }
                n
            }
        };
        Ok(Cidr { base, prefix })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.base, normalize(addr)) {
            (IpAddr::V4(b), IpAddr::V4(a)) => {
                masked_v4(b, self.prefix) == masked_v4(a, self.prefix)
            }
            (IpAddr::V6(b), IpAddr::V6(a)) => {
                masked_v6(b, self.prefix) == masked_v6(a, self.prefix)
            }
            _ => false,
        }
    }
}

/// True when `addr` may connect. An empty list means no filtering at all,
/// not deny-all.
pub fn addr_allowed(list: &[Cidr], addr: IpAddr) -> bool {
    list.is_empty() || list.iter().any(|c| c.contains(addr))
}

/// A v4 client arriving on a dual-stack socket appears as `::ffff:a.b.c.d`.
/// Normalizing both rule and source means a v4 prefix matches it.
fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn masked_v4(a: Ipv4Addr, prefix: u8) -> u32 {
    // Shifting by the full width is undefined, so /0 is special-cased.
    if prefix == 0 {
        0
    } else {
        u32::from(a) & (!0u32 << (32 - prefix))
    }
}

fn masked_v6(a: Ipv6Addr, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::from(a) & (!0u128 << (128 - prefix))
    }
}
```

Note: `Cidr::parse("::ffff:192.168.1.0/24")` normalizes the base to `192.168.1.0` and then validates `/24` against the v4 maximum of 32, which is why the mapped-rule test passes.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test auth_tests`
Expected: PASS, 33 tests.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/auth.rs rust_proxy/tests/auth_tests.rs
git commit -m "feat(auth): add CIDR source-address matching"
```

---

### Task 3: CLI flags, credential loading, and startup validation

**Files:**
- Modify: `rust_proxy/src/lib.rs` (`Args`, plus new `RuntimeConfig` and loaders)
- Test: `rust_proxy/tests/auth_tests.rs` (append)

**Interfaces:**
- Consumes: `Credentials`, `Cidr` from Tasks 1-2.
- Produces:
  - `pub const AUTH_ENV_VAR: &str = "RUST_PROXY_AUTH"`
  - `Args` fields `auth_file: Option<String>`, `allow_anonymous: bool`, `allow_from: Vec<String>`
  - `pub struct RuntimeConfig { pub policy: RewritePolicy, pub auth: Option<Arc<Credentials>>, pub allow_from: Vec<Cidr> }` with `pub fn anonymous(policy: RewritePolicy) -> Self`
  - `pub fn build_runtime_config(args: &Args, env_auth: Option<String>) -> Result<RuntimeConfig, ProxyError>`
  - `pub fn load_credentials_file(path: &str) -> Result<Credentials, ProxyError>`

Note that `build_runtime_config` takes the environment value as a parameter rather than reading it. `std::env::set_var` from parallel tests is a classic source of flakes; injection removes the shared global entirely.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/auth_tests.rs`:

```rust
use clap::Parser;
use rust_proxy::{build_runtime_config, load_credentials_file, Args, RuntimeConfig};
use rust_proxy::http_rewrite::RewritePolicy;
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
    let err = build_runtime_config(&args_from(&["--allow-anonymous"]), Some("a:b".into()))
        .unwrap_err();
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
    assert!(build_runtime_config(
        &args_from(&["--allow-from", "10.0.0.0/8"]),
        None
    )
    .is_err());
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test auth_tests`
Expected: FAIL to compile, `no build_runtime_config in the root`.

- [ ] **Step 3: Add the CLI flags**

In `rust_proxy/src/lib.rs`, inside `pub struct Args`, after the `rewrite_fallback` field, add:

```rust
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
```

- [ ] **Step 4: Add `RuntimeConfig` and the loaders**

In `rust_proxy/src/lib.rs`, immediately after the closing brace of the `impl Args` block (the one containing `rewrite_policy`), add:

```rust
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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test auth_tests`
Expected: PASS, 47 tests.

The `--help` assertion requires the phrase "open relay" in the `--allow-anonymous` doc comment, which the text in Step 3 provides.

- [ ] **Step 6: Confirm nothing else broke**

Run: `cargo test`
Expected: PASS. Nothing calls `build_runtime_config` yet, so `main.rs` still starts without a credential; the subprocess suites are unaffected until Task 4.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/auth_tests.rs
git commit -m "feat(auth): add auth flags, credential loading, startup validation"
```

---

### Task 4: Thread `RuntimeConfig` through the I/O layer

No behavior change. This task exists so the enforcement tasks that follow each have a small, reviewable diff instead of being tangled with a signature migration.

**Files:**
- Modify: `rust_proxy/src/lib.rs:279` (`handle_client`), `:334` (`Upstream`), `:344` (`connect_and_tunnel`), `:418` (`handle_http`), `:515` (`handle_socks5`)
- Modify: `rust_proxy/src/main.rs` (`accept_and_spawn`, `main`)
- Modify: `rust_proxy/tests/relay_tests.rs:47`, `rust_proxy/tests/golden_equality_tests.rs:62`
- Modify: `rust_proxy/tests/integration_tests.rs`, `statistics_tests.rs`, `logging_tests.rs`

**Interfaces:**
- Consumes: `RuntimeConfig` from Task 3.
- Produces:
  - `pub async fn handle_client(client_socket: TcpStream, stats: Arc<ProxyStats>, config: Arc<RuntimeConfig>) -> Result<(), ProxyError>`
  - `Upstream::Http { first_head: Vec<u8>, config: Arc<RuntimeConfig> }`
  - `proxy_roundtrip_with(client_bytes: &[u8], config: Arc<RuntimeConfig>) -> (Vec<u8>, Arc<ProxyStats>)` in `relay_tests.rs`

- [ ] **Step 1: Change `handle_client`**

In `rust_proxy/src/lib.rs`, replace the signature and dispatch of `handle_client`. Replace:

```rust
pub async fn handle_client(
    client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    policy: crate::http_rewrite::RewritePolicy,
) -> Result<(), ProxyError> {
```

with:

```rust
pub async fn handle_client(
    client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
```

and replace the dispatch block:

```rust
    let result = if peek_buf[0] == 0x05 {
        // SOCKS5 is a blind byte relay: nothing to rewrite.
        handle_socks5(client_socket, stats.clone()).await
    } else {
        handle_http(client_socket, stats.clone(), policy).await
    };
```

with:

```rust
    let result = if peek_buf[0] == 0x05 {
        // SOCKS5 is a blind byte relay after the handshake: nothing to rewrite.
        handle_socks5(client_socket, stats.clone(), config).await
    } else {
        handle_http(client_socket, stats.clone(), config).await
    };
```

- [ ] **Step 2: Change `Upstream` and `connect_and_tunnel`**

Replace the `Upstream::Http` variant:

```rust
    /// Plain HTTP: rewrite this head, then every later head on the connection.
    Http {
        first_head: Vec<u8>,
        policy: crate::http_rewrite::RewritePolicy,
    },
```

with:

```rust
    /// Plain HTTP: rewrite this head, then every later head on the connection.
    Http {
        first_head: Vec<u8>,
        config: Arc<RuntimeConfig>,
    },
```

In `connect_and_tunnel`, the `Upstream::Http` match arm currently destructures `{ first_head, policy }` and calls `RequestStream::new(policy, MAX_REQUEST_HEAD_SIZE)`. Change the pattern to `Upstream::Http { first_head, config }` and the construction to:

```rust
                    let mut stream = crate::http_rewrite::RequestStream::new(
                        config.policy,
                        MAX_REQUEST_HEAD_SIZE,
                    );
```

`RequestStream::new` gains its credential parameter in Task 7; leave it two-argument here.

- [ ] **Step 3: Change `handle_http`**

Replace:

```rust
async fn handle_http(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    policy: crate::http_rewrite::RewritePolicy,
) -> Result<(), ProxyError> {
```

with:

```rust
async fn handle_http(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
```

and in the absolute-form branch, replace the `Upstream::Http` construction:

```rust
            Upstream::Http {
                first_head: raw_headers.clone(),
                policy,
            },
```

with:

```rust
            Upstream::Http {
                first_head: raw_headers.clone(),
                config: config.clone(),
            },
```

- [ ] **Step 4: Change `handle_socks5`**

Replace:

```rust
async fn handle_socks5(mut client_socket: TcpStream, stats: Arc<ProxyStats>) -> Result<(), ProxyError> {
```

with:

```rust
async fn handle_socks5(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    config: Arc<RuntimeConfig>,
) -> Result<(), ProxyError> {
```

The body does not use `config` yet. Add `let _ = &config;` as the first line of the body to keep the build warning-free, and delete that line in Task 9 when the RFC 1929 handshake starts using it.

- [ ] **Step 5: Change `main.rs`**

Replace the `accept_and_spawn` signature parameter:

```rust
    policy: rust_proxy::http_rewrite::RewritePolicy,
```

with:

```rust
    config: &Arc<RuntimeConfig>,
```

and inside it, before `tokio::spawn`, add a clone next to the existing `stats_clone`:

```rust
    let config_clone = config.clone();
```

then change the spawn body call from `handle_client(client_socket, stats_clone, policy)` to:

```rust
        if let Err(e) = handle_client(client_socket, stats_clone, config_clone).await {
```

In `main`, replace:

```rust
    let policy = args.rewrite_policy();
    stats.set_fallback_active(args.rewrite_fallback);
```

with:

```rust
    stats.set_fallback_active(args.rewrite_fallback);
```

and immediately **after** the `env_logger` init block and **before** the `#[cfg(windows)]` block, insert the configuration gate. Order matters: the logger must exist so the permission warning is visible, and an invalid configuration must not get as far as opening a Windows firewall port.

```rust
    // Validate before touching the host or the network: an invalid credential
    // configuration must not open a firewall port or bind a listener.
    let config = match build_runtime_config(&args, std::env::var(AUTH_ENV_VAR).ok()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(2);
        }
    };
```

Finally, change the accept loop call from `accept_and_spawn(&listener, &sem_for_accept, &stats_for_accept, policy)` to:

```rust
                accept_and_spawn(&listener, &sem_for_accept, &stats_for_accept, &config).await;
```

- [ ] **Step 6: Update the in-process test helpers**

In `rust_proxy/tests/relay_tests.rs`, replace the `proxy_roundtrip` function with a delegating pair, so the six existing call sites keep compiling unchanged:

```rust
/// Run one client byte-stream through a real proxy connection and return what
/// the origin actually received.
async fn proxy_roundtrip(client_bytes: &[u8], policy: RewritePolicy) -> (Vec<u8>, Arc<ProxyStats>) {
    proxy_roundtrip_with(client_bytes, Arc::new(RuntimeConfig::anonymous(policy))).await
}

/// Same, with an explicit runtime configuration, for the auth cases.
async fn proxy_roundtrip_with(
    client_bytes: &[u8],
    config: Arc<RuntimeConfig>,
) -> (Vec<u8>, Arc<ProxyStats>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(recording_origin(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();

    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, config).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = String::from_utf8_lossy(client_bytes)
        .replace("ORIGIN", &origin_addr.to_string())
        .into_bytes();
    client.write_all(&request).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;

    let received = origin_task.await.unwrap();
    (received, stats)
}
```

If `RuntimeConfig` is not already in scope there, the file uses `use rust_proxy::*;`, which exports it. If it uses named imports instead, add `RuntimeConfig` to them.

In `rust_proxy/tests/golden_equality_tests.rs`, inside `proxied_bytes`, replace:

```rust
        let _ = handle_client(socket, stats, RewritePolicy::FailClosed).await;
```

with:

```rust
        let config = Arc::new(RuntimeConfig::anonymous(RewritePolicy::FailClosed));
        let _ = handle_client(socket, stats, config).await;
```

- [ ] **Step 7: Add `--allow-anonymous` to the subprocess suites**

Auth is now mandatory, so every subprocess launch must opt out explicitly. In each of the following 14 `.args(&[...])` calls, insert `"--allow-anonymous"` as the final element:

- `tests/integration_tests.rs` lines 12, 49, 90, 135, 219, 285
- `tests/statistics_tests.rs` lines 30, 76, 109, 180, 271
- `tests/logging_tests.rs` lines 13, 47, 75

For example, `tests/integration_tests.rs:12` becomes:

```rust
        .args(&["run", "--", "--host", "127.0.0.1", "--port", "3130", "--log-level", "error", "--allow-anonymous"])
```

`tests/logging_tests.rs:75` launches with `--log-level invalid` on purpose and must still start, so it needs the flag too.

- [ ] **Step 8: Build and run everything**

Run: `cargo test`
Expected: PASS, with the same test count as before this task. Any subprocess test that hangs or times out means a launch site is missing `--allow-anonymous` and the proxy exited with code 2.

- [ ] **Step 9: Verify the new startup gate by hand**

Run: `cargo run -- --host 127.0.0.1 --port 3199`
Expected: exits immediately with status 2 and prints `Configuration error: no credential configured. Pass --auth-file <path>, set RUST_PROXY_AUTH=user:password, or pass --allow-anonymous to run an open relay on purpose`.

Run: `cargo run -- --host 127.0.0.1 --port 3199 --allow-anonymous`
Expected: starts and logs `Proxy server starting on 127.0.0.1:3199`. Stop it with Ctrl-C.

- [ ] **Step 10: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 11: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/src/main.rs rust_proxy/tests/
git commit -m "refactor: thread RuntimeConfig through the connection handlers"
```

---

### Task 5: Statistics counters

Done before enforcement so the enforcement tasks have somewhere to record.

**Files:**
- Modify: `rust_proxy/src/lib.rs` (`ProxyStats` struct, `new`, `log_stats`)
- Modify: `rust_proxy/src/main.rs` (anonymous banner)
- Test: `rust_proxy/tests/auth_tests.rs` (append)

**Interfaces:**
- Produces: `ProxyStats` fields `auth_failures: AtomicU64`, `acl_rejections: AtomicU64`, `allow_anonymous_active: AtomicBool`, and `pub fn set_anonymous_active(&self, active: bool)`.

- [ ] **Step 1: Write the failing test**

Append to `rust_proxy/tests/auth_tests.rs`:

```rust
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

    // log_stats must not panic with the new fields populated.
    stats.log_stats();
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --test auth_tests auth_counters`
Expected: FAIL to compile, `no field auth_failures on ProxyStats`.

- [ ] **Step 3: Add the fields**

In `rust_proxy/src/lib.rs`, in `pub struct ProxyStats`, after the `rewrite_fallback_active` field, add:

```rust
    /// Requests refused for a missing, malformed, or unrecognized credential.
    pub auth_failures: AtomicU64,
    /// Connections refused because the source address is outside --allow-from.
    pub acl_rejections: AtomicU64,
    /// Whether `--allow-anonymous` is enabled, for the report banner.
    pub allow_anonymous_active: AtomicBool,
```

In `ProxyStats::new`, after the `rewrite_fallback_active` initializer, add:

```rust
            auth_failures: AtomicU64::new(0),
            acl_rejections: AtomicU64::new(0),
            allow_anonymous_active: AtomicBool::new(false),
```

After the existing `set_fallback_active` method, add:

```rust
    pub fn set_anonymous_active(&self, active: bool) {
        self.allow_anonymous_active
            .store(active, Ordering::Relaxed);
    }
```

- [ ] **Step 4: Report them**

In `log_stats`, immediately after the `--rewrite-fallback` banner block (the `if self.rewrite_fallback_active.load(...)` block) and before the anomaly loop, add:

```rust
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
```

- [ ] **Step 5: Wire the banner in `main.rs`**

In `rust_proxy/src/main.rs`, `let addr = format!(...)` already precedes `stats.set_fallback_active(...)`, so `addr` is in scope. After the existing `stats.set_fallback_active(args.rewrite_fallback);` line and its `if args.rewrite_fallback` warning block, add:

```rust
    stats.set_anonymous_active(config.auth.is_none());
    if config.auth.is_none() {
        warn!("--allow-anonymous is enabled: any client that can reach {} may relay", addr);
        if config.allow_from.is_empty() {
            warn!("and no --allow-from restriction is set, so that is every reachable host.");
        }
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test --test auth_tests auth_counters`
Expected: PASS.

Run: `cargo test`
Expected: PASS.

- [ ] **Step 7: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/src/main.rs rust_proxy/tests/auth_tests.rs
git commit -m "feat(auth): count auth failures and source rejections"
```

---

### Task 6: HTTP and CONNECT enforcement

**Files:**
- Modify: `rust_proxy/src/lib.rs` (new `PROXY_AUTH_REQUIRED` constant; check in `handle_http`)
- Test: `rust_proxy/tests/relay_tests.rs` (append)

**Interfaces:**
- Consumes: `Credentials::check_head`, `AuthResult`, `RuntimeConfig`, `ProxyStats::auth_failures`, `proxy_roundtrip_with`.
- Produces: `pub const PROXY_AUTH_REQUIRED: &[u8]`.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/relay_tests.rs`:

```rust
use rust_proxy::auth::Credentials;
use std::sync::atomic::Ordering;

fn auth_config(file_contents: &str) -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: Some(Arc::new(
            Credentials::parse_file_contents(file_contents).unwrap(),
        )),
        allow_from: Vec::new(),
    })
}

#[tokio::test]
async fn unauthenticated_request_never_reaches_the_origin() {
    // The check has to happen before the origin dial, so the origin must see
    // nothing at all — not even a connection's worth of zero bytes.
    let request = b"GET http://ORIGIN/secret HTTP/1.1\r\nHost: ORIGIN\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    assert!(
        received.is_empty(),
        "origin saw bytes from an unauthenticated client: {:?}",
        String::from_utf8_lossy(&received)
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_wrong_password_never_reaches_the_origin() {
    // base64("user:wrong")
    let request = b"GET http://ORIGIN/secret HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjp3cm9uZw==\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    assert!(received.is_empty(), "{:?}", String::from_utf8_lossy(&received));
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_authenticated_request_reaches_the_origin_without_the_credential() {
    // base64("user:secret"). Rule 4 already drops Proxy-Authorization, so the
    // credential must not appear upstream and the request must be rewritten to
    // origin form as usual.
    let request = b"GET http://ORIGIN/ok HTTP/1.1\r\nHost: ORIGIN\r\n\
                    Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";
    let (received, stats) = proxy_roundtrip_with(request, auth_config("user:secret")).await;
    let text = String::from_utf8(received.clone()).expect("origin bytes must be UTF-8 here");
    assert!(text.starts_with("GET /ok HTTP/1.1\r\n"), "{text:?}");
    assert!(
        !text.to_lowercase().contains("proxy-authorization"),
        "credential leaked upstream: {text:?}"
    );
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_unauthenticated_client_is_told_how_to_authenticate() {
    // A bare close would leave a client guessing. The 407 must name the scheme
    // and must not carry Server or Date.
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let config = auth_config("user:secret");
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats, config).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!("GET http://{origin_addr}/x HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;

    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 407 "), "{text:?}");
    assert!(text.contains("Proxy-Authenticate: Basic"), "{text:?}");
    let lowered = text.to_lowercase();
    assert!(!lowered.contains("\r\nserver:"), "{text:?}");
    assert!(!lowered.contains("\r\ndate:"), "{text:?}");
    drop(origin);
}

#[tokio::test]
async fn unauthenticated_connect_is_refused_before_the_tunnel_opens() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_check = stats.clone();
    let config = auth_config("user:secret");
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats, config).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;

    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 407 "), "{text:?}");
    assert!(
        !text.contains("200 Connection Established"),
        "a tunnel was acknowledged to an unauthenticated client: {text:?}"
    );
    assert_eq!(stats_check.auth_failures.load(Ordering::Relaxed), 1);
    drop(origin);
}

#[tokio::test]
async fn allow_anonymous_leaves_http_behavior_unchanged() {
    let request = b"GET http://ORIGIN/plain HTTP/1.1\r\nHost: ORIGIN\r\n\r\n";
    let (received, stats) = proxy_roundtrip(request, RewritePolicy::FailClosed).await;
    let text = String::from_utf8(received).unwrap();
    assert!(text.starts_with("GET /plain HTTP/1.1\r\n"), "{text:?}");
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test relay_tests`
Expected: the four auth tests FAIL — the unauthenticated requests reach the origin, because nothing checks yet.

- [ ] **Step 3: Add the 407 constant**

In `rust_proxy/src/lib.rs`, after the `MAX_REQUEST_HEAD_SIZE` constant, add:

```rust
/// Client-facing challenge. `Connection: close` removes any question about
/// stream state after a rejection; clients reconnect and retry, which is
/// ordinary Basic behavior. No `Server` and no `Date`, matching the 502s.
pub const PROXY_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"rust_proxy\"\r\n\
    Content-Length: 0\r\n\
    Connection: close\r\n\
    \r\n";
```

- [ ] **Step 4: Check in `handle_http`**

In `handle_http`, immediately after the `if parts.len() < 3 { return Ok(()); }` block and before `let method = parts[0];`, insert:

```rust
    // Before any origin dial: an unauthenticated client must not be able to
    // make this proxy open an outbound connection. Every head on a reused
    // connection is re-checked inside `RequestStream`, which is what makes the
    // gate per-request rather than per-connection.
    if let Some(creds) = config.auth.as_deref() {
        let outcome = creds.check_head(&raw_headers);
        if !outcome.is_granted() {
            stats.auth_failures.fetch_add(1, Ordering::Relaxed);
            let peer = client_socket
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            warn!("Refusing request from {}: {}", peer, outcome.reason());
            client_socket.write_all(PROXY_AUTH_REQUIRED).await?;
            return Ok(());
        }
    }
```

The `warn!` records the source address and a fixed reason code. It must never be extended to log the header value or the username.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test relay_tests`
Expected: PASS, all tests.

Run: `cargo test`
Expected: PASS.

- [ ] **Step 6: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 7: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/relay_tests.rs
git commit -m "feat(auth): require a credential for HTTP and CONNECT"
```

---

### Task 7: Per-request enforcement on reused connections

This is the task that closes the real bypass. Without it, one authenticated request unlocks a keep-alive connection permanently.

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs` (`PushError`, `RequestStream`)
- Modify: `rust_proxy/src/lib.rs` (`connect_and_tunnel` error handling, `tunnel_fast` hook)
- Modify: `rust_proxy/tests/http_rewrite_tests.rs`
- Test: `rust_proxy/tests/http_rewrite_tests.rs` (append)

**Interfaces:**
- Consumes: `Credentials` from Task 1, `PROXY_AUTH_REQUIRED` from Task 6.
- Produces:
  - `pub enum PushError { Anomaly(RewriteAnomaly), Unauthorized }` with `impl From<RewriteAnomaly> for PushError` and `impl Display`
  - `RequestStream::new(policy: RewritePolicy, max_head: usize, auth: Option<Arc<Credentials>>) -> Self`
  - `RequestStream::push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), PushError>`

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
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
```

- [ ] **Step 2: Migrate the existing assertions in that file**

`RequestStream::new` gains a third argument and `push` changes its error type. Update the existing tests:

Add `, None` as the third argument to `RequestStream::new` at all 14 call sites in `tests/http_rewrite_tests.rs`: lines 306, 455, 473, 486, 499, 511, 524, 540, 562, 581, 596, 613, 629, 651. Line 306 is inside the `drive` helper and takes `policy`; the rest are literal `RewritePolicy::` values. A single `serena_replace_in_files`-style bulk replacement of `, 65536)` with `, 65536, None)` restricted to that file covers all 14 — verify the count is exactly 14 before applying.

Change the `drive` helper's return type from `Result<Vec<u8>, RewriteAnomaly>` to `Result<Vec<u8>, PushError>`.

Wrap the expected errors at the six `drive` and `stream.push` assertion sites — lines 425, 437, 464, 490, 605, and 622 — so for example line 424-425 becomes:

```rust
            drive(policy, input, 4096),
            Err(PushError::Anomaly(RewriteAnomaly::FramingConflict)),
```

Leave lines 65, 73, 275, 281, and 293 unchanged: those assert on `sanitize_request_head`, which still returns `Result<Vec<u8>, RewriteAnomaly>`. Leave line 479's `take_anomalies()` assertion unchanged too — it still yields `Vec<RewriteAnomaly>`.

Line numbers shift as you edit. Do the `RequestStream::new` bulk replacement first (it does not change line counts), then the `drive` signature, then the six error assertions, re-locating each by its surrounding code rather than trusting the original number.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL to compile, `no PushError in rust_proxy::http_rewrite`.

- [ ] **Step 4: Add `PushError`**

In `rust_proxy/src/http_rewrite.rs`, at the top, extend the module doc comment with a note about the new dependency, and add the imports:

```rust
use crate::auth::Credentials;
use std::sync::Arc;
```

`crate::auth` is pure — no I/O, no logging, no `ProxyStats` — so depending on it does not weaken this module's purity rule.

After the `RewritePolicy` enum definition, add:

```rust
/// Why a `push` refused to forward.
///
/// Auth is a separate variant rather than a `RewriteAnomaly` because it is not
/// a property of the rewrite, and because it must never reach `on_anomaly`:
/// that is where `--rewrite-fallback` decides to forward verbatim, and no
/// operator flag may turn an unauthenticated request into a forwarded one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    Anomaly(RewriteAnomaly),
    Unauthorized,
}

impl From<RewriteAnomaly> for PushError {
    fn from(a: RewriteAnomaly) -> Self {
        PushError::Anomaly(a)
    }
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushError::Anomaly(a) => write!(f, "rewrite anomaly '{}'", a.name()),
            PushError::Unauthorized => write!(f, "unauthenticated request"),
        }
    }
}
```

- [ ] **Step 5: Give `RequestStream` the credential set and change the error type**

Add a field to `struct RequestStream`, after `policy`:

```rust
    /// `None` means `--allow-anonymous`; then no head is ever checked.
    auth: Option<Arc<Credentials>>,
```

Change `RequestStream::new`:

```rust
    pub fn new(
        policy: RewritePolicy,
        max_head: usize,
        auth: Option<Arc<Credentials>>,
    ) -> Self {
        Self {
            state: State::ReadingHead,
            pending: Vec::new(),
            max_head,
            policy,
            auth,
            anomalies: Vec::new(),
            requests_sanitized_total: 0,
            requests_sanitized: 0,
            upgrade_offered: false,
            response_head: Vec::new(),
        }
    }
```

Change three return types from `RewriteAnomaly` to `PushError`:

- `pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), PushError>`
- `fn handle_head(&mut self, head: &[u8], out: &mut Vec<u8>) -> Result<(), PushError>`
- `fn step_chunked(&mut self, out: &mut Vec<u8>) -> Result<bool, PushError>`
- `fn on_anomaly(&mut self, anomaly: RewriteAnomaly, verbatim: &[u8], out: &mut Vec<u8>) -> Result<(), PushError>`

In `on_anomaly`, change the final `Err(anomaly)` to `Err(anomaly.into())`. The `?` operators and `return self.on_anomaly(...)` sites need no other change, because `From<RewriteAnomaly>` covers them.

- [ ] **Step 6: Check the credential in `handle_head`**

At the very top of `handle_head`, before the `framing_of` call, insert:

```rust
        // Every head, first or hundredth, on this connection. A one-shot check
        // at connection setup would leave a reused keep-alive connection
        // unlocked after its first authenticated request. Returning before any
        // `out` mutation guarantees nothing partial went upstream.
        if let Some(creds) = self.auth.as_deref() {
            if !creds.check_head(head).is_granted() {
                return Err(PushError::Unauthorized);
            }
        }
```

- [ ] **Step 7: Pass the credentials in and handle the new error in `lib.rs`**

In `connect_and_tunnel`, change the `RequestStream::new` call to:

```rust
                    let mut stream = crate::http_rewrite::RequestStream::new(
                        config.policy,
                        MAX_REQUEST_HEAD_SIZE,
                        config.auth.clone(),
                    );
```

Replace the `if let Err(anomaly) = push_result { ... }` block with:

```rust
                    if let Err(err) = push_result {
                        // Nothing has gone upstream yet, so the client can still
                        // be told. Mid-stream failures cannot be, which is why
                        // the relay path just closes.
                        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                        match err {
                            crate::http_rewrite::PushError::Unauthorized => {
                                // Unreachable in practice: `handle_http` already
                                // gated this head. Answering correctly anyway
                                // beats an `unreachable!` in a security path.
                                stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                                warn!("Unauthenticated request to {}:{} — refusing", host, port);
                                client_socket.write_all(PROXY_AUTH_REQUIRED).await?;
                            }
                            crate::http_rewrite::PushError::Anomaly(anomaly) => {
                                warn!(
                                    "Rewrite anomaly '{}' on first request to {}:{} — refusing",
                                    anomaly.name(),
                                    host,
                                    port
                                );
                                client_socket
                                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                                    .await?;
                            }
                        }
                        return Ok(());
                    }
```

In `tunnel_fast`, replace the client-to-origin hook's error block:

```rust
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
```

with:

```rust
                    if let Err(err) = result {
                        // Mid-stream, so no status line can be injected; closing
                        // is the only option that does not leak.
                        if matches!(err, crate::http_rewrite::PushError::Unauthorized) {
                            out_stats.auth_failures.fetch_add(1, Ordering::Relaxed);
                        }
                        warn!("{} for {} — closing connection", err, out_host);
                        return Err(ProxyError::from("refusing to forward"));
                    }
```

`out_stats` is already captured by that closure for `flush_rewrite_stats`, so no new capture is needed.

Note one deliberate behavior change: `connection_errors` is now incremented for both variants, where it previously only counted anomalies. A refused connection is a connection error either way, and keeping the increment outside the match avoids duplicating it.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS.

Run: `cargo test`
Expected: PASS.

- [ ] **Step 9: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 10: Commit**

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/src/lib.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat(auth): re-check the credential on every request in a connection"
```

---

### Task 8: Source-address allowlist enforcement

**Files:**
- Modify: `rust_proxy/src/lib.rs:279` (`handle_client`)
- Test: `rust_proxy/tests/auth_relay_tests.rs` (create)

**Interfaces:**
- Consumes: `addr_allowed`, `RuntimeConfig`, `ProxyStats::acl_rejections`.

- [ ] **Step 1: Write the failing tests**

Create `rust_proxy/tests/auth_relay_tests.rs`:

```rust
use rust_proxy::auth::{Cidr, Credentials};
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, ProxyStats, RuntimeConfig};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Spawn a proxy that serves exactly one connection. Returns its address and
/// the stats it will record into.
async fn one_shot_proxy(config: Arc<RuntimeConfig>) -> (std::net::SocketAddr, Arc<ProxyStats>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, config).await;
    });
    (addr, stats)
}

fn config_with_allowlist(specs: &[&str]) -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: None,
        allow_from: specs.iter().map(|s| Cidr::parse(s).unwrap()).collect(),
    })
}

#[tokio::test]
async fn a_disallowed_source_gets_no_response_at_all() {
    // Silence, not an error page: a scanner should not learn a proxy is here.
    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["10.0.0.0/8"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"GET http://e.example/ HTTP/1.1\r\n\r\n").await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await;
    assert!(
        response.is_empty(),
        "responded to a disallowed source: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_rejected_connection_is_not_counted_as_a_connection() {
    // Rejecting before the counters run keeps the traffic numbers honest and
    // avoids needing a matching decrement.
    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["10.0.0.0/8"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.write_all(b"x").await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn an_allowed_source_proceeds_normally() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut socket, _) = origin.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        buf
    });

    let (addr, stats) = one_shot_proxy(config_with_allowlist(&["127.0.0.1"])).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let request = format!("GET http://{origin_addr}/ok HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(2), origin_task)
        .await
        .expect("origin should have been reached")
        .unwrap();
    let text = String::from_utf8_lossy(&received);
    assert!(text.starts_with("GET /ok HTTP/1.1\r\n"), "{text:?}");
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn an_empty_allowlist_allows_loopback() {
    let (addr, stats) = one_shot_proxy(Arc::new(RuntimeConfig::anonymous(
        RewritePolicy::FailClosed,
    )))
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let _ = client.write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\n\r\n").await;
    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut sink),
    )
    .await;
    assert_eq!(stats.acl_rejections.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 1);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test auth_relay_tests`
Expected: the first two tests FAIL — nothing filters yet, so `acl_rejections` stays 0 and `total_connections` becomes 1.

- [ ] **Step 3: Enforce in `handle_client`**

In `rust_proxy/src/lib.rs`, replace the opening of `handle_client`:

```rust
    // Configure socket options for better performance
    client_socket.set_nodelay(true)?;

    let client_addr = client_socket.peer_addr()?;
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    debug!("Handling client connection from: {}", client_addr);
```

with:

```rust
    // Configure socket options for better performance
    client_socket.set_nodelay(true)?;

    let client_addr = client_socket.peer_addr()?;

    // Before the connection counters and before reading a single byte. Closing
    // in silence is deliberate: an error page would confirm to a scanner that a
    // proxy is listening here.
    if !crate::auth::addr_allowed(&config.allow_from, client_addr.ip()) {
        stats.acl_rejections.fetch_add(1, Ordering::Relaxed);
        warn!("Refusing connection from {}: outside --allow-from", client_addr);
        return Ok(());
    }

    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    debug!("Handling client connection from: {}", client_addr);
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test auth_relay_tests`
Expected: PASS, 4 tests.

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/auth_relay_tests.rs
git commit -m "feat(auth): filter connections by source address"
```

---

### Task 9: SOCKS5 RFC 1929 authentication

**Files:**
- Modify: `rust_proxy/src/lib.rs:515` (`handle_socks5`)
- Test: `rust_proxy/tests/auth_relay_tests.rs` (append)

**Interfaces:**
- Consumes: `Credentials::verify_pair`, `RuntimeConfig`, `one_shot_proxy` from Task 8.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/auth_relay_tests.rs`:

```rust
fn socks_auth_config() -> Arc<RuntimeConfig> {
    Arc::new(RuntimeConfig {
        policy: RewritePolicy::FailClosed,
        auth: Some(Arc::new(
            Credentials::parse_file_contents("user:secret").unwrap(),
        )),
        allow_from: Vec::new(),
    })
}

/// RFC 1929 sub-negotiation request: VER(0x01) ULEN uname PLEN passwd.
fn rfc1929(user: &str, pass: &str) -> Vec<u8> {
    let mut out = vec![0x01, user.len() as u8];
    out.extend_from_slice(user.as_bytes());
    out.push(pass.len() as u8);
    out.extend_from_slice(pass.as_bytes());
    out
}

#[tokio::test]
async fn socks5_offers_username_password_when_a_credential_is_configured() {
    // 0x00 must not be offered at all, or the gate is decorative.
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // VER=5, NMETHODS=2, METHODS=[0x00, 0x02]
    client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x02], "expected method 0x02 to be selected");
}

#[tokio::test]
async fn socks5_rejects_a_client_that_cannot_do_username_password() {
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // Offers only 0x00.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0xFF], "expected NO ACCEPTABLE METHODS");
}

#[tokio::test]
async fn socks5_accepts_the_configured_credential() {
    let (addr, stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x02]);

    client.write_all(&rfc1929("user", "secret")).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    // RFC 1929 replies with VER=0x01, not 0x05 — a frequent implementation bug.
    assert_eq!(auth_reply, [0x01, 0x00]);
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn socks5_rejects_a_wrong_password() {
    let (addr, stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();

    client.write_all(&rfc1929("user", "wrong")).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x01], "expected an auth failure reply");

    // And the connection must be closed, not left waiting for a request.
    let mut trailing = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_to_end(&mut trailing),
    )
    .await;
    assert!(trailing.is_empty());
    assert_eq!(stats.auth_failures.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn socks5_rejects_a_bad_subnegotiation_version() {
    // Sending 0x05 here instead of 0x01 is the classic client-side bug; it must
    // be refused rather than silently accepted.
    let (addr, _stats) = one_shot_proxy(socks_auth_config()).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();

    let mut bad = rfc1929("user", "secret");
    bad[0] = 0x05;
    client.write_all(&bad).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [0x01, 0x01]);
}

#[tokio::test]
async fn socks5_under_allow_anonymous_is_unchanged() {
    let (addr, _stats) = one_shot_proxy(Arc::new(RuntimeConfig::anonymous(
        RewritePolicy::FailClosed,
    )))
    .await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00], "anonymous SOCKS5 must be unchanged");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test auth_relay_tests socks5`
Expected: the auth tests FAIL — the proxy still replies `[0x05, 0x00]` unconditionally.

- [ ] **Step 3: Implement the handshake**

In `rust_proxy/src/lib.rs`, in `handle_socks5`, delete the `let _ = &config;` line added in Task 4, then replace:

```rust
    // We only support "no authentication" (0x00).
    if !methods.contains(&0x00) {
        // 0xFF = NO ACCEPTABLE METHODS
        client_socket.write_all(&[0x05, 0xFF]).await?;
        warn!("SOCKS5 client offered no acceptable auth methods");
        return Ok(());
    }
    client_socket.write_all(&[0x05, 0x00]).await?;
```

with:

```rust
    // With a credential configured, "no authentication" is never offered: a
    // SOCKS5 client that could still pick 0x00 would be a bypass around the
    // HTTP gate on the same port.
    let selected: u8 = if config.auth.is_some() { 0x02 } else { 0x00 };
    if !methods.contains(&selected) {
        // 0xFF = NO ACCEPTABLE METHODS
        client_socket.write_all(&[0x05, 0xFF]).await?;
        warn!("SOCKS5 client offered no acceptable auth methods");
        return Ok(());
    }
    client_socket.write_all(&[0x05, selected]).await?;

    if let Some(creds) = config.auth.as_deref() {
        // RFC 1929: VER(0x01) | ULEN | UNAME | PLEN | PASSWD.
        // Note VER is 0x01 here, not 0x05.
        let mut ver_ulen = [0u8; 2];
        timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut ver_ulen)).await??;
        if ver_ulen[0] != 0x01 {
            client_socket.write_all(&[0x01, 0x01]).await?;
            stats.auth_failures.fetch_add(1, Ordering::Relaxed);
            warn!("SOCKS5 username/password sub-negotiation had a bad version");
            return Ok(());
        }

        let mut uname = vec![0u8; ver_ulen[1] as usize];
        if !uname.is_empty() {
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut uname)).await??;
        }
        let mut plen = [0u8; 1];
        timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut plen)).await??;
        let mut passwd = vec![0u8; plen[0] as usize];
        if !passwd.is_empty() {
            timeout(CONNECT_TIMEOUT, client_socket.read_exact(&mut passwd)).await??;
        }

        if !creds.verify_pair(&uname, &passwd) {
            stats.auth_failures.fetch_add(1, Ordering::Relaxed);
            // No username in the log: a client may have put its password there.
            warn!("SOCKS5 authentication failed for {}", client_socket
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string()));
            client_socket.write_all(&[0x01, 0x01]).await?;
            return Ok(());
        }
        client_socket.write_all(&[0x01, 0x00]).await?;
    }
```

Both length fields are `u8`, so `uname` and `passwd` are bounded at 255 bytes each by the protocol — no additional cap is needed.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test auth_relay_tests`
Expected: PASS, 10 tests.

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Lint**

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/auth_relay_tests.rs
git commit -m "feat(auth): authenticate SOCKS5 with RFC 1929"
```

---

### Task 10: Golden equality for an authenticated request

The test of the goal. If a credential changes what the origin sees, the whole feature has broken the project's core invariant.

**Files:**
- Modify: `rust_proxy/tests/golden_equality_tests.rs`

**Interfaces:**
- Consumes: `RuntimeConfig`, `Credentials`, and the file's existing `direct_bytes` and `assert_indistinguishable`.

- [ ] **Step 1: Write the failing test**

In `rust_proxy/tests/golden_equality_tests.rs`, add an authenticating variant of `proxied_bytes` next to the existing one:

```rust
/// Bytes the origin sees when the request goes through an authenticating proxy.
async fn proxied_bytes_authenticated(request: &str, origin_placeholder: &str) -> Vec<u8> {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let task = tokio::spawn(record_one(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let config = Arc::new(RuntimeConfig {
            policy: RewritePolicy::FailClosed,
            auth: Some(Arc::new(
                rust_proxy::auth::Credentials::parse_file_contents("user:secret").unwrap(),
            )),
            allow_from: Vec::new(),
        });
        let _ = handle_client(socket, stats, config).await;
    });

    let wire = request.replace(origin_placeholder, &origin_addr.to_string());
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(wire.as_bytes()).await.unwrap();

    let mut sink = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(600),
        client.read_to_end(&mut sink),
    )
    .await;
    drop(client);
    task.await.unwrap()
}
```

Then append the test:

```rust
#[tokio::test]
async fn an_authenticated_request_is_indistinguishable_from_direct() {
    // Rule 4 already drops Proxy-Authorization, so adding a credential must
    // change nothing the origin can observe. If this ever fails, the feature
    // has turned a privacy proxy into a fingerprint.
    let direct = "GET /path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n";
    // base64("user:secret")
    let proxied = "GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n";

    let from_direct = direct_bytes(direct, "ORIGIN").await;
    let from_proxy = proxied_bytes_authenticated(proxied, "ORIGIN").await;

    // Byte-exact after normalizing only the origin's own address, which
    // legitimately differs between the two listeners.
    let normalize = |bytes: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        for line in bytes.split_inclusive(|&b| b == b'\n') {
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
                out.extend_from_slice(b"Host: NORMALIZED\r\n");
            } else {
                out.extend_from_slice(line);
            }
        }
        out
    };

    assert_eq!(
        normalize(&from_direct),
        normalize(&from_proxy),
        "origin can distinguish an authenticated proxied request\n direct: {:?}\nproxied: {:?}",
        String::from_utf8_lossy(&from_direct),
        String::from_utf8_lossy(&from_proxy)
    );
}
```

This normalizer works on bytes rather than `String::from_utf8_lossy`. Non-UTF-8 divergence collapses to U+FFFD on both sides and compares equal, which blinds the guard exactly where byte-identity matters.

- [ ] **Step 2: Run the test to verify it fails, then passes**

Run: `cargo test --test golden_equality_tests an_authenticated_request`

If Tasks 6 and 7 are correct, this should PASS on the first run. That is expected — it is a regression guard rather than a driver of new code. To confirm it can actually fail, temporarily comment out the `if name_is(line, b"Proxy-Authorization") { continue; }` line in `src/http_rewrite.rs`, re-run, observe FAIL, then restore it and re-run to observe PASS.

- [ ] **Step 3: Full suite**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add rust_proxy/tests/golden_equality_tests.rs
git commit -m "test: assert an authenticated request stays byte-identical to direct"
```

---

### Task 11: Documentation

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`

- [ ] **Step 1: Correct the false claim in the README**

`README.md:219` currently advertises "SOCKS5 with no authentication". Locate that line and change it to describe both modes, for example:

```markdown
- SOCKS5 (RFC 1928, CONNECT only). Username/password authentication per RFC 1929
  when a credential is configured; no authentication under `--allow-anonymous`.
```

- [ ] **Step 2: Add an Authentication section to the README**

Insert a new section, placed after the existing usage/flags material:

```markdown
## Authentication

The proxy refuses to start without either a credential or an explicit
`--allow-anonymous`. Forwarding for anyone who can reach the port is a choice
you have to make on purpose.

| Flag / variable | Meaning |
| --- | --- |
| `--auth-file <PATH>` | Credentials file, `user:password` per line. Takes precedence over the environment variable. |
| `RUST_PROXY_AUTH=user:password` | Single credential, for launchers where a file is awkward. |
| `--allow-anonymous` | Run with no credential. Open relay. |
| `--allow-from <CIDR>` | Only accept connections from this address or range. Repeatable. Not a substitute for a credential. |

Credentials file format: one `user:password` per line, `#` comments and blank
lines ignored, split on the first colon so passwords may contain colons, CRLF
line endings accepted. Keep it mode 600; the proxy warns if it is readable
beyond its owner.

HTTP clients authenticate with `Proxy-Authorization: Basic`, which is what
`http://user:password@host:3129` in `HTTP_PROXY` produces. SOCKS5 clients
authenticate with RFC 1929 username/password. `--allow-from` is checked first,
then the credential.

### These credentials are not confidential in transit

This proxy contains no TLS library, by design. HTTP Basic and SOCKS5 RFC 1929
both send the credential in cleartext, so anyone who can observe the path
between your client and the proxy can read it and replay it. Authentication here
stops an unauthorized party from *using* the proxy; it does not protect the
credential.

Do not expose the port to the internet. If the proxy is not on the same host as
its clients, put it behind a tunnel — WireGuard on OpenWrt is the intended
pattern — and treat `--allow-from` and the credential as defense in depth behind
that tunnel. Brute-force protection is the firewall's job, not this proxy's.

### Deployment notes

Windows VM: keep the credentials file on the shared folder that the guest sees
as `G:\`, and launch with `--auth-file G:\rust_proxy_auth`.

OpenWrt: `/etc/rust_proxy/auth`, mode 600, root-owned, referenced from a procd
init script. Building and packaging for OpenWrt is not covered here.
```

- [ ] **Step 3: Extend the README's "what this does not hide" section**

That section is a privacy claim and must stay honest. Add a bullet:

```markdown
- **Your proxy credential, if anyone can watch the client-to-proxy path.** Basic
  and RFC 1929 are cleartext and this proxy has no TLS. See Authentication.
```

- [ ] **Step 4: Update `AGENTS.md`**

Add a subsection under the security-properties material:

```markdown
## Authentication is enforced in three places

Auth is checked at each protocol's natural granularity. If you add a code path
that forwards bytes, confirm it passes one of these:

1. `handle_http` — after the head is read, **before any origin dial**. Covers
   CONNECT and the first plain-HTTP request, and is the only site that can still
   write a 407. Checking later would let an unauthenticated client make the
   proxy open arbitrary outbound connections.
2. `RequestStream::handle_head` — every head, so requests 2..n on a reused
   keep-alive connection are re-checked. A one-shot check at connection setup is
   the same class of bug as a one-shot rewrite: it leaks on the common case.
3. `handle_socks5` — RFC 1929. With a credential configured, method `0x00` is
   never offered, or SOCKS5 becomes a bypass around the HTTP gate on the same
   port.

**`PushError::Unauthorized` must never route through `on_anomaly`.** That is
where `--rewrite-fallback` decides to forward verbatim. The flag buys a rewrite
leak; it must never buy an access-control bypass. There is a test asserting
rejection under both policies — if you touch the error plumbing, that is the one
that matters.

Auth is mandatory: startup fails without either a credential or
`--allow-anonymous`. Every subprocess test therefore passes `--allow-anonymous`.

Never log any part of a credential, including the username. `AuthResult::reason`
exists to give the log a fixed, credential-free string.
```

- [ ] **Step 5: Check the README for drifted constants**

The README has repeatedly drifted from the code. Confirm no number you touched is now stale, and confirm the default port in the new Authentication section matches `Args::port` (3129).

Run: `rg -n '3129|64KB|10,000|1 hour' README.md`
Expected: only correct, current values.

- [ ] **Step 6: Full verification**

Run: `cargo test`
Expected: PASS.

Run: `cargo clippy -p rust_proxy --lib -- -D warnings`
Expected: no warnings.

Run: `cargo check --target x86_64-pc-windows-gnu`
Expected: success. The `#[cfg(unix)]` permission check in `load_credentials_file` must compile out cleanly on Windows; this is the only new platform-conditional code.

- [ ] **Step 7: Commit**

```bash
git add README.md AGENTS.md
git commit -m "docs: document proxy authentication and its cleartext limits"
```

---

## Post-Implementation Manual Verification

Not a task; a checklist for the human before trusting this in the VM.

- [ ] `printf 'spencer:somepassword\n' > /tmp/auth && chmod 600 /tmp/auth`
- [ ] `cargo run -- --host 0.0.0.0 --port 3129 --auth-file /tmp/auth`
- [ ] `curl -x http://127.0.0.1:3129 http://example.com/` → expect 407
- [ ] `curl -x http://spencer:somepassword@127.0.0.1:3129 http://example.com/` → expect 200
- [ ] `curl -x http://spencer:somepassword@127.0.0.1:3129 https://example.com/` → expect 200 (CONNECT path)
- [ ] `curl --socks5 spencer:somepassword@127.0.0.1:3129 https://example.com/` → expect 200
- [ ] `curl --socks5 127.0.0.1:3129 https://example.com/` → expect failure
- [ ] `chmod 644 /tmp/auth` and restart → expect the permission warning
- [ ] `cargo run -- --port 3129` → expect exit status 2 and the configuration error
- [ ] Cross-compile and deploy per the `win11-vm` skill; confirm the Windows VM's system proxy settings accept the credential and that a non-elevated start still comes up.




