# Proxy Fingerprint Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the proxy from announcing itself to origin servers by rewriting every plain-HTTP request into the exact form a directly-connected client would have sent.

**Architecture:** A new pure-logic module `http_rewrite.rs` holds a byte-exact request-head sanitizer and an HTTP/1.1 message-stream state machine; `lib.rs` keeps all I/O and gains an asymmetric relay that pipes the client→origin direction through that state machine while leaving origin→client a blind zero-copy copy. TCP timer tuning moves to the client-facing socket only.

**Tech Stack:** Rust 2021, tokio, clap, `httparse` (new), `libc`/`winapi` for socket options.

**Spec:** `docs/superpowers/specs/2026-07-27-proxy-fingerprint-reduction-design.md`

## Global Constraints

- **Byte-identity is the goal.** Output for an origin must be byte-identical to what the client would have sent connecting directly. Never canonicalize, reorder, re-case, or reflow anything not explicitly named in rules 1-5.
- **Never emit** `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Proxy-Agent`, `Server`, or `Date`.
- **`http_rewrite.rs` performs zero I/O**, holds no `Arc<ProxyStats>`, and does no logging. It records anomalies into a `Vec` the caller drains. This is what makes it exhaustively unit-testable.
- **`framing_conflict` always fails closed**, regardless of `--rewrite-fallback`. It is a request-smuggling vector.
- **`--rewrite-fallback` defaults to off.**
- **Do not change the signature of `bounded_copy_with_stats`** — `tests/unit_tests.rs:209-300` calls it directly.
- **Do not change `find_request_end` or `parse_host_port`** — `tests/unit_tests.rs` covers them.
- Max request head: `65536` bytes (was `8192` at `lib.rs:248`).
- Forwardable `Connection` tokens: exactly `keep-alive`, `close`, `upgrade`.
- All commands run from `rust_proxy/` unless stated otherwise.

## File Structure

| File | Responsibility |
| --- | --- |
| `rust_proxy/src/http_rewrite.rs` (new) | `RewriteAnomaly`, `RewritePolicy`, `sanitize_request_head`, `RequestStream`. Pure; no I/O. |
| `rust_proxy/src/lib.rs` (modify) | `Args` flag, `ProxyStats` counters + report, `Upstream` enum, `connect_and_tunnel`, `rewriting_copy`, `tunnel_fast`, `configure_client_socket`. |
| `rust_proxy/src/main.rs` (modify) | Thread `RewritePolicy` from `Args` to `handle_client`. |
| `rust_proxy/Cargo.toml` (modify) | Add `httparse`. |
| `rust_proxy/tests/http_rewrite_tests.rs` (new) | Byte-exact sanitizer + framing + anomaly unit tests. |
| `rust_proxy/tests/golden_equality_tests.rs` (new) | Direct-vs-proxied byte-equality harness. |
| `README.md` (modify) | What this does and does not hide; document the flag. |

---

### Task 1: Module scaffolding, anomaly taxonomy, and request-line rewriting

**Files:**
- Modify: `rust_proxy/Cargo.toml:14-22`
- Create: `rust_proxy/src/http_rewrite.rs`
- Modify: `rust_proxy/src/lib.rs:12-13`
- Create: `rust_proxy/tests/http_rewrite_tests.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `RewriteAnomaly` (with `ALL: [RewriteAnomaly; 4]`, `index() -> usize`, `name() -> &'static str`, `fallback_eligible() -> bool`), and `sanitize_request_head(head: &[u8]) -> Result<Vec<u8>, RewriteAnomaly>`.

- [ ] **Step 1: Add the `httparse` dependency**

In `rust_proxy/Cargo.toml`, add to `[dependencies]` after the `clap` line:

```toml
httparse = "1.8"
```

- [ ] **Step 2: Declare the module**

In `rust_proxy/src/lib.rs`, immediately after line 13 (`pub mod windows;` and its `#[cfg(windows)]`), add:

```rust
pub mod http_rewrite;
```

- [ ] **Step 3: Write the failing tests**

Create `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL to compile — `unresolved module or unlinked crate 'http_rewrite'` / `file not found for module`.

- [ ] **Step 5: Write the implementation**

Create `rust_proxy/src/http_rewrite.rs`:

```rust
//! Byte-exact HTTP/1.1 request rewriting.
//!
//! Goal: the bytes an origin server receives are byte-identical to what the
//! client would have sent had it connected directly. Only the five rules in
//! `sanitize_request_head` change anything; every other byte is copied verbatim.
//! Canonicalizing anything else would trade one proxy fingerprint for another.
//!
//! This module performs no I/O and does no logging, so it is fully testable
//! without sockets.

pub const CRLF: &[u8] = b"\r\n";
pub const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Tokens forwarded in `Connection` rather than acted on.
///
/// `upgrade` is included even though RFC 7230 classes it hop-by-hop: dropping it
/// (and the `Upgrade` header it names) would make upgrade passthrough
/// unreachable. A proxy that intends to relay an upgrade must forward the offer.
pub const FORWARDABLE_CONNECTION_TOKENS: [&[u8]; 3] = [b"keep-alive", b"close", b"upgrade"];

/// Why a request could not be rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RewriteAnomaly {
    /// Request head exceeded the configured cap.
    HeadTooLarge,
    /// Deprecated line folding inside a header rules 1-5 must modify.
    ObsFoldInRewrittenHeader,
    /// Not recognizable as an HTTP/1.x request.
    Unparseable,
    /// `Transfer-Encoding: chunked` plus `Content-Length`, or duplicate
    /// conflicting `Content-Length`. A request-smuggling vector.
    FramingConflict,
}

impl RewriteAnomaly {
    /// Number of reasons. Used as the array length for counter storage.
    pub const COUNT: usize = 4;

    pub const ALL: [RewriteAnomaly; Self::COUNT] = [
        RewriteAnomaly::HeadTooLarge,
        RewriteAnomaly::ObsFoldInRewrittenHeader,
        RewriteAnomaly::Unparseable,
        RewriteAnomaly::FramingConflict,
    ];

    /// Stable index for counter arrays.
    pub fn index(self) -> usize {
        match self {
            RewriteAnomaly::HeadTooLarge => 0,
            RewriteAnomaly::ObsFoldInRewrittenHeader => 1,
            RewriteAnomaly::Unparseable => 2,
            RewriteAnomaly::FramingConflict => 3,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RewriteAnomaly::HeadTooLarge => "head_too_large",
            RewriteAnomaly::ObsFoldInRewrittenHeader => "obs_fold_in_rewritten_header",
            RewriteAnomaly::Unparseable => "unparseable",
            RewriteAnomaly::FramingConflict => "framing_conflict",
        }
    }

    /// Whether `--rewrite-fallback` may forward this verbatim.
    ///
    /// `FramingConflict` is always false: forwarding it verbatim would turn the
    /// proxy into a request-smuggling gadget aimed at the origin. That refusal
    /// rests on security grounds independent of privacy, so it is not the
    /// operator's trade to make.
    pub fn fallback_eligible(self) -> bool {
        !matches!(self, RewriteAnomaly::FramingConflict)
    }
}

/// First index of `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split a complete head (through its terminating CRLFCRLF) into the request
/// line and the header lines, with all line terminators removed.
fn split_head(head: &[u8]) -> Option<(&[u8], Vec<&[u8]>)> {
    if !head.ends_with(HEAD_TERMINATOR) {
        return None;
    }
    // Drop only the final CRLF, leaving every line CRLF-terminated.
    let mut rest = &head[..head.len() - 2];
    let mut lines: Vec<&[u8]> = Vec::new();
    while let Some(pos) = find(rest, CRLF) {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    if !rest.is_empty() || lines.is_empty() {
        return None;
    }
    let request_line = lines.remove(0);
    Some((request_line, lines))
}

/// Split an absolute-form target into (authority, path-and-query).
fn split_absolute_target(target: &[u8]) -> Option<(&[u8], &[u8])> {
    let sep = find(target, b"://")?;
    let after = &target[sep + 3..];
    let end = after
        .iter()
        .position(|&b| b == b'/' || b == b'?' || b == b'#')
        .unwrap_or(after.len());
    let authority = &after[..end];
    if authority.is_empty() {
        return None;
    }
    Some((authority, &after[end..]))
}

/// Authority reduced to the `Host` header value: userinfo removed, default port
/// for the scheme stripped. IPv6 literals keep their brackets.
fn host_from_authority(authority: &[u8], scheme: &[u8]) -> Vec<u8> {
    let host_port = match authority.iter().rposition(|&b| b == b'@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let default_port: &[u8] = if scheme.eq_ignore_ascii_case(b"https") {
        b":443"
    } else {
        b":80"
    };
    if host_port.len() > default_port.len() && host_port.ends_with(default_port) {
        return host_port[..host_port.len() - default_port.len()].to_vec();
    }
    host_port.to_vec()
}

/// Rule 1: absolute-form request-target becomes origin-form.
///
/// Returns the rewritten line and the `Host` value implied by the target, which
/// is empty when the request was already in origin form (no authority to take).
fn rewrite_request_line(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RewriteAnomaly> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let method = parts.next().ok_or(RewriteAnomaly::Unparseable)?;
    let target = parts.next().ok_or(RewriteAnomaly::Unparseable)?;
    let version = parts.next().ok_or(RewriteAnomaly::Unparseable)?;
    if method.is_empty() || target.is_empty() || !version.starts_with(b"HTTP/") {
        return Err(RewriteAnomaly::Unparseable);
    }

    // Already origin form: rules 2-5 still apply, but there is nothing to
    // rewrite here and no authority to harvest. Forwarding this leaks nothing,
    // because origin form is exactly what this rule produces.
    if target.starts_with(b"/") || target == b"*" {
        return Ok((line.to_vec(), Vec::new()));
    }

    let scheme_end = find(target, b"://").ok_or(RewriteAnomaly::Unparseable)?;
    let scheme = &target[..scheme_end];
    let (authority, path) = split_absolute_target(target).ok_or(RewriteAnomaly::Unparseable)?;

    let mut out = Vec::with_capacity(line.len());
    out.extend_from_slice(method);
    out.push(b' ');
    if path.is_empty() || path[0] != b'/' {
        out.push(b'/');
    }
    out.extend_from_slice(path);
    out.push(b' ');
    out.extend_from_slice(version);

    Ok((out, host_from_authority(authority, scheme)))
}

/// Rewrite one complete request head into the form a direct client would send.
pub fn sanitize_request_head(head: &[u8]) -> Result<Vec<u8>, RewriteAnomaly> {
    let (request_line, header_lines) = split_head(head).ok_or(RewriteAnomaly::Unparseable)?;
    let (new_request_line, _authority) = rewrite_request_line(request_line)?;

    let mut out = Vec::with_capacity(head.len() + 32);
    out.extend_from_slice(&new_request_line);
    out.extend_from_slice(CRLF);
    for line in &header_lines {
        out.extend_from_slice(line);
        out.extend_from_slice(CRLF);
    }
    out.extend_from_slice(CRLF);
    Ok(out)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 9 passed.

- [ ] **Step 7: Verify nothing else regressed**

Run: `cargo test`
Expected: all pre-existing tests still pass.

- [ ] **Step 8: Commit**

```bash
git add rust_proxy/Cargo.toml rust_proxy/src/http_rewrite.rs rust_proxy/src/lib.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat: add http_rewrite module with origin-form request-line rewriting"
```

---

### Task 2: Rule 2 — `Host` takes the authority from the request-target

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs`
- Modify: `rust_proxy/tests/http_rewrite_tests.rs`

**Interfaces:**
- Consumes: `sanitize_request_head`, `find`, `host_from_authority` from Task 1.
- Produces: helpers `header_name(line: &[u8]) -> Option<&[u8]>`, `name_is(line: &[u8], name: &[u8]) -> bool`, `replace_header_value(line: &[u8], new_value: &[u8]) -> Vec<u8>`, used by Task 3.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL — `host_header_takes_authority_from_request_target` and friends show `Host: stale.example` where `Host: real.example` was expected; `absent_host_header_is_inserted_first` shows no `Host` line.

- [ ] **Step 3: Add the header helpers**

In `rust_proxy/src/http_rewrite.rs`, insert after `host_from_authority`:

```rust
/// Field name of a header line, or `None` if it has no colon.
pub fn header_name(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    Some(&line[..colon])
}

/// Whether a header line's field name equals `name`, case-insensitively.
pub fn name_is(line: &[u8], name: &[u8]) -> bool {
    header_name(line).is_some_and(|n| n.eq_ignore_ascii_case(name))
}

/// True for a deprecated `obs-fold` continuation line.
pub fn is_obs_fold(line: &[u8]) -> bool {
    matches!(line.first(), Some(b' ') | Some(b'\t'))
}

/// Replace a header line's value, preserving the field name bytes exactly and
/// the original optional whitespace between the colon and the value.
pub fn replace_header_value(line: &[u8], new_value: &[u8]) -> Vec<u8> {
    let colon = match line.iter().position(|&b| b == b':') {
        Some(i) => i,
        None => return line.to_vec(),
    };
    let after = &line[colon + 1..];
    let ws = after
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(after.len());

    let mut out = Vec::with_capacity(colon + 1 + ws + new_value.len());
    out.extend_from_slice(&line[..=colon]);
    out.extend_from_slice(&after[..ws]);
    out.extend_from_slice(new_value);
    out
}
```

- [ ] **Step 4: Apply rule 2 in `sanitize_request_head`**

Replace the body of `sanitize_request_head` in `rust_proxy/src/http_rewrite.rs` with:

```rust
pub fn sanitize_request_head(head: &[u8]) -> Result<Vec<u8>, RewriteAnomaly> {
    let (request_line, header_lines) = split_head(head).ok_or(RewriteAnomaly::Unparseable)?;
    let (new_request_line, authority) = rewrite_request_line(request_line)?;

    let mut out = Vec::with_capacity(head.len() + 32);
    out.extend_from_slice(&new_request_line);
    out.extend_from_slice(CRLF);

    // Rule 2: insert Host first when the client omitted it. First is where
    // browsers and curl put it.
    let has_host = header_lines.iter().any(|l| name_is(l, b"Host"));
    if !has_host && !authority.is_empty() {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(&authority);
        out.extend_from_slice(CRLF);
    }

    for line in &header_lines {
        if name_is(line, b"Host") && !authority.is_empty() {
            out.extend_from_slice(&replace_header_value(line, &authority));
        } else {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(CRLF);
    }

    out.extend_from_slice(CRLF);
    Ok(out)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 19 passed.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat: correct Host header from request-target authority"
```

---

### Task 3: Rules 3-5 — proxy headers and hop-by-hop cleanup

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs`
- Modify: `rust_proxy/tests/http_rewrite_tests.rs`

**Interfaces:**
- Consumes: `header_name`, `name_is`, `replace_header_value`, `is_obs_fold` from Task 2.
- Produces: `connection_tokens(value: &[u8]) -> Vec<Vec<u8>>` and a `sanitize_request_head` that implements all five rules. Task 4 calls `sanitize_request_head` only.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL — `Proxy-Connection`, `Proxy-Authorization`, and hop-by-hop headers all still present in output; `obs_fold_in_rewritten_header_is_an_anomaly` gets `Ok(..)` instead of `Err`.

- [ ] **Step 3: Add the token helpers**

In `rust_proxy/src/http_rewrite.rs`, insert after `replace_header_value`:

```rust
/// Trim leading and trailing spaces and horizontal tabs.
fn trim(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &s[start..end]
}

/// Lowercased, comma-separated `Connection` tokens with empties removed.
pub fn connection_tokens(value: &[u8]) -> Vec<Vec<u8>> {
    value
        .split(|&b| b == b',')
        .map(|t| trim(t).to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

fn is_forwardable_token(token: &[u8]) -> bool {
    FORWARDABLE_CONNECTION_TOKENS
        .iter()
        .any(|t| t.eq_ignore_ascii_case(token))
}

/// The value part of a header line (after the colon and optional whitespace).
fn header_value(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == b':') {
        Some(colon) => trim(&line[colon + 1..]),
        None => b"",
    }
}

/// Reduce a `Connection` value to its forwardable tokens, preserving each
/// surviving token's original bytes and their order. `None` means drop the line.
fn reduce_connection_value(value: &[u8]) -> Option<Vec<u8>> {
    let kept: Vec<&[u8]> = value
        .split(|&b| b == b',')
        .map(trim)
        .filter(|t| !t.is_empty() && is_forwardable_token(t))
        .collect();
    if kept.is_empty() {
        return None;
    }
    Some(kept.join(&b", "[..]))
}
```

- [ ] **Step 4: Apply rules 3-5 in `sanitize_request_head`**

Replace the whole `sanitize_request_head` function in `rust_proxy/src/http_rewrite.rs` with:

```rust
/// Rewrite one complete request head into the form a direct client would send.
///
/// The five rules are applied in order; rule 5 operates on the `Connection`
/// header as rule 3 leaves it. Every byte not named by a rule is copied verbatim.
pub fn sanitize_request_head(head: &[u8]) -> Result<Vec<u8>, RewriteAnomaly> {
    let (request_line, header_lines) = split_head(head).ok_or(RewriteAnomaly::Unparseable)?;
    let (new_request_line, authority) = rewrite_request_line(request_line)?;

    // Pass 1: decide what rules 3-5 will do before emitting anything.
    let has_connection = header_lines.iter().any(|l| name_is(l, b"Connection"));
    let has_host = header_lines.iter().any(|l| name_is(l, b"Host"));

    // Rule 3: an absent Connection means Proxy-Connection becomes the Connection
    // header, so rule 5's token list comes from whichever one will survive.
    let effective_connection: Vec<Vec<u8>> = header_lines
        .iter()
        .find(|l| {
            name_is(l, b"Connection") || (!has_connection && name_is(l, b"Proxy-Connection"))
        })
        .map(|l| connection_tokens(header_value(l)))
        .unwrap_or_default();

    let named_hop_by_hop: Vec<&Vec<u8>> = effective_connection
        .iter()
        .filter(|t| !is_forwardable_token(t))
        .collect();

    // A rewritten header cannot be safely edited if a fold continues its value.
    let rewritten = |line: &[u8]| {
        name_is(line, b"Host")
            || name_is(line, b"Connection")
            || name_is(line, b"Proxy-Connection")
            || name_is(line, b"Proxy-Authorization")
    };
    for pair in header_lines.windows(2) {
        if rewritten(pair[0]) && is_obs_fold(pair[1]) {
            return Err(RewriteAnomaly::ObsFoldInRewrittenHeader);
        }
    }

    // Pass 2: emit.
    let mut out = Vec::with_capacity(head.len() + 32);
    out.extend_from_slice(&new_request_line);
    out.extend_from_slice(CRLF);

    if !has_host && !authority.is_empty() {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(&authority);
        out.extend_from_slice(CRLF);
    }

    for line in &header_lines {
        // Rule 4.
        if name_is(line, b"Proxy-Authorization") {
            continue;
        }
        // Rule 5: drop headers named by a non-forwardable Connection token.
        if named_hop_by_hop
            .iter()
            .any(|t| name_is(line, t.as_slice()))
        {
            continue;
        }
        // Rule 3.
        if name_is(line, b"Proxy-Connection") {
            if has_connection {
                continue;
            }
            match reduce_connection_value(header_value(line)) {
                Some(v) => {
                    out.extend_from_slice(b"Connection: ");
                    out.extend_from_slice(&v);
                }
                None => continue,
            }
            out.extend_from_slice(CRLF);
            continue;
        }
        // Rule 5, second half: reduce the Connection line itself.
        if name_is(line, b"Connection") {
            match reduce_connection_value(header_value(line)) {
                Some(v) => out.extend_from_slice(&replace_header_value(line, &v)),
                None => continue,
            }
            out.extend_from_slice(CRLF);
            continue;
        }
        // Rule 2.
        if name_is(line, b"Host") && !authority.is_empty() {
            out.extend_from_slice(&replace_header_value(line, &authority));
            out.extend_from_slice(CRLF);
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(CRLF);
    }

    out.extend_from_slice(CRLF);
    Ok(out)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 29 passed.

- [ ] **Step 6: Confirm no clippy regressions in the new module**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: no warnings in `http_rewrite.rs`.

- [ ] **Step 7: Commit**

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat: strip proxy and hop-by-hop headers per RFC 7230"
```

---

### Task 4: `RequestStream` — rewrite every request on the connection

This is the task that justifies the whole architecture. A one-shot rewrite at connection setup leaks on every reused connection, which is the common case.

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs`
- Modify: `rust_proxy/tests/http_rewrite_tests.rs`

**Interfaces:**
- Consumes: `sanitize_request_head`, `RewriteAnomaly`, `find`, `split_head`, `name_is`, `header_value`, `trim` from Tasks 1-3.
- Produces: `RewritePolicy { FailClosed, Fallback }`; `RequestStream::new(policy: RewritePolicy, max_head: usize)`, `push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), RewriteAnomaly>`, `take_anomalies(&mut self) -> Vec<RewriteAnomaly>`, `requests_sanitized(&self) -> u64`, `is_passthrough(&self) -> bool`. Task 5 adds upgrade methods; Tasks 8 and 10 call `push` and `take_anomalies`.

- [ ] **Step 0: Fix the orphaned obs-fold hole from Task 3 (carry-forward)**

The Task 3 review found a byte-integrity gap in `sanitize_request_head`: the
obs-fold guard only fires when a fold follows a header in the hard-coded
`rewritten` set (`Host`/`Connection`/`Proxy-Connection`/`Proxy-Authorization`).
A fold continuing a header that **rule 5 drops** (a header named by a
non-forwardable `Connection` token) is neither flagged nor dropped — pass 2
emits it as an orphaned continuation line. That is a malformed byte on the wire,
exactly what this module exists to prevent, so it must fail closed.

In `rust_proxy/src/http_rewrite.rs`, the `rewritten` closure and its scan
currently read:

```rust
    // A rewritten header cannot be safely edited if a fold continues its value.
    let rewritten = |line: &[u8]| {
        name_is(line, b"Host")
            || name_is(line, b"Connection")
            || name_is(line, b"Proxy-Connection")
            || name_is(line, b"Proxy-Authorization")
    };
    for pair in header_lines.windows(2) {
        if rewritten(pair[0]) && is_obs_fold(pair[1]) {
            return Err(RewriteAnomaly::ObsFoldInRewrittenHeader);
        }
    }
```

Replace that block with one that also covers rule-5-dropped headers. Note
`named_hop_by_hop` is already computed just above this point:

```rust
    // A header whose value pass 2 rewrites OR drops cannot carry an obs-fold
    // continuation safely: rewriting can't see past the first line, and dropping
    // the header would orphan the fold onto its own line. Both fail closed.
    let touched = |line: &[u8]| {
        name_is(line, b"Host")
            || name_is(line, b"Connection")
            || name_is(line, b"Proxy-Connection")
            || name_is(line, b"Proxy-Authorization")
            || named_hop_by_hop.iter().any(|t| name_is(line, t.as_slice()))
    };
    for pair in header_lines.windows(2) {
        if touched(pair[0]) && is_obs_fold(pair[1]) {
            return Err(RewriteAnomaly::ObsFoldInRewrittenHeader);
        }
    }
```

Add a regression test to `rust_proxy/tests/http_rewrite_tests.rs` proving the
orphan case now fails closed:

```rust
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
```

Run: `cargo test --test http_rewrite_tests`
Expected: the new test passes; all previously-passing tests still pass. Commit
this fix separately before starting the `RequestStream` work below:

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "fix: fail closed on obs-fold continuing a rule-5-dropped header

The obs-fold guard only covered explicitly-rewritten headers, so a fold
continuing a Connection-named hop-by-hop header that rule 5 drops was orphaned
onto its own line instead of failing closed."
```

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
use rust_proxy::http_rewrite::{RequestStream, RewritePolicy};

/// Feed `input` through a stream in `chunk`-sized pieces. Small chunk sizes
/// exercise the split-read paths that blind relays never hit.
fn drive(
    policy: RewritePolicy,
    input: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, RewriteAnomaly> {
    let mut stream = RequestStream::new(policy, 65536);
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
            Err(RewriteAnomaly::FramingConflict),
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
        Err(RewriteAnomaly::FramingConflict)
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
    input.extend(std::iter::repeat(b'a').take(70_000));
    input.extend_from_slice(b"\r\n\r\n");

    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
    let mut out = Vec::new();
    let mut result = Ok(());
    for piece in input.chunks(4096) {
        result = stream.push(piece, &mut out);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(RewriteAnomaly::HeadTooLarge));
}

#[test]
fn fallback_forwards_verbatim_and_switches_to_passthrough() {
    // Unparseable is fallback-eligible. With the flag on, the bytes go through
    // untouched — that is the leak the flag buys — and parsing stops, because
    // the failed parse is the same parse that would find the next boundary.
    let input = b"!!! not http !!!\r\n\r\nany trailing bytes at all";
    let mut stream = RequestStream::new(RewritePolicy::Fallback, 65536);
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
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
    let mut out = Vec::new();
    assert_eq!(
        stream.push(b"!!! not http !!!\r\n\r\n", &mut out),
        Err(RewriteAnomaly::Unparseable)
    );
    assert_eq!(stream.take_anomalies(), vec![RewriteAnomaly::Unparseable]);
}

#[test]
fn sanitized_request_count_tracks_successful_rewrites() {
    let input = b"GET http://e.example/one HTTP/1.1\r\nHost: e.example\r\n\r\n\
                  GET http://e.example/two HTTP/1.1\r\nHost: e.example\r\n\r\n";
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
    let mut out = Vec::new();
    stream.push(input, &mut out).unwrap();
    assert_eq!(stream.requests_sanitized(), 2);
    assert!(stream.take_anomalies().is_empty());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL to compile — `cannot find type 'RequestStream'` and `cannot find type 'RewritePolicy'`.

- [ ] **Step 3: Add framing detection**

In `rust_proxy/src/http_rewrite.rs`, append:

```rust
/// How the body of a request is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body; the next request head follows immediately.
    None,
    Length(u64),
    Chunked,
}

/// Determine body framing, rejecting the ambiguous combinations that are also
/// request-smuggling vectors.
fn framing_of(head: &[u8]) -> Result<Framing, RewriteAnomaly> {
    let (_, header_lines) = split_head(head).ok_or(RewriteAnomaly::Unparseable)?;

    let mut te_present = false;
    let mut chunked = false;
    let mut lengths: Vec<u64> = Vec::new();

    for line in &header_lines {
        if name_is(line, b"Transfer-Encoding") {
            te_present = true;
            let value = header_value(line);
            let last = value.split(|&b| b == b',').map(trim).last().unwrap_or(b"");
            if last.eq_ignore_ascii_case(b"chunked") {
                chunked = true;
            }
        } else if name_is(line, b"Content-Length") {
            let text = std::str::from_utf8(header_value(line))
                .map_err(|_| RewriteAnomaly::FramingConflict)?;
            let n: u64 = text
                .trim()
                .parse()
                .map_err(|_| RewriteAnomaly::FramingConflict)?;
            lengths.push(n);
        }
    }

    if let Some(&first) = lengths.first() {
        if lengths.iter().any(|&n| n != first) {
            return Err(RewriteAnomaly::FramingConflict);
        }
    }
    // Both present: RFC 7230 says ignore Content-Length, but implementations
    // disagree, and that disagreement is the smuggling primitive. Refuse.
    if te_present && !lengths.is_empty() {
        return Err(RewriteAnomaly::FramingConflict);
    }
    // A Transfer-Encoding we cannot frame leaves us unable to find the next
    // request boundary.
    if te_present && !chunked {
        return Err(RewriteAnomaly::FramingConflict);
    }
    if chunked {
        return Ok(Framing::Chunked);
    }
    match lengths.first() {
        Some(&n) if n > 0 => Ok(Framing::Length(n)),
        _ => Ok(Framing::None),
    }
}
```

- [ ] **Step 4: Add the state machine**

In `rust_proxy/src/http_rewrite.rs`, append:

```rust
/// What to do when a request cannot be rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewritePolicy {
    /// Close the connection. Forwarding unrewritten bytes *is* the leak.
    FailClosed,
    /// Forward verbatim and record it. Leaks proxy presence for that request.
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkPhase {
    Size,
    Data { remaining: u64 },
    DataCrlf,
    Trailers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    ReadingHead,
    Body { remaining: u64 },
    Chunked(ChunkPhase),
    /// No longer HTTP/1.1 messages: relay bytes untouched forever.
    Passthrough,
}

/// Rewrites every request in a client→origin byte stream.
///
/// Responses are never rewritten, so only this direction needs parsing.
pub struct RequestStream {
    state: State,
    pending: Vec<u8>,
    max_head: usize,
    policy: RewritePolicy,
    anomalies: Vec<RewriteAnomaly>,
    requests_sanitized: u64,
}

impl RequestStream {
    pub fn new(policy: RewritePolicy, max_head: usize) -> Self {
        Self {
            state: State::ReadingHead,
            pending: Vec::new(),
            max_head,
            policy,
            anomalies: Vec::new(),
            requests_sanitized: 0,
        }
    }

    pub fn is_passthrough(&self) -> bool {
        matches!(self.state, State::Passthrough)
    }

    pub fn requests_sanitized(&self) -> u64 {
        self.requests_sanitized
    }

    /// Drain recorded anomalies. Destructive, so a caller polling repeatedly
    /// cannot double-count.
    pub fn take_anomalies(&mut self) -> Vec<RewriteAnomaly> {
        std::mem::take(&mut self.anomalies)
    }

    /// Feed client bytes in, get origin bytes out.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), RewriteAnomaly> {
        if matches!(self.state, State::Passthrough) {
            out.extend_from_slice(input);
            return Ok(());
        }
        self.pending.extend_from_slice(input);

        loop {
            match self.state {
                State::Passthrough => {
                    out.append(&mut self.pending);
                    return Ok(());
                }
                State::ReadingHead => {
                    let terminator = find(&self.pending, HEAD_TERMINATOR);
                    let Some(p) = terminator else {
                        if self.pending.len() > self.max_head {
                            let all: Vec<u8> = self.pending.drain(..).collect();
                            return self.on_anomaly(RewriteAnomaly::HeadTooLarge, &all, out);
                        }
                        return Ok(());
                    };
                    let head_len = p + HEAD_TERMINATOR.len();
                    if head_len > self.max_head {
                        let all: Vec<u8> = self.pending.drain(..).collect();
                        return self.on_anomaly(RewriteAnomaly::HeadTooLarge, &all, out);
                    }
                    let head: Vec<u8> = self.pending.drain(..head_len).collect();
                    self.handle_head(&head, out)?;
                }
                State::Body { remaining } => {
                    let take = std::cmp::min(remaining, self.pending.len() as u64) as usize;
                    out.extend(self.pending.drain(..take));
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        State::ReadingHead
                    } else {
                        State::Body { remaining: left }
                    };
                }
                State::Chunked(_) => {
                    if !self.step_chunked(out)? {
                        return Ok(());
                    }
                }
            }

            if self.pending.is_empty() && !matches!(self.state, State::Passthrough) {
                return Ok(());
            }
        }
    }

    /// Rewrite one head and set up body framing.
    fn handle_head(&mut self, head: &[u8], out: &mut Vec<u8>) -> Result<(), RewriteAnomaly> {
        let framing = match framing_of(head) {
            Ok(f) => f,
            Err(a) => return self.on_anomaly(a, head, out),
        };
        let sanitized = match sanitize_request_head(head) {
            Ok(s) => s,
            Err(a) => return self.on_anomaly(a, head, out),
        };

        out.extend_from_slice(&sanitized);
        self.requests_sanitized += 1;
        self.state = match framing {
            Framing::None => State::ReadingHead,
            Framing::Length(n) => State::Body { remaining: n },
            Framing::Chunked => State::Chunked(ChunkPhase::Size),
        };
        Ok(())
    }

    /// Advance one chunked-body step. `Ok(false)` means "need more bytes".
    fn step_chunked(&mut self, out: &mut Vec<u8>) -> Result<bool, RewriteAnomaly> {
        let phase = match self.state {
            State::Chunked(p) => p,
            _ => return Ok(false),
        };

        match phase {
            ChunkPhase::Size => match httparse::parse_chunk_size(&self.pending) {
                Ok(httparse::Status::Complete((consumed, size))) => {
                    out.extend(self.pending.drain(..consumed));
                    self.state = if size == 0 {
                        State::Chunked(ChunkPhase::Trailers)
                    } else {
                        State::Chunked(ChunkPhase::Data { remaining: size })
                    };
                    Ok(true)
                }
                Ok(httparse::Status::Partial) => Ok(false),
                Err(_) => {
                    let all: Vec<u8> = self.pending.drain(..).collect();
                    self.on_anomaly(RewriteAnomaly::Unparseable, &all, out)?;
                    Ok(true)
                }
            },
            ChunkPhase::Data { remaining } => {
                let take = std::cmp::min(remaining, self.pending.len() as u64) as usize;
                out.extend(self.pending.drain(..take));
                let left = remaining - take as u64;
                self.state = if left == 0 {
                    State::Chunked(ChunkPhase::DataCrlf)
                } else {
                    State::Chunked(ChunkPhase::Data { remaining: left })
                };
                Ok(true)
            }
            ChunkPhase::DataCrlf => {
                if self.pending.len() < 2 {
                    return Ok(false);
                }
                out.extend(self.pending.drain(..2));
                self.state = State::Chunked(ChunkPhase::Size);
                Ok(true)
            }
            ChunkPhase::Trailers => {
                let Some(p) = find(&self.pending, CRLF) else {
                    return Ok(false);
                };
                out.extend(self.pending.drain(..p + 2));
                if p == 0 {
                    // Empty line: trailer section over.
                    self.state = State::ReadingHead;
                }
                Ok(true)
            }
        }
    }

    /// Record an anomaly, then either forward verbatim or fail closed.
    ///
    /// On fallback the connection also becomes `Passthrough`: the parse that just
    /// failed is the same parse that would locate the next request boundary, so
    /// continuing would be guesswork. One leak per connection, not a
    /// desynchronized stream.
    fn on_anomaly(
        &mut self,
        anomaly: RewriteAnomaly,
        verbatim: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), RewriteAnomaly> {
        self.anomalies.push(anomaly);

        if self.policy == RewritePolicy::Fallback && anomaly.fallback_eligible() {
            out.extend_from_slice(verbatim);
            out.append(&mut self.pending);
            self.state = State::Passthrough;
            return Ok(());
        }
        Err(anomaly)
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 41 passed.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat: rewrite every request on a reused keep-alive connection"
```

---

### Task 5: `Upgrade` passthrough gated on a `101` response

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs`
- Modify: `rust_proxy/tests/http_rewrite_tests.rs`

**Interfaces:**
- Consumes: `RequestStream` from Task 4.
- Produces: `RequestStream::upgrade_offered(&self) -> bool` and `RequestStream::observe_response(&mut self, bytes: &[u8])`. Task 10 calls `upgrade_offered` to decide whether to feed response bytes back in.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/http_rewrite_tests.rs`:

```rust
const WS_REQUEST: &[u8] = b"GET http://e.example/ws HTTP/1.1\r\nHost: e.example\r\n\
                            Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

#[test]
fn upgrade_request_arms_the_response_check_but_does_not_switch_yet() {
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
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
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
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
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
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
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
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
    let mut stream = RequestStream::new(RewritePolicy::FailClosed, 65536);
    let mut out = Vec::new();
    stream.push(WS_REQUEST, &mut out).unwrap();
    for piece in b"HTTP/1.1 101 Switching Protocols\r\n".chunks(1) {
        stream.observe_response(piece);
    }
    assert!(stream.is_passthrough());
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test http_rewrite_tests`
Expected: FAIL to compile — `no method named 'upgrade_offered'` / `no method named 'observe_response'`.

- [ ] **Step 3: Detect the upgrade offer**

In `rust_proxy/src/http_rewrite.rs`, add this free function after `framing_of`:

```rust
/// Whether a request offers a protocol upgrade. Requires both the `Upgrade`
/// header and the `upgrade` connection token, per RFC 7230.
fn offers_upgrade(head: &[u8]) -> bool {
    let Some((_, header_lines)) = split_head(head) else {
        return false;
    };
    let has_upgrade_header = header_lines.iter().any(|l| name_is(l, b"Upgrade"));
    let has_upgrade_token = header_lines
        .iter()
        .filter(|l| name_is(l, b"Connection") || name_is(l, b"Proxy-Connection"))
        .any(|l| {
            connection_tokens(header_value(l))
                .iter()
                .any(|t| t.eq_ignore_ascii_case(b"upgrade"))
        });
    has_upgrade_header && has_upgrade_token
}
```

- [ ] **Step 4: Add the response-side one-shot check**

In `rust_proxy/src/http_rewrite.rs`, add two fields to `RequestStream`:

```rust
    upgrade_offered: bool,
    response_head: Vec<u8>,
```

Initialize them in `RequestStream::new`:

```rust
            upgrade_offered: false,
            response_head: Vec::new(),
```

Add to `impl RequestStream`:

```rust
    pub fn upgrade_offered(&self) -> bool {
        self.upgrade_offered
    }

    /// Feed origin→client bytes in only while an upgrade offer is outstanding.
    ///
    /// Switching to `Passthrough` on the request alone would leak absolute form
    /// on every later request whenever the origin *declines* the upgrade, so the
    /// status line is the deciding evidence. Inert otherwise, which keeps the
    /// response path a blind zero-copy relay for all normal traffic.
    pub fn observe_response(&mut self, bytes: &[u8]) {
        if !self.upgrade_offered || matches!(self.state, State::Passthrough) {
            return;
        }
        // Only ever buffers one short status line.
        let room = 64usize.saturating_sub(self.response_head.len());
        self.response_head
            .extend_from_slice(&bytes[..std::cmp::min(room, bytes.len())]);

        if let Some(eol) = find(&self.response_head, CRLF) {
            let status_line = &self.response_head[..eol];
            if status_line.windows(4).any(|w| w == b" 101") {
                self.state = State::Passthrough;
            }
            self.upgrade_offered = false;
            self.response_head.clear();
        } else if self.response_head.len() >= 64 {
            // Not a status line we recognize; stop watching.
            self.upgrade_offered = false;
            self.response_head.clear();
        }
    }
```

In `handle_head`, set the flag after a successful rewrite. Insert immediately after `self.requests_sanitized += 1;`:

```rust
        if offers_upgrade(head) {
            self.upgrade_offered = true;
            self.response_head.clear();
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 46 passed.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/http_rewrite.rs rust_proxy/tests/http_rewrite_tests.rs
git commit -m "feat: gate upgrade passthrough on a 101 response"
```

---

### Task 6: Anomaly counters and the health report block

**Files:**
- Modify: `rust_proxy/src/lib.rs:1-10` (imports), `lib.rs:26-35` (struct), `lib.rs:44-55` (`new`), `lib.rs:57-76` (`log_stats`)
- Create: `rust_proxy/tests/rewrite_stats_tests.rs`

**Interfaces:**
- Consumes: `RewriteAnomaly` from Task 1.
- Produces: `ProxyStats::record_sanitized(&self, n: u64)`, `ProxyStats::record_anomaly(&self, anomaly: RewriteAnomaly, host: &str, forwarded: bool)`, `ProxyStats::set_fallback_active(&self, active: bool)`, and public fields `requests_sanitized`, `rewrite_anomalies`, `rewrite_fallback_forwarded`. Tasks 8 and 10 call `record_sanitized` and `record_anomaly` via `flush_rewrite_stats`; Task 8 calls `set_fallback_active`.

- [ ] **Step 1: Write the failing tests**

Create `rust_proxy/tests/rewrite_stats_tests.rs`:

```rust
use rust_proxy::http_rewrite::RewriteAnomaly;
use rust_proxy::{Ordering, ProxyStats};

#[test]
fn counters_start_at_zero() {
    let stats = ProxyStats::new();
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 0);
    for a in RewriteAnomaly::ALL {
        assert_eq!(stats.rewrite_anomalies[a.index()].load(Ordering::Relaxed), 0);
    }
    assert_eq!(stats.rewrite_fallback_forwarded.load(Ordering::Relaxed), 0);
}

#[test]
fn sanitized_requests_accumulate() {
    let stats = ProxyStats::new();
    stats.record_sanitized(3);
    stats.record_sanitized(2);
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 5);
}

#[test]
fn anomalies_are_counted_per_reason_not_as_one_total() {
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "api.example.com", false);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "other.example.com", false);
    stats.record_anomaly(RewriteAnomaly::FramingConflict, "legacy.internal", false);

    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::HeadTooLarge.index()].load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::FramingConflict.index()].load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        stats.rewrite_anomalies[RewriteAnomaly::Unparseable.index()].load(Ordering::Relaxed),
        0
    );
}

#[test]
fn last_offending_host_is_retained_per_reason() {
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "first.example", false);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "second.example", false);
    stats.record_anomaly(RewriteAnomaly::Unparseable, "other.example", false);

    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::HeadTooLarge).as_deref(),
        Some("second.example")
    );
    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::Unparseable).as_deref(),
        Some("other.example")
    );
    assert_eq!(
        stats.last_anomaly_host(RewriteAnomaly::FramingConflict),
        None
    );
}

#[test]
fn only_forwarded_anomalies_count_toward_the_leak_total() {
    // A fail-closed anomaly leaked nothing, so it must not inflate the banner.
    let stats = ProxyStats::new();
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "a.example", true);
    stats.record_anomaly(RewriteAnomaly::FramingConflict, "b.example", false);
    assert_eq!(stats.rewrite_fallback_forwarded.load(Ordering::Relaxed), 1);
}

#[test]
fn log_stats_runs_with_and_without_anomalies() {
    // Smoke test: the report must not panic on the empty or populated path.
    let stats = ProxyStats::new();
    stats.log_stats();

    stats.record_sanitized(10);
    stats.record_anomaly(RewriteAnomaly::HeadTooLarge, "api.example.com", true);
    stats.set_fallback_active(true);
    stats.log_stats();
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test rewrite_stats_tests`
Expected: FAIL to compile — `no field 'requests_sanitized' on type 'ProxyStats'`.

- [ ] **Step 3: Extend the imports**

In `rust_proxy/src/lib.rs`, change line 1 from:

```rust
pub use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
```

to:

```rust
pub use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
pub use std::sync::Mutex;
```

Then add after the `pub mod http_rewrite;` line from Task 1:

```rust
use crate::http_rewrite::RewriteAnomaly;
```

- [ ] **Step 4: Add the fields**

In `rust_proxy/src/lib.rs`, replace the `ProxyStats` struct (`lib.rs:25-35`) with:

```rust
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
    pub start_time: Instant,
}
```

- [ ] **Step 5: Initialize them and add the recording methods**

In `rust_proxy/src/lib.rs`, replace the `ProxyStats::new` body (`lib.rs:44-55`) with:

```rust
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
```

- [ ] **Step 6: Add the report block**

In `rust_proxy/src/lib.rs`, insert at the end of `log_stats`, immediately after the existing `info!("   Connection Errors: {}", errors);` line (`lib.rs:75`):

```rust
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
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --test rewrite_stats_tests`
Expected: PASS, 6 passed.

- [ ] **Step 8: Verify the pre-existing statistics tests still pass**

Run: `cargo test`
Expected: all tests pass, including `tests/statistics_tests.rs`.

- [ ] **Step 9: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/rewrite_stats_tests.rs
git commit -m "feat: add per-reason rewrite anomaly counters to health report"
```

---

### Task 7: The `--rewrite-fallback` flag

**Files:**
- Modify: `rust_proxy/src/lib.rs:79-93` (`Args`)
- Modify: `rust_proxy/tests/rewrite_stats_tests.rs`

**Interfaces:**
- Consumes: `RewritePolicy` from Task 4.
- Produces: `Args::rewrite_fallback: bool` and `Args::rewrite_policy(&self) -> RewritePolicy`. Task 8 calls `rewrite_policy`.

- [ ] **Step 1: Write the failing tests**

Append to `rust_proxy/tests/rewrite_stats_tests.rs`:

```rust
use clap::Parser;
use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::Args;

#[test]
fn fallback_is_off_by_default() {
    // The safe posture must be the one you get without thinking about it.
    let args = Args::try_parse_from(["rust_proxy"]).unwrap();
    assert!(!args.rewrite_fallback);
    assert_eq!(args.rewrite_policy(), RewritePolicy::FailClosed);
}

#[test]
fn fallback_flag_opts_into_leaking() {
    let args = Args::try_parse_from(["rust_proxy", "--rewrite-fallback"]).unwrap();
    assert!(args.rewrite_fallback);
    assert_eq!(args.rewrite_policy(), RewritePolicy::Fallback);
}

#[test]
fn fallback_flag_composes_with_existing_flags() {
    let args = Args::try_parse_from([
        "rust_proxy",
        "--host",
        "127.0.0.1",
        "--port",
        "9999",
        "--rewrite-fallback",
    ])
    .unwrap();
    assert_eq!(args.host, "127.0.0.1");
    assert_eq!(args.port, 9999);
    assert!(args.rewrite_fallback);
}

#[test]
fn help_text_names_the_privacy_cost() {
    // A flag whose downside is discoverable only by reading the design doc is a trap.
    let help = Args::try_parse_from(["rust_proxy", "--help"])
        .unwrap_err()
        .to_string();
    assert!(help.contains("--rewrite-fallback"));
    let lowered = help.to_lowercase();
    assert!(
        lowered.contains("leak"),
        "help must state the leak: {help}"
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test rewrite_stats_tests`
Expected: FAIL to compile — `no field 'rewrite_fallback' on type 'Args'`.

- [ ] **Step 3: Add the flag**

In `rust_proxy/src/lib.rs`, insert into the `Args` struct immediately before its closing brace (after the `log_level` field at `lib.rs:90-92`):

```rust
    /// Forward requests verbatim when rewriting fails instead of closing the
    /// connection. Leaks proxy presence to the origin for each affected request.
    #[arg(long, default_value_t = false)]
    pub rewrite_fallback: bool,
```

Then add after the `Args` struct:

```rust
impl Args {
    pub fn rewrite_policy(&self) -> crate::http_rewrite::RewritePolicy {
        if self.rewrite_fallback {
            crate::http_rewrite::RewritePolicy::Fallback
        } else {
            crate::http_rewrite::RewritePolicy::FailClosed
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --test rewrite_stats_tests`
Expected: PASS, 10 passed.

- [ ] **Step 5: Verify the existing `Args` tests still pass**

Run: `cargo test --test unit_tests`
Expected: PASS — `tests/unit_tests.rs:84-140` parses `Args` and must be unaffected by an added defaulted flag.

- [ ] **Step 6: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/tests/rewrite_stats_tests.rs
git commit -m "feat: add --rewrite-fallback flag, off by default"
```

---

### Task 8: Socket timers face the client, not the origin

**Files:**
- Modify: `rust_proxy/src/lib.rs:419-446` (Unix), `lib.rs:448-482` (Windows), `lib.rs:487` (call site)

**Interfaces:**
- Consumes: nothing.
- Produces: `configure_client_socket(client: &TcpStream)`, replacing `configure_keepalive(src, dst)`. Task 9 calls it.

**Why:** `configure_keepalive(&src, &dst)` applies identical settings to both sockets, so `TCP_KEEPIDLE=60` with a 1s probe interval and `TCP_USER_TIMEOUT=10_000` currently face the **origin**. A 10-second user timeout resets a briefly-stalled origin where a normal client waits minutes — measurable from the origin side. The origin-facing socket should inherit OS defaults.

- [ ] **Step 1: Rename and narrow the Unix implementation**

In `rust_proxy/src/lib.rs`, replace the Unix `configure_keepalive` (`lib.rs:424-446`) with:

```rust
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
```

- [ ] **Step 2: Rename and narrow the Windows implementation**

In `rust_proxy/src/lib.rs`, replace the Windows `configure_keepalive` (`lib.rs:448-482`) with:

```rust
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
```

- [ ] **Step 3: Update the call site**

In `rust_proxy/src/lib.rs`, change `tunnel_fast`'s line 487 from:

```rust
    configure_keepalive(&src, &dst);
```

to:

```rust
    // `src` is the client; `dst` is the origin and keeps OS defaults.
    configure_client_socket(&src);
```

Note `dst.set_nodelay(true)` on line 486 **stays**. Browsers and `curl` also disable Nagle, so it is fingerprint-neutral and load-bearing for latency.

- [ ] **Step 4: Verify no caller passes the origin socket**

Run: `rg -n 'configure_keepalive|configure_client_socket' rust_proxy/src/`
Expected: exactly three matches — the two `configure_client_socket` definitions and the single call site. No occurrence of `configure_keepalive` remains, and no call passes two sockets. The function signature taking one socket is itself the guard; there is no portable way to assert `setsockopt` state from userspace, so a flaky `ss`-parsing test is not worth writing.

- [ ] **Step 5: Verify the build and suite on this platform**

Run: `cargo build && cargo test`
Expected: builds clean, all tests pass.

- [ ] **Step 6: Verify the Windows variant still compiles**

Run: `cargo check --target x86_64-pc-windows-gnu`
Expected: success. If that target is not installed, skip it and note that CI's Windows job (`.github/workflows/release.yml:14-33`) covers it.

- [ ] **Step 7: Commit**

```bash
git add rust_proxy/src/lib.rs
git commit -m "fix: apply non-default TCP timers to the client socket only

The origin-facing socket inherited a 60s keepalive with 1s probes and a 10s
TCP_USER_TIMEOUT, both far from OS defaults and observable from the origin."
```

---

### Task 9: Asymmetric relay plumbing (pure refactor)

Introduces the machinery for a rewriting relay **without changing behavior**: every call site passes `None`, so the proxy still relays blind exactly as before. Task 10 flips the plain-HTTP path to `Some(stream)`.

**Files:**
- Modify: `rust_proxy/src/http_rewrite.rs` (add `take_sanitized`, `is_fallback`)
- Modify: `rust_proxy/src/lib.rs:484-506` (`tunnel_fast`), `lib.rs:508-574` (`bounded_copy_with_stats`), and the two existing `tunnel_fast` call sites

**Interfaces:**
- Consumes: `RequestStream` (Tasks 4-5); `ProxyStats::record_sanitized` / `record_anomaly` (Task 6); `configure_client_socket` (Task 8).
- Produces: `Transformed`; private `copy_loop`; `RewriteShared`; `flush_rewrite_stats(&mut RequestStream, &ProxyStats, &str, bool)`; `tunnel_fast(src, dst, rewrite: Option<RequestStream>, host: &str, stats)`; `RequestStream::take_sanitized()`; `RequestStream::is_fallback()`. Task 10 supplies `Some(stream)`.
- `bounded_copy_with_stats` keeps its exact public signature — `tests/unit_tests.rs:209-300` depends on it.

**Verification approach:** this task adds no new tests deliberately. It is a behavior-preserving refactor, so the gate is that the **existing** suite still passes unchanged — especially `bounded_copy_with_stats` (`tests/unit_tests.rs:209-300`), CONNECT (`tests/integration_tests.rs:76-115`), and SOCKS5 (`tests/integration_tests.rs:117-307`). The behavioral tests for rewriting arrive in Task 10, which is where the behavior arrives.

- [ ] **Step 1: Add the drain accessor**

In `rust_proxy/src/http_rewrite.rs`, add to `impl RequestStream`:

```rust
    /// Drain the sanitized-request count. Destructive, mirroring
    /// `take_anomalies`, so the I/O layer can flush counters on every read
    /// without double-counting. `requests_sanitized()` remains the cumulative
    /// accessor used by tests.
    pub fn take_sanitized(&mut self) -> u64 {
        std::mem::take(&mut self.requests_sanitized)
    }
```

Change the `requests_sanitized` field to track both by adding a second field. Replace the field declaration:

```rust
    requests_sanitized: u64,
```

with:

```rust
    /// Cumulative, for tests and diagnostics.
    requests_sanitized_total: u64,
    /// Undrained delta, for the stats layer.
    requests_sanitized: u64,
```

Initialize `requests_sanitized_total: 0,` in `new`, increment it alongside the other in `handle_head`:

```rust
        self.requests_sanitized += 1;
        self.requests_sanitized_total += 1;
```

and change the cumulative accessor to read the total:

```rust
    pub fn requests_sanitized(&self) -> u64 {
        self.requests_sanitized_total
    }
```

- [ ] **Step 2: Confirm the Task 4 and 5 tests still pass**

Run: `cargo test --test http_rewrite_tests`
Expected: PASS, 46 passed — `sanitized_request_count_tracks_successful_rewrites` still sees the cumulative 2.

- [ ] **Step 3: Expose the policy on `RequestStream`**

In `rust_proxy/src/http_rewrite.rs`, add to `impl RequestStream`:

```rust
    pub fn is_fallback(&self) -> bool {
        self.policy == RewritePolicy::Fallback
    }
```

- [ ] **Step 4: Add the stats flush helper**

In `rust_proxy/src/lib.rs`, insert immediately before `async fn connect_and_tunnel` (`lib.rs:208`):

```rust
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
```

- [ ] **Step 5: Extract a hooked copy loop**

In `rust_proxy/src/lib.rs`, replace `bounded_copy_with_stats` (`lib.rs:508-574`) with the following. Behavior is unchanged; the loop body is now shared with the rewriting and observing paths so there is one place where idle timeout, byte caps, and stats accounting live.

```rust
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

// Copy with size limits and statistics tracking.
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
```

- [ ] **Step 6: Add the shared rewriter state**

In `rust_proxy/src/lib.rs`, insert immediately before `tunnel_fast` (`lib.rs:484`):

```rust
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
```

- [ ] **Step 7: Make `tunnel_fast` asymmetric**

In `rust_proxy/src/lib.rs`, replace `tunnel_fast` (`lib.rs:484-506`) with:

```rust
async fn tunnel_fast(
    mut src: TcpStream,
    mut dst: TcpStream,
    rewrite: Option<crate::http_rewrite::RequestStream>,
    host: &str,
    stats: Arc<ProxyStats>,
) -> Result<(), ProxyError> {
    src.set_nodelay(true)?;
    dst.set_nodelay(true)?;
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
```

- [ ] **Step 8: Update both existing call sites to pass `None`**

`connect_and_tunnel` still has its original signature at this point; only the `tunnel_fast` call changes. In `rust_proxy/src/lib.rs`, change the call inside `connect_and_tunnel` from:

```rust
            tunnel_fast(client_socket, remote, stats).await
```

to:

```rust
            tunnel_fast(client_socket, remote, None, host, stats).await
```

In `handle_socks5`, change its `tunnel_fast` call to:

```rust
    tunnel_fast(client_socket, remote, None, host.as_str(), stats).await
```

- [ ] **Step 9: Verify nothing changed behaviorally**

Run: `cargo test`
Expected: all pre-existing tests pass with no modifications. Since every caller passes `None`, the `Some(..)` arm is not yet exercised — that is intentional and Task 10 covers it.

- [ ] **Step 10: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/src/http_rewrite.rs
git commit -m "refactor: add rewriting-relay plumbing behind an Option

Extracts the shared copy loop, adds the asymmetric tunnel_fast shape and the
stats flush helper. Every call site still passes None, so behavior is
unchanged; Task 10 enables rewriting on the plain-HTTP path."
```

---

### Task 10: Wire the rewriter into `handle_http`, and fix the `https://` bug

Turns on everything Task 9 built. This is where the privacy behavior actually starts.

**Files:**
- Modify: `rust_proxy/src/lib.rs:17-22` (consts), `lib.rs:180-206` (`handle_client`), `lib.rs:208-242` (`connect_and_tunnel`), `lib.rs:244-299` (`handle_http`)
- Modify: `rust_proxy/src/main.rs:7-30`, `main.rs:60-79`
- Create: `rust_proxy/tests/relay_tests.rs`

**Interfaces:**
- Consumes: `tunnel_fast`, `flush_rewrite_stats` (Task 9); `RequestStream`, `RewritePolicy`, `RewriteAnomaly` (Tasks 1-5); `ProxyStats::set_fallback_active` (Task 6); `Args::rewrite_policy` (Task 7).
- Produces: `MAX_REQUEST_HEAD_SIZE: usize`; `Upstream { Tunnel, Http { first_head: Vec<u8>, policy: RewritePolicy } }`; `handle_client(TcpStream, Arc<ProxyStats>, RewritePolicy)`.

- [ ] **Step 1: Write the failing tests**

Create `rust_proxy/tests/relay_tests.rs`:

```rust
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, Ordering, ProxyStats};

/// Origin that records the exact bytes it receives, then replies.
async fn recording_origin(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = match socket.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        received.extend_from_slice(&buf[..n]);
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        if received.windows(4).any(|w| w == b"\r\n\r\n") {
            // Give a pipelined second request a chance to arrive.
            let mut extra = [0u8; 4096];
            if let Ok(Ok(m)) = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                socket.read(&mut extra),
            )
            .await
            {
                if m > 0 {
                    received.extend_from_slice(&extra[..m]);
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            }
            break;
        }
    }
    received
}

/// Run one client byte-stream through a real proxy connection and return what
/// the origin actually received.
async fn proxy_roundtrip(client_bytes: &[u8], policy: RewritePolicy) -> (Vec<u8>, Arc<ProxyStats>) {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(recording_origin(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    let stats_for_proxy = stats.clone();

    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats_for_proxy, policy).await;
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

#[tokio::test]
async fn origin_never_sees_absolute_form() {
    let (received, stats) = proxy_roundtrip(
        b"GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let text = String::from_utf8_lossy(&received);
    assert!(
        text.starts_with("GET /path?q=1 HTTP/1.1\r\n"),
        "origin got: {text:?}"
    );
    assert!(!text.contains("http://"), "absolute form leaked: {text:?}");
    assert_eq!(stats.requests_sanitized.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn origin_never_sees_proxy_headers() {
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\n\
          Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic zzz\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let lowered = String::from_utf8_lossy(&received).to_lowercase();
    assert!(!lowered.contains("proxy-connection"), "{lowered:?}");
    assert!(!lowered.contains("proxy-authorization"), "{lowered:?}");
    assert!(lowered.contains("connection: keep-alive"), "{lowered:?}");
}

#[tokio::test]
async fn second_pipelined_request_is_also_rewritten() {
    // The whole reason for a streaming rewriter rather than a one-shot.
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\r\n\
          GET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("GET /one HTTP/1.1"), "{text:?}");
    assert!(text.contains("GET /two HTTP/1.1"), "{text:?}");
    assert!(!text.contains("http://"), "absolute form leaked: {text:?}");
}

#[tokio::test]
async fn proxy_never_injects_identifying_headers() {
    let (received, _) = proxy_roundtrip(
        b"GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        RewritePolicy::FailClosed,
    )
    .await;

    let lowered = String::from_utf8_lossy(&received).to_lowercase();
    for banned in ["via:", "x-forwarded-for", "forwarded:", "x-real-ip"] {
        assert!(!lowered.contains(banned), "{banned} present in {lowered:?}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --test relay_tests`
Expected: FAIL to compile — `handle_client` takes 2 arguments, not 3. After Step 7 it compiles, and before Step 5 the pipelined case still fails.

- [ ] **Step 3: Add the head-size constant**

In `rust_proxy/src/lib.rs`, add after line 22 (`pub const STATS_FLUSH_THRESHOLD`):

```rust
/// Max request head. Raised from the original 8KB: browsers with large cookie
/// jars and `Authorization: Bearer` tokens exceed 8KB routinely, and that was the
/// likeliest source of spurious rewrite anomalies.
pub const MAX_REQUEST_HEAD_SIZE: usize = 65536;
```

- [ ] **Step 4: Add the `Upstream` enum**

In `rust_proxy/src/lib.rs`, insert immediately before `async fn connect_and_tunnel` (`lib.rs:208`), next to `flush_rewrite_stats` from Task 9:

```rust
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
        policy: crate::http_rewrite::RewritePolicy,
    },
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
```

- [ ] **Step 5: Rewrite `connect_and_tunnel`**

In `rust_proxy/src/lib.rs`, replace the whole `connect_and_tunnel` function (`lib.rs:208-242`) with:

```rust
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
                Upstream::Http { first_head, policy } => {
                    remote.set_nodelay(true)?;

                    let mut stream = crate::http_rewrite::RequestStream::new(
                        policy,
                        MAX_REQUEST_HEAD_SIZE,
                    );
                    let mut rewritten = Vec::with_capacity(first_head.len() + 64);
                    let push_result = stream.push(&first_head, &mut rewritten);

                    let fallback = policy == crate::http_rewrite::RewritePolicy::Fallback;
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
```

- [ ] **Step 6: Update `handle_http`**

In `rust_proxy/src/lib.rs`, replace the signature and the dispatch tail of `handle_http`. Change line 244 to:

```rust
async fn handle_http(
    mut client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    policy: crate::http_rewrite::RewritePolicy,
) -> Result<(), ProxyError> {
```

Change the header cap at `lib.rs:248` from:

```rust
    let max_header_size = 8192;
```

to:

```rust
    let max_header_size = MAX_REQUEST_HEAD_SIZE;
```

Replace the `if method.eq_ignore_ascii_case("CONNECT")` block through the end of the function (`lib.rs:279-298`) with:

```rust
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
                policy,
            },
            |_e| {},
            stats,
        )
        .await?;
    }

    Ok(())
}
```

- [ ] **Step 7: Thread the policy through `handle_client`**

In `rust_proxy/src/lib.rs`, change `handle_client`'s signature (`lib.rs:180`) to:

```rust
pub async fn handle_client(
    client_socket: TcpStream,
    stats: Arc<ProxyStats>,
    policy: crate::http_rewrite::RewritePolicy,
) -> Result<(), ProxyError> {
```

and its dispatch (`lib.rs:197-201`) to:

```rust
    let result = if peek_buf[0] == 0x05 {
        // SOCKS5 is a blind byte relay: nothing to rewrite.
        handle_socks5(client_socket, stats.clone()).await
    } else {
        handle_http(client_socket, stats.clone(), policy).await
    };
```

- [ ] **Step 8: Thread the policy through `main.rs`**

In `rust_proxy/src/main.rs`, change `accept_and_spawn` (`main.rs:7`) to:

```rust
async fn accept_and_spawn(
    listener: &TcpListener,
    semaphore: &Arc<Semaphore>,
    stats: &Arc<ProxyStats>,
    policy: rust_proxy::http_rewrite::RewritePolicy,
) {
```

and its spawn body (`main.rs:26`) to:

```rust
        if let Err(e) = handle_client(client_socket, stats_clone, policy).await {
```

In `main`, after `let stats = Arc::new(ProxyStats::new());` (`main.rs:67`), add:

```rust
    let policy = args.rewrite_policy();
    stats.set_fallback_active(args.rewrite_fallback);
    if args.rewrite_fallback {
        warn!("--rewrite-fallback is enabled: requests that fail rewriting will be");
        warn!("forwarded unrewritten, revealing proxy presence to the origin.");
    }
```

and change the accept call (`main.rs:92`) to:

```rust
                accept_and_spawn(&listener, &sem_for_accept, &stats_for_accept, policy).await;
```

- [ ] **Step 9: Run the new tests**

Run: `cargo test --test relay_tests`
Expected: PASS, 4 passed.

- [ ] **Step 10: Verify the full suite**

Run: `cargo test`
Expected: all pass, including `tests/unit_tests.rs:209-300` (`bounded_copy_with_stats` signature preserved), `tests/integration_tests.rs:76-115` (CONNECT), and `tests/integration_tests.rs:117-307` (SOCKS5).

- [ ] **Step 11: Commit**

```bash
git add rust_proxy/src/lib.rs rust_proxy/src/main.rs rust_proxy/tests/relay_tests.rs
git commit -m "feat: rewrite every plain-HTTP request before forwarding upstream

Replaces connect_and_tunnel's forward_headers flag with an Upstream enum,
making the https-absolute-form bug unrepresentable, and raises the request
head cap to 64KB."
```

---

### Task 11: Golden byte-equality — the test of the actual goal

Every other test checks our rules against our own expectations. This one checks the *goal*: that the origin cannot tell the difference. It therefore catches leaks nobody enumerated.

**Files:**
- Create: `rust_proxy/tests/golden_equality_tests.rs`

**Interfaces:**
- Consumes: `handle_client` (Task 8), `RewritePolicy` (Task 4), `ProxyStats` (Task 6).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the test harness and its assertions**

Create `rust_proxy/tests/golden_equality_tests.rs`:

```rust
//! The origin must not be able to distinguish a proxied request from a direct
//! one. Each case sends the *same logical request* twice — once straight to a
//! recording origin, once through the proxy — and requires the recorded bytes to
//! match exactly.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rust_proxy::http_rewrite::RewritePolicy;
use rust_proxy::{handle_client, ProxyStats};

const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

/// Accept one connection, record everything received until the peer stops
/// sending for 250ms, then return the exact bytes.
async fn record_one(listener: TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            socket.read(&mut buf),
        )
        .await;

        match read {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                received.extend_from_slice(&buf[..n]);
                let _ = socket.write_all(RESPONSE).await;
            }
            Ok(Err(_)) => break,
        }
    }
    received
}

/// Bytes the origin sees when the client connects directly.
async fn direct_bytes(request: &str, origin_placeholder: &str) -> Vec<u8> {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = origin.local_addr().unwrap();
    let task = tokio::spawn(record_one(origin));

    let wire = request.replace(origin_placeholder, &addr.to_string());
    let mut client = TcpStream::connect(addr).await.unwrap();
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

/// Bytes the origin sees when the same request goes through the proxy.
async fn proxied_bytes(request: &str, origin_placeholder: &str) -> Vec<u8> {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let task = tokio::spawn(record_one(origin));

    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let stats = Arc::new(ProxyStats::new());
    tokio::spawn(async move {
        let (socket, _) = proxy.accept().await.unwrap();
        let _ = handle_client(socket, stats, RewritePolicy::FailClosed).await;
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

/// `direct` is what the client would send on its own; `proxied` is what it sends
/// to a proxy for the same resource. The origin must see identical bytes.
async fn assert_indistinguishable(direct: &str, proxied: &str) {
    let from_direct = direct_bytes(direct, "ORIGIN").await;
    let from_proxy = proxied_bytes(proxied, "ORIGIN").await;

    // Normalize only the origin's own address, which legitimately differs
    // between the two listeners.
    let strip = |bytes: &[u8]| {
        let text = String::from_utf8_lossy(bytes).to_string();
        let re_host = text
            .lines()
            .map(|l| {
                if l.to_lowercase().starts_with("host:") {
                    "Host: NORMALIZED".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        re_host
    };

    assert_eq!(
        strip(&from_direct),
        strip(&from_proxy),
        "origin can distinguish proxied traffic\n direct: {:?}\nproxied: {:?}",
        String::from_utf8_lossy(&from_direct),
        String::from_utf8_lossy(&from_proxy)
    );
}

#[tokio::test]
async fn simple_get_is_indistinguishable() {
    assert_indistinguishable(
        "GET /path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
        "GET http://ORIGIN/path?q=1 HTTP/1.1\r\nHost: ORIGIN\r\nAccept: */*\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn keep_alive_intent_survives_as_connection_not_proxy_connection() {
    // A direct client sends `Connection: keep-alive`. A client talking to a proxy
    // sends `Proxy-Connection: keep-alive`. The origin must see the former.
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nHost: ORIGIN\r\nConnection: keep-alive\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\nProxy-Connection: keep-alive\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn post_with_body_is_indistinguishable() {
    assert_indistinguishable(
        "POST /submit HTTP/1.1\r\nHost: ORIGIN\r\nContent-Length: 9\r\n\r\nkey=value",
        "POST http://ORIGIN/submit HTTP/1.1\r\nHost: ORIGIN\r\nContent-Length: 9\r\n\r\nkey=value",
    )
    .await;
}

#[tokio::test]
async fn chunked_post_is_indistinguishable() {
    assert_indistinguishable(
        "POST /submit HTTP/1.1\r\nHost: ORIGIN\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "POST http://ORIGIN/submit HTTP/1.1\r\nHost: ORIGIN\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn unusual_header_casing_and_spacing_survive() {
    // Canonicalizing these would swap one fingerprint for another.
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nHost: ORIGIN\r\nx-WeIrD:   spaced   \r\nUser-Agent: curl/8.5.0\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nHost: ORIGIN\r\nx-WeIrD:   spaced   \r\nUser-Agent: curl/8.5.0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn header_order_survives() {
    assert_indistinguishable(
        "GET / HTTP/1.1\r\nAccept: */*\r\nHost: ORIGIN\r\nUser-Agent: x\r\n\r\n",
        "GET http://ORIGIN/ HTTP/1.1\r\nAccept: */*\r\nHost: ORIGIN\r\nUser-Agent: x\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn two_requests_on_one_connection_are_indistinguishable() {
    assert_indistinguishable(
        "GET /one HTTP/1.1\r\nHost: ORIGIN\r\n\r\nGET /two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
        "GET http://ORIGIN/one HTTP/1.1\r\nHost: ORIGIN\r\n\r\nGET http://ORIGIN/two HTTP/1.1\r\nHost: ORIGIN\r\n\r\n",
    )
    .await;
}
```

- [ ] **Step 2: Run the tests**

Run: `cargo test --test golden_equality_tests`
Expected: PASS, 7 passed.

If `two_requests_on_one_connection_are_indistinguishable` fails while the others pass, the streaming rewriter from Task 10 is not being reached — check that `tunnel_fast` received `Some(stream)` rather than `None`.

- [ ] **Step 3: Run the whole suite**

Run: `cargo test`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add rust_proxy/tests/golden_equality_tests.rs
git commit -m "test: assert origin cannot distinguish proxied from direct requests"
```

---

### Task 12: Document what this hides and what it does not

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the `--rewrite-fallback` flag (Task 7).
- Produces: nothing.

- [ ] **Step 1: Add the privacy section**

In `README.md`, add a new top-level section. Place it after the feature list near `README.md:1-30`:

```markdown
## Proxy visibility

This proxy does not announce itself to origin servers. Requests are rewritten
into the exact form a directly-connected client would send:

- Absolute-form request lines become origin-form, so the origin sees
  `GET /path HTTP/1.1` rather than `GET http://host/path HTTP/1.1`.
- `Host` is corrected from the request-target authority.
- `Proxy-Connection` is renamed to `Connection`, preserving the client's stated
  intent rather than dropping it.
- `Proxy-Authorization` and headers named by `Connection` tokens are removed
  per RFC 7230 §6.1.
- Every request on a reused keep-alive connection is rewritten, not just the
  first.
- No `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Proxy-Agent`,
  `Server`, or `Date` header is ever added.
- Non-default TCP keepalive and user-timeout values apply to the client-facing
  socket only; the origin-facing socket inherits OS defaults.

Nothing else is normalized. Header order, field-name casing, and whitespace are
preserved byte-for-byte, because tidying them would replace one fingerprint
with another.

### What this does not hide

- **Your IP address.** Traffic egresses from the same network with or without
  the proxy.
- **Your TLS fingerprint.** HTTPS travels through a CONNECT tunnel and is never
  terminated, so the origin sees your client's own ClientHello and JA3/JA4.
  Nothing to hide and nothing to fix.
- **Your TCP/IP stack.** The origin observes the proxy host's TTL, MSS, and
  window scaling, which may not match the OS your `User-Agent` claims. Matching
  them is an explicit non-goal: it needs per-OS kernel tuning, breaks on
  updates, and defeats only p0f-class analysis. A mismatch reads as "someone
  behind a NAT," which describes billions of connections.
- **Anything from your own client.** Error responses the proxy returns are seen
  only by the local client, which already knows the proxy exists.

### `--rewrite-fallback`

Off by default. When a request cannot be rewritten, the proxy closes the
connection rather than forward unrewritten bytes, because forwarding them is
exactly the leak this feature removes.

Enabling `--rewrite-fallback` forwards those requests verbatim instead, which
reveals proxy presence to the origin for each one. Use it to diagnose a client
the rewriter mishandles, then turn it back off. While it is enabled the
statistics report carries a banner showing how many requests leaked.

Request-smuggling conflicts — `Transfer-Encoding: chunked` together with
`Content-Length`, or duplicate conflicting `Content-Length` — always close the
connection regardless of this flag. Forwarding those verbatim would make the
proxy a smuggling gadget aimed at the origin.

### Statistics

The periodic report includes rewrite health. A clean run is one line:

```
   Rewrite: 1,234 sanitized, 0 anomalies
```

Problems are itemized by reason, with the last host that triggered each:

```
   Rewrite: 1,230 sanitized, 4 anomalies
      head_too_large: 3 (last: api.example.com)
      framing_conflict: 1 (last: legacy.internal)
```
```

- [ ] **Step 2: Correct the stale numbers in the paragraphs being touched**

The README's performance claims contradict the code. Fix these three:

- `64KB` buffer claim → **16KB** (`rust_proxy/src/lib.rs:17`, `BUFFER_SIZE`)
- `10,000` connections claim → **1,000** (`lib.rs:18`, `MAX_CONNECTIONS`)
- `1-hour` idle timeout claim → **300 seconds** (`lib.rs:20`, `IDLE_TIMEOUT`)

Run this to locate them: `rg -n '64KB|64 KB|10,000|10000|1 hour|1-hour|3600' README.md`

Also document the new request head cap where the other limits are listed: **64KB max request head** (`lib.rs`, `MAX_REQUEST_HEAD_SIZE`).

- [ ] **Step 3: Add the flag to the CLI usage section**

Find the usage/options block in `README.md` (near the `--host` / `--port` / `--log-level` documentation) and add:

```
--rewrite-fallback    Forward requests verbatim when rewriting fails, instead
                      of closing the connection. Leaks proxy presence to the
                      origin for each affected request. Off by default.
```

- [ ] **Step 4: Verify the documented values against the code**

Run: `rg -n 'BUFFER_SIZE|MAX_CONNECTIONS|IDLE_TIMEOUT|MAX_REQUEST_HEAD_SIZE|CONNECT_TIMEOUT' rust_proxy/src/lib.rs`
Expected: the constants match every number now written in the README. Fix the README, not the code — these are documentation drift, not behavior changes.

- [ ] **Step 5: Final full verification**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all tests pass; no clippy warnings.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "docs: document proxy visibility, non-goals, and --rewrite-fallback"
```

---

## Verification Summary

After Task 12, these must all hold:

| Claim | How it is proven |
| --- | --- |
| Origin never sees absolute-form | `golden_equality_tests.rs`, `relay_tests.rs::origin_never_sees_absolute_form` |
| Requests 2..N on a reused connection are rewritten | `http_rewrite_tests.rs::every_request_on_a_reused_connection_is_rewritten`, `golden_equality_tests.rs::two_requests_on_one_connection_are_indistinguishable` |
| Proxy headers never reach the origin | `relay_tests.rs::origin_never_sees_proxy_headers` |
| No identifying header is added | `relay_tests.rs::proxy_never_injects_identifying_headers` |
| Nothing is canonicalized away | `golden_equality_tests.rs::unusual_header_casing_and_spacing_survive`, `header_order_survives` |
| Smuggling conflicts fail closed even with the flag | `http_rewrite_tests.rs::transfer_encoding_plus_content_length_always_fails_closed` |
| Fallback is opt-in | `rewrite_stats_tests.rs::fallback_is_off_by_default` |
| Anomalies are visible per reason | `rewrite_stats_tests.rs::anomalies_are_counted_per_reason_not_as_one_total` |
| Declined upgrades keep being rewritten | `http_rewrite_tests.rs::declined_upgrade_keeps_parsing_and_still_rewrites_later_requests` |
| Origin socket keeps OS default timers | `configure_client_socket` takes one socket; Task 8 Step 4 |
| HTTPS/CONNECT path unchanged | `integration_tests.rs::test_connect_proxy_request` |
| SOCKS5 path unchanged | `integration_tests.rs:117-307` |

