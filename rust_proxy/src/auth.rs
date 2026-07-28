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
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Stored pre-joined as `user:password` bytes, which is exactly the form
    /// both the HTTP and SOCKS5 paths compare against.
    joined: Vec<Vec<u8>>,
}

/// Deliberately opaque: `joined` holds plaintext `user:password` bytes, and
/// this type is embedded in a `Debug`-deriving config. A derived `Debug` would
/// leak the password into any log line, panic message, or assertion failure.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("entries", &self.joined.len())
            .finish()
    }
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

    /// Structurally always `false`: `parse_file_contents` rejects a file that
    /// parses to zero entries. This exists to satisfy `len_without_is_empty`,
    /// not to answer "is authentication disabled" — that question is answered
    /// by `Option<Credentials>` being `None`.
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
