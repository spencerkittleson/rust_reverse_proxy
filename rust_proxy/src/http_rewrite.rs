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
