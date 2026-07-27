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
            let last = value.split(|&b| b == b',').map(trim).next_back().unwrap_or(b"");
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
    upgrade_offered: bool,
    response_head: Vec<u8>,
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
            upgrade_offered: false,
            response_head: Vec::new(),
        }
    }

    pub fn is_passthrough(&self) -> bool {
        matches!(self.state, State::Passthrough)
    }

    pub fn requests_sanitized(&self) -> u64 {
        self.requests_sanitized
    }

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
        if offers_upgrade(head) {
            self.upgrade_offered = true;
            self.response_head.clear();
        }
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
