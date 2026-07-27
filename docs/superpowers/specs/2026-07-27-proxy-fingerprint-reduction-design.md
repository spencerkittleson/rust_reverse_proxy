# Proxy Fingerprint Reduction — Design

Date: 2026-07-27
Status: approved, pending implementation plan

## Problem

The proxy announces itself to origin servers on the plain-HTTP path. Two signals do
the announcing:

1. The request line is forwarded in **absolute form**. The origin receives
   `GET http://host/path HTTP/1.1` (`rust_proxy/src/lib.rs:222`). Only a proxy
   ever sends that.
2. **Hop-by-hop headers pass through untouched**, including `Proxy-Connection`
   and `Proxy-Authorization`. No RFC 7230 §6.1 stripping happens anywhere.

A third, weaker signal is observable from the origin side: the origin-facing
socket carries non-default TCP timers — `TCP_KEEPIDLE=60` with a 1s probe
interval and `TCP_USER_TIMEOUT=10_000` (`lib.rs:440-445`, `lib.rs:463-464`).
A 10-second user timeout resets a briefly-stalled origin where a normal client
would wait minutes.

Nothing else in the codebase leaks. The proxy adds no headers, emits no `Via`,
`X-Forwarded-For`, or `Server`, and writes no branded error page. TLS is never
terminated — there is no TLS library in the dependency tree — so a CONNECT
tunnel carries the client's own ClientHello and its genuine JA3/JA4.

## Goal

**The bytes an origin server receives should be byte-identical to what the client
would have sent had it connected directly.**

Identical, not merely clean. Canonicalizing header casing, sorting headers, or
normalizing whitespace would each remove a proxy tell and introduce a new one,
because no real client emits perfectly tidy headers. Every rule below follows
from this.

## Scope

**In scope**

- Plain-HTTP request rewriting: absolute-form → origin-form, `Host` correction,
  hop-by-hop header removal.
- Correct rewriting of **every** request on a reused keep-alive connection, not
  just the first.
- Removing non-default TCP timers from the origin-facing socket.
- Fixing the latent `https://`-absolute-form bug at `lib.rs:291`.

**Explicit non-goals**

- **TCP/IP stack matching.** Making the Windows VM's TTL/MSS/window-scaling
  imitate the Linux client requires registry edits, breaks on Windows updates,
  and defeats only p0f-class analysis. An OS mismatch reads as "someone behind a
  NAT," which describes billions of connections.
- **Hiding traffic from the corporate VPN.** Protocol-hygiene fixes apply
  uniformly, but no feature exists to make traffic opaque to employer security
  controls.
- **Changing egress IP or TLS fingerprint.** The IP is unchanged with or without
  the proxy; the TLS fingerprint is already the client's own.
- **DNS relocation.** No DNS behavior reveals a proxy to an origin server, and
  having the VM resolve internal hostnames is required for the VPN path.
- **Client-facing output.** The 502 responses at `lib.rs:232` and `lib.rs:238`
  reach only the local client, which already knows the proxy exists.

## Architecture

One new module, `rust_proxy/src/http_rewrite.rs` — pure logic, zero I/O, so it is
exhaustively unit-testable without sockets. All I/O stays in `lib.rs`.

### Components

**`sanitize_request_head(head: &[u8]) -> Result<Vec<u8>>`**
Pure function over one complete request head (through `\r\n\r\n`).

**`RequestStream`**
State machine locating request boundaries in the client→origin byte stream.
States: `ReadingHead` → `StreamingBody { remaining }` → back to `ReadingHead`;
plus `StreamingChunked { .. }`, and a terminal `Passthrough` for post-`Upgrade`
traffic. Consumes `&[u8]`, emits `&[u8]`, buffers only a partial head.

**`httparse`**
New dependency in `rust_proxy/Cargo.toml`. Zero-copy, `no_std`, and it reports
byte offsets for each header name and value — exactly what minimal-touch
rewriting needs.

### Changes in `lib.rs`

`connect_and_tunnel` (`lib.rs:208-242`) loses the `forward_headers: bool` /
`raw_headers: &[u8]` pair. That flag is the source of the bug at `lib.rs:291`,
where a non-CONNECT request sends `200 Connection Established` to a client that
never requested a tunnel. It is replaced by an enum, making the bug
unrepresentable rather than patched:

```rust
enum Upstream {
    Tunnel,                       // CONNECT: 200 to client, blind relay both ways
    Http { first_head: Vec<u8> },  // rewrite first head, then rewriting relay
}
```

`tunnel_fast` (`lib.rs:484-506`) becomes asymmetric. It currently runs two
identical `bounded_copy_with_stats` halves under `try_join!`:

- **client→origin** — `rewriting_copy`, piping bytes through `RequestStream`.
  Retains the existing idle timeout, byte cap, and stats accounting from
  `bounded_copy_with_stats` (`lib.rs:509-574`); only the inner transform differs.
- **origin→client** — unchanged `bounded_copy_with_stats`. Responses are never
  rewritten, so this stays a blind zero-copy relay. The single exception is the
  one-shot `101` status-line check described under *`Upgrade` handling*, which is
  armed only after an upgrade request has been seen and is inert otherwise.

CONNECT and SOCKS5 keep both halves blind. Parsing cost lands only on plain HTTP;
the HTTPS fast path, which carries the bulk of traffic, is untouched.

## Rewrite rules

Exactly five edits, applied in the numbered order below — rule 5 operates on the
`Connection` header as rule 3 leaves it. Every other byte is preserved.

1. **Request line: absolute-form → origin-form.**
   `GET http://host:8080/path?q HTTP/1.1` → `GET /path?q HTTP/1.1`. Method and
   version bytes copied verbatim. Empty path becomes `/`. Highest-value change in
   the design.

2. **`Host` takes the authority from the request-target.** The request-target
   authority wins over a disagreeing `Host` header. If `Host` exists, replace
   *only its value bytes*, preserving field-name position and original casing.
   If absent, insert `Host` as the first header line — where browsers and `curl`
   put it. Strip the default port (`:80` for http); retain non-default ports.
   When the client's `Host` already matches, this is a zero-byte change.

3. **`Proxy-Connection` is renamed, not deleted.** With no `Connection` header
   present, rewrite the field name in place to `Connection`, keeping value and
   line position: `Proxy-Connection: keep-alive` → `Connection: keep-alive`.
   Deleting it would strip the client's stated intent and produce a header set no
   real client emits. If a `Connection` header is present, drop the
   `Proxy-Connection` line entirely.

4. **`Proxy-Authorization` is dropped unconditionally.** Proxy credentials never
   belong upstream.

5. **Hop-by-hop cleanup, RFC 7230 §6.1.** For each token listed in `Connection`,
   drop the header it names. Then *reduce* `Connection` to its surviving
   end-to-end tokens, where the only tokens kept are `keep-alive` and `close`; if
   neither survives, drop the `Connection` line. Reduce only — never invent a
   token the client did not send.

### Codified prohibitions

Written as rules so a later change does not helpfully reintroduce them: never
emit `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Proxy-Agent`, `Server`,
or `Date`. Never reorder headers. Never alter field-name casing. Never adjust
whitespace around `:`. Never fold or unfold `obs-fold` continuation lines.

## Message framing

Body framing, in precedence order:

1. Final `Transfer-Encoding` of `chunked` → parse chunk framing (size lines,
   terminal zero-chunk, trailers).
2. `Content-Length: N` → stream exactly N bytes.
3. Neither → no body; the next head begins immediately.

Pipelined heads arriving in a single read are handled by looping until the buffer
drains. The head size cap stays at the existing 8192 bytes (`lib.rs:248`).

### Fail closed, never leak

On any framing ambiguity or parse failure, terminate the connection rather than
degrade to verbatim forwarding — verbatim forwarding *is* the leak. This covers:

- `Transfer-Encoding: chunked` and `Content-Length` both present (also a request
  smuggling vector, so refusing is correct on two counts)
- duplicate conflicting `Content-Length`
- `obs-fold` that cannot be rewritten safely
- oversized heads
- a mid-stream request that is not in absolute form

This is a deliberate availability-for-privacy trade: a malformed request drops the
connection instead of silently announcing the proxy.

### `Upgrade` handling

After a successful upgrade (websockets, h2c) the connection stops carrying
HTTP/1.1 messages, so `RequestStream` must switch to `Passthrough`. Success
cannot be determined from the request alone, and assuming success on a *declined*
upgrade would leak absolute-form on every subsequent request on that connection.

Therefore: when a request carries `Upgrade`, arm a one-shot check that reads only
the response status line and switches to `Passthrough` only on `101`. The check
is armed solely when an upgrade request was seen, so the response path remains a
blind zero-copy relay for all normal traffic. The simpler alternative — refusing
`Upgrade` on plain HTTP — is rejected because it would break websockets to
internal hosts.

## Socket timers

**Structural rule: the origin-facing socket inherits OS defaults; only the
client-facing socket is tuned.**

`configure_keepalive(&src, &dst)` (`lib.rs:487`) applies identical settings to
both sockets today, which is how the non-default timers came to face the origin.
It becomes `configure_client_socket(&src)`. The rename makes the asymmetry
self-documenting rather than a comment that gets deleted.

Settings that move to client-only: `SO_KEEPALIVE`, `TCP_KEEPIDLE=60`,
`TCP_QUICKACK`, `TCP_USER_TIMEOUT=10_000` on Unix (`lib.rs:424-446`); the
`SIO_KEEPALIVE_VALS` 60s/1s pair on Windows (`lib.rs:448-482`).

`set_nodelay(true)` on the origin socket stays. Browsers and `curl` also disable
Nagle, so it is fingerprint-neutral, and it is load-bearing for latency.

Accepted cost: fast dead-origin detection is lost. A half-open origin connection
lingers up to `IDLE_TIMEOUT` (300s, `lib.rs:20`) instead of resetting at 10s;
connection establishment remains bounded by `CONNECT_TIMEOUT` (10s, `lib.rs:19`).
Waiting minutes on a stalled peer is what a normal client does, so the
fingerprint fix and the correct behavior coincide.

## Error handling

Client-facing errors are unchanged. The 502s reach only the local client.

Sanitize and framing failures form a new error class. Behavior depends on timing:
on the first head, before any bytes have gone upstream, a 502 can still be
returned to the client. Mid-stream it cannot — a status line cannot be injected
into a relay already in progress — so the connection closes.

Every such failure logs at `warn` with the reason and target host, and increments
a new `rewrite_failures` counter on `ProxyStats` (`lib.rs:26-77`). Without that
counter, fail-closed behavior becomes silent connection drops and is very hard to
debug. Header bytes are logged at `debug` only, never `info`.

## Testing

Three layers, ascending in value.

**Unit — byte-exact, table-driven** over `sanitize_request_head`: default-port
stripping, non-default port retained, `Host` present-and-matching (must be a
zero-byte change), present-and-disagreeing, absent, `Proxy-Connection` rename,
`Proxy-Connection` dropped when `Connection` exists, `Proxy-Authorization`
removal, `Connection`-token hop-by-hop removal, casing preserved, order
preserved, empty path → `/`, query string preserved, HTTP/1.0.

**Framing — fed one byte at a time** to catch split-read bugs: `Content-Length`
bodies, chunked bodies, pipelined heads in a single read, `Upgrade`→`101`
switching to passthrough, `Upgrade`→declined continuing to parse. Plus the case
that motivated this architecture: **requests #2 and #3 on a reused connection
must also be rewritten.** Plus the fail-closed set: `TE`+`CL` together,
duplicate conflicting `CL`, oversized head, origin-form mid-stream.

**Golden byte-equality — the test of the actual goal.** A small in-test origin
server records the exact bytes it receives. The same request is issued twice,
once direct and once through the proxy, and the two recordings must be
byte-identical. This validates the guiding principle instead of testing the rules
back to themselves, so it catches leaks not enumerated above.

**One existing assertion inverts.** `tests/integration_tests.rs:61` asserts the
origin receives absolute form. That assertion flips and becomes the permanent
regression guard for this feature.

## Docs

Add a README section stating plainly what this does and does not hide: the proxy
no longer announces itself in the request bytes; the TLS fingerprint was always
the client's own; the egress IP is unchanged; TCP/IP stack matching is an
explicit non-goal.

While editing those paragraphs, correct the drift in the numbers being touched —
the README claims 64KB buffers, 10,000 connections, and a 1-hour idle timeout,
against actual values of 16KB (`lib.rs:17`), 1,000 (`lib.rs:18`), and 300s
(`lib.rs:20`).
