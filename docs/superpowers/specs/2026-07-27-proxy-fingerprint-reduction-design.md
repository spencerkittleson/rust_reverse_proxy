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
- Raising the request head cap from 8KB to 64KB, which eliminates the most likely
  source of spurious rewrite anomalies.
- Reason-keyed anomaly counters surfaced in the existing 180s health report.
- A `--rewrite-fallback` flag (off by default) trading privacy for availability
  when the rewriter mishandles a client.

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
   forwardable tokens — exactly `keep-alive`, `close`, and `upgrade`; if none
   survive, drop the `Connection` line. Reduce only — never invent a token the
   client did not send.

   `upgrade` is deliberately forwardable even though RFC 7230 classes it
   hop-by-hop. Dropping it, and with it the `Upgrade` header it names, would make
   the `Upgrade` passthrough described below unreachable. A proxy that intends to
   relay an upgrade must forward the offer.

### Codified prohibitions

Written as rules so a later change does not helpfully reintroduce them: never
emit `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Proxy-Agent`, `Server`,
or `Date`. Never reorder headers. Never alter field-name casing. Never adjust
whitespace around `:`. Never fold or unfold `obs-fold` continuation lines —
headers containing `obs-fold` are passed through byte-for-byte. Since no modern
client emits `obs-fold`, byte-identity with a direct client is unaffected either
way; passing it through is simply the least-touch option. The sole exception is
`obs-fold` inside one of the five headers rules 1-5 must modify, which is handled
as an anomaly below.

## Message framing

Body framing, in precedence order:

1. Final `Transfer-Encoding` of `chunked` → parse chunk framing (size lines,
   terminal zero-chunk, trailers).
2. `Content-Length: N` → stream exactly N bytes.
3. Neither → no body; the next head begins immediately.

Pipelined heads arriving in a single read are handled by looping until the buffer
drains.

**The head size cap rises from 8192 (`lib.rs:248`) to 65536.** 8KB is the single
likeliest cause of spurious anomalies in practice — browsers with large cookie
jars and `Authorization: Bearer` tokens exceed it routinely. Raising the cap is
the actual fix for that class; no fallback behavior is needed to accommodate it.

### Anomaly handling

Two response modes, selected by the `--rewrite-fallback` flag.

**Default (flag absent): fail closed.** Terminate the connection rather than
forward unrewritten bytes, because forwarding unrewritten bytes *is* the leak.
Verbatim fallback is a retroactive privacy failure: once it fires, the
absolute-form request line has already reached the origin, and the periodic health
report can only tell you afterward. Failing closed surfaces the same information
immediately, through the broken request.

**With `--rewrite-fallback`: forward verbatim and count it.** For diagnosing a
client that the rewriter mishandles, at the cost of leaking on each occurrence.
The health report displays a persistent banner while the flag is active so the
trade is never silent.

When fallback fires, the connection also switches permanently to `Passthrough`.
The parse that just failed is the same parse that would locate the next request
boundary, so continuing to parse after forwarding an unrewritten head would be
guesswork. One leak per connection, not a desynchronized stream.

The residual anomaly set, after the head cap increase:

| Anomaly | Fallback eligible |
| --- | --- |
| `head_too_large` (>64KB) | yes |
| `obs_fold_in_rewritten_header` | yes |
| `unparseable` — not recognizable as an HTTP/1.x request | yes |
| `framing_conflict` — `TE: chunked` + `Content-Length`, or duplicate conflicting `Content-Length` | **no, never** |

`framing_conflict` fails closed regardless of the flag. It is a request-smuggling
vector, and forwarding it verbatim would make the proxy a smuggling gadget aimed
at whatever origin it is talking to. That refusal rests on security grounds
independent of privacy, so it is not the user's trade to make.

**A mid-stream request already in origin form is not an anomaly.** Forwarding it
leaks nothing, because origin form is exactly what rule 1 would produce. It takes
rules 2-5 and nothing else, and is a fully supported input.

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

When an anomaly fails closed, behavior depends on timing: on the first head,
before any bytes have gone upstream, a 502 can still be returned to the client.
Mid-stream it cannot — a status line cannot be injected into a relay already in
progress — so the connection closes.

Every anomaly, whether it failed closed or fell back, logs at `warn` with its
reason and target host and increments its reason counter. Header bytes are logged
at `debug` only, never `info`.

## Observability

Anomalies are useless unless visible, and a silently-dropped connection is
miserable to debug. Both modes therefore feed the same counters.

`ProxyStats` (`lib.rs:26-77`) gains a `[AtomicU64; N]` array indexed by a
`RewriteAnomaly` enum, plus a `requests_sanitized` counter. Reason-keyed rather
than a single total, so the report says *what* went wrong; array-indexed rather
than named fields, so adding a reason is one line and the report iterates. Each
reason also retains the last offending host in a small lock (`Mutex<Option<String>>`
or equivalent) — one string per reason, written only on anomaly, so it costs
nothing on the hot path.

`log_stats` (`lib.rs:57-76`, fired every 180s from `main.rs:72`) gains a rewrite
block. Only non-zero reasons print, so a clean run stays a single line:

```
   Rewrite: 1,234 sanitized, 0 anomalies
```

A run with problems itemizes them:

```
   Rewrite: 1,230 sanitized, 4 anomalies
      head_too_large: 3 (last: api.example.com)
      framing_conflict: 1 (last: legacy.internal)
```

While `--rewrite-fallback` is active the block carries a persistent banner, so an
ongoing privacy trade can never be forgotten about:

```
   Rewrite: 1,230 sanitized, 4 anomalies
      ⚠ --rewrite-fallback ACTIVE — 3 requests forwarded unrewritten (proxy visible to origin)
      head_too_large: 3 (last: api.example.com)
```

The banner counts only fallback-eligible anomalies that actually forwarded, since
`framing_conflict` fails closed regardless and leaks nothing.

## CLI surface

One new flag on `Args` (`lib.rs:79-93`), joining `--host`, `--port`, and
`--log-level`:

```
--rewrite-fallback    Forward requests verbatim when rewriting fails, instead of
                      closing the connection. Leaks proxy presence to the origin
                      for each affected request. Off by default.
```

The help text names the cost explicitly. A flag whose downside is discoverable
only by reading the design doc is a trap.

## Testing

Four layers, ascending in value.

**Unit — byte-exact, table-driven** over `sanitize_request_head`: default-port
stripping, non-default port retained, `Host` present-and-matching (must be a
zero-byte change), present-and-disagreeing, absent, `Proxy-Connection` rename,
`Proxy-Connection` dropped when `Connection` exists, `Proxy-Authorization`
removal, `Connection`-token hop-by-hop removal, casing preserved, order
preserved, empty path → `/`, query string preserved, HTTP/1.0, `obs-fold` in an
untouched header passed through byte-for-byte, and a mid-stream origin-form
request taking rules 2-5 only.

**Framing — fed one byte at a time** to catch split-read bugs: `Content-Length`
bodies, chunked bodies, pipelined heads in a single read, `Upgrade`→`101`
switching to passthrough, `Upgrade`→declined continuing to parse. Plus the case
that motivated this architecture: **requests #2 and #3 on a reused connection
must also be rewritten.**

**Anomaly behavior — each reason tested in both modes.** Default mode: every
reason closes the connection and increments its counter. With
`--rewrite-fallback`: `head_too_large`, `obs_fold_in_rewritten_header`, and
`unparseable` forward verbatim and increment; `framing_conflict` **still closes**
— that assertion is the guard against the smuggling hole, so it is the single most
important test in this layer. Reasons cover heads over 64KB, `TE`+`CL` together,
duplicate conflicting `CL`, and `obs-fold` inside a rewritten header.

**Golden byte-equality — the test of the actual goal.** A small in-test origin
server records the exact bytes it receives. The same request is issued twice,
once direct and once through the proxy, and the two recordings must be
byte-identical. This validates the guiding principle instead of testing the rules
back to themselves, so it catches leaks not enumerated above.

**No existing assertion inverts, and that is the problem.** An earlier draft of
this spec claimed `tests/integration_tests.rs:61` asserts the origin receives
absolute form. It does not — line 61 is the *client's* request **to** the proxy,
which correctly remains absolute form forever, and `unit_tests.rs:62` likewise
asserts a client-side parse. The echo server at `integration_tests.rs:36-45`
reads the request into a buffer and discards it. **No current test inspects what
the origin receives**, which is precisely why this leak survived. The golden
byte-equality harness is therefore new coverage, not a modified assertion, and it
is the permanent regression guard for this feature.

## Docs

Add a README section stating plainly what this does and does not hide: the proxy
no longer announces itself in the request bytes; the TLS fingerprint was always
the client's own; the egress IP is unchanged; TCP/IP stack matching is an
explicit non-goal. Document `--rewrite-fallback` alongside it, including the
leak it accepts.

While editing those paragraphs, correct the drift in the numbers being touched —
the README claims 64KB buffers, 10,000 connections, and a 1-hour idle timeout,
against actual values of 16KB (`lib.rs:17`), 1,000 (`lib.rs:18`), and 300s
(`lib.rs:20`).
