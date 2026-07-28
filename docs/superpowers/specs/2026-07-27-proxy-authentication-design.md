# Proxy Authentication — Design

Date: 2026-07-27
Status: Approved, ready for implementation planning

## Problem

`rust_proxy` binds `0.0.0.0:3129` with no access control of any kind. Anything
that can reach the port can use it as an open relay. The client address is read
once at `lib.rs:287` and used only for a `debug!` line; it is never compared or
filtered. SOCKS5 advertises "no authentication required" (`lib.rs:529-536`), and
`Proxy-Authorization` is discarded without ever being validated
(`http_rewrite.rs:317`).

Two deployment targets motivate the change:

1. **Local VM.** A work laptop proxies to a Windows VM on the same machine via
   `0.0.0.0:3129`. Same-host, low risk, but still unauthenticated on every
   interface.
2. **Router.** A future OpenWrt deployment where the proxy grants network
   access from off-box. Deployment topology is undecided, so the design assumes
   the hostile case.

## Threat model and its hard limit

The proxy has **no TLS library at all**, by deliberate project constraint — no
`rustls`, no `native-tls`, no `openssl`. Consequently any credential presented
to the proxy travels in cleartext on the path to the proxy. This cannot be
fixed inside the proxy without violating a core invariant.

The available protocol mechanisms are HTTP Basic (`Proxy-Authorization`) and
SOCKS5 RFC 1929. Both are cleartext. A custom challenge-response scheme was
rejected: no browser and no `HTTP_PROXY=http://user:pass@host:3129` consumer
can speak it, which makes it unusable for the actual clients.

Therefore the design is **a standard cleartext credential plus compensating
controls**, and the documentation must state the exposure plainly rather than
imply the credential is protected. Transport confidentiality is the operator's
responsibility (a WireGuard tunnel terminated on the router is the intended
pattern); brute-force resistance at scale is the firewall's responsibility.

## What this defends against

- An unauthenticated party on a reachable network using the proxy as an open
  relay.
- An unauthenticated party causing the proxy to open arbitrary outbound TCP
  connections.
- Connections from source addresses outside an operator-declared range.

## What this does not defend against

- Credential capture by anyone who can observe the client-to-proxy path.
- Replay of a captured credential.
- Credential disclosure to anyone who can read the credentials file.
- Distributed or high-volume brute force (delegated to the firewall).

## Decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Credential source | File, with env-var fallback | Keeps the password out of `ps`, Task Manager, init scripts, and shell history; identical on Windows and OpenWrt |
| Default posture | Auth required unless `--allow-anonymous` | Matches the project's documented fail-closed ethos; a typo cannot silently produce an open relay |
| Password at rest | Plaintext | The credential already crosses the wire in cleartext, so hashing at rest defends a strictly narrower threat; avoids a crypto dependency and a hash-generation mode |
| SOCKS5 | Authenticated via RFC 1929 | Otherwise SOCKS5 on the same port is a wide-open bypass around the HTTP gate |
| IP allowlist | In scope | Useful for the router deployment; cheap and orthogonal |
| Failure lockout | Out of scope | Requires shared mutable state, a cleanup path, and carries a memory-growth risk from spoofed source addresses, for modest gain over firewall rate limiting |

## Approach

Enforce at each protocol's natural granularity, with one shared pure verifier.
Three check sites:

1. `handle_http` (lib.rs:446), after the head is read, before any origin dial —
   covers CONNECT and the first plain-HTTP request, and can still write a 407.
2. `RequestStream::handle_head` (http_rewrite.rs:625), the single choke point
   through which every head passes — covers requests 2..n on a reused
   keep-alive connection.
3. `handle_socks5` (lib.rs:529) — RFC 1929, replacing the unconditional
   `[0x05, 0x00]`.

The first plain-HTTP head is verified twice (once at site 1, once at site 2).
This is intentional and cheap: site 1 is what prevents a pre-authentication
origin dial, and site 2 is what makes the check per-request.

### Approaches rejected

**A single check in `handle_client` after protocol detection.** One site, less
code, but it duplicates the head-reading loop `handle_http` already has and it
cannot see requests 2..n. A connection that authenticated once could then send
unauthenticated requests indefinitely — the exact keep-alive gotcha AGENTS.md
warns about.

**Fronting the proxy with squid or tinyproxy on OpenWrt.** Zero code, but an
upstream proxy injects its own headers, destroying the byte-exactness invariant
the project exists to protect.

## Configuration surface

| Flag / variable | Meaning |
| --- | --- |
| `--auth-file <PATH>` | Credentials file, `user:password` per line |
| `RUST_PROXY_AUTH=user:password` | Single-credential environment fallback |
| `--allow-anonymous` | Explicit opt-out of authentication |
| `--allow-from <CIDR>` | Repeatable source-address allowlist; empty means allow all |

### Credentials file format

- One `user:password` per line. Multiple lines mean multiple users.
- Lines whose first non-whitespace character is `#` are comments, and blank
  lines are ignored.
- A single trailing `\r` is stripped, so a file edited on Windows works.
- The line is split on the **first** colon only, so passwords may contain
  colons.
- Trailing whitespace in the password is **preserved** (only the single `\r` is
  removed), because a password may legitimately end in a space.
- An empty username is an error. An empty password is an error. A line with no
  colon is an error.
- A file that parses to zero valid entries is a startup error, never a silent
  fallback to no authentication.
- On Unix, warn if the file mode grants group or world read. Skipped on
  Windows.

### Precedence

`--auth-file` takes precedence. If `RUST_PROXY_AUTH` is also set, log a warning
that it is ignored. Never the reverse: a stale environment variable must not
silently override the file the operator just edited.

### Startup validation

Performed before `TcpListener::bind`, each failure exiting non-zero with a
message that names the fix:

- Credentials configured **and** `--allow-anonymous` → error, contradictory.
- No credentials **and** no `--allow-anonymous` → error naming all three
  resolutions (`--auth-file`, `RUST_PROXY_AUTH`, `--allow-anonymous`).
- Any `--allow-from` value that does not parse → error.

An allowlist is explicitly **not** a substitute for a credential. An operator
who wants only address filtering passes `--allow-anonymous --allow-from ...`,
making the choice visible in the command line.

## Architecture

A new `RuntimeConfig` carries per-connection policy:

```rust
pub struct RuntimeConfig {
    pub policy: RewritePolicy,
    pub auth: Option<Arc<Credentials>>,
    pub allow_from: Vec<Cidr>,   // empty = allow all
}
```

Passed as `Arc<RuntimeConfig>`, replacing the bare `policy: RewritePolicy`
parameter on `handle_client`. `auth` is an inner `Arc` so `RequestStream` can
hold a cheap clone rather than copying the credential set per connection.

The parameter change propagates to `handle_http`, to `connect_and_tunnel` via
the `Upstream::Http` variant (which currently carries `policy` and now carries
the config), and to `handle_socks5`, which today receives no policy at all and
must now receive the config. Two test call sites are affected
(`relay_tests.rs:59`, `golden_equality_tests.rs:72`).

A new module `src/auth.rs` holds pure logic only: `Credentials`, `Cidr`, Basic
parsing, constant-time comparison, and prefix matching. File and environment
loading lives with `Args` in `lib.rs`, mirroring the existing
`Args::rewrite_policy()` pattern. This keeps `auth.rs` free of I/O so
`http_rewrite.rs` may depend on it without violating its no-I/O,
no-logging rule.

`RequestStream::new` gains an `Option<Arc<Credentials>>` parameter alongside
`policy` and `max_head`.

### Error channel

`RequestStream::push` and `handle_head` change from
`Result<(), RewriteAnomaly>` to `Result<(), PushError>`:

```rust
pub enum PushError {
    Anomaly(RewriteAnomaly),
    Unauthorized,
}
```

Reusing `RewriteAnomaly` with a new variant was rejected: an authentication
failure is not a rewrite anomaly, and AGENTS.md scopes that taxonomy to the
rewriter. The type change is mechanical and compiler-checked across
`lib.rs:371`, `lib.rs:779`, and the `drive` helper in `http_rewrite_tests.rs`.

Critically, `PushError::Unauthorized` never routes through `on_anomaly`, so it
cannot reach the `--rewrite-fallback` branch at all. Auth is non-bypassable
structurally, not by a policy check.

## Enforcement behavior

### Address allowlist

In `handle_client`, immediately after `peer_addr()` (lib.rs:287) and before the
protocol-detection peek. A disallowed source increments `acl_rejections`, logs
at `warn`, and the connection closes with **no response bytes written**.
Silence is correct: a scanner should not learn that a proxy is listening.

### HTTP and CONNECT

In `handle_http` after the head is read (lib.rs:446) and before any origin
dial. Locate `Proxy-Authorization`, require the `Basic` scheme
(case-insensitive), base64-decode, then compare the whole decoded
`user:password` byte string in constant time against each configured
credential's joined form.

Not splitting the decoded value is equivalent to splitting it — stored
usernames cannot contain a colon, because the file format splits on the first
one — and it avoids a parse step on attacker-controlled bytes. The SOCKS5 path,
which receives username and password as separate length-prefixed fields, joins
them the same way and additionally rejects any presented username containing a
colon, so `user="a:b", pass="c"` cannot be confused with a stored
`("a", "b:c")`.

**More than one `Proxy-Authorization` header is a rejection**, not a
first-wins or last-wins choice. Two conflicting credentials in one head is the
same class of ambiguity as conflicting `Content-Length`, and this project
resolves ambiguity by failing closed.

On failure, write exactly these bytes and nothing else:

```
HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="rust_proxy"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n
```

then close. `Connection: close` removes any question about stream state after a
rejection; clients reconnect and retry with credentials, which is ordinary
Basic behavior. The response carries no `Server` and no `Date`, matching the
existing 502 shape at `lib.rs:491`.

Identical treatment for CONNECT and absolute-form requests. Checking here
rather than in `connect_and_tunnel` is what prevents an unauthenticated client
from making the proxy dial an arbitrary host.

### Keep-alive requests 2..n

In `RequestStream::handle_head`, before the `framing_of` call. Failure returns
`Err(PushError::Unauthorized)` and the connection closes with no 407, matching
the existing reasoning at `lib.rs:376-379`: mid-stream failures cannot be
reported to the client, so the relay path just closes. A compliant client sends
`Proxy-Authorization` on every request once it knows the realm, so a mid-stream
absence is anomalous.

### SOCKS5

In `handle_socks5` at `lib.rs:529`. With credentials configured, `0x00` is
never offered:

- The client's method list must contain `0x02`; otherwise take the existing
  `[0x05, 0xFF]` path and close.
- Reply `[0x05, 0x02]`, then read the RFC 1929 sub-negotiation:
  `VER ULEN uname PLEN passwd`, where **`VER` is `0x01`, not `0x05`** — a
  frequent implementation bug.
- Success replies `[0x01, 0x00]` and proceeds to the request read at
  `lib.rs:540`. Failure replies `[0x01, 0x01]` and closes.

With `--allow-anonymous`, SOCKS5 behavior is byte-for-byte what it is today.

## Interaction with the privacy invariant

The change lands without touching the five rewrite rules:

- Rule 4 already drops `Proxy-Authorization` unconditionally
  (`http_rewrite.rs:317`), so the credential never reaches the origin and an
  authenticated proxied request stays byte-identical to a direct one.
- No new header is emitted on the origin-facing wire.
- The 407 is client-facing only and carries no `Server` or `Date`.
- SOCKS5 remains a blind relay once the handshake completes.
- Auth is never bypassable by `--rewrite-fallback`, structurally.

## Statistics and logging

Two counters on `ProxyStats`:

- `auth_failures: AtomicU64` — missing or invalid credential.
- `acl_rejections: AtomicU64` — source address outside the allowlist.

Both are printed by `log_stats` only when non-zero, matching the anomaly
block's style at `lib.rs:150-159`. A recurring `warn!` banner is emitted when
`--allow-anonymous` is active, mirroring the fallback banner at
`lib.rs:143-146`; an open relay deserves to keep nagging.

**No part of a credential is ever logged, at any level, including the
username.** Operators paste passwords into username fields, and a debug-level
leak into a log file is a real failure mode. Rejection logs carry the source
address and a reason code only.

## Dependencies

- `base64 = "0.22"` — hand-rolling a decoder that correctly *rejects*
  malformed input is a known bug source, and this decoder is security-relevant.
- Constant-time comparison: roughly six lines, XOR-accumulate, no `subtle`
  dependency. Documented caveat: it early-returns on length mismatch, so
  password length is theoretically observable via timing. Behind TCP and a full
  head parse this is not a practically exploitable channel, but it is stated
  rather than hidden.
- CIDR handling: hand-rolled on `std::net::IpAddr`. Parse `addr/prefix`,
  mask-compare as `u32` or `u128`, and treat a bare address as `/32` or `/128`.
  Roughly forty lines, no dependency, and no build script — which keeps a
  future OpenWrt cross-compile straightforward.
- No hashing dependency, per the plaintext-at-rest decision.

## Testing

| Layer | What it proves |
| --- | --- |
| New `tests/auth_tests.rs` | Basic parsing: wrong scheme, case-insensitive `basic`, invalid base64, decoded value with no colon, empty username, non-UTF-8 decoded bytes, oversized header. File parsing: CRLF line endings, comments, blank lines, colon inside password, empty file, line without a colon. CIDR: v4 and v6, `/0`, `/32`, `/128`, boundary addresses, malformed input. Constant-time comparison correctness. |
| `http_rewrite_tests.rs` | A keep-alive second request without credentials is rejected, fed one byte at a time to catch split-read bugs; and rejected under **both** `FailClosed` and `Fallback`, the same shape as the existing `FramingConflict` test. |
| `relay_tests.rs` | Unauthenticated request: the origin receives zero bytes. Authenticated request: the origin never sees `Proxy-Authorization`. |
| `golden_equality_tests.rs` | An authenticated proxied request is still byte-identical to the same request sent directly. Byte-exact comparison, never `from_utf8_lossy`. |
| SOCKS5, in-process | `0x02` negotiation happy path; wrong password yields `[0x01, 0x01]`; a method list without `0x02` yields `[0x05, 0xFF]`. |
| Allowlist | A connection from a disallowed source closes with no bytes written. |
| Startup validation | Contradictory and missing-credential flag combinations are rejected, via `Args::try_parse_from` plus the validation function. |
| Existing subprocess suites | `integration_tests.rs`, `statistics_tests.rs`, and `logging_tests.rs` gain `--allow-anonymous` in their argument vectors. |

Verification commands, run from `rust_proxy/`:

```
cargo build
cargo test
cargo clippy -p rust_proxy --lib -- -D warnings
```

Note that `cargo clippy --all-targets -- -D warnings` fails on roughly 25
pre-existing errors in the test files and 4 in `src/windows.rs`. Those predate
this work and are out of scope.

## Documentation changes

- `README.md`: a new Authentication section. The "SOCKS5 with no
  authentication" claim at `README.md:219` becomes false and must change. The
  "what this does not hide" section gains a plain statement that Basic and
  RFC 1929 credentials cross the wire in cleartext, and that the port should be
  tunneled rather than exposed to the internet.
- `AGENTS.md`: the three enforcement points, and the rule that authentication
  is never bypassable by `--rewrite-fallback`.
- Deployment notes for both targets: a credentials file on `G:\` for the
  Windows VM, and `/etc/rust_proxy/auth` plus a procd init script for OpenWrt.

## Non-goals

- Building and packaging for OpenWrt (musl target selection, procd
  integration, opkg). The dependency choices keep this feasible; the work is
  separate.
- Terminating or inspecting TLS. Unchanged project constraint.
- Protecting the credential in transit. Delegated to the operator's tunnel.
- Per-user authorization rules, quotas, or destination allowlists.
- Digest or NTLM proxy authentication.
- Brute-force lockout or per-source rate limiting.
