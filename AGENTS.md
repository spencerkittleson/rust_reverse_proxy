# AGENTS.md — rust_reverse_proxy

Guidance for coding agents working in this repository.

## What this project actually is

Despite the repo name, this is a **forward proxy**, not a reverse proxy. It
listens on one port and auto-detects the protocol from the first byte:

- `0x05` → SOCKS5 (RFC 1928, CONNECT only; RFC 1929 username/password required
  unless `--allow-anonymous`)
- anything else → HTTP (absolute-form requests, or `CONNECT` for HTTPS)

It is a **pure TCP relay with no TLS library at all** — no `rustls`, no
`native-tls`, no `openssl`. HTTPS is passed through opaquely via `CONNECT`, never
terminated. If a task seems to require inspecting TLS or MITM, re-read the spec
before adding a TLS dependency; `TODO_CERTIFICATE_PROXY.md` describes an
unimplemented aspiration, not current behavior.

Layout (single crate, no workspace — the package is in the `rust_proxy/`
subdirectory, so **run all cargo commands from `rust_proxy/`**):

| File | Responsibility |
| --- | --- |
| `rust_proxy/src/http_rewrite.rs` | Pure-logic request rewriter: rules 1-5, `RequestStream` streaming state machine, framing, anomaly taxonomy. **Zero I/O, no logging, no `ProxyStats`.** |
| `rust_proxy/src/lib.rs` | All I/O: `ProxyStats`, `Args`, `handle_client`/`handle_http`/`handle_socks5`, `connect_and_tunnel`, `tunnel_fast`, `copy_loop`, socket options. |
| `rust_proxy/src/main.rs` | Entry point, CLI, stats task, graceful drain. |
| `rust_proxy/src/windows.rs` | Windows-only host setup (firewall, network profile, power). |

## The invariant that governs this codebase

**The bytes an origin server receives must be byte-identical to what the client
would have sent connecting directly.**

This is a privacy property, and it constrains changes in a non-obvious way:
*canonicalizing is a bug*. Do not normalize header casing, sort headers, collapse
whitespace, or reflow anything a rewrite rule does not explicitly name — tidy
headers are themselves a fingerprint, because no real client emits them.

Only five rewrites are permitted, applied in order (rule 5 operates on the
`Connection` header as rule 3 leaves it):

1. Absolute-form request-target → origin-form.
2. `Host` takes the authority from the request-target.
3. `Proxy-Connection` renamed in place to `Connection` (dropped if a
   `Connection` header already exists).
4. `Proxy-Authorization` dropped unconditionally.
5. RFC 7230 §6.1 hop-by-hop cleanup; `Connection` reduced to its forwardable
   tokens.

Forwardable `Connection` tokens are exactly `keep-alive`, `close`, `upgrade`.
`upgrade` is deliberately included even though RFC 7230 classes it hop-by-hop —
dropping it would make the `Upgrade`/`101` passthrough unreachable.

**Never emit** `Via`, `Forwarded`, `X-Forwarded-For`, `X-Real-IP`,
`Proxy-Agent`, `Server`, or `Date`.

## Rules that are security properties, not preferences

- **`RewriteAnomaly::FramingConflict` always fails closed**, regardless of
  `--rewrite-fallback`. `Transfer-Encoding: chunked` together with
  `Content-Length`, or duplicate conflicting `Content-Length`, is a
  request-smuggling vector; forwarding it verbatim would make this proxy a
  smuggling gadget aimed at the origin. This is not the operator's trade to make.
  There is a test asserting this under *both* policies — if you touch anomaly
  handling, that test is the one that matters.
- **Fail closed is the default.** Forwarding an unrewritten request *is* the leak
  the project exists to prevent. `--rewrite-fallback` is an opt-in escape hatch
  and switches the connection to `Passthrough` after it fires (one leak per
  connection, never a desynchronized stream).
- **Bound anything you buffer from the network.** Incomplete request heads,
  chunk-size lines, and trailer blocks are all capped at `MAX_REQUEST_HEAD_SIZE`
  (65536). An unbounded parse buffer is a remotely-triggerable OOM; this was a
  real bug found in review, so treat new buffering as suspect.
- **Only the client-facing socket is tuned.** `configure_client_socket(&src)`
  takes one socket by design — the origin-facing socket inherits OS defaults,
  because non-default keepalive/user-timeout values are observable from the
  origin side. In `tunnel_fast`, `src` is the client and `dst` is the origin.
- **SOCKS5 and CONNECT stay blind relays.** No rewriting, no parsing.

## Authentication is enforced in three places

Auth is checked at each protocol's natural granularity. If you add a code path
that forwards bytes, confirm it passes one of these:

1. `handle_http` — after the head is read, **before any origin dial**. Covers
   CONNECT and the first plain-HTTP request, and is the only site that can
   still write a 407. Checking later would let an unauthenticated client make
   the proxy open arbitrary outbound connections.
2. `RequestStream::handle_head` — every head, so requests 2..n on a reused
   keep-alive connection are re-checked. A one-shot check at connection setup
   is the same class of bug as a one-shot rewrite: it leaks on the common case.
3. `handle_socks5` — RFC 1929. With a credential configured, method `0x00` is
   never offered, or SOCKS5 becomes a bypass around the HTTP gate on the same
   port.

`--allow-from` is checked earliest of all, in `handle_client`, before a byte is
read and before the connection counters — but it is a source-address filter,
not a credential check, and is not a substitute for one.

**`PushError::Unauthorized` must never route through `on_anomaly`.** That is
where `--rewrite-fallback` decides to forward verbatim. The flag buys a
rewrite leak; it must never buy an access-control bypass. There is a test
asserting rejection under both policies — if you touch the error plumbing,
that is the one that matters. The one narrow, accepted exception is the
reverse direction: once a connection has already authenticated and
`--rewrite-fallback` later latches it into `State::Passthrough` for an
unrelated rewrite anomaly, that passthrough state stops re-checking the
credential for the rest of the connection (see the `auth` field doc on
`RequestStream` in `http_rewrite.rs`). That is documented, requires the opt-in
flag plus a connection that already authenticated, and never lets an
unauthenticated request through — treat it as settled unless the review
record says otherwise.

Auth is mandatory: startup fails (exit status 2) without either a credential
or `--allow-anonymous`. Every subprocess test therefore passes
`--allow-anonymous`.

Never log any part of a credential, including the username. `AuthResult::reason`
exists to give the log a fixed, credential-free string.

## Explicit non-goals

Do not "improve" these; they are deliberate and documented in the spec:

- Matching the host's TCP/IP stack fingerprint (TTL/MSS/window scaling).
- Hiding the egress IP — it is unchanged with or without the proxy.
- Changing the TLS fingerprint — it is already the client's own, since CONNECT
  is never terminated.
- Making traffic opaque to a corporate VPN.

## Build, test, verify

```bash
cd rust_proxy
cargo build
cargo test                    # full suite; completes in well under a minute
cargo clippy -p rust_proxy --lib -- -D warnings
```

- **`cargo clippy --all-targets -- -D warnings` fails on ~25 PRE-EXISTING errors**
  in `tests/integration_tests.rs`, `tests/logging_tests.rs`,
  `tests/unit_tests.rs`, and `tests/statistics_tests.rs` (mostly
  `needless_borrow` on `.args(&[...])`), plus 4 in `src/windows.rs`. These
  predate current work and are out of scope — do not "fix" them as a side effect
  of an unrelated task, and do not treat them as your regression. Verify against
  a clean worktree before blaming your change.
- Cross-compile for Windows with the **gnu** target (no MSVC needed):
  `cargo build --release --target x86_64-pc-windows-gnu`. The `#[cfg(windows)]`
  code in `lib.rs`/`windows.rs` is only type-checked under a Windows target, so
  run `cargo check --target x86_64-pc-windows-gnu` after touching it.

### Test layers, and which one to trust

| File | What it proves |
| --- | --- |
| `tests/http_rewrite_tests.rs` | Byte-exact unit tests of the rules and the state machine, fed one byte at a time to catch split-read bugs. |
| `tests/relay_tests.rs` | Real proxy + recording origin; asserts on bytes the origin actually received. |
| `tests/golden_equality_tests.rs` | **The test of the goal**: same request issued direct vs. proxied, both recordings must be byte-identical. Catches leaks nobody enumerated. |

`assert_sanitized` and the golden comparisons must stay **byte-exact**. Comparing
`String::from_utf8_lossy` values was a real bug: non-UTF-8 divergence collapses
to U+FFFD on both sides and compares equal, blinding the guard precisely where
byte-identity matters.

## Gotchas that have cost real time

- **`handle_http`'s first head and the streaming path share one `RequestStream`.**
  A one-shot rewrite at connection setup leaks on every reused keep-alive
  connection, which is the common case. If you add a code path that forwards a
  head, confirm it goes through the stream — the raw head must never reach
  `remote.write_all`.
- **`split_head` splits on CRLF only.** Bare-LF heads are treated as
  `Unparseable` by design. Do not "fix" the splitter; malformed input should fail
  closed.
- **Windows: the setup prompt is a modal `MessageBoxW`** that auto-declines after
  5 seconds so a headless launch cannot hang. Do not remove that timeout.
- **Windows: `build_elevated_script` currently emits invalid PowerShell**
  (`Missing statement block after if ( condition )`), so the elevated setup path
  fails on every startup. Known bug; fix it deliberately rather than being
  surprised by the log noise.
- **A non-elevated Windows start takes ~17s** — 5s prompt timeout plus ~11s of
  elevation-requiring setup being attempted anyway. Known; the proxy does come up.

## Manual testing on the Windows VM

See the `win11-vm` skill for credentials and connection details. Condensed:

```bash
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/rust_proxy.exe ~/Work/forticlient_certs/  # == G:\ on the VM
```

- The host directory `~/Work/forticlient_certs/` is mounted as `G:\` on the VM,
  and is the deployment channel — **SCP/SFTP are broken** there because the
  OpenSSH default shell is PowerShell.
- **Write multi-line scripts on the host into that shared folder, then run them
  on the VM.** Piping a script via `powershell -Command -` over stdin mangles
  here-strings and nested quoting — it behaves as if typed interactively. This
  wastes a lot of time if you don't know it.
- **Windows OpenSSH kills the session's process tree on disconnect**, so a proxy
  backgrounded from an SSH command dies when you log out. Run the whole test
  inside one SSH session, or use a scheduled task, or have the human start it
  interactively.
- To test non-elevated behavior from an (elevated) SSH session, de-elevate with
  `runas /trustlevel:0x20000 "..."`.
- The guest **cannot** reach a listener on the host at `10.0.2.2` (actively
  refused), so put the test origin *on the guest* and drive it from there.

## Docs are load-bearing

`README.md` has repeatedly drifted from the constants in `lib.rs` (it once
claimed 64KB buffers, 10,000 connections, and a 1-hour idle timeout against
actual values of 16KB, 1,000, and 300s). If you change a constant, grep the
README for the old number. The README's "what this does not hide" section is a
privacy claim — keep it honest and do not let it drift into implying anonymity.

Design docs live in `docs/superpowers/specs/` and `docs/superpowers/plans/`.
