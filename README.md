# zero-trust-server

A zero-trust HTTP/1.1 server written in Rust — **standard library only** for the
HTTP stack, **rustls** for TLS 1.3. No framework, no async runtime, no web
server dependency. It is the software that serves [mhebert.dev](https://mhebert.dev).

## What it is

Every request to the site passes a proof-of-work gate before one byte of
content is served: the server issues a SHA-256 challenge, the visitor's
browser solves it (compiled to WASM), and only then is a signed session cookie
issued. Public pre-gate endpoints are the challenge assets, `/pow/verify`,
`/health`, `/robots.txt`, `/.well-known/security.txt`, `/transparency` (what
the server records), and the operator dashboard at `/admin` and
`/admin/login`, which carry their own credential instead of a visitor
session.

- HTTP/1.1 parsed and served from raw TCP sockets — parser, router, headers,
  and concurrency all hand-rolled (`src/http.rs`, `src/router.rs`)
- TLS 1.3 only, via rustls — never OpenSSL (`src/tls.rs`)
- SHA-256 proof-of-work gate with a browser-side WASM solver (see
  [`WASM_BUILD.md`](WASM_BUILD.md) for provenance)
- Session cookies: HMAC-SHA256-signed, `HttpOnly`, `Secure`, `SameSite=Strict`
- An operator dashboard at `/admin`, behind its own signed cookie and a
  password gate, showing in-process request, solve-time, session, and uptime
  metrics. No database and no external service feeds it
- A public `/transparency` page that states what the server records and what
  it never does, linked from the footer of every page including the gate
- Full security-header suite on every response: CSP, HSTS (preload),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, COOP, COEP, CORP
- Concurrency bounded by a 128-permit semaphore across both listeners;
  saturation answered inline (clean 503 on the plaintext port, prompt drop on
  the TLS port) instead of unbounded threads
- 5s read and write timeouts on every socket
- Structured TAB-delimited audit line for every request: timestamp, listener,
  peer, method, path, status, session presence, latency, proof-of-work solve
  time, and the request's count within its session

No `unsafe` anywhere in the server code.

## Layout

```
src/
  main.rs         entry point; concurrency bound; env config
  http.rs         HTTP/1.1 parser + response serializer
  router.rs       middleware chain: public → session gate → dispatch → headers
  tls.rs          rustls server config
  redirect.rs     plaintext :80 listener — 301 to HTTPS + ACME HTTP-01 webroot
  semaphore.rs    128-permit bound
  middleware/     pow (challenge verify), session (cookies), admin (dashboard
                  auth), headers (suite)
  handlers/       admin (dashboard pages), challenge (gate page),
                  content (the pages, incl. transparency)
  metrics.rs      in-process dashboard counters
  audit.rs        structured request log
static/           post-gate pages + challenge assets (embedded at build time)
scripts/          Playwright capture tooling, WASM solve-time harness
```

The five portfolio pages and the `/transparency` page are
`include_str!`-embedded into the binary; the challenge assets
(`static/pow_challenge.{js,wasm}`) are byte-identical build output of the
[`portfolio-wasm`](https://github.com/mhebert-security/portfolio-wasm) crate.

## Deployment

Runs on NixOS on a Hetzner VPS (config in
[`site-infrastructure`](https://github.com/mhebert-security/site-infrastructure)):
systemd unit under an unprivileged user, nftables `REDIRECT` of 443→8443 and
80→8080, Let's Encrypt certificates via the NixOS `security.acme` module, and
three secrets (`SESSION_SECRET`, `ZTS_ADMIN_SECRET`, `ZTS_ADMIN_PASSWORD`)
supplied only through a root-only `EnvironmentFile` on the host. The admin
secrets are required at startup, so they must be placed before a build that
needs them is started (see the unit comment in `configuration.nix`).

`deploy.sh` cross-compiles a `--release` musl binary and pushes it to the host
with the limited `deploy` user.

## Design intent

The site is the demonstration: a proof-of-work challenge wall in front of a
hand-built HTTP server is a deliberately unusual way to serve a portfolio,
because the point is that the software carrying your data should be small
enough to trust.
