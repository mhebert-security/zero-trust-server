use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod audit;
mod crypto;
mod metrics;
mod tls;
mod http;
mod router;
mod redirect;
mod semaphore;
mod middleware {
    pub mod admin;
    pub mod headers;
    pub mod pow;
    pub mod session;
}
mod handlers {
    pub mod admin;
    pub mod challenge;
    pub mod content;
}

/// Maximum number of concurrent connections handled at once.
/// Every accepted socket is handled on its own OS thread; without a bound
/// an attacker who opens N sockets costs N threads (memory + scheduler
/// pressure). The accept loop holds a permit from this semaphore per
/// connection, so at most `MAX_CONNECTIONS` threads ever run. Further
/// connections are rejected inline (see `reject_saturated_*`) rather than
/// spawning unbounded threads.
/// → DESIGN.md: bounded concurrency
const MAX_CONNECTIONS: usize = 128;

/// Read timeout applied to every accepted socket before TLS is layered on.
/// A slow-loris client that dribbles bytes slower than this between reads is
/// dropped instead of holding a thread open forever.
/// → DESIGN.md: 5-second read timeout bounds slow-loris.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Write timeout applied to every accepted socket, symmetric to `READ_TIMEOUT`.
/// A client that sends a request and then stops reading must not pin a worker
/// thread on a blocked `write_tls` forever: rustls writes through the
/// underlying socket, so the socket write timeout applies. Without it one
/// client could hold one of the 128 slots open indefinitely by never draining
/// its receive buffer.
/// → GitHub issue: write timeout on `TlsStream` (symmetric to read timeout).
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    // Validate required environment variables at startup.
    // Fail fast with a clear error rather than silently misconfiguring.
    let _session_secret = env_or_fail(
        "SESSION_SECRET",
        "The server cannot issue or verify session cookies.",
    );
    // The operator dashboard at /admin has its own two secrets, required like
    // SESSION_SECRET: a signing key for the zts-admin cookie and the password
    // that mints it. An admin surface that silently accepted no password, or
    // signed cookies with a missing key, would be worse than none.
    let _admin_secret = env_or_fail(
        "ZTS_ADMIN_SECRET",
        "ZTS_ADMIN_SECRET signs the zts-admin cookie that opens /admin.",
    );
    let _admin_password = env_or_fail(
        "ZTS_ADMIN_PASSWORD",
        "ZTS_ADMIN_PASSWORD is the password that opens /admin/login.",
    );
    let cert_path = env_or_fail(
        "CERT_PATH",
        "Point CERT_PATH at the PEM certificate chain.",
    );
    let key_path = env_or_fail(
        "KEY_PATH",
        "Point KEY_PATH at the PEM private key.",
    );

    // Optional listen addresses. Defaults match the original root-run
    // deployment (bind 443/80 directly). The NixOS service runs
    // unprivileged and overrides these to 8443/8080 with nftables
    // REDIRECTing 443→8443 and 80→8080 (→ GitHub issue #1).
    let tls_listen =
        std::env::var("TLS_LISTEN").unwrap_or_else(|_| "0.0.0.0:443".into());
    let http_listen =
        std::env::var("HTTP_LISTEN").unwrap_or_else(|_| "0.0.0.0:80".into());

    // Fallback hostname used by the HTTP→HTTPS redirect when a request
    // carries no usable Host header.
    let public_host = std::env::var("PUBLIC_HOST")
        .unwrap_or_else(|_| "mhebert.dev".into());

    // Optional directory served under /.well-known/acme-challenge/ by the
    // HTTP listener so ACME HTTP-01 validation can reach this server (which
    // is not nginx). Everything else on port 80 is 301-redirected.
    let acme_webroot = std::env::var("ACME_WEBROOT")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    // Load TLS config once at startup.
    let tls_config = tls::load_config(&cert_path, &key_path);

    // Start the process-global metrics clock at startup, so the uptime shown
    // on /admin counts from process start rather than from the first request.
    metrics::init_at_startup();

    // Bound total concurrency across BOTH listeners.
    let semaphore = Arc::new(semaphore::Semaphore::new(MAX_CONNECTIONS));

    let tls_listener = TcpListener::bind(&tls_listen)
        .unwrap_or_else(|e| panic!("Failed to bind TLS listener on {tls_listen}: {e}"));
    println!("Zero-trust server (TLS) listening on {tls_listen}");

    let http_listener = match TcpListener::bind(&http_listen) {
        Ok(l) => {
            println!("HTTP→HTTPS redirect listening on {http_listen}");
            Some(l)
        }
        Err(e) => {
            // Ancillary listener — if it cannot bind (e.g. a non-root dev
            // box where :80 is taken), keep serving TLS and say so loudly.
            eprintln!("WARNING: cannot bind HTTP redirect on {http_listen}: {e}");
            None
        }
    };

    // http_ctx (like tls_config) is created before the scope below so the
    // accept-loop threads can borrow it for their whole (infinite) lifetime.
    let http_ctx = http_listener.as_ref().map(|_| {
        Arc::new(redirect::RedirectConfig {
            public_host,
            acme_webroot,
        })
    });

    // Run one accept loop per listener inside a scope, so each loop can borrow
    // the listeners and shared configs for its whole (infinite) lifetime; the
    // scope then blocks forever, which keeps main() alive exactly as the old
    // explicit join did. Each loop accepts a socket, tries to take a semaphore
    // permit, and either hands the socket to a worker thread that holds the
    // permit for the connection's lifetime or — when all permits are held —
    // rejects the surplus inline without blocking (see accept_loop).
    thread::scope(|scope| {
        scope.spawn(|| {
            accept_loop(
                &tls_listener,
                &semaphore,
                &tls_config,
                handle_tls_connection,
                reject_saturated_tls,
            );
        });

        if let (Some(listener), Some(ctx)) =
            (http_listener.as_ref(), http_ctx.as_ref())
        {
            scope.spawn(|| {
                accept_loop(
                    listener,
                    &semaphore,
                    ctx,
                    handle_http_connection,
                    reject_saturated_http,
                );
            });
        }
    });
}

/// Run the accept→bound-spawn loop for one listener.
///
/// `handle` is a plain function pointer so the same loop serves both the TLS
/// and plaintext-HTTP listeners; `reject` is the per-listener answer when all
/// `MAX_CONNECTIONS` permits are already held. `shared` is the config `Arc`
/// each worker thread needs. The listener and shared configs are borrowed —
/// the loop runs forever, inside scoped threads that `main()` never leaves, so
/// the borrows live for the whole process rather than being moved in.
fn accept_loop<H: Send + Sync + 'static>(
    listener: &TcpListener,
    semaphore: &Arc<semaphore::Semaphore>,
    shared: &Arc<H>,
    handle: fn(TcpStream, &Arc<H>),
    reject: fn(&mut TcpStream),
) {
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Take a permit WITHOUT blocking the accept loop. When every
                // permit is held we still accept the socket and reject it
                // inline (cheap, no thread) instead of waiting here — a
                // parked accept loop makes a saturated server look hung, and
                // lets the kernel backlog swallow connections that just time
                // out client-side. Excess demand gets a prompt, honest
                // failure instead. → GitHub issue: clean 503 on saturation.
                match semaphore.try_acquire_owned() {
                    Some(permit) => {
                        let shared = Arc::clone(shared);
                        thread::spawn(move || {
                            // Permit lives for the whole connection: bounds
                            // the number of concurrently alive worker threads.
                            let _permit = permit;
                            handle(stream, &shared);
                        });
                    }
                    None => reject(&mut stream),
                }
            }
            Err(e) => {
                eprintln!("Connection accept error: {e}");
            }
        }
    }
}

/// Reject one excess connection on the TLS listener.
///
/// When every one of the `MAX_CONNECTIONS` worker threads is busy, the accept
/// loop cannot afford to do a TLS handshake per excess socket just to send a
/// 503 body — under attack that would stall the accept loop on clients that
/// never send a `ClientHello`. The cheap, honest answer is to drop the socket:
/// the client sees an immediate connection close rather than an indefinite
/// hang, and the server keeps accepting (so a freed permit is picked up at
/// once). A TLS-layer 503 is deliberately not attempted for this reason.
const fn reject_saturated_tls(_stream: &mut TcpStream) {
    // Nothing to write: the borrow is returned and the accept loop drops the
    // owned socket, sending FIN. No handshake, no thread, no wait.
}

/// Reject one excess connection on the plaintext (redirect/ACME) listener
/// with a real HTTP 503. No TLS handshake is required on this port, so a
/// full 503 with the security header set is affordable inline; a browser
/// hitting the port-80 redirect while the server is saturated sees a clean
/// "service unavailable", not a hang. Security headers are injected exactly
/// as every other response gets them.
fn reject_saturated_http(stream: &mut TcpStream) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "unknown".to_string(), |a| a.to_string());
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        eprintln!("set_write_timeout failed during 503 reject: {e}");
    }
    let started = Instant::now();
    let response = http::Response {
        status: 503,
        reason: "Service Unavailable",
        // Connection: close is NOT set here — into_bytes (the single wire
        // funnel) adds it to every response.
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: b"The server is at capacity. Try again in a moment.".to_vec(),
    };
    let bytes = middleware::headers::inject(response).into_bytes(false);
    if let Err(e) = stream.write_all(&bytes) {
        eprintln!("503 reject write failed: {e}");
    }
    // Saturation is an incident, not background noise — the audit line makes
    // it visible: method/path are "-" (no request was read) and session "na".
    audit::AuditCtx {
        listener: "http80",
        peer,
        method: "-".to_string(),
        path: "-".to_string(),
        session: None,
        pow_solve_ms: None,
        request_count: None,
    }
    .finish(503, started.elapsed());
}

/// Read an env var or print a clear error and exit(1).
fn env_or_fail(name: &str, hint: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("ERROR: environment variable {name} is not set.");
            eprintln!("{hint}");
            std::process::exit(1);
        }
    }
}

/// Handle one TLS connection: 5s read timeout → TLS handshake → read the full
/// request → route through the middleware chain → respond.
fn handle_tls_connection(
    stream: TcpStream,
    config: &Arc<rustls::ServerConfig>,
) {
    let peer_addr = stream.peer_addr().ok();
    let peer = peer_addr
        .as_ref()
        .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);
    // Client address for the per-IP budgets (the /pow/verify rate limit).
    // None when the socket has no resolvable address; those requests skip
    // the rate check rather than sharing one anonymous bucket.
    let peer_ip = peer_addr.map(|addr| addr.ip());

    // Bound slow-loris clients at the socket before TLS is layered on:
    // every blocked read on this socket now returns after READ_TIMEOUT of
    // silence and the connection is dropped. Without this a client could
    // open a socket and dribble a byte every few seconds forever, pinning
    // a worker thread. → DESIGN.md 5-second read timeout.
    if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
        eprintln!("set_read_timeout failed for {peer}: {e}");
    }

    // Symmetric write timeout, set on the raw socket before the TLS wrap (as
    // with the read timeout — rustls writes through this socket, so the
    // socket write timeout bounds write_tls). A client that sends a request
    // and then never reads the response must not be able to pin a worker
    // thread on a blocked write forever; the slot is released after 5s of an
    // undrained socket buffer.
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        eprintln!("set_write_timeout failed for {peer}: {e}");
    }

    // Wrap raw TCP stream in TLS FIRST.
    let mut tls_stream = match tls::wrap(stream, Arc::clone(config)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS wrap error from {peer}: {e}");
            return;
        }
    };

    // Latency is measured from handler start (first byte read) to the last
    // byte written, so a slow request body or a stalled write shows up as a
    // high latency value in the audit log.
    let started = Instant::now();

    // Read the full request from the TLS stream.
    // A single read() can return only part of a request — TLS records and
    // TCP segments split large requests (notably POST bodies) across
    // multiple reads. Rejecting the request the moment the first read is
    // short would wrongly 400 every request whose body arrived in a later
    // segment (observed intermittently on /pow/verify). Keep reading until
    // the request is complete or a hard parse error says to stop.
    let mut buf: Vec<u8> = Vec::new();
    let request = loop {
        let mut chunk = [0u8; 8192];
        let n = match tls_stream.read(&mut chunk) {
            Ok(0) => return, // client closed before the request completed
            Ok(n) => n,
            Err(e) => {
                eprintln!("Read error from {peer}: {e}");
                return;
            }
        };
        buf.extend_from_slice(&chunk[..n]);

        match http::parse_request(&buf) {
            http::ParseOutcome::Complete(req) => break req,
            http::ParseOutcome::Incomplete => {
                // Not a complete request yet — fall out of the match (the loop
                // body's end) and read another chunk.
            }
            http::ParseOutcome::Rejected(error_response) => {
                // A request rejected during parsing never reached
                // router::handle, which is the only place that normally runs
                // headers::inject. Unsupported methods (PUT, DELETE, …)
                // produce a 405 here, so those responses were being sent raw
                // with NO security headers — a real bypass. Inject them now:
                // every response on this listener must carry them.
                // → GitHub issue: 405s skipping headers::inject.
                //
                // Method/path are best-effort from the raw buffer (the
                // request never parsed) and the session gate never ran → na.
                let ctx = audit::AuditCtx {
                    listener: "tls",
                    peer,
                    method: audit::method_token(&buf),
                    path: audit::path_token(&buf),
                    session: None,
                    pow_solve_ms: None,
                    request_count: None,
                };
                let response =
                    middleware::headers::inject(error_response);
                send_response(&mut tls_stream, response, &ctx, started);
                return;
            }
        }
    };

    // Capture the audit fields before the request is moved into routing: the
    // method's name and the path it asked for. Session presence is only known
    // once the gate runs inside router::handle, which returns it alongside
    // the response (Routed).
    let method = audit::method_name(&request.method).to_string();
    let path = request.path.clone();

    // Route through middleware chain and handlers.
    let routed = router::handle(&request, peer_ip);

    // The dashboard counters and the two appended audit columns are computed
    // here, in the one place that knows how routing ruled, so a number the
    // operator sees on /admin equals the number the audit line records.
    metrics::global().record_request(&path);

    // Solve time: milliseconds between challenge issue and solve arrival,
    // present only for a successful POST /pow/verify (a 302 that set the
    // session cookie). The same value feeds the audit column and the
    // dashboard's ring buffer, so the two always agree.
    let pow_solve_ms = if method == "POST"
        && path == "/pow/verify"
        && routed.response.status == 302
    {
        let elapsed = middleware::pow::solve_elapsed_ms(&request.body);
        if let Some(ms) = elapsed {
            metrics::global().record_solve(ms);
        }
        elapsed
    } else {
        None
    };

    // The request's number within the valid session it presented, present
    // only where the gate ruled yes. It counts exactly the requests the
    // session column marks "yes": the counter starts at 1 for the first such
    // request and climbs from there.
    let request_count = if routed.session == Some(true) {
        middleware::session::session_key(&request)
            .map(|key| metrics::global().record_valid_request(key))
    } else {
        None
    };

    let ctx = audit::AuditCtx {
        listener: "tls",
        peer,
        method,
        path,
        session: routed.session,
        pow_solve_ms,
        request_count,
    };
    send_response(&mut tls_stream, routed.response, &ctx, started);
}

/// Handle one plaintext HTTP connection on the redirect/ACME port.
/// Everything gets a 301 to the HTTPS equivalent except ACME HTTP-01
/// challenge fetches, which are served from the webroot.
fn handle_http_connection(
    stream: TcpStream,
    config: &Arc<redirect::RedirectConfig>,
) {
    redirect::connection(stream, config);
}

fn send_response(
    stream: &mut tls::TlsStream,
    response: http::Response,
    ctx: &audit::AuditCtx,
    started: Instant,
) {
    // HEAD responses carry the GET headers (incl. Content-Length) but no
    // body — the serializer strips it given this flag.
    let head = ctx.method == "HEAD";
    let status = response.status;
    let bytes = response.into_bytes(head);

    // Drain the full body. rustls Write may accept only part of a large
    // response per call (and the write timeout added in main.rs means a call
    // can now also fail mid-response), so a single write() could truncate.
    // Loop until every byte is accepted; 0 or an error ends the attempt.
    let mut sent = 0;
    while sent < bytes.len() {
        match stream.write(&bytes[sent..]) {
            Ok(0) => {
                eprintln!("Write stalled to {}: 0 bytes accepted", ctx.peer);
                break;
            }
            Ok(n) => sent += n,
            Err(e) => {
                eprintln!("Write error to {}: {e}", ctx.peer);
                break;
            }
        }
    }

    // Emit the audit line whether the write completed or stalled/errored: a
    // request that reached the point of a response still gets a record, and
    // the latency value distinguishes a clean send from a stalled one.
    ctx.finish(status, started.elapsed());
}
