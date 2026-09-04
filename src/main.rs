use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod tls;
mod http;
mod router;
mod redirect;
mod semaphore;
mod middleware {
    pub mod pow;
    pub mod session;
    pub mod headers;
}
mod handlers {
    pub mod challenge;
    pub mod content;
}

/// Maximum number of concurrent connections handled at once.
/// Every accepted socket is handled on its own OS thread; without a bound
/// an attacker who opens N sockets costs N threads (memory + scheduler
/// pressure). The accept loop holds a permit from this semaphore per
/// connection, so at most MAX_CONNECTIONS threads ever run. Further
/// connections wait in the accept queue (kernel backpressure) until a
/// permit frees — they are refused rather than spawning unbounded threads.
/// → DESIGN.md: bounded concurrency
const MAX_CONNECTIONS: usize = 128;

/// Read timeout applied to every accepted socket before TLS is layered on.
/// A slow-loris client that dribbles bytes slower than this between reads is
/// dropped instead of holding a thread open forever.
/// → DESIGN.md: 5-second read timeout bounds slow-loris.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    // Validate required environment variables at startup.
    // Fail fast with a clear error rather than silently misconfiguring.
    let _session_secret = env_or_fail(
        "SESSION_SECRET",
        "The server cannot issue or verify session cookies.",
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

    // Spawn an accept loop per listener. Each accepts a socket, acquires a
    // semaphore permit (blocking the loop when at capacity — kernel
    // backpressure instead of unbounded threads), then hands the socket to
    // a worker thread that holds the permit for the connection's lifetime.
    let tls_handle = {
        let semaphore = Arc::clone(&semaphore);
        thread::spawn(move || {
            accept_loop(tls_listener, semaphore, tls_config, handle_tls_connection)
        })
    };

    if let Some(listener) = http_listener {
        let http_ctx = Arc::new(redirect::RedirectConfig {
            public_host,
            acme_webroot,
        });
        thread::spawn(move || {
            accept_loop(listener, semaphore, http_ctx, handle_http_connection)
        });
    }

    // The accept loops run forever; joining keeps main() alive.
    let _ = tls_handle.join();
}

/// Run the accept→bound-spawn loop for one listener.
///
/// `handle` is a plain function pointer so the same loop serves both the TLS
/// and plaintext-HTTP listeners. `shared` is the Arc each worker needs.
fn accept_loop<H: Send + Sync + 'static>(
    listener: TcpListener,
    semaphore: Arc<semaphore::Semaphore>,
    shared: Arc<H>,
    handle: fn(TcpStream, Arc<H>),
) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Block here (rather than accept) when at capacity: new
                // sockets wait in the kernel backlog instead of spawning
                // unbounded threads — an attacker opening N sockets costs at
                // most MAX_CONNECTIONS live threads, the rest are refused by
                // backlog overflow.
                let permit = Arc::clone(&semaphore).acquire_owned();
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    // Permit lives for the whole connection: bounds the
                    // number of concurrently alive worker threads.
                    let _permit = permit;
                    handle(stream, shared);
                });
            }
            Err(e) => {
                eprintln!("Connection accept error: {e}");
            }
        }
    }
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
    config: Arc<rustls::ServerConfig>,
) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Bound slow-loris clients at the socket before TLS is layered on:
    // every blocked read on this socket now returns after READ_TIMEOUT of
    // silence and the connection is dropped. Without this a client could
    // open a socket and dribble a byte every few seconds forever, pinning
    // a worker thread. → DESIGN.md 5-second read timeout.
    if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
        eprintln!("set_read_timeout failed for {peer}: {e}");
    }

    // Wrap raw TCP stream in TLS FIRST.
    let mut tls_stream = match tls::wrap(stream, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS wrap error from {peer}: {e}");
            return;
        }
    };

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
            http::ParseOutcome::Incomplete => continue,
            http::ParseOutcome::Rejected(error_response) => {
                send_response(&mut tls_stream, error_response, &peer);
                return;
            }
        }
    };

    // Route through middleware chain and handlers.
    let response = router::handle(request);

    // Send the response.
    send_response(&mut tls_stream, response, &peer);
}

/// Handle one plaintext HTTP connection on the redirect/ACME port.
/// Everything gets a 301 to the HTTPS equivalent except ACME HTTP-01
/// challenge fetches, which are served from the webroot.
fn handle_http_connection(
    stream: TcpStream,
    config: Arc<redirect::RedirectConfig>,
) {
    redirect::connection(stream, &config);
}

fn send_response(
    stream: &mut tls::TlsStream,
    response: http::Response,
    peer: &str,
) {
    let status = response.status;
    let bytes = response.into_bytes();

    if let Err(e) = stream.write(&bytes) {
        eprintln!("Write error to {peer}: {e}");
    } else {
        println!("{peer} -> {status}");
    }
}
