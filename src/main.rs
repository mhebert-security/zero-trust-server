use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

mod tls;
mod http;
mod router;
mod middleware {
    pub mod pow;
    pub mod session;
    pub mod headers;
}
mod handlers {
    pub mod challenge;
    pub mod content;
}

fn main() {
    // Validate required environment variables at startup.
    // Fail fast with a clear error rather than silently
    // misconfiguring the server.
    if std::env::var("SESSION_SECRET").is_err() {
        eprintln!("ERROR: SESSION_SECRET environment variable not set.");
        eprintln!("The server cannot issue or verify session cookies.");
        eprintln!("Set SESSION_SECRET to a long random string before starting.");
        std::process::exit(1);
    }

    // Load TLS config once at startup.
    // Arc allows the config to be shared across connection threads.
    // → GitHub issue #5: move paths to environment variables
    let tls_config = tls::load_config(
        "/etc/ssl/certs/server.pem",
        "/etc/ssl/private/server.key",
    );

    // Bind to all interfaces on port 443.
    // → GitHub issue #1: run as unprivileged user with nftables REDIRECT
    let listener = TcpListener::bind("0.0.0.0:443")
        .expect("Failed to bind to port 443");

    println!("Zero-trust server listening on 0.0.0.0:443");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = Arc::clone(&tls_config);
                thread::spawn(move || {
                    handle_connection(stream, config);
                });
            }
            Err(e) => {
                eprintln!("Connection accept error: {e}");
            }
        }
    }
}

fn handle_connection(
    stream: std::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) {
    let peer = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Wrap raw TCP stream in TLS.
    let mut tls_stream = match tls::wrap(stream, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS wrap error from {peer}: {e}");
            return;
        }
    };

    // Read the raw request bytes from the TLS stream.
    // Buffer size matches our MAX_HEADER_SIZE + MAX_BODY_SIZE.
    // → GitHub issue #6: review buffer size against real requirements
    let mut buf = vec![0u8; 8192 + 65536];
    let n = match tls_stream.read(&mut buf) {
        Ok(0) => {
            // Client closed connection before sending anything.
            return;
        }
        Ok(n) => n,
        Err(e) => {
            eprintln!("Read error from {peer}: {e}");
            return;
        }
    };

    // Parse the raw bytes into a structured Request.
    // On parse failure, parse_request returns an error Response
    // ready to send directly — no further processing needed.
    let request = match http::parse_request(&buf[..n]) {
        Ok(req) => req,
        Err(error_response) => {
            send_response(&mut tls_stream, error_response, &peer);
            return;
        }
    };

    // Route the request through the middleware chain and handlers.
    // router::handle() runs:
    // 1. session verification
    // 2. handler dispatch
    // 3. security header injection
    let response = router::handle(request);

    // Send the response.
    send_response(&mut tls_stream, response, &peer);
}

/// Serialise and write a Response to the TLS stream.
/// Logs errors but does not panic — a write failure
/// means the client disconnected, which is not an error
/// worth crashing the thread over.
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
