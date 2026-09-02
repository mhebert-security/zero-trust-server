use std::net::TcpListener;
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
    // Bind to all interfaces on port 443.
    // Requires root or CAP_NET_BIND_SERVICE.
    // Known issue: should run as unprivileged user with nftables
    // REDIRECT 443 → high port. Documented in main.md.
    let listener = TcpListener::bind("0.0.0.0:443")
        .expect("Failed to bind to port 443");

    println!("Zero-trust server listening on 0.0.0.0:443");

    // Accept loop — runs forever, one thread per connection.
    // Unbounded thread spawning is a known limitation documented
    // in main.md. nftables rate limiting provides the outer bound.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Move the stream into the spawned thread.
                // No shared state between threads at this level.
                thread::spawn(move || {
                    handle_connection(stream);
                });
            }
            Err(e) => {
                // Log the error and continue accepting.
                // A single failed accept does not kill the server.
                eprintln!("Connection accept error: {e}");
            }
        }
    }
}

fn handle_connection(stream: std::net::TcpStream) {
    // This function will grow as modules are implemented.
    // Current state: placeholder, logs connection and drops stream.
    // Next: TLS handshake via tls::wrap(stream)
    let peer = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("Connection from: {peer}");
    // stream is dropped here, closing the connection.
    // Next commit: tls::wrap(stream) → router::handle(tls_stream)
}
