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
    // Load TLS config once at startup.
    // Cert paths will move to environment variables (future issue).
    let tls_config = tls::load_config(
        "/etc/ssl/certs/server.pem",
        "/etc/ssl/private/server.key",
    );

    let listener = TcpListener::bind("0.0.0.0:443")
        .expect("Failed to bind to port 443");

    println!("Zero-trust server listening on 0.0.0.0:443");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Clone the Arc — cheap reference count increment,
                // not a copy of the config itself.
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

    println!("Connection from: {peer}");

    // Wrap the raw stream in TLS.
    // Handshake completes on first read/write.
    let _tls_stream = match tls::wrap(stream, config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS wrap error from {peer}: {e}");
            return;
        }
    };

    // Next: pass tls_stream to http::parse_request()
    println!("TLS connection established with {peer}");
}
