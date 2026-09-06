//! Live TLS handshake probe: report which protocol, cipher suite, and key
//! exchange group a real server negotiates.
//!
//! Run `cargo run --example pq_probe -- [host] [port]`. Reads system trust
//! roots from `/etc/ssl/certs/ca-certificates.crt` (override with the
//! `SSL_CERT_FILE` environment variable). Exits non-zero if the handshake
//! fails or the negotiated group is not the one requested via `--expect`.
//!
//! This is a development and operations tool, not part of the served site.

use std::fs::File;
use std::io::{BufReader, Read as _, Write as _};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "mhebert.dev".to_string());
    let port = args.next().unwrap_or_else(|| "443".to_string());
    let expect = args.next();
    let ca_path = std::env::var("SSL_CERT_FILE")
        .unwrap_or_else(|_| "/etc/ssl/certs/ca-certificates.crt".to_string());

    let mut roots = rustls::RootCertStore::empty();
    let ca = File::open(&ca_path)?;
    let mut pem = BufReader::new(ca);
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)?;
    roots.add_parsable_certificates(certs);

    let config = Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let name = ServerName::try_from(host.clone()).expect("host is a valid DNS name");
    let mut conn = ClientConnection::new(config, name).expect("client connection");
    let mut sock = TcpStream::connect(format!("{host}:{port}"))?;

    // Drive the handshake to completion: flush writes (ClientHello, Finished)
    // and read until rustls reports it is no longer handshaking.
    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        if conn.wants_read() {
            conn.read_tls(&mut sock)?;
            conn.process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
    }
    while conn.wants_write() {
        conn.write_tls(&mut sock)?;
    }

    let group = conn
        .negotiated_key_exchange_group()
        .map_or_else(|| "none".to_string(), |g| format!("{:?}", g.name()));
    let suite = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "none".to_string(), |cs| format!("{:?}", cs.suite()));
    let version = conn
        .protocol_version()
        .map_or_else(|| "none".to_string(), |v| format!("{v:?}"));

    println!("server  {host}:{port}");
    println!("version {version}");
    println!("suite   {suite}");
    println!("kx      {group}");

    if let Some(expected) = expect
        && group != expected
    {
        eprintln!("expected kx group {expected}, negotiated {group}");
        std::process::exit(1);
    }

    // Send a HEAD request through the TLS writer, then read the response
    // head through the TLS reader: proves the session carries application
    // data, not just a negotiated handshake.
    {
        let mut writer = conn.writer();
        let _ = writer.write_all(
            b"HEAD / HTTP/1.1\r\nHost: mhebert.dev\r\nConnection: close\r\n\r\n",
        );
    }
    while conn.wants_write() {
        conn.write_tls(&mut sock)?;
    }
    // Pump TLS records until the reader yields plaintext: a single read on the
    // rustls reader never pulls more bytes from the socket by itself.
    let mut buf = [0u8; 512];
    let mut n = 0;
    while n == 0 {
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        if conn.wants_read() {
            conn.read_tls(&mut sock)?;
            conn.process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        let mut reader = conn.reader();
        n = reader.read(&mut buf).unwrap_or(0);
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    println!("status  {}", head.lines().next().unwrap_or("no response"));

    Ok(())
}
