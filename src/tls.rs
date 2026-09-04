use std::fs::File;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

/// A TLS-wrapped TCP stream.
/// After wrap() succeeds, callers read and write encrypted bytes
/// through this type as if it were a plain stream.
pub struct TlsStream {
    pub conn: ServerConnection,
    pub sock: TcpStream,
}

impl TlsStream {
    /// Read bytes from the TLS stream into buf.
    /// Handles TLS handshake and record decryption transparently.
    ///
    /// Critical: during the TLS handshake the server must both
    /// read AND write. The original implementation only read,
    /// causing the handshake to stall — the client waits for
    /// the server's handshake response which never gets flushed.
    /// This corrected version flushes writes at every opportunity.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Flush any pending writes FIRST.
            // During handshake, rustls queues ServerHello and other
            // handshake messages that must be sent before the client
            // will send more data. Without this flush the handshake
            // deadlocks — both sides wait for the other.
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock)?;
            }

            // Read incoming TLS records from the socket.
            if self.conn.wants_read() {
                if let Err(e) = self.conn.read_tls(&mut self.sock) {
                    return Err(e);
                }
                // Decrypt records and advance the TLS state machine.
                if let Err(e) = self.conn.process_new_packets() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e,
                    ));
                }
            }

            // Flush again — process_new_packets may have queued
            // additional handshake messages (e.g. Finished).
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock)?;
            }

            // Attempt to read decrypted plaintext bytes.
            // Only available after handshake is complete.
            let mut reader = self.conn.reader();
            match std::io::Read::read(&mut reader, buf) {
                Ok(0) if buf.is_empty() => return Ok(0),
                Ok(n) => return Ok(n),
                // WouldBlock means no plaintext available yet —
                // handshake may still be in progress, loop again.
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Write bytes to the TLS stream.
    /// Handles TLS record encryption transparently.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write plaintext into rustls — it encrypts internally.
        let mut writer = self.conn.writer();
        let n = std::io::Write::write(&mut writer, buf)?;
        drop(writer);

        // Flush all encrypted bytes to the socket.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }

        Ok(n)
    }
}

/// Load the TLS ServerConfig from PEM certificate and key files.
/// Called once at startup. The resulting config is wrapped in Arc
/// and shared across all connection-handling threads.
pub fn load_config(cert_path: &str, key_path: &str) -> Arc<ServerConfig> {
    let cert_file = File::open(cert_path)
        .unwrap_or_else(|e| panic!("Cannot open cert file {cert_path}: {e}"));
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certificates");

    let key_file = File::open(key_path)
        .unwrap_or_else(|e| panic!("Cannot open key file {key_path}: {e}"));
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer = private_key(&mut key_reader)
        .expect("Failed to read private key")
        .expect("No private key found in file");

    // Pin TLS 1.3 exclusively — no TLS 1.2 fallback at all.
    // builder() would otherwise allow TLS 1.2 (and its legacy cipher
    // suites) as a negotiated fallback; builder_with_protocol_versions
    // restricts the offered/negotiated versions to exactly TLS 1.3,
    // eliminating the entire TLS 1.2 attack surface. TLS 1.3 requires
    // AEAD (no CBC), forward secrecy on every handshake, and no
    // renegotiation — all desirable for a zero-trust endpoint.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");

    Arc::new(config)
}

/// Wrap a raw TcpStream in a TLS server connection.
/// The TLS handshake completes on first read() call, not here.
pub fn wrap(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> std::io::Result<TlsStream> {
    let conn = ServerConnection::new(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(TlsStream { conn, sock: stream })
}