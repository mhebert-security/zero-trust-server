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
    /// Handles TLS record decryption transparently.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Complete any pending TLS handshake IO first.
            if self.conn.wants_read() {
                if let Err(e) = self.conn.read_tls(&mut self.sock) {
                    return Err(e);
                }
                if let Err(e) = self.conn.process_new_packets() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e,
                    ));
                }
            }

            // Read decrypted plaintext bytes.
            let mut reader = self.conn.reader();
            match std::io::Read::read(&mut reader, buf) {
                Ok(0) if buf.is_empty() => return Ok(0),
                Ok(n) => return Ok(n),
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

        // Flush encrypted bytes out to the socket.
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
    // Load certificate chain from PEM file.
    let cert_file = File::open(cert_path)
        .unwrap_or_else(|e| panic!("Cannot open cert file {cert_path}: {e}"));
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse certificates");

    // Load private key from PEM file.
    let key_file = File::open(key_path)
        .unwrap_or_else(|e| panic!("Cannot open key file {key_path}: {e}"));
    let mut key_reader = BufReader::new(key_file);
    let key: PrivateKeyDer = private_key(&mut key_reader)
        .expect("Failed to read private key")
        .expect("No private key found in file");

    // Build ServerConfig.
    // rustls defaults: TLS 1.3 preferred, TLS 1.2 minimum.
    // No TLS 1.0, no TLS 1.1, no legacy cipher suites.
    // These are secure defaults — we do not override them.
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");

    Arc::new(config)
}

/// Wrap a raw TcpStream in a TLS server connection.
/// Returns a TlsStream ready for encrypted IO.
/// The TLS handshake is completed lazily on first read/write.
pub fn wrap(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> std::io::Result<TlsStream> {
    let conn = ServerConnection::new(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(TlsStream { conn, sock: stream })
}
