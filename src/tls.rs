//! TLS termination: TLS 1.3 only, with hybrid post-quantum key agreement.
//!
//! The server pins TLS 1.3 and the aws-lc-rs crypto provider. That provider
//! carries the X25519MLKEM768 hybrid key exchange, and its default group
//! list offers it first. rustls negotiates the client's first offered group
//! that the server supports, so a client that offers the hybrid gets it,
//! while a classic-only client still lands on X25519. The regression tests
//! in this module pin both sides of that behavior.

use std::fs::File;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

/// A TLS-wrapped TCP stream.
/// After `wrap()` succeeds, callers read and write encrypted bytes
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
                self.conn.read_tls(&mut self.sock)?;
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
                // handshake may still be in progress; fall out of the match
                // (the loop body's end) and loop again.
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Write bytes to the TLS stream.
    /// Handles TLS record encryption transparently.
    pub fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write plaintext into rustls — it encrypts internally. The writer is
        // a transparent wrapper borrowing `self.conn`, so it lives in a tight
        // scope: the &mut borrow must end before the flush loop re-borrows
        // `self.conn` below.
        let n = {
            let mut writer = self.conn.writer();
            std::io::Write::write(&mut writer, buf)?
        };

        // Flush all encrypted bytes to the socket.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }

        Ok(n)
    }
}

/// Load the TLS `ServerConfig` from PEM certificate and key files.
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

    // Select the crypto provider explicitly rather than relying on the rustls
    // feature defaults. aws-lc-rs is the provider that implements the
    // X25519MLKEM768 hybrid key exchange; install_default is idempotent, so
    // a later call from a worker or a test is a no-op.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    // Pin TLS 1.3 exclusively — no TLS 1.2 fallback at all.
    // builder() would otherwise allow TLS 1.2 (and its legacy cipher
    // suites) as a negotiated fallback; builder_with_protocol_versions
    // restricts the offered/negotiated versions to exactly TLS 1.3,
    // eliminating the entire TLS 1.2 attack surface. TLS 1.3 requires
    // AEAD (no CBC), forward secrecy on every handshake, and no
    // renegotiation — all desirable for a zero-trust endpoint. The same
    // builder selects the process default provider installed above, whose
    // group list offers X25519MLKEM768 before X25519.
    let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");

    Arc::new(config)
}

/// Wrap a raw `TcpStream` in a TLS server connection.
/// The TLS handshake completes on first `read()` call, not here.
pub fn wrap(
    stream: TcpStream,
    config: Arc<ServerConfig>,
) -> std::io::Result<TlsStream> {
    let conn = ServerConnection::new(config).map_err(std::io::Error::other)?;

    Ok(TlsStream { conn, sock: stream })
}

#[cfg(test)]
mod tests {
    use super::load_config;
    use rustls::crypto::aws_lc_rs::default_provider;
    use rustls::crypto::aws_lc_rs::kx_group::{X25519, X25519MLKEM768};
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, Connection, NamedGroup, ServerConfig, ServerConnection};
    use std::fs::File;
    use std::io::BufReader;
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// Self-signed test CA and a localhost leaf signed by it, generated once
    /// with openssl and committed under tests/fixtures/pq. The key is a
    /// throwaway that authenticates nothing real; it exists so a full TLS
    /// handshake can run in the test without trusting a network host.
    const FIXTURES: &str = "tests/fixtures/pq";

    /// Upper bound on a handshake step, so a negotiation failure surfaces as
    /// a test error instead of a hung thread.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURES)
            .join(name)
    }

    /// The real production config path: loads the on-disk PEM fixtures and
    /// runs the same cert parsing, provider install, and TLS 1.3 pinning that
    /// `load_config` applies to the live certificate.
    fn server_config() -> Arc<ServerConfig> {
        let cert = fixture("server-cert.pem");
        let key = fixture("server-key.pem");
        load_config(
            cert.to_str().expect("utf-8 fixture path"),
            key.to_str().expect("utf-8 fixture path"),
        )
    }

    fn root_store() -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        let file = File::open(fixture("ca-cert.pem")).expect("open CA fixture");
        let mut reader = BufReader::new(file);
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<_, _>>()
            .expect("parse CA fixture");
        roots.add_parsable_certificates(certs);
        roots
    }

    /// A client config that offers exactly `groups`, pinned to TLS 1.3 and
    /// trusting the test CA. Constraining the offered groups is how a test
    /// forces the negotiation to a single key exchange.
    fn client_config(
        groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    ) -> Arc<ClientConfig> {
        let mut provider = default_provider();
        provider.kx_groups = groups;
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 supported")
                .with_root_certificates(root_store())
                .with_no_client_auth(),
        )
    }

    fn drive_handshake(conn: &mut Connection, sock: &mut TcpStream) {
        while conn.is_handshaking() {
            conn.complete_io(sock)
                .expect("TLS handshake completes before the timeout");
        }
    }

    /// Complete a real TLS 1.3 handshake over loopback between the production
    /// server config and the given client config, and return the key exchange
    /// group both sides settled on.
    fn negotiated_group(client: Arc<ClientConfig>) -> NamedGroup {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("loopback address");
        let server = server_config();

        let server_thread = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("client connects");
            sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
                .expect("set read timeout");
            sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
                .expect("set write timeout");
            let mut conn = Connection::Server(
                ServerConnection::new(server).expect("server connection"),
            );
            drive_handshake(&mut conn, &mut sock);
        });

        let mut sock = TcpStream::connect(addr).expect("connect loopback");
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .expect("set read timeout");
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .expect("set write timeout");
        let name = ServerName::try_from("localhost").expect("localhost is a valid name");
        let mut conn = Connection::Client(
            ClientConnection::new(client, name).expect("client connection"),
        );
        drive_handshake(&mut conn, &mut sock);
        let group = conn
            .negotiated_key_exchange_group()
            .expect("a key exchange group was negotiated")
            .name();
        server_thread.join().expect("server thread finishes clean");
        group
    }

    /// The aws-lc-rs provider must list the hybrid group at all. This is the
    /// cheapest guard against a Cargo feature change silently dropping
    /// post-quantum support before any socket opens.
    #[test]
    fn default_provider_lists_the_hybrid_key_exchange() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("a default provider is installed");
        let names: Vec<NamedGroup> = provider
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert!(
            names.contains(&NamedGroup::X25519MLKEM768),
            "the provider must offer the hybrid group; names: {names:?}"
        );
    }

    /// A modern default client offers the hybrid first, exactly as the
    /// current Chromium and curl-with-aws-lc builds do. The server must
    /// accept it: the negotiated group is the hybrid, not a classic fallback.
    #[test]
    fn default_client_negotiates_the_hybrid_group() {
        let client = client_config(default_provider().kx_groups);
        assert_eq!(
            negotiated_group(client),
            NamedGroup::X25519MLKEM768,
            "a client that offers the hybrid first must get it"
        );
    }

    /// A client that offers only the hybrid, with no classic group to fall
    /// back to, must still complete the handshake. This rules out the case
    /// where the earlier test passes by falling back to X25519.
    #[test]
    fn hybrid_only_client_completes_the_handshake() {
        let client = client_config(vec![X25519MLKEM768]);
        assert_eq!(
            negotiated_group(client),
            NamedGroup::X25519MLKEM768,
            "the server must complete a handshake with no classic fallback"
        );
    }

    /// A classic-only client keeps working unchanged: the server still offers
    /// X25519, so turning on the hybrid never breaks an older client.
    #[test]
    fn classic_only_client_falls_back_to_x25519() {
        let client = client_config(vec![X25519]);
        assert_eq!(
            negotiated_group(client),
            NamedGroup::X25519,
            "a client without post-quantum support still connects"
        );
    }
}