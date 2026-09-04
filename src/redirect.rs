//! Plaintext-HTTP listener on the port-80 path.
//!
//! Its only jobs:
//!   1. 301-redirect every request to the HTTPS equivalent, and
//!   2. serve ACME HTTP-01 challenge tokens from a webroot so the Let's
//!      Encrypt (or ZeroSSL) client can validate this host — the zero-trust
//!      server is its own web server, so nobody else can serve those files.
//!
//! Everything is decided from the request line + headers; request bodies are
//! never read (a HEAD-less GET has none, and reading one would let a client
//! pin the connection open). If the header section never terminates we stop
//! at 8 KiB and redirect anyway.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::http::{self, Method, Request, Response};

/// How long a client may keep a redirect-socket read blocked.
/// Mirrors the TLS listener timeout (main.rs). The redirect port is just as
/// exposed to slow-loris as any other socket.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Symmetric write timeout (mirrors WRITE_TIMEOUT in main.rs). A client that
/// stops reading while we send the redirect/ACME response must not hold the
/// worker thread on a blocked write forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on buffered header bytes before we give up waiting for a well-formed
/// request and redirect anyway.
const MAX_HEADER_BYTES: usize = 8192;

/// Configuration the redirect/ACME listener needs.
pub struct RedirectConfig {
    /// Hostname used to build https:// URLs when a request's Host header is
    /// absent or unusable.
    pub public_host: String,
    /// If set, `/.well-known/acme-challenge/<token>` GETs are served from
    /// this directory instead of being redirected.
    pub acme_webroot: Option<PathBuf>,
}

/// Serve one plaintext HTTP connection.
pub fn connection(stream: TcpStream, cfg: &RedirectConfig) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    if let Err(e) = stream.set_read_timeout(Some(READ_TIMEOUT)) {
        eprintln!("set_read_timeout failed for {peer}: {e}");
    }

    // Symmetric to the TLS listener (main.rs): a client that never drains its
    // receive buffer must not pin this thread on a blocked write forever.
    if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
        eprintln!("set_write_timeout failed for {peer}: {e}");
    }

    let mut stream = stream;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let mut chunk = [0u8; 2048];
        let n = match stream.read(&mut chunk) {
            Ok(0) => return, // client closed without sending a request
            Ok(n) => n,
            Err(e) => {
                eprintln!("Read error on redirect connection from {peer}: {e}");
                return;
            }
        };
        buf.extend_from_slice(&chunk[..n]);

        // Enough to decide: header section complete, or given up on it.
        if has_header_terminator(&buf) || buf.len() >= MAX_HEADER_BYTES {
            let response = match http::parse_request(&buf) {
                http::ParseOutcome::Complete(req) => respond(&req, cfg),
                // Malformed or body-missing — never a valid ACME fetch, and
                // the safe answer to a broken plaintext request is still a
                // redirect to HTTPS.
                _ => redirect_to_https(&cfg.public_host, "/", None),
            };
            write_response(&mut stream, response, &peer);
            return;
        }
    }
}

/// Decide the response for a parsed plaintext request: an ACME token file,
/// or a 301 redirect to the HTTPS equivalent of the requested path.
fn respond(req: &Request, cfg: &RedirectConfig) -> Response {
    // ACME HTTP-01: GET /.well-known/acme-challenge/<token>
    if req.method == Method::Get
        && let (Some(webroot), Some(token)) =
            (cfg.acme_webroot.as_ref(), acme_token(req.path.as_str()))
    {
        return serve_token(webroot, token);
    }

    let host = match req.headers.get("host").map(String::as_str) {
        Some(h) if valid_host(h) => h.to_string(),
        _ => cfg.public_host.clone(),
    };
    redirect_to_https(&host, req.path.as_str(), Some(&cfg.public_host))
}

/// A 301 Moved Permanently to the HTTPS equivalent of `path` on `host`.
/// `fallback_host` is used when the caller could not derive a usable host.
fn redirect_to_https(
    host: &str,
    path: &str,
    _fallback_host: Option<&str>,
) -> Response {
    let location = format!("https://{}{}", host, safe_target(path));
    Response {
        status: 301,
        reason: "Moved Permanently",
        headers: vec![
            // Body-less redirects still want a hint for very old clients.
            ("Content-Type".to_string(), "text/html; charset=utf-8".to_string()),
            ("Location".to_string(), location),
        ],
        body: b"<html><body>Moved to <a href=\"\">HTTPS</a></body></html>"
            .to_vec(),
    }
}

/// Serve an ACME challenge token file from the webroot, or 404 if absent or
/// the token is not a plain single segment.
fn serve_token(webroot: &Path, token: &str) -> Response {
    // Reject anything that could escape the webroot: tokens are single
    // URL-safe segments (letters/digits/-/_), no separators or dot-prefixes.
    let valid = !token.is_empty()
        && token.len() <= 255
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

    if !valid {
        return not_found();
    }

    match std::fs::read(webroot.join(token)) {
        Ok(bytes) => Response {
            status: 200,
            reason: "OK",
            headers: vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Content-Length".to_string(), bytes.len().to_string()),
            ],
            body: bytes,
        },
        Err(_) => not_found(),
    }
}

fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        headers: Vec::new(),
        body: b"404 Not Found".to_vec(),
    }
}

/// Extract the token segment from an ACME challenge path, if the path is
/// exactly `/.well-known/acme-challenge/<single-segment>`.
fn acme_token(path: &str) -> Option<&str> {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    let rest = path.strip_prefix(PREFIX)?;
    if rest.is_empty() || rest.contains('/') {
        None
    } else {
        Some(rest)
    }
}

/// Return a path that is safe to reflect into a Location header.
/// Keeps normal paths/query strings; replaces anything that could smuggle a
/// header or confuse a browser (controls, space, non-ASCII, empty, "//")
/// with "/".
fn safe_target(path: &str) -> &str {
    if path.is_empty()
        || path.len() > 2048
        || !path.starts_with('/')
        || path.contains("//")
        || !path.is_ascii()
        || path.bytes().any(|b| b < 0x21 || b == 0x7f)
    {
        return "/";
    }
    path
}

/// A Host header value we are willing to build an https:// URL for:
/// ASCII hostname (optionally with :port) or bracketed IPv6.
fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.is_ascii()
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        })
}

fn has_header_terminator(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, response: Response, peer: &str) {
    let status = response.status;
    let bytes = response.into_bytes();
    if let Err(e) = stream.write_all(&bytes) {
        eprintln!("Write error on redirect connection to {peer}: {e}");
    } else {
        println!("{peer} -> {status} (http)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn req(method: Method, path: &str, host: Option<&str>) -> Request {
        let mut headers = HashMap::new();
        if let Some(h) = host {
            headers.insert("host".to_string(), h.to_string());
        }
        Request {
            method,
            path: path.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn safe_target_keeps_normal_paths() {
        assert_eq!(safe_target("/"), "/");
        assert_eq!(safe_target("/index.html"), "/index.html");
        assert_eq!(safe_target("/some/deep?q=1&x=2"), "/some/deep?q=1&x=2");
    }

    #[test]
    fn safe_target_rejects_abuse() {
        assert_eq!(safe_target(""), "/");
        assert_eq!(safe_target("no-leading-slash"), "/");
        assert_eq!(safe_target("//evil.example/x"), "/");
        assert_eq!(safe_target("/x\r\nLocation: /steal"), "/");
        assert_eq!(safe_target("/spaced out"), "/");
        assert_eq!(safe_target("/é"), "/");
    }

    #[test]
    fn valid_host_accepts_real_and_rejects_garbage() {
        assert!(valid_host("mhebert.dev"));
        assert!(valid_host("mhebert.dev:8080"));
        assert!(valid_host("127.0.0.1"));
        assert!(valid_host("[2001:db8::1]"));
        assert!(!valid_host("evil\r\n"));
        assert!(!valid_host("has space"));
        assert!(!valid_host(""));
    }

    #[test]
    fn redirect_builds_https_location_with_clean_path() {
        let r = respond(&req(Method::Get, "/blog/hello", Some("mhebert.dev")), &no_acme());
        assert_eq!(r.status, 301);
        let loc = r.headers.iter().find(|(n, _)| n == "Location").unwrap().1.clone();
        assert_eq!(loc, "https://mhebert.dev/blog/hello");
    }

    #[test]
    fn redirect_falls_back_to_public_host() {
        let cfg = RedirectConfig {
            public_host: "mhebert.dev".to_string(),
            acme_webroot: None,
        };
        // Missing and unusable Host headers both fall back.
        let r = respond(&req(Method::Get, "/", None), &cfg);
        let loc = r.headers.iter().find(|(n, _)| n == "Location").unwrap().1.clone();
        assert_eq!(loc, "https://mhebert.dev/");

        let evil = req(Method::Get, "/", Some("bad\r\nHost: x"));
        // valid_host rejects the control char, so fallback host is used.
        let r2 = respond(&evil, &cfg);
        let loc2 = r2.headers.iter().find(|(n, _)| n == "Location").unwrap().1.clone();
        assert_eq!(loc2, "https://mhebert.dev/");
    }

    #[test]
    fn acme_path_is_served_not_redirected() {
        let cfg = RedirectConfig {
            public_host: "mhebert.dev".to_string(),
            acme_webroot: Some(PathBuf::from("/nonexistent-webroot")),
        };
        let r = respond(
            &req(Method::Get, "/.well-known/acme-challenge/tok-123", Some("mhebert.dev")),
            &cfg,
        );
        // Token not actually on disk → 404, but crucially NOT a 301 redirect.
        assert_eq!(r.status, 404);
    }

    #[test]
    fn acme_token_rejects_non_single_segment() {
        assert_eq!(acme_token("/.well-known/acme-challenge/abc"), Some("abc"));
        assert_eq!(acme_token("/.well-known/acme-challenge/"), None);
        assert_eq!(acme_token("/.well-known/acme-challenge/a/b"), None);
        assert_eq!(acme_token("/other"), None);
    }

    #[test]
    fn serve_token_blocks_traversal() {
        let cfg_ok = RedirectConfig {
            public_host: "x".to_string(),
            acme_webroot: Some(PathBuf::from("/tmp")),
        };
        let webroot = cfg_ok.acme_webroot.as_ref().unwrap();
        // "../etc/passwd" and absolute-style tokens never reach fs::read.
        assert_eq!(serve_token(webroot, "../etc/passwd").status, 404);
        assert_eq!(serve_token(webroot, "a/b").status, 404);
    }

    fn no_acme() -> RedirectConfig {
        RedirectConfig {
            public_host: "mhebert.dev".to_string(),
            acme_webroot: None,
        }
    }
}
