use std::collections::HashMap;

/// Maximum header section size in bytes.
/// Protects against slowloris-style attacks that send headers
/// slowly and never terminate them.
/// → GitHub issue #6: review this limit against real requirements
const MAX_HEADER_SIZE: usize = 8192; // 8KB

/// Maximum body size in bytes.
/// → GitHub issue #6: review this limit against real requirements
const MAX_BODY_SIZE: usize = 65536; // 64KB

/// HTTP method — only the subset this server needs to handle.
/// Anything else returns 405 Method Not Allowed.
#[derive(Debug, PartialEq)]
pub enum Method {
    Get,
    Post,
}

/// A parsed HTTP/1.1 request.
#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// An HTTP response ready to be written to the wire.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Serialise the response into bytes suitable for writing
    /// directly to a TlsStream.
    /// Format: status line + headers + blank line + body.
    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();

        // Status line
        out.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status, self.reason)
                .as_bytes(),
        );

        // Headers
        for (name, value) in &self.headers {
            out.extend_from_slice(
                format!("{}: {}\r\n", name, value).as_bytes(),
            );
        }

        // Content-Length is always set — required by HTTP/1.1
        out.extend_from_slice(
            format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
        );

        // Blank line separates headers from body
        out.extend_from_slice(b"\r\n");

        // Body
        out.extend_from_slice(&self.body);

        out
    }

    /// Convenience constructor for a 400 Bad Request response.
    pub fn bad_request() -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            headers: Vec::new(),
            body: b"400 Bad Request".to_vec(),
        }
    }

    /// Convenience constructor for a 405 Method Not Allowed response.
    pub fn method_not_allowed() -> Self {
        Self {
            status: 405,
            reason: "Method Not Allowed",
            headers: vec![
                ("Allow".to_string(), "GET, POST".to_string()),
            ],
            body: b"405 Method Not Allowed".to_vec(),
        }
    }

    /// Convenience constructor for a 413 Payload Too Large response.
    pub fn payload_too_large() -> Self {
        Self {
            status: 413,
            reason: "Payload Too Large",
            headers: Vec::new(),
            body: b"413 Payload Too Large".to_vec(),
        }
    }

    /// Convenience constructor for a 505 HTTP Version Not Supported.
    /// HTTP/1.0 and below are explicitly not supported.
    /// This is a permanent architectural decision, not a known issue.
    pub fn version_not_supported() -> Self {
        Self {
            status: 505,
            reason: "HTTP Version Not Supported",
            headers: Vec::new(),
            body: b"505 HTTP Version Not Supported".to_vec(),
        }
    }
}

/// The outcome of parsing a request from bytes that may arrive in parts.
#[derive(Debug)]
pub enum ParseOutcome {
    /// The buffer contained a complete, well-formed request.
    Complete(Request),
    /// The buffer does not yet hold the full request — the header section
    /// or the Content-Length body has not fully arrived. This is NOT an
    /// error: a request legitimately arrives split across TCP segments and
    /// TLS records. The caller should read more bytes and parse again.
    Incomplete,
    /// The bytes form a malformed or over-limit request. The response is
    /// ready to send directly to the client.
    Rejected(Response),
}

/// Parse a raw byte buffer into a Request.
/// The buffer may hold only part of the request — see ParseOutcome.
///
/// Design: fail fast and fail loudly for malformed input. But a request
/// whose bytes simply have not all arrived yet is not malformed; it yields
/// Incomplete so the caller can keep reading instead of rejecting a request
/// that would have parsed fine once the rest of its body arrived.
pub fn parse_request(buf: &[u8]) -> ParseOutcome {
    // Find the end of the header section first.
    let header_end = match find_header_end(buf) {
        Some(e) => e,
        None => {
            // No header terminator in the buffer yet.
            if buf.len() >= MAX_HEADER_SIZE {
                // Over the header budget with no terminator — more bytes
                // cannot make this valid.
                return ParseOutcome::Rejected(Response::payload_too_large());
            }
            // Headers may still be arriving — ask the caller for more.
            return ParseOutcome::Incomplete;
        }
    };

    // Parse the header section as UTF-8 text.
    // HTTP/1.1 headers must be ASCII — UTF-8 is a superset of ASCII
    // so this is correct and slightly more permissive than necessary.
    let header_section = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return ParseOutcome::Rejected(Response::bad_request()),
    };

    let mut lines = header_section.lines();

    // Parse the request line: METHOD PATH HTTP/VERSION
    let request_line = match lines.next() {
        Some(l) => l,
        None => return ParseOutcome::Rejected(Response::bad_request()),
    };

    let mut parts = request_line.splitn(3, ' ');

    let method = match parts.next() {
        Some("GET") => Method::Get,
        Some("POST") => Method::Post,
        Some(_) => return ParseOutcome::Rejected(Response::method_not_allowed()),
        None => return ParseOutcome::Rejected(Response::bad_request()),
    };

    let path = match parts.next() {
        Some(p) => p.to_string(),
        None => return ParseOutcome::Rejected(Response::bad_request()),
    };

    // Enforce HTTP/1.1 only.
    // Permanent decision — see Explicit Design Decisions in http.md.
    match parts.next() {
        Some("HTTP/1.1") => {}
        Some(_) => return ParseOutcome::Rejected(Response::version_not_supported()),
        None => return ParseOutcome::Rejected(Response::bad_request()),
    }

    // Parse headers into a HashMap.
    // Header names are lowercased for case-insensitive lookup —
    // HTTP/1.1 header names are case-insensitive per RFC 7230.
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(nv) => nv,
            None => return ParseOutcome::Rejected(Response::bad_request()),
        };
        headers.insert(
            name.trim().to_lowercase(),
            value.trim().to_string(),
        );
    }

    // Parse body if present.
    // Body length is determined by the Content-Length header.
    // No Content-Length means no body — correct for GET requests.
    let body = if let Some(len_str) = headers.get("content-length") {
        let content_length: usize = match len_str.trim().parse() {
            Ok(l) => l,
            Err(_) => return ParseOutcome::Rejected(Response::bad_request()),
        };

        if content_length > MAX_BODY_SIZE {
            return ParseOutcome::Rejected(Response::payload_too_large());
        }

        let body_start = header_end + 4; // skip past \r\n\r\n
        if buf.len() < body_start + content_length {
            // Header section is complete but the body has not fully
            // arrived — read more before parsing.
            return ParseOutcome::Incomplete;
        }

        buf[body_start..body_start + content_length].to_vec()
    } else {
        Vec::new()
    };

    ParseOutcome::Complete(Request { method, path, headers, body })
}

/// Find the end of the HTTP header section.
/// Headers end at the first occurrence of \r\n\r\n.
/// Returns the index of the \r in the terminating \r\n\r\n,
/// or None if not found within MAX_HEADER_SIZE bytes.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let search_limit = buf.len().min(MAX_HEADER_SIZE);
    buf[..search_limit]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full GET request.
    fn get_request() -> Vec<u8> {
        b"GET / HTTP/1.1\r\nHost: mhebert.dev\r\n\r\n".to_vec()
    }

    /// The header section of a POST with a 5-byte body.
    fn post_headers() -> Vec<u8> {
        b"POST /pow/verify HTTP/1.1\r\nHost: mhebert.dev\r\n\
          Content-Type: application/x-www-form-urlencoded\r\n\
          Content-Length: 5\r\n\r\n"
            .iter()
            .copied()
            .collect()
    }

    #[test]
    fn complete_get_parses() {
        let outcome = parse_request(&get_request());
        match outcome {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.method, Method::Get);
                assert_eq!(req.path, "/");
                assert!(req.body.is_empty());
            }
            _ => panic!("complete GET should parse, got {outcome:?}"),
        }
    }

    #[test]
    fn complete_post_parses_body() {
        let mut buf = post_headers();
        buf.extend_from_slice(b"hello");
        match parse_request(&buf) {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.method, Method::Post);
                assert_eq!(req.path, "/pow/verify");
                assert_eq!(req.body, b"hello");
            }
            _ => panic!("complete POST should parse"),
        }
    }

    #[test]
    fn post_without_body_is_incomplete() {
        // Header terminator present, Content-Length advertises a body that
        // has not arrived yet — must be Incomplete, not rejected.
        let outcome = parse_request(&post_headers());
        assert!(
            matches!(outcome, ParseOutcome::Incomplete),
            "missing body should be Incomplete, got {outcome:?}"
        );
    }

    #[test]
    fn post_split_across_reads_accumulates() {
        // Simulate the real failure: headers arrive first, body in a later
        // read. Parsing after each read must not reject the request.
        let buf = post_headers();
        match parse_request(&buf) {
            ParseOutcome::Incomplete => {}
            other => panic!("first read (headers only) should be Incomplete, got {other:?}"),
        }

        let mut buf = post_headers();
        buf.extend_from_slice(b"he"); // partial body in a second read
        match parse_request(&buf) {
            ParseOutcome::Incomplete => {}
            other => panic!("partial body should still be Incomplete, got {other:?}"),
        }

        buf.extend_from_slice(b"llo"); // rest of the body
        match parse_request(&buf) {
            ParseOutcome::Complete(req) => assert_eq!(req.body, b"hello"),
            other => panic!("full request should parse, got {other:?}"),
        }
    }

    #[test]
    fn partial_headers_are_incomplete() {
        // No \r\n\r\n yet and well under the header cap: keep reading.
        let buf = b"POST /pow/verify HTTP/1.1\r\nHost: mhebert".to_vec();
        assert!(matches!(parse_request(&buf), ParseOutcome::Incomplete));
    }

    #[test]
    fn malformed_request_is_rejected() {
        // Garbage that can never become valid must be Rejected, not spin.
        let outcome = parse_request(b"not http\r\n\r\n".as_ref());
        assert!(matches!(outcome, ParseOutcome::Rejected(_)));
    }
}
