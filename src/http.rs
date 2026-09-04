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
    /// Routed exactly like GET but answered bodyless (RFC 9110: HEAD must be
    /// supported wherever GET is, returning the GET headers — including
    /// Content-Length — minus the body). The router treats it as GET; the
    /// serializer suppresses the body at the wire (see Response::into_bytes).
    Head,
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
    /// Serialise the response into bytes suitable for writing directly to a
    /// TlsStream. This is the SINGLE wire funnel every response flows through
    /// — per-request framing lives here and only here:
    ///
    ///   * Content-Length always reflects the full body length. For a HEAD
    ///     response (`head == true`) the length is that of the body a GET
    ///     would have carried, but the body bytes themselves are omitted
    ///     (RFC 9110 §9.3.2).
    ///   * `Connection: close` is always announced. The server answers at
    ///     most one request per connection and then closes it, so every
    ///     response — 200, 301, 404, 405, 413, 503, … — must say so rather
    ///     than leave a client expecting keep-alive. No caller may add the
    ///     header itself (nor Content-Length): that would duplicate it.
    pub fn into_bytes(self, head: bool) -> Vec<u8> {
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

        // Content-Length is always set — required by HTTP/1.1, and for HEAD
        // it is the length the corresponding GET would have sent.
        out.extend_from_slice(
            format!("Content-Length: {}\r\n", self.body.len()).as_bytes(),
        );

        out.extend_from_slice(b"Connection: close\r\n");

        // Blank line separates headers from body
        out.extend_from_slice(b"\r\n");

        // Body — suppressed for HEAD (headers above already carried its
        // length).
        if !head {
            out.extend_from_slice(&self.body);
        }

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
                ("Allow".to_string(), "GET, HEAD, POST".to_string()),
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

    // Reject control characters inside the request line. HTTP/1.1 delimits
    // lines with CRLF and str::lines() has already stripped that trailing
    // terminator, so a well-formed request line contains no CR or LF. A lone
    // CR (not followed by LF) or other CTL would otherwise survive verbatim
    // into `path` — RFC 9112 §3.2 requires rejecting a request-target that
    // contains such bytes rather than echoing them anywhere downstream.
    if request_line.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return ParseOutcome::Rejected(Response::bad_request());
    }

    let mut parts = request_line.splitn(3, ' ');

    let method = match parts.next() {
        Some("GET") => Method::Get,
        Some("HEAD") => Method::Head,
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
        let name = name.trim().to_lowercase();
        let value = value.trim().to_string();

        // Content-Length duplicates with differing values are a classic
        // request-smuggling ambiguity and MUST be rejected (RFC 9112 §7.3.1).
        // Repeated identical values are unambiguous and tolerated. (A real
        // attacker never sends two equal ones; a legitimate client never
        // sends two at all.)
        if name == "content-length"
            && let Some(prev) = headers.get("content-length")
            && prev != &value
        {
            return ParseOutcome::Rejected(Response::bad_request());
        }

        headers.insert(name, value);
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

    #[test]
    fn unsupported_method_is_rejected_405() {
        // PUT, DELETE, OPTIONS … are rejected at parse time. (HEAD is not in
        // the list — it now parses; see head_parses_as_head.) This is the
        // response main.rs must run through headers::inject before sending
        // (it never reaches router::handle) — that was the "405s skip
        // security headers" bypass.
        for method in ["PUT", "DELETE", "OPTIONS", "PATCH"] {
            let req = format!("{method} / HTTP/1.1\r\nHost: mhebert.dev\r\n\r\n");
            match parse_request(req.as_bytes()) {
                ParseOutcome::Rejected(r) => {
                    assert_eq!(r.status, 405, "{method} should reject 405");
                    assert!(
                        r.headers.iter().any(|(n, _)| n == "Allow"),
                        "{method} 405 must carry an Allow header",
                    );
                }
                other => panic!("{method} should be Rejected(405), got {other:?}"),
            }
        }
    }

    #[test]
    fn head_parses_as_head() {
        // HEAD is a first-class method now (RFC 9110), not a 405.
        let buf = b"HEAD / HTTP/1.1\r\nHost: mhebert.dev\r\n\r\n";
        match parse_request(buf.as_ref()) {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.method, Method::Head);
                assert_eq!(req.path, "/");
                assert!(req.body.is_empty());
            }
            other => panic!("HEAD should parse, got {other:?}"),
        }
    }

    #[test]
    fn serialization_sets_content_length_and_connection_close() {
        let full = sample_response().into_bytes(false);
        let s = String::from_utf8_lossy(&full);
        assert!(s.contains("Content-Length: 2\r\n"), "got: {s}");
        assert!(
            s.contains("Connection: close\r\n"),
            "every response must announce close, got: {s}"
        );
        assert!(full.ends_with(b"hi"));
    }

    #[test]
    fn head_serialization_keeps_length_drops_body() {
        // HEAD must carry the GET Content-Length but no body bytes — and the
        // two wire images differ only by the omitted body.
        let full = sample_response().into_bytes(false);
        let head = sample_response().into_bytes(true);

        assert!(String::from_utf8_lossy(&head).contains("Content-Length: 2\r\n"));
        assert!(!head.ends_with(b"hi"));
        assert_eq!(full.len(), head.len() + 2, "HEAD image = GET image minus body");
    }

    fn sample_response() -> Response {
        Response {
            status: 200,
            reason: "OK",
            headers: vec![
                ("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()),
            ],
            body: b"hi".to_vec(),
        }
    }

    // ── Exhaustive audit (2026-09-04) — HTTP parser edge cases ──────────────

    #[test]
    fn post_with_content_length_zero_parses_empty_body() {
        // A legitimate Content-Length: 0 on POST (e.g. an empty form submit)
        // must parse as Complete with an empty body, not hang as Incomplete.
        let buf = b"POST /pow/verify HTTP/1.1\r\n\
                    Host: mhebert.dev\r\n\
                    Content-Length: 0\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.method, Method::Post);
                assert!(req.body.is_empty(), "CL:0 POST carries no body");
            }
            other => panic!("Content-Length: 0 should parse, got {other:?}"),
        }
    }

    #[test]
    fn differing_duplicate_content_length_is_rejected() {
        // Two Content-Length headers with different values = the canonical
        // request-smuggling ambiguity. After the 2026-09-04 hardening the
        // parser rejects (400) instead of silently letting the last one win.
        let buf = b"POST /pow/verify HTTP/1.1\r\n\
                    Host: mhebert.dev\r\n\
                    Content-Length: 5\r\n\
                    Content-Length: 6\r\n\r\nhello";
        match parse_request(buf) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 400),
            other => panic!("conflicting Content-Length must be Rejected(400), got {other:?}"),
        }
    }

    #[test]
    fn identical_duplicate_content_length_is_accepted() {
        // Repeated identical Content-Length values are unambiguous per
        // RFC 9112 §7.3.1 and tolerated.
        let buf = b"POST /pow/verify HTTP/1.1\r\n\
                    Host: mhebert.dev\r\n\
                    Content-Length: 5\r\n\
                    Content-Length: 5\r\n\r\nhello";
        match parse_request(buf) {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.body, b"hello");
            }
            other => panic!("identical Content-Length should parse, got {other:?}"),
        }
    }

    #[test]
    fn percent_encoded_dotdot_is_kept_literal_not_decoded() {
        // The parser is deliberately not a percent-decoder: %2e%2e stays
        // %2e%2e in `path`. Nothing downstream decodes it either (fs access
        // in content::static_asset blocks literal `/` and `..` and never sees
        // a decoded path), so URL-encoded traversal is inert. The assertion
        // here locks in that no decoding/normalization happens at parse time.
        let buf = b"GET /static/%2e%2e%2fetc%2fpasswd HTTP/1.1\r\n\
                    Host: mhebert.dev\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Complete(req) => {
                assert_eq!(
                    req.path,
                    "/static/%2e%2e%2fetc%2fpasswd",
                    "parser must not decode or normalize the path"
                );
            }
            other => panic!("encoded path should parse verbatim, got {other:?}"),
        }
    }

    #[test]
    fn embedded_crlf_splits_request_line_is_rejected() {
        // A premature CRLF that tries to inject a second request line
        // ("request splitting") lands the forged line in the header section
        // where it has no ':' — rejected, never executed as a second request.
        let buf = b"GET / HTTP/1.1\r\nPOST /admin HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 400),
            other => panic!("smuggled second request line must be Rejected(400), got {other:?}"),
        }
    }

    #[test]
    fn lone_cr_in_request_target_is_rejected() {
        // A single \r not followed by \n previously survived verbatim into
        // `path` (lines() only strips a trailing CR). After the 2026-09-04
        // hardening, any control byte in the request line is rejected.
        let buf = b"GET /a\rb HTTP/1.1\r\nHost: x\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 400),
            other => panic!("lone CR in request target must be Rejected(400), got {other:?}"),
        }
    }

    #[test]
    fn header_value_crlf_becomes_separate_headers_not_one_tampered_value() {
        // A raw CRLF inside what the attacker *intends* as one header value is
        // just HTTP's line terminator: the parser reads it as two discrete
        // headers. No stored header value can therefore contain a CR or LF —
        // verify none do, and that a would-be injected header is visible as a
        // separate, inert entry (nothing downstream echoes request headers).
        let buf = b"GET / HTTP/1.1\r\n\
                    Host: mhebert.dev\r\n\
                    X-Contained: a\r\n\
                    X-Injected: evil\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Complete(req) => {
                assert_eq!(req.headers.get("host").map(String::as_str), Some("mhebert.dev"));
                assert_eq!(req.headers.get("x-contained").map(String::as_str), Some("a"));
                assert_eq!(req.headers.get("x-injected").map(String::as_str), Some("evil"));
                for value in req.headers.values() {
                    assert!(
                        !value.contains(['\r', '\n']),
                        "no parsed header value may contain a line break: {value:?}"
                    );
                }
            }
            other => panic!("multi-line headers should parse, got {other:?}"),
        }
    }

    #[test]
    fn obs_fold_without_colon_is_rejected() {
        // HTTP/1.1 obsolete line folding (a continuation line starting with a
        // space) is not supported. The continuation line has no ':' → 400.
        let buf = b"GET / HTTP/1.1\r\n\
                    Host: x\r\n\
                    \tfolded continuation\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 400),
            other => panic!("obs-fold continuation must be Rejected(400), got {other:?}"),
        }
    }

    #[test]
    fn content_length_overflowing_usize_is_rejected() {
        // A Content-Length that cannot fit in usize must 400, not panic or
        // wrap. parse::<usize> fails on overflow → bad_request.
        let buf = b"POST /pow/verify HTTP/1.1\r\n\
                    Host: x\r\n\
                    Content-Length: 99999999999999999999999999999999\r\n\r\n";
        match parse_request(buf) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 400),
            other => panic!("overflowing Content-Length must be Rejected(400), got {other:?}"),
        }
    }

    #[test]
    fn content_length_over_body_cap_is_rejected_413() {
        // A Content-Length that parses fine but exceeds MAX_BODY_SIZE must
        // answer 413 Payload Too Large before any body is buffered.
        let big = MAX_BODY_SIZE as u64 + 1;
        let buf = format!(
            "POST /pow/verify HTTP/1.1\r\nHost: x\r\nContent-Length: {big}\r\n\r\n"
        );
        match parse_request(buf.as_bytes()) {
            ParseOutcome::Rejected(r) => assert_eq!(r.status, 413),
            other => panic!("oversize Content-Length must be Rejected(413), got {other:?}"),
        }
    }
}
