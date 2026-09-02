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

/// Parse a raw byte buffer into a Request.
/// Returns Ok(Request) on success.
/// Returns Err(Response) on any parse failure — the error response
/// is ready to send directly to the client.
///
/// Design: fail fast and fail loudly. Any deviation from valid
/// HTTP/1.1 syntax returns an error response immediately.
/// No leniency, no guessing intent.
pub fn parse_request(buf: &[u8]) -> Result<Request, Response> {
    // Enforce maximum header size before any parsing.
    // Find the end of the header section first.
    let header_end = find_header_end(buf)
        .ok_or_else(|| {
            if buf.len() >= MAX_HEADER_SIZE {
                Response::payload_too_large()
            } else {
                Response::bad_request()
            }
        })?;

    // Parse the header section as UTF-8 text.
    // HTTP/1.1 headers must be ASCII — UTF-8 is a superset of ASCII
    // so this is correct and slightly more permissive than necessary.
    let header_section = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| Response::bad_request())?;

    let mut lines = header_section.lines();

    // Parse the request line: METHOD PATH HTTP/VERSION
    let request_line = lines.next()
        .ok_or_else(Response::bad_request)?;

    let mut parts = request_line.splitn(3, ' ');

    let method = match parts.next().ok_or_else(Response::bad_request)? {
        "GET"  => Method::Get,
        "POST" => Method::Post,
        _      => return Err(Response::method_not_allowed()),
    };

    let path = parts.next()
        .ok_or_else(Response::bad_request)?
        .to_string();

    // Enforce HTTP/1.1 only.
    // Permanent decision — see Explicit Design Decisions in http.md.
    match parts.next().ok_or_else(Response::bad_request)? {
        "HTTP/1.1" => {}
        _ => return Err(Response::version_not_supported()),
    }

    // Parse headers into a HashMap.
    // Header names are lowercased for case-insensitive lookup —
    // HTTP/1.1 header names are case-insensitive per RFC 7230.
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')
            .ok_or_else(Response::bad_request)?;
        headers.insert(
            name.trim().to_lowercase(),
            value.trim().to_string(),
        );
    }

    // Parse body if present.
    // Body length is determined by the Content-Length header.
    // No Content-Length means no body — correct for GET requests.
    let body = if let Some(len_str) = headers.get("content-length") {
        let content_length: usize = len_str.trim().parse()
            .map_err(|_| Response::bad_request())?;

        if content_length > MAX_BODY_SIZE {
            return Err(Response::payload_too_large());
        }

        let body_start = header_end + 4; // skip past \r\n\r\n
        if buf.len() < body_start + content_length {
            return Err(Response::bad_request());
        }

        buf[body_start..body_start + content_length].to_vec()
    } else {
        Vec::new()
    };

    Ok(Request { method, path, headers, body })
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
