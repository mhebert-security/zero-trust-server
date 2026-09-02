use crate::http::Response;

/// Inject security headers into every response.
/// Stub — full headers in next commit.
pub fn inject(mut response: Response) -> Response {
    // These will expand to the full security header set.
    // Stub includes only the most critical headers.
    response.headers.push((
        "X-Frame-Options".to_string(),
        "DENY".to_string(),
    ));
    response.headers.push((
        "X-Content-Type-Options".to_string(),
        "nosniff".to_string(),
    ));
    response
}
