use crate::http::{Request, Response};

/// Serve the portfolio index page.
pub fn index(_request: &Request) -> Response {
    stub_response(b"<html><body>Index stub</body></html>")
}

/// Serve the about page.
pub fn about(_request: &Request) -> Response {
    stub_response(b"<html><body>About stub</body></html>")
}

/// Serve the projects page.
pub fn projects(_request: &Request) -> Response {
    stub_response(b"<html><body>Projects stub</body></html>")
}

/// Serve the writing page.
pub fn writing(_request: &Request) -> Response {
    stub_response(b"<html><body>Writing stub</body></html>")
}

/// Serve the contact page.
pub fn contact(_request: &Request) -> Response {
    stub_response(b"<html><body>Contact stub</body></html>")
}

/// Serve a static asset from /static/.
/// Stub — real implementation reads from disk.
pub fn static_asset(_path: &str) -> Response {
    stub_response(b"static asset stub")
}

fn stub_response(body: &'static [u8]) -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: body.to_vec(),
    }
}
