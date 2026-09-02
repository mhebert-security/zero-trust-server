use crate::http::{Request, Response};

/// Serve the portfolio index page.
/// Verified visitors only — session check happens in router.rs.
pub fn index(_request: &Request) -> Response {
    html_response(include_str!("../../static/index.html"))
}

/// Serve the about page.
pub fn about(_request: &Request) -> Response {
    html_response(include_str!("../../static/about.html"))
}

/// Serve the projects page.
pub fn projects(_request: &Request) -> Response {
    html_response(include_str!("../../static/projects.html"))
}

/// Serve the writing page.
pub fn writing(_request: &Request) -> Response {
    html_response(include_str!("../../static/writing.html"))
}

/// Serve the contact page.
pub fn contact(_request: &Request) -> Response {
    html_response(include_str!("../../static/contact.html"))
}

/// Serve a static asset from the /static/ path prefix.
/// Path validation happens here — not in the router.
/// Prevents directory traversal attacks.
pub fn static_asset(path: &str) -> Response {
    // Strip the /static/ prefix to get the filename.
    let filename = match path.strip_prefix("/static/") {
        Some(f) => f,
        None => return not_found(),
    };

    // Reject any path containing traversal sequences.
    // A request for /static/../etc/passwd has filename ../etc/passwd
    // which contains ".." — reject immediately.
    if filename.contains("..") || filename.contains('/') {
        return not_found();
    }

    // Determine Content-Type from file extension.
    let content_type = match filename.rsplit_once('.') {
        Some((_, "html")) => "text/html; charset=utf-8",
        Some((_, "css"))  => "text/css",
        Some((_, "js"))   => "application/javascript",
        Some((_, "wasm")) => "application/wasm",
        Some((_, "ico"))  => "image/x-icon",
        Some((_, "png"))  => "image/png",
        Some((_, "svg"))  => "image/svg+xml",
        _                 => "application/octet-stream",
    };

    // Read the file from the static directory.
    // The static directory is at the project root.
    // Path is: static/{filename} — already validated above.
    let file_path = format!("static/{}", filename);
    match std::fs::read(&file_path) {
        Ok(bytes) => Response {
            status: 200,
            reason: "OK",
            headers: vec![
                ("Content-Type".to_string(), content_type.to_string()),
                // Static assets are cached aggressively.
                // → Open question: add content-hashed filenames
                //   for cache busting. See content.md.
                ("Cache-Control".to_string(),
                 "public, max-age=3600".to_string()),
            ],
            body: bytes,
        },
        Err(_) => not_found(),
    }
}

/// Build a standard HTML response.
fn html_response(html: &str) -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: html.as_bytes().to_vec(),
    }
}

/// Standard 404 response.
fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: b"<html><body>404 Not Found</body></html>".to_vec(),
    }
}
