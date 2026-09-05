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

/// Serve /transparency — what this server records, and what it never does.
/// Public pre-gate like robots.txt: the page is the journal explaining
/// itself to a visitor who has not solved anything yet, so the gate must not
/// stand between them and it. It is a normal `.page` HTML document and gets
/// the full security header set from the router.
pub fn transparency() -> Response {
    html_response(include_str!("../../static/transparency.html"))
}

/// Serve /robots.txt for crawlers.
/// This is a public pre-gate route: a bot that must solve the puzzle to read
/// the crawl rules would never crawl anything. The router calls it before the
/// session check.
pub fn robots() -> Response {
    disk_asset("static/robots.txt", "text/plain; charset=utf-8")
}

/// Serve /.well-known/security.txt (RFC 9116) for security researchers.
/// Also public pre-gate, for the same reason as robots.txt: the file is the
/// address a researcher uses to report a flaw, and hiding that address
/// behind the gate hides the way in. The file lives at static/security.txt;
/// only the URL is /.well-known/security.txt.
pub fn security_txt() -> Response {
    disk_asset("static/security.txt", "text/plain; charset=utf-8")
}

/// Read a plain-text file from disk and serve it. Missing file becomes the
/// standard 404 page. No cache: robots rules and a security contact must be
/// read fresh, not from a stale copy.
fn disk_asset(path: &str, content_type: &str) -> Response {
    std::fs::read(path).map_or_else(
        |_| not_found(),
        |bytes| Response {
            status: 200,
            reason: "OK",
            headers: vec![
                ("Content-Type".to_string(), content_type.to_string()),
                ("Cache-Control".to_string(), "no-cache".to_string()),
            ],
            body: bytes,
        },
    )
}

/// Serve a static asset from the /static/ path prefix.
/// Path validation happens here — not in the router.
/// Prevents directory traversal attacks.
pub fn static_asset(path: &str) -> Response {
    // Strip the /static/ prefix to get the filename.
    let Some(filename) = path.strip_prefix("/static/") else {
        return not_found();
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
    let file_path = format!("static/{filename}");
    std::fs::read(&file_path).map_or_else(
        |_| not_found(),
        |bytes| Response {
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
    )
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
/// The body is one sentence that reads like the site, not a bare reason
/// line. Every miss is real: the server wrote the request into its journal.
/// Shared by the router's catch-all so a gated unknown path and a missing
/// asset answer in the same voice.
pub fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: b"<html><body><p>Nothing lives at that address, and the server wrote your visit into its journal.</p></body></html>".to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exhaustive audit (2026-09-04) — /static/ path traversal containment.
    // The http.rs parser keeps %2e%2e literal (no decoder exists anywhere),
    // so the only way to reach the filesystem is through static_asset, which
    // rejects any filename containing a real '/' or "..". These lock that in.

    #[test]
    fn literal_parent_dotdot_is_rejected_before_fs() {
        assert_eq!(static_asset("/static/../etc/passwd").status, 404);
        assert_eq!(static_asset("/static/..%2fsecret").status, 404, "contains '..'");
        assert_eq!(static_asset("/static/%2e./x").status, 404);
    }

    #[test]
    fn percent_encoded_traversal_never_reaches_fs() {
        // Encoded-only traversal names a literal "%"-containing file that
        // does not exist; any real separator that would change directory is
        // rejected outright. Either way: 404, never fs::read of a parent.
        assert_eq!(static_asset("/static/%2e%2e%2fetc%2fpasswd").status, 404);
        assert_eq!(static_asset("/static/%2e%2e/x").status, 404, "real '/' rejected");
        assert_eq!(static_asset("/static/%2e%2e").status, 404);
    }

    #[test]
    fn real_css_asset_serves_200() {
        // Sanity: the guard above is not rejecting everything.
        let r = static_asset("/static/style.css");
        assert_eq!(r.status, 200);
        assert!(
            r.headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "text/css")
        );
    }

    #[test]
    fn favicon_serves_200_with_icon_type() {
        let r = static_asset("/static/favicon.ico");
        assert_eq!(r.status, 200);
        assert!(
            r.headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "image/x-icon")
        );
        assert!(!r.body.is_empty(), "the icon carries image bytes");
        // ICO container magic: reserved 00 00, type 01 00 (icon).
        assert_eq!(&r.body[..4], &[0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn every_page_head_declares_the_favicon() {
        // A page without a declared icon makes the browser fall back to
        // /favicon.ico, which 404s and pollutes the audit log on every load.
        // All five gated pages must name the real asset.
        let request = Request {
            method: crate::http::Method::Get,
            path: String::new(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
        };
        for page in [index, about, projects, writing, contact] {
            let response = page(&request);
            let body = String::from_utf8(response.body).expect("html is utf-8");
            assert!(
                body.contains(r#"<link rel="icon" href="/static/favicon.ico">"#),
                "page head must declare the favicon"
            );
        }
    }

    #[test]
    fn transparency_page_declares_favicon_and_stylesheet() {
        let response = transparency();
        let body = String::from_utf8(response.body).expect("html is utf-8");
        assert!(body.contains(r#"<link rel="icon" href="/static/favicon.ico">"#));
        assert!(body.contains(r#"<link rel="stylesheet" href="/static/style.css">"#));
    }
}
