use crate::http::{Request, Response};

/// Marker the static contact page carries where the PGP fingerprint lands.
/// `content::contact` replaces it at serve time with `pgp::fingerprint_display`,
/// so the printed value always belongs to the key the /.well-known endpoints
/// actually serve, and the repo never stores the fingerprint in two places.
const FINGERPRINT_MARKER: &str = "{{FINGERPRINT}}";

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
/// The PGP fingerprint block is inserted at serve time from the embedded key
/// (see [`FINGERPRINT_MARKER`]), so the fingerprint a visitor reads always
/// matches the key the /.well-known endpoints serve.
pub fn contact(_request: &Request) -> Response {
    let html = include_str!("../../static/contact.html")
        .replace(FINGERPRINT_MARKER, &crate::pgp::fingerprint_display());
    html_response(&html)
}

/// Serve a project writeup at /projects/<slug>.
/// The writeups are Markdown files read from disk once at startup (see
/// writeup.rs); this handler only looks the slug up in that already-loaded
/// store, so a request can never touch the filesystem. A slug the store does
/// not hold (an unknown project, a traversal attempt, a trailing slash) gets
/// the shared 404, exactly like any other miss.
pub fn project(path: &str) -> Response {
    let Some(slug) = path.strip_prefix("/projects/") else {
        return not_found();
    };
    crate::writeup::get(slug).map_or_else(not_found, |page| html_response(&page.html))
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

/// Serve the ASCII-armored `OpenPGP` public key at /.well-known/pgp. Public
/// pre-gate like security.txt: a researcher who wants to encrypt a report
/// fetches this key before solving anything. The body is the committed
/// armor itself (pgp.rs embeds it), so the wire artifact is exactly what
/// sits in the repo and stays reviewable.
pub fn pgp_armored() -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: vec![
            (
                "Content-Type".to_string(),
                "application/pgp-keys".to_string(),
            ),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body: crate::pgp::armored().as_bytes().to_vec(),
    }
}

/// Serve the Web Key Directory policy file (direct method). The WKD spec
/// requires this file at /.well-known/openpgpkey/policy for the directory
/// to be valid; an empty body is explicitly sufficient.
pub fn pgp_policy() -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: vec![
            (
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body: Vec::new(),
    }
}

/// Serve the binary `OpenPGP` key at a Web Key Directory leaf,
/// /.well-known/openpgpkey/hu/<hash>. Only the leaf a WKD client computes
/// for the site mailbox answers; any other hash names a mailbox this site
/// does not hold and gets the standard 404. A query string carrying the
/// local part (?l=...) is tolerated. The spec wants binary on the wire,
/// with application/octet-stream.
pub fn pgp_wkd(path: &str) -> Response {
    let Some(rest) = path.strip_prefix(crate::pgp::WKD_PREFIX) else {
        return not_found();
    };
    let leaf = rest.split(['?', '/']).next().unwrap_or("");
    if leaf == crate::pgp::wkd_leaf() {
        Response {
            status: 200,
            reason: "OK",
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/octet-stream".to_string(),
                ),
                ("Cache-Control".to_string(), "no-cache".to_string()),
            ],
            body: crate::pgp::binary().to_vec(),
        }
    } else {
        not_found()
    }
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
        Some((_, "css")) => "text/css",
        Some((_, "js")) => "application/javascript",
        Some((_, "wasm")) => "application/wasm",
        Some((_, "ico")) => "image/x-icon",
        Some((_, "png")) => "image/png",
        Some((_, "svg")) => "image/svg+xml",
        _ => "application/octet-stream",
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
                (
                    "Cache-Control".to_string(),
                    "public, max-age=3600".to_string(),
                ),
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
///
/// Each 404 also plants a canary token: 16 random bytes, hex encoded, on a
/// data attribute of an invisible span (see canary.rs). The token rides the
/// request's audit line, and a later request that echoes it back trips a
/// CANARY alert. The span is hidden with the `hidden` attribute, not inline
/// styling, because these pages carry a style-src CSP.
pub fn not_found() -> Response {
    let token = crate::canary::mint();
    let body = format!(
        "<html><body><p>Nothing lives at that address, and the server wrote your visit into its journal.</p><span data-c=\"{token}\" hidden></span></body></html>"
    );
    Response {
        status: 404,
        reason: "Not Found",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: body.into_bytes(),
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
        assert_eq!(
            static_asset("/static/..%2fsecret").status,
            404,
            "contains '..'"
        );
        assert_eq!(static_asset("/static/%2e./x").status, 404);
    }

    #[test]
    fn percent_encoded_traversal_never_reaches_fs() {
        // Encoded-only traversal names a literal "%"-containing file that
        // does not exist; any real separator that would change directory is
        // rejected outright. Either way: 404, never fs::read of a parent.
        assert_eq!(static_asset("/static/%2e%2e%2fetc%2fpasswd").status, 404);
        assert_eq!(
            static_asset("/static/%2e%2e/x").status,
            404,
            "real '/' rejected"
        );
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

    #[test]
    fn known_project_writeup_serves_from_the_loaded_store() {
        // The writeup store is loaded at startup; this test seeds it from a
        // fixture so the handler serves the same way it would in production.
        crate::writeup::seed_test_pages();
        let response = project("/projects/sample");
        assert_eq!(response.status, 200);
        assert!(
            response
                .headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "text/html; charset=utf-8")
        );
        let body = String::from_utf8(response.body).expect("html is utf-8");
        assert!(body.contains(r#"<link rel="icon" href="/static/favicon.ico">"#));
        assert!(body.contains("<h1 class=\"page-title\">sample</h1>"));
        assert!(
            body.contains("<h2>A section</h2>"),
            "markdown body is rendered"
        );
        assert!(body.contains("served by <code>zero-trust-server</code>"));
    }

    #[test]
    fn not_found_plants_a_unique_invisible_canary_span() {
        // Each 404 mints a fresh token, embeds it as a data attribute on an
        // invisible span, and leaves it pending for the audit line. Two 404s
        // must never carry the same token: uniqueness is what makes a later
        // echo attributable to a specific miss.
        let first = not_found();
        let token_a = crate::canary::take_pending().expect("404 reports its token");
        not_found();
        let token_b = crate::canary::take_pending().expect("404 reports its token");
        assert_ne!(token_a, token_b, "each 404 mints a fresh canary");
        assert_eq!(token_a.len(), 32);
        let body = String::from_utf8(first.body).expect("404 body is utf-8");
        assert!(
            body.contains(&format!("data-c=\"{token_a}\"")),
            "token on the span"
        );
        assert!(body.contains("<span"), "token rides an explicit span");
        assert!(
            body.contains(" hidden"),
            "span is invisible without inline style"
        );
    }

    #[test]
    fn unknown_or_malformed_project_slug_is_404() {
        crate::writeup::seed_test_pages();
        // A real slug the store does not hold, a traversal attempt, and a
        // bare "/projects/" all miss — none of them names a loaded page.
        assert_eq!(project("/projects/second").status, 200, "second is loaded");
        for path in [
            "/projects/does-not-exist",
            "/projects/../static/style.css",
            "/projects/",
            "/projects",
        ] {
            assert_eq!(project(path).status, 404, "{path} must miss");
        }
    }

    #[test]
    fn contact_page_prints_the_fingerprint_of_the_served_key() {
        // The fingerprint block on the rendered contact page must name the
        // same key the WKD and /.well-known/pgp endpoints serve. A visitor
        // who verifies the printed value against a key fetched from WKD
        // would otherwise see the two disagree.
        let request = Request {
            method: crate::http::Method::Get,
            path: String::new(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
        };
        let body = String::from_utf8(contact(&request).body).expect("html is utf-8");
        assert!(
            body.contains(&crate::pgp::fingerprint_display()),
            "the rendered page must carry the fingerprint of the embedded key"
        );
        assert!(
            !body.contains("{{FINGERPRINT}}"),
            "the marker is always replaced before serving"
        );
    }

    #[test]
    fn pgp_armored_and_policy_serve_static_machine_readable_bodies() {
        let key = pgp_armored();
        assert_eq!(key.status, 200);
        assert!(
            key.headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "application/pgp-keys")
        );
        let body = String::from_utf8(key.body).expect("armor is ascii");
        assert!(
            body.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            "the armored key is served verbatim"
        );

        let policy = pgp_policy();
        assert_eq!(policy.status, 200);
        assert!(
            policy.body.is_empty(),
            "an empty WKD policy file is spec-legal"
        );
    }

    #[test]
    fn wkd_leaf_is_served_binary_and_unknown_leafs_miss() {
        let leaf = crate::pgp::wkd_leaf();
        let hit = pgp_wkd(&format!("/.well-known/openpgpkey/hu/{leaf}"));
        assert_eq!(hit.status, 200);
        assert!(
            hit.headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "application/octet-stream")
        );
        assert_eq!(
            hit.body,
            crate::pgp::binary(),
            "the wire bytes are the binary key"
        );

        // A query string carrying the local part must not break the match.
        let queried = pgp_wkd(&format!("/.well-known/openpgpkey/hu/{leaf}?l=admin"));
        assert_eq!(queried.status, 200);

        // Any other hash names a mailbox the site does not hold.
        assert_eq!(
            pgp_wkd("/.well-known/openpgpkey/hu/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").status,
            404
        );
    }
}
