use crate::http::{Method, Request, Response};
use crate::middleware::{headers, session};
use crate::handlers::{challenge, content};

/// Entry point for all request routing.
/// Every request passes through here — no exceptions.
///
/// Middleware order is fixed and deliberate:
/// 1. Session verification (PoW challenge gate)
/// 2. Handler dispatch (method + path matching)
/// 3. Security header injection (every response)
pub fn handle(request: Request) -> Response {
    // Step 1 — Session verification.
    // If the request does not carry a valid session cookie,
    // short-circuit immediately and serve the PoW challenge.
    // The handler never runs for unverified requests.
    // This is the zero trust enforcement point.
    if !session::is_valid(&request) {
        let challenge_response = challenge::serve(&request);
        return headers::inject(challenge_response);
    }

    // Step 2 — Handler dispatch.
    // Route on method + path. Only explicitly listed routes
    // are valid. Everything else returns 404.
    // Adding a route requires changing this match statement —
    // intentional, see router.md Explicit Design Decisions.
    let response = match (&request.method, request.path.as_str()) {
        // PoW solution submission — POST only.
        // The browser submits the computed nonce here.
        (Method::Post, "/pow/verify") => {
            crate::middleware::pow::verify(&request)
        }

        // Main portfolio content — GET only.
        (Method::Get, "/") => content::index(&request),
        (Method::Get, "/about") => content::about(&request),
        (Method::Get, "/projects") => content::projects(&request),
        (Method::Get, "/writing") => content::writing(&request),
        (Method::Get, "/contact") => content::contact(&request),

        // WASM bundle and static assets — GET only.
        // These are served to the challenge page before session
        // verification passes — the only exception to the zero
        // trust gate above. The challenge page needs the WASM
        // bundle to solve the PoW puzzle.
        (Method::Get, path) if path.starts_with("/static/") => {
            content::static_asset(path)
        }

        // Catch-all — 404 for anything not explicitly listed.
        _ => Response {
            status: 404,
            reason: "Not Found",
            headers: Vec::new(),
            body: b"404 Not Found".to_vec(),
        },
    };

    // Step 3 — Security header injection.
    // Runs on every response regardless of which handler produced it.
    // Headers include CSP, HSTS, X-Frame-Options, etc.
    // Defined in middleware/headers.rs.
    headers::inject(response)
}
