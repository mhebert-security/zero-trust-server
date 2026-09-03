use crate::http::{Method, Request, Response};
use crate::middleware::{headers, session};
use crate::handlers::{challenge, content};

/// Entry point for all request routing.
/// Every request passes through here — no exceptions.
///
/// Middleware order is fixed and deliberate:
/// 1. Public endpoints (static assets + /pow/verify) — pre-session
/// 2. Session verification (PoW challenge gate)
/// 3. Handler dispatch (method + path matching)
/// 4. Security header injection (every response)
pub fn handle(request: Request) -> Response {
    // Step 0 — Public endpoints reachable WITHOUT a session.
    // Exactly two things are public before the gate: the static assets the
    // challenge page needs (CSS/JS/WASM) and the PoW submission endpoint.
    // An unverified visitor must be able to submit a solution to /pow/verify
    // to RECEIVE a session cookie. If either sat behind the session gate
    // below, the challenge could never complete: assets would come back as
    // challenge HTML (wrong MIME type, module import fails) and the verify
    // POST would never reach pow::verify at all.

    // Static assets — the challenge page fetches these before a session
    // exists.
    if request.method == Method::Get && request.path.starts_with("/static/") {
        return headers::inject(content::static_asset(&request.path));
    }

    // PoW solution submission — the only way an unverified visitor obtains a
    // session. On success pow::verify returns 302 + Set-Cookie.
    if request.method == Method::Post && request.path == "/pow/verify" {
        return headers::inject(crate::middleware::pow::verify(&request));
    }

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
    // /pow/verify is NOT here — it is handled in Step 0 because it is
    // public (it issues the session cookie to unverified visitors).
    let response = match (&request.method, request.path.as_str()) {
        // Main portfolio content — GET only.
        (Method::Get, "/") => content::index(&request),
        (Method::Get, "/about") => content::about(&request),
        (Method::Get, "/projects") => content::projects(&request),
        (Method::Get, "/writing") => content::writing(&request),
        (Method::Get, "/contact") => content::contact(&request),

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
