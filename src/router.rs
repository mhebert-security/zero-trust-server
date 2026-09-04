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
    // Three things are public before the gate: the static assets the
    // challenge page needs (CSS/JS/WASM), the PoW submission endpoint, and
    // /health. An unverified visitor must be able to submit a solution to
    // /pow/verify to RECEIVE a session cookie; and /health must answer 200 to
    // a cookie-less uptime monitor. If either sat behind the session gate
    // below, the challenge could never complete (assets come back as
    // challenge HTML, the verify POST never reaches pow::verify) and an
    // external monitor would false-alarm on every check.

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

    // /health — minimal liveness probe for external uptime monitors (item:
    // public health endpoint). Pre-session, GET-only, static body: a 200 here
    // proves the full path (TLS, parse, routing, headers) is alive without
    // leaking anything. No cookie required.
    if request.method == Method::Get && request.path == "/health" {
        return headers::inject(Response {
            status: 200,
            reason: "OK",
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: b"ok".to_vec(),
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn request(method: Method, path: &str) -> Request {
        Request {
            method,
            path: path.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    fn has_header(resp: &Response, name: &str) -> bool {
        resp.headers.iter().any(|(n, _)| n == name)
    }

    #[test]
    fn health_is_public_and_injected() {
        // No cookie, no session — /health still answers 200 for the monitor,
        // and the full security header set is applied.
        let resp = handle(request(Method::Get, "/health"));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        assert!(has_header(&resp, "Content-Security-Policy"));
        assert!(has_header(&resp, "Strict-Transport-Security"));
        assert!(has_header(&resp, "X-Content-Type-Options"));
    }

    #[test]
    fn every_handler_response_is_injected() {
        // Reach the 404 catch-all (which sits AFTER the session gate) with a
        // valid session cookie, and confirm even the 404 carries CSP.
        // edition 2024 makes env::set_var unsafe — this test mints a real
        // cookie, so it needs the secret configured.
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let cookie = crate::middleware::session::issue_cookie().expect("cookie");
        let zts = cookie.split(';').next().unwrap().to_string();
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), zts);
        let req = Request {
            method: Method::Get,
            path: "/definitely-not-a-route".to_string(),
            headers,
            body: Vec::new(),
        };

        let resp = handle(req);
        assert_eq!(resp.status, 404);
        assert!(has_header(&resp, "Content-Security-Policy"));
        assert!(has_header(&resp, "Strict-Transport-Security"));
    }
}
