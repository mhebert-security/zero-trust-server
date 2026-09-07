use std::net::IpAddr;

use crate::handlers::{admin, challenge, content};
use crate::http::{Method, Request, Response};
use crate::middleware::{headers, session};

/// Outcome of routing: the response to send, plus the session gate's ruling.
///
/// The response carries no memory of the request that produced it, but the
/// audit log needs to know whether the gate ran and how it ruled — so routing
/// returns both. The caller (the connection handler) pairs this with the
/// request-derived method/path it already captured.
pub struct Routed {
    pub response: Response,
    /// Some(true/false) when the session gate ran on this request; None for
    /// the public pre-gate routes (static assets, /pow/verify, /health,
    /// /robots.txt, security.txt, /transparency, /admin), which never
    /// consulted the session cookie.
    pub session: Option<bool>,
}

/// Entry point for all request routing.
/// Every request passes through here — no exceptions.
/// `peer` is the client's address, threaded down to the endpoints that need
/// it (the /pow/verify and /admin/login per-IP budgets); it is None only when
/// the connection layer could not resolve a socket address.
///
/// Middleware order is fixed and deliberate:
/// 1. Public endpoints (static assets + /pow/verify + /health) — pre-session
/// 2. Session verification (`PoW` challenge gate)
/// 3. Handler dispatch (method + path matching)
/// 4. Security header injection (every response)
pub fn handle(request: &Request, peer: Option<IpAddr>) -> Routed {
    // Step 0 — Public endpoints reachable WITHOUT a session. Each sits before
    // the gate for one shared reason: it is a surface a cookie-less visitor
    // must reach. If any of them ran behind the gate, the challenge could
    // never complete, an uptime monitor would false-alarm on every check, and
    // the operator would be locked out the moment they cleared their cookies.
    // public_route names them in order, with the reason per route.
    if let Some(response) = public_route(request, peer) {
        return Routed {
            response: headers::inject(response),
            session: None,
        };
    }

    // Step 1 — Session verification.
    // If the request does not carry a valid session cookie,
    // short-circuit immediately and serve the PoW challenge.
    // The handler never runs for unverified requests.
    // This is the zero trust enforcement point.
    if !session::is_valid(request) {
        let challenge_response = challenge::serve(request);
        return Routed {
            response: headers::inject(challenge_response),
            session: Some(false),
        };
    }

    // Step 2 — Handler dispatch.
    // Route on method + path. Only explicitly listed routes
    // are valid. Everything else returns 404.
    // Adding a route requires changing this match statement —
    // intentional, see router.md Explicit Design Decisions.
    // /pow/verify is NOT here — it is handled in Step 0 because it is
    // public (it issues the session cookie to unverified visitors).
    //
    // HEAD shares the GET handlers: it must answer any resource GET answers,
    // with the same headers and no body (RFC 9110). The serializer decides
    // whether to strip the body from the caller's knowledge of the method;
    // here it is enough to route HEAD exactly like GET.
    let is_get = matches!(request.method, Method::Get | Method::Head);
    let response = match (is_get, request.path.as_str()) {
        // Main portfolio content — GET/HEAD.
        (true, "/") => content::index(request),
        (true, "/about") => content::about(request),
        (true, "/projects") => content::projects(request),
        (true, "/writing") => content::writing(request),
        (true, "/contact") => content::contact(request),

        // Project writeups — /projects/<slug>. The slug is looked up in the
        // store of Markdown pages loaded at startup (content::project), never
        // on the filesystem, so an unknown slug, a traversal attempt, or a
        // trailing slash all fall through to the shared 404 below. The exact
        // "/projects" arm above wins, so the index and a writeup never
        // collide.
        (true, path) if path.starts_with("/projects/") => content::project(path),

        // Catch-all — 404 for anything not explicitly listed. Shared with the
        // static-asset miss handler so both answer in the same human voice.
        _ => content::not_found(),
    };

    // Step 3 — Security header injection.
    // Runs on every response regardless of which handler produced it.
    // Headers include CSP, HSTS, X-Frame-Options, etc.
    // Defined in middleware/headers.rs.
    Routed {
        response: headers::inject(response),
        session: Some(true),
    }
}

/// Match a request against the public pre-gate routes, in a fixed order.
/// Returns the response for the first route the request names, or None when
/// no public route claims it and the request must pass the session gate.
///
/// The static assets the challenge page needs (CSS/JS/WASM) and the `PoW`
/// submission endpoint let an unverified visitor complete the puzzle and
/// receive a session cookie; /health answers 200 to a cookie-less uptime
/// monitor; /robots.txt and /.well-known/security.txt are the public crawler
/// and researcher doors; /transparency explains the journal to someone who
/// has not solved anything yet; and /admin plus /admin/login carry their own
/// credential (a cookie signed with `ZTS_ADMIN_SECRET`) that must not be
/// re-gated by the visitor puzzle.
///
/// HEAD routes as GET on every endpoint here, so a monitor or link checker
/// that probes with HEAD sees the same result a GET would (the serializer
/// drops the body at the wire). The caller injects the security header set
/// onto whatever this returns, exactly as it does for gated responses.
fn public_route(request: &Request, peer: Option<IpAddr>) -> Option<Response> {
    // Static assets — the challenge page fetches these before a session
    // exists.
    if is_get(&request.method) && request.path.starts_with("/static/") {
        return Some(content::static_asset(&request.path));
    }

    // PoW solution submission — the only way an unverified visitor obtains a
    // session. On success pow::verify returns 302 + Set-Cookie; the client
    // address feeds its per-IP rate budget.
    if request.method == Method::Post && request.path == "/pow/verify" {
        return Some(crate::middleware::pow::verify(request, peer));
    }

    // /health — minimal liveness probe for external uptime monitors. A 200
    // here proves the full path (TLS, parse, routing, headers) is alive
    // without leaking anything. No cookie required.
    if is_get(&request.method) && request.path == "/health" {
        return Some(Response {
            status: 200,
            reason: "OK",
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: b"ok".to_vec(),
        });
    }

    // /robots.txt — crawl rules. A crawler that had to solve the puzzle to
    // read them would never crawl anything, so the file sits before the gate.
    if is_get(&request.method) && request.path == "/robots.txt" {
        return Some(content::robots());
    }

    // /.well-known/security.txt (RFC 9116) — the address a researcher uses
    // to report a flaw. Hiding it behind the gate hides the way in.
    if is_get(&request.method) && request.path == "/.well-known/security.txt" {
        return Some(content::security_txt());
    }

    // The OpenPGP key disclosure (pgp.rs): the armored key at
    // /.well-known/pgp, the WKD policy file, and the WKD leaf URL a client
    // computes from the site mailbox. All three sit pre-gate for the same
    // reason as security.txt, so a researcher who wants to encrypt a report
    // reaches the key before solving the visitor puzzle.
    if is_get(&request.method) && request.path == "/.well-known/pgp" {
        return Some(content::pgp_armored());
    }
    if is_get(&request.method) && request.path == "/.well-known/openpgpkey/policy" {
        return Some(content::pgp_policy());
    }
    if is_get(&request.method) && request.path.starts_with(crate::pgp::WKD_PREFIX) {
        return Some(content::pgp_wkd(&request.path));
    }

    // /transparency — what this server records, and what it never does. It
    // is the journal explaining itself to the visitor who has not solved
    // anything yet, so the gate must not stand between it and them.
    if is_get(&request.method) && request.path == "/transparency" {
        return Some(content::transparency());
    }

    // /admin/login and /admin — the operator dashboard. Both live pre-gate:
    // the admin session is its own credential. GET /admin/login shows the
    // password form (or bounces a request that already carries a valid admin
    // cookie to the dashboard); POST /admin/login checks the password and
    // mints the zts-admin cookie; GET /admin renders the metrics (or bounces
    // a cookie-less request to the login form).
    if is_get(&request.method) && request.path == "/admin/login" {
        return Some(admin::login_form(request));
    }
    if request.method == Method::Post && request.path == "/admin/login" {
        return Some(admin::login(request, peer));
    }
    if is_get(&request.method) && request.path == "/admin" {
        return Some(admin::dashboard(request));
    }

    None
}

/// A handler-servable read method: GET, or HEAD (which routes as GET).
const fn is_get(m: &Method) -> bool {
    matches!(m, Method::Get | Method::Head)
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
        // and the full security header set is applied. The gate did not run,
        // so the audit context is None ("na").
        let routed = handle(&request(Method::Get, "/health"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        assert_eq!(routed.session, None);
        assert!(has_header(resp, "Content-Security-Policy"));
        assert!(has_header(resp, "Strict-Transport-Security"));
        assert!(has_header(resp, "X-Content-Type-Options"));
    }

    #[test]
    fn robots_and_security_txt_are_public_pre_gate() {
        // Both machine-readable files must answer a cookie-less GET with 200
        // and full security headers, exactly like /health: a crawler or a
        // researcher never solves the puzzle first.
        for path in ["/robots.txt", "/.well-known/security.txt"] {
            let routed = handle(&request(Method::Get, path), None);
            let resp = &routed.response;
            assert_eq!(resp.status, 200, "{path} must serve pre-gate");
            assert_eq!(routed.session, None, "{path} is a public route");
            assert!(has_header(resp, "Content-Security-Policy"));
            assert!(has_header(resp, "Strict-Transport-Security"));
        }
    }

    #[test]
    fn robots_and_security_serve_plain_text() {
        let robots = handle(&request(Method::Get, "/robots.txt"), None);
        assert!(
            robots
                .response
                .headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "text/plain; charset=utf-8")
        );
        let sec = handle(&request(Method::Get, "/.well-known/security.txt"), None);
        assert!(
            sec.response
                .headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "text/plain; charset=utf-8")
        );
    }

    #[test]
    fn transparency_is_public_pre_gate() {
        // A cookie-less visitor must read what the server records before
        // deciding whether to solve anything. Pre-gate, 200, injected.
        let routed = handle(&request(Method::Get, "/transparency"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(routed.session, None, "/transparency is a public route");
        assert!(has_header(resp, "Content-Security-Policy"));
        let body = String::from_utf8(resp.body.clone()).expect("html is utf-8");
        assert!(
            body.contains("what this server records"),
            "the page states its subject plainly"
        );
    }

    #[test]
    fn admin_pages_sit_before_the_gate() {
        // The operator dashboard must be reachable without a visitor session:
        // an operator who cleared cookies and hits /admin must not be asked
        // to solve the visitor puzzle.
        let login = handle(&request(Method::Get, "/admin/login"), None);
        assert_eq!(login.session, None, "/admin/login is not PoW gated");
        assert_eq!(login.response.status, 200, "the login form serves pre-gate");
        let login_body = String::from_utf8(login.response.body).expect("utf-8");
        assert!(
            login_body.contains("password"),
            "the form asks for the password"
        );

        // GET /admin with no admin cookie redirects to the login form, which
        // is dashboard gating, not the visitor puzzle.
        let admin = handle(&request(Method::Get, "/admin"), None);
        assert_eq!(admin.session, None, "/admin is not PoW gated");
        assert_eq!(admin.response.status, 302);
        assert_eq!(
            admin
                .response
                .headers
                .iter()
                .find(|(n, _)| n == "Location")
                .unwrap()
                .1,
            "/admin/login"
        );
    }

    #[test]
    fn gated_404_body_reads_like_the_site_not_a_status_line() {
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let cookie = crate::middleware::session::issue_cookie().expect("cookie");
        let zts = cookie.split(';').next().unwrap().to_string();
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), zts);
        let req = Request {
            method: Method::Get,
            path: "/not-a-page".to_string(),
            headers,
            body: Vec::new(),
        };
        let routed = handle(&req, None);
        assert_eq!(routed.response.status, 404);
        let body = String::from_utf8(routed.response.body).expect("utf-8");
        assert!(
            body.contains("Nothing lives at that address"),
            "the 404 body must be a human sentence"
        );
        assert!(
            !body.contains("404 Not Found"),
            "the bare status text must not leak into the body"
        );
    }

    #[test]
    fn head_health_matches_get() {
        // A monitor probing /health with HEAD (the common uptime pattern)
        // must get exactly what GET returns — routing is shared.
        let routed = handle(&request(Method::Head, "/health"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
        assert_eq!(routed.session, None);
        // Body suppression is the serializer's job, driven by the caller's
        // knowledge that this was HEAD — asserted in http.rs tests.
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

        let routed = handle(&req, None);
        let resp = &routed.response;
        assert_eq!(resp.status, 404);
        // A valid session reached the gate, which ruled true.
        assert_eq!(routed.session, Some(true));
        assert!(has_header(resp, "Content-Security-Policy"));
        assert!(has_header(resp, "Strict-Transport-Security"));
    }

    #[test]
    fn unsessioned_page_request_is_gate_denied() {
        // No cookie on a gated page → the challenge is served and the audit
        // context records the gate ruled no.
        let routed = handle(&request(Method::Get, "/"), None);
        assert_eq!(routed.session, Some(false));
    }

    #[test]
    fn head_gated_page_with_session_routes_as_get() {
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let cookie = crate::middleware::session::issue_cookie().expect("cookie");
        let zts = cookie.split(';').next().unwrap().to_string();
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), zts);
        let req = Request {
            method: Method::Head,
            path: "/".to_string(),
            headers,
            body: Vec::new(),
        };
        let routed = handle(&req, None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(routed.session, Some(true));
        assert!(has_header(resp, "Content-Security-Policy"));
    }

    /// A request carrying a freshly minted valid session cookie, so a test
    /// can reach the Step 2 dispatch (the code after the session gate).
    fn gated_request(method: Method, path: &str) -> Request {
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let cookie = crate::middleware::session::issue_cookie().expect("cookie");
        let zts = cookie.split(';').next().unwrap().to_string();
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), zts);
        Request {
            method,
            path: path.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn gated_project_writeup_routes_to_the_page_with_a_session() {
        // /projects/<slug> is portfolio content like /about: it answers only
        // after the session gate, and its pages come from the store loaded at
        // startup (seeded here from a fixture).
        crate::writeup::seed_test_pages();
        let routed = handle(&gated_request(Method::Get, "/projects/sample"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(routed.session, Some(true));
        assert!(has_header(resp, "Content-Security-Policy"));
        let body = String::from_utf8(resp.body.clone()).expect("utf-8");
        assert!(body.contains("<h1 class=\"page-title\">sample</h1>"));
        assert!(
            body.contains("<h2>A section</h2>"),
            "markdown renders through routing"
        );
        assert!(body.contains(r#"<link rel="icon" href="/static/favicon.ico">"#));
    }

    #[test]
    fn head_project_writeup_routes_as_get() {
        crate::writeup::seed_test_pages();
        let routed = handle(&gated_request(Method::Head, "/projects/sample"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(routed.session, Some(true));
        // Body suppression happens at the wire (Response::into_bytes), so the
        // routed response still carries the GET body — assert the routing
        // decided 200, which is the HEAD contract.
        assert!(!resp.body.is_empty());
    }

    #[test]
    fn unknown_project_slug_after_the_gate_is_404() {
        crate::writeup::seed_test_pages();
        let routed = handle(&gated_request(Method::Get, "/projects/not-a-project"), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 404);
        assert_eq!(routed.session, Some(true));
        let body = String::from_utf8(resp.body.clone()).expect("utf-8");
        assert!(
            body.contains("Nothing lives at that address"),
            "a writeup miss answers in the same voice as the catch-all"
        );
    }

    #[test]
    fn project_writeup_is_gated_behind_the_challenge() {
        // No cookie: exactly like / or /about, the writeup is not served.
        // The challenge answers and the audit context records the gate no.
        let routed = handle(&request(Method::Get, "/projects/sample"), None);
        assert_eq!(routed.session, Some(false));
    }

    #[test]
    fn pgp_disclosure_is_public_and_serves_the_correct_bodies() {
        // The armored key, the WKD policy file, and the WKD leaf for the
        // site mailbox answer a cookie-less GET with full security headers.
        // The key is disclosure, and it stands with security.txt before the
        // gate.
        let armored = handle(&request(Method::Get, "/.well-known/pgp"), None);
        assert_eq!(armored.response.status, 200);
        assert_eq!(armored.session, None, "the key is a public pre-gate route");
        assert!(has_header(&armored.response, "Content-Security-Policy"));
        assert!(
            String::from_utf8(armored.response.body)
                .expect("armor is ascii")
                .contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        );

        let policy = handle(
            &request(Method::Get, "/.well-known/openpgpkey/policy"),
            None,
        );
        assert_eq!(policy.response.status, 200);
        assert_eq!(policy.session, None);
        assert!(policy.response.body.is_empty());

        let leaf = crate::pgp::wkd_leaf();
        let wkd = handle(
            &request(Method::Get, &format!("/.well-known/openpgpkey/hu/{leaf}")),
            None,
        );
        assert_eq!(wkd.response.status, 200);
        assert_eq!(wkd.session, None);
        assert_eq!(wkd.response.body, crate::pgp::binary());
        assert!(
            wkd.response
                .headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "application/octet-stream")
        );

        // A query string carrying the local part is tolerated; an unknown
        // hash is a miss for a mailbox this site does not hold.
        let queried = handle(
            &request(
                Method::Get,
                &format!("/.well-known/openpgpkey/hu/{leaf}?l=admin"),
            ),
            None,
        );
        assert_eq!(queried.response.status, 200);
        let miss = handle(
            &request(
                Method::Get,
                "/.well-known/openpgpkey/hu/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
            ),
            None,
        );
        assert_eq!(miss.response.status, 404);
        assert_eq!(miss.session, None, "the miss is still a pre-gate 404");
    }
}
