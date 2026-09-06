//! Operator dashboard handlers: /admin and /admin/login.
//!
//! `/admin/login` accepts the password (POST) and mints the `zts-admin`
//! cookie; `/admin` renders the metrics dashboard to a request that carries
//! one. Both live pre-gate in the router: the admin session is its own
//! credential and must not sit behind the visitor proof-of-work gate.
//!
//! Every page here is private, so each response carries `Cache-Control:
//! no-store` and the dashboard refreshes itself every 60 seconds through a
//! meta tag, which needs no script under the site's CSP.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::http::{Request, Response};
use crate::metrics;
use crate::middleware::admin;

// `Method` is referenced only by the test builders below, so it must not be
// imported in the production build where the test module is compiled away.
#[cfg(test)]
use crate::http::Method;

/// GET/HEAD /admin/login — the password form. A request that already carries
/// a valid admin cookie is sent straight to the dashboard instead.
pub fn login_form(request: &Request) -> Response {
    if admin::is_authorized(request) {
        return redirect_to_dashboard();
    }
    html_admin(200, "OK", login_page(None))
}

/// GET/HEAD /admin — the metrics dashboard, gated on the admin cookie.
pub fn dashboard(request: &Request) -> Response {
    if !admin::is_authorized(request) {
        return redirect_to_login();
    }
    html_admin(200, "OK", dashboard_html())
}

/// POST /admin/login — check the password and mint the admin cookie.
/// The cookie is issued only here, on a correct password. `peer` feeds the
/// per-IP attempt throttle, so a guesser cannot hammer the password check at
/// TCP speed.
pub fn login(request: &Request, peer: Option<IpAddr>) -> Response {
    // Throttle before the password work: every POST spends the per-IP budget
    // whether the password is right or wrong, so the cap cannot be dodged by
    // sending only well-formed attempts. A request with no resolvable peer
    // skips the check, matching the /pow/verify gate.
    if let Some(ip) = peer
        && admin::login_attempt_denied(ip)
    {
        return html_admin(
            429,
            "Too Many Requests",
            login_page(Some("Too many attempts. Wait and try again.")),
        );
    }

    let provided = field(&request.body, "password").unwrap_or_default();
    if !admin::check_password(&provided) {
        return html_admin(401, "Unauthorized", login_page(Some("That password did not match.")));
    }

    // The password was right: never let earlier wrong guesses in the same
    // window count against the operator who finally typed it correctly.
    if let Some(ip) = peer {
        admin::login_succeeded(ip);
    }

    let Some(cookie) = admin::issue_cookie() else {
        // ZTS_ADMIN_SECRET absent — main() validates it at startup, so this
        // only trips on a mid-run environment change. Fail closed.
        return Response {
            status: 500,
            reason: "Internal Server Error",
            headers: vec![(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: b"The server is misconfigured. Try again in a few minutes.".to_vec(),
        };
    };

    Response {
        status: 302,
        reason: "Found",
        headers: vec![
            ("Location".to_string(), "/admin".to_string()),
            ("Set-Cookie".to_string(), cookie),
            no_store(),
        ],
        body: Vec::new(),
    }
}

fn redirect_to_login() -> Response {
    Response {
        status: 302,
        reason: "Found",
        headers: vec![
            ("Location".to_string(), "/admin/login".to_string()),
            no_store(),
        ],
        body: Vec::new(),
    }
}

fn redirect_to_dashboard() -> Response {
    Response {
        status: 302,
        reason: "Found",
        headers: vec![
            ("Location".to_string(), "/admin".to_string()),
            no_store(),
        ],
        body: Vec::new(),
    }
}

/// Wrap HTML in a Response with the admin content type and no-store.
fn html_admin(status: u16, reason: &'static str, body: String) -> Response {
    Response {
        status,
        reason,
        headers: vec![
            (
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            no_store(),
        ],
        body: body.into_bytes(),
    }
}

fn no_store() -> (String, String) {
    ("Cache-Control".to_string(), "no-store".to_string())
}

/// The shared head both admin pages use. `refresh` adds a meta auto-reload.
fn page_head(title: &str, refresh: bool) -> String {
    let mut head = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <meta name="robots" content="noindex, nofollow">
    <link rel="icon" href="/static/favicon.ico">
    <link rel="stylesheet" href="/static/admin.css">
"#
    );
    if refresh {
        head.push_str("    <meta http-equiv=\"refresh\" content=\"60\">\n");
    }
    head.push_str("</head>\n<body>\n");
    head
}

/// The login page. `message` is rendered as one line above the form when the
/// last attempt failed or was throttled. It renders no script and no inline
/// style (CSP), and the form posts to itself.
fn login_page(message: Option<&'static str>) -> String {
    let mut html = page_head("mhebert.dev · operator", false);
    html.push_str(
        r#"    <main class="admin-login">
        <a class="wordmark" href="/">mhebert<span class="dot">.</span>dev</a>
        <h1 class="page-title">operator</h1>
"#,
    );
    if let Some(message) = message {
        html.push_str("        <p class=\"admin-error\" role=\"alert\">");
        html.push_str(message);
        html.push_str("</p>\n");
    }
    html.push_str(
        r#"        <p class="muted">This login is the only door to the server's metrics. The password lives in the server environment, not in a database.</p>
        <form class="admin-form" action="/admin/login" method="post">
            <label for="password">password</label>
            <input type="password" id="password" name="password" autocomplete="current-password" required>
            <button type="submit">open dashboard</button>
        </form>
    </main>
</body>
</html>
"#,
    );
    html
}

/// The dashboard: totals by path, solve distribution, active sessions, and
/// uptime, all computed from in-process metrics. Plain HTML and one
/// stylesheet; no script, no external call, no file read.
fn dashboard_html() -> String {
    let snap = metrics::global().snapshot();

    let mut html = page_head("mhebert.dev · operator dashboard", true);
    html.push_str(
        r#"    <main class="admin">
        <header class="admin-head">
            <a class="wordmark" href="/">mhebert<span class="dot">.</span>dev</a>
            <p class="muted">operator dashboard · refreshes every 60 seconds</p>
        </header>
"#,
    );

    // Requests since restart, by path.
    html.push_str(
        r#"        <section>
            <h2 class="rule">requests since restart</h2>
            <table class="admin-table">
                <thead><tr><th>path</th><th class="num">count</th></tr></thead>
                <tbody>
"#,
    );
    if snap.path_counts.is_empty() {
        html.push_str(
            r#"                    <tr><td colspan="2" class="muted">no requests since restart</td></tr>
"#,
        );
    } else {
        for (path, count) in &snap.path_counts {
            let path_esc = escape(path);
            let _ = writeln!(
                html,
                r#"                    <tr><td>{path_esc}</td><td class="num">{count}</td></tr>"#
            );
        }
    }
    html.push_str("                </tbody>\n            </table>\n");
    let total = snap.total_requests;
    let _ = write!(
        html,
        r#"            <p class="muted">total {total} across all paths</p>
        </section>
"#
    );

    // Proof of work solve distribution over the ring buffer.
    html.push_str(
        r#"        <section>
            <h2 class="rule">proof of work</h2>
"#,
    );
    match &snap.solves {
        Some(stats) => {
            let count = stats.count;
            let median = stats.median_ms;
            let p95 = stats.p95_ms;
            let max = stats.max_ms;
            let _ = write!(
                html,
                r#"            <p class="muted">solve times, last {count} solves</p>
            <dl class="admin-stats">
                <div><dt>median</dt><dd>{median} ms</dd></div>
                <div><dt>p95</dt><dd>{p95} ms</dd></div>
                <div><dt>max</dt><dd>{max} ms</dd></div>
            </dl>
        </section>
"#
            );
        }
        None => {
            html.push_str(
                r#"            <p class="muted">no solves recorded since restart</p>
        </section>
"#,
            );
        }
    }

    // Sessions and uptime.
    let hours = snap.uptime_secs / 3600;
    let minutes = (snap.uptime_secs % 3600) / 60;
    let uptime_line = format!(
        "{} {} {} {}",
        hours,
        plural(hours, "hour"),
        minutes,
        plural(minutes, "minute"),
    );
    let active = snap.active_sessions;
    let _ = write!(
        html,
        r#"        <section class="admin-bottom">
            <h2 class="rule">sessions</h2>
            <p>active sessions in the last hour: <span class="num-inline">{active}</span></p>
        </section>
        <section class="admin-bottom">
            <h2 class="rule">uptime</h2>
            <p>{uptime_line}</p>
        </section>
    </main>
</body>
</html>
"#
    );

    html
}

/// Escape text for interpolation into HTML, at the boundary where an
/// attacker-controlled request path reaches the dashboard markup.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// English plural helper: `plural(1, "hour")` → "hour", `plural(2, "hour")`
/// → "hours".
fn plural(n: u64, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

/// Read one `name=value` field from an `application/x-www-form-urlencoded`
/// body, percent-decoding the value. None when the field is absent.
fn field(body: &[u8], name: &str) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    for pair in body_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') && k == name {
            return Some(url_decode(v));
        }
    }
    None
}

/// Minimal form-urlencoded decoder: `+` becomes space and `%XX` is decoded
/// as a byte. Undecodable sequences pass through literally, so a malformed
/// value still compares (and fails) instead of panicking.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// ASCII hex digit value, or None for a non-hex byte.
const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fixed admin env values, matching middleware/admin.rs tests so both
    /// modules can run concurrently in one test process without env races.
    const TEST_ADMIN_SECRET: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const TEST_ADMIN_PASSWORD: &str = "correct horse battery staple";

    fn set_admin_env() {
        // edition 2024 makes env mutation unsafe — established idiom.
        unsafe {
            std::env::set_var("ZTS_ADMIN_SECRET", TEST_ADMIN_SECRET);
            std::env::set_var("ZTS_ADMIN_PASSWORD", TEST_ADMIN_PASSWORD);
        }
    }

    fn request(method: Method, body: &[u8]) -> Request {
        Request {
            method,
            path: "/admin/login".to_string(),
            headers: HashMap::new(),
            body: body.to_vec(),
        }
    }

    fn with_cookie(method: Method, cookie: &str) -> Request {
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), cookie.to_string());
        Request {
            method,
            path: "/admin".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn correct_password_issues_cookie_and_redirects() {
        set_admin_env();
        let body = format!("password={TEST_ADMIN_PASSWORD}");
        let response = login(&request(Method::Post, body.as_bytes()), None);
        assert_eq!(response.status, 302);
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(n, _)| n == "Location")
                .unwrap()
                .1,
            "/admin"
        );
        assert!(
            response
                .headers
                .iter()
                .any(|(n, v)| n == "Set-Cookie" && v.starts_with("zts-admin="))
        );
    }

    #[test]
    fn wrong_password_is_unauthorized_and_sets_no_cookie() {
        set_admin_env();
        let response = login(&request(Method::Post, b"password=nope"), None);
        assert_eq!(response.status, 401);
        assert!(!response.headers.iter().any(|(n, _)| n == "Set-Cookie"));
        let body = String::from_utf8(response.body).expect("html is utf-8");
        assert!(body.contains("did not match"));
    }

    /// Repeated wrong passwords from one address eventually hit the per-IP
    /// throttle and answer 429 instead of 401. The exact boundary is pinned
    /// in the middleware unit tests; this exercises the handler end to end.
    #[test]
    fn repeated_wrong_passwords_eventually_answer_429() {
        set_admin_env();
        // Dedicated address so no other test shares this IP's attempt budget.
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 91, 0, 9));

        for _ in 0..10 {
            let response = login(&request(Method::Post, b"password=nope"), Some(ip));
            assert!(
                response.status == 401 || response.status == 429,
                "a wrong password inside the budget is 401, over it 429"
            );
        }
        let throttled = login(&request(Method::Post, b"password=nope"), Some(ip));
        assert_eq!(throttled.status, 429, "past the allowance the login is refused");
        assert!(
            !throttled.headers.iter().any(|(n, _)| n == "Set-Cookie"),
            "a throttled login must not set a cookie"
        );
    }

    #[test]
    fn percent_encoded_password_decodes_before_compare() {
        set_admin_env();
        // "correct horse battery staple" with each space sent as %20.
        let encoded = "correct%20horse%20battery%20staple";
        let body = format!("password={encoded}");
        let response = login(&request(Method::Post, body.as_bytes()), None);
        assert_eq!(response.status, 302, "encoded spaces must match the real password");
    }

    #[test]
    fn dashboard_without_cookie_redirects_to_login() {
        let response = dashboard(&request(Method::Get, b""));
        assert_eq!(response.status, 302);
        assert_eq!(
            response
                .headers
                .iter()
                .find(|(n, _)| n == "Location")
                .unwrap()
                .1,
            "/admin/login"
        );
    }

    #[test]
    fn dashboard_with_cookie_renders_and_is_never_cached() {
        set_admin_env();
        let cookie = admin::issue_cookie().expect("admin secret set");
        let value = cookie.split(';').next().unwrap().to_string();
        let response = dashboard(&with_cookie(Method::Get, &value));
        assert_eq!(response.status, 200);
        let html = String::from_utf8(response.body).expect("html is utf-8");
        assert!(html.contains("requests since restart"));
        assert!(html.contains("uptime"));
        assert!(html.contains("http-equiv=\"refresh\" content=\"60\""));
        assert!(
            response
                .headers
                .iter()
                .any(|(n, v)| n == "Cache-Control" && v == "no-store")
        );
    }

    #[test]
    fn login_page_renders_and_is_never_cached() {
        let response = login_form(&request(Method::Get, b""));
        assert_eq!(response.status, 200);
        let html = String::from_utf8(response.body).expect("html is utf-8");
        assert!(html.contains("name=\"password\""));
        assert!(
            response
                .headers
                .iter()
                .any(|(n, v)| n == "Cache-Control" && v == "no-store")
        );
    }

    #[test]
    fn dashboard_escapes_hostile_path_text() {
        // A path that reached the metrics map is attacker-controlled; it must
        // never become markup on the operator's screen. Record one into the
        // process global (other dashboard tests never assert on path contents,
        // so this cannot cross-invalidate them) and confirm it renders
        // escaped, not live.
        crate::metrics::global().record_request("/x<script>alert(1)</script>");
        let html = String::from_utf8(dashboard_html().into_bytes()).expect("utf-8");
        assert!(html.contains("&lt;script&gt;"), "hostile path must be escaped");
        assert!(!html.contains("<script>"), "no raw script tag may render");
    }

    #[test]
    fn escape_neutralizes_markup() {
        assert_eq!(escape("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#39;");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn url_decode_handles_plus_and_percent() {
        assert_eq!(url_decode("a+b"), "a b");
        assert_eq!(url_decode("a%20b"), "a b");
        assert_eq!(url_decode("100%25"), "100%");
        assert_eq!(url_decode("dangling%"), "dangling%");
        assert_eq!(url_decode(""), "");
    }

    #[test]
    fn field_ignores_other_fields_and_unknown_names() {
        assert_eq!(
            field(b"password=secret&junk=x", "password").as_deref(),
            Some("secret")
        );
        assert_eq!(field(b"user=bob", "password"), None);
        assert_eq!(field(b"", "password"), None);
        assert!(field(b"not-form-encoded", "password").is_none());
    }
}
