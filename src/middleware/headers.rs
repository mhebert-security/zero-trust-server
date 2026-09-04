use crate::http::Response;

/// Inject security headers into every response.
///
/// Every response on the TLS listener passes through here: router::handle is
/// the normal path (main.rs → router.rs step 3), and parse-time rejections —
/// a HEAD/PUT/DELETE request hitting the 405 path before routing — are
/// injected too (main.rs ParseOutcome::Rejected). The plaintext port-80
/// listener is the one deliberate exception: a pre-TLS 301 redirect cannot
/// meaningfully carry CSP or HSTS (HSTS is only honored over an existing TLS
/// session), so those responses are not injected — except the saturation 503,
/// which is, for consistency (main.rs reject_saturated_http).
pub fn inject(mut response: Response) -> Response {
    // Content Security Policy.
    // Blocks inline scripts, eval(), and any resource not from
    // the same origin. The WASM bundle is same-origin only.
    // If a third-party resource is ever needed, it must be
    // explicitly added here and the security implications reviewed.
    //
    // 'wasm-unsafe-eval' in script-src is required for the browser to
    // compile/instantiate the WebAssembly PoW module. It permits WASM
    // compilation ONLY — it does NOT allow JS eval() or Function().
    // Without it, Chrome refuses WebAssembly.instantiateStreaming and the
    // challenge gate fails closed for every real visitor (found via
    // Playwright capture of the live site, 2026-09-03).
    response.headers.push((
        "Content-Security-Policy".to_string(),
        concat!(
            "default-src 'self'; ",
            "script-src 'self' 'wasm-unsafe-eval'; ",
            "style-src 'self'; ",
            "img-src 'self'; ",
            "font-src 'self'; ",
            "connect-src 'self'; ",
            "frame-ancestors 'none'; ",
            "base-uri 'self'; ",
            "form-action 'self'",
        ).to_string(),
    ));

    // HTTP Strict Transport Security.
    // Tells the browser to only connect via HTTPS for 1 year.
    // Prevents SSL stripping attacks where an attacker downgrades
    // the connection from HTTPS to HTTP.
    // max-age=31536000 is exactly one year in seconds.
    // includeSubDomains + preload are now safe to send: the whole domain is
    // HTTPS-only (port 80 is a 301 redirect — see redirect.rs) with no HTTP
    // subdomains. NOTE: the preload directive only takes effect once the
    // domain is submitted at https://hstspreload.org — a one-time manual
    // step, still pending.
    response.headers.push((
        "Strict-Transport-Security".to_string(),
        "max-age=31536000; includeSubDomains; preload".to_string(),
    ));

    // X-Frame-Options.
    // Prevents this page from being embedded in an iframe
    // on any other domain. Blocks clickjacking attacks.
    // DENY is stricter than SAMEORIGIN — no iframes at all,
    // not even from the same domain.
    response.headers.push((
        "X-Frame-Options".to_string(),
        "DENY".to_string(),
    ));

    // X-Content-Type-Options.
    // Prevents the browser from MIME-sniffing a response away
    // from the declared Content-Type. Without this, a browser
    // might execute a file served as text/plain as JavaScript
    // if it looks like a script. nosniff disables this behaviour.
    response.headers.push((
        "X-Content-Type-Options".to_string(),
        "nosniff".to_string(),
    ));

    // Referrer-Policy.
    // Controls how much referrer information is sent with requests
    // to other origins. no-referrer means no referrer header is
    // sent at all — the visitor's navigation path is not leaked.
    response.headers.push((
        "Referrer-Policy".to_string(),
        "no-referrer".to_string(),
    ));

    // Permissions-Policy.
    // Disables browser features this site does not use.
    // Each empty list () disables that feature entirely.
    // Reduces attack surface from browser API abuse.
    response.headers.push((
        "Permissions-Policy".to_string(),
        concat!(
            "camera=(), ",
            "microphone=(), ",
            "geolocation=(), ",
            "payment=(), ",
            "usb=(), ",
            "interest-cohort=()",
        ).to_string(),
    ));

    // Cross-Origin-Opener-Policy.
    // Isolates the browsing context from other origins.
    // Prevents cross-origin documents from getting a reference
    // to this window object. Required for SharedArrayBuffer
    // if WASM threading is ever used.
    response.headers.push((
        "Cross-Origin-Opener-Policy".to_string(),
        "same-origin".to_string(),
    ));

    // Cross-Origin-Embedder-Policy.
    // Prevents the document from loading cross-origin resources
    // that do not explicitly grant permission.
    // Required alongside COOP for SharedArrayBuffer access.
    response.headers.push((
        "Cross-Origin-Embedder-Policy".to_string(),
        "require-corp".to_string(),
    ));

    // Cross-Origin-Resource-Policy.
    // Prevents other origins from reading the responses to
    // requests made to this server. Blocks cross-origin
    // information leakage.
    response.headers.push((
        "Cross-Origin-Resource-Policy".to_string(),
        "same-origin".to_string(),
    ));

    response
}
