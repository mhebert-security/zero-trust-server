use crate::http::{Request, Response};
use crate::middleware::pow;

pub fn serve(request: &Request) -> Response {
    let Some((nonce, nonce_sig)) = pow::generate_challenge() else {
        return Response {
            status: 500,
            reason: "Internal Server Error",
            headers: vec![(
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            )],
            body: b"The server is misconfigured. Try again in a few minutes.".to_vec(),
        };
    };

    let destination = extract_destination(request);
    let html = build_challenge_html(&nonce, &nonce_sig, &destination);

    Response {
        status: 200,
        reason: "OK",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: html.into_bytes(),
    }
}

fn extract_destination(request: &Request) -> String {
    let path = &request.path;
    if path.starts_with('/') && !path.contains("//") {
        path.clone()
    } else {
        "/".to_string()
    }
}

fn build_challenge_html(
    nonce: &str,
    nonce_sig: &str,
    destination: &str,
) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matthew Hebert · verifying</title>
    <!-- External stylesheet: CSP style-src 'self' forbids inline <style>. -->
    <link rel="stylesheet" href="/static/challenge.css">
    <!-- Favicon is self-hosted like every other byte on this site. Without a
         real icon the browser falls back to /favicon.ico and 404s on every
         load, polluting the audit log. -->
    <link rel="icon" href="/static/favicon.ico">
</head>
<body>
    <!-- Hidden via the #challenge-data rule in challenge.css, NOT an
         inline style attribute — CSP style-src 'self' forbids those. -->
    <div id="challenge-data"
         data-nonce="{nonce}"
         data-nonce-sig="{nonce_sig}"
         data-destination="{destination}">
    </div>

    <div class="container">
        <p class="status" id="status">Verifying your browser...</p>
        <p class="error" id="error">
            Your browser does not support WebAssembly.
            Please update your browser to access this site.
        </p>
    </div>

    <!-- External module: CSP script-src 'self' forbids inline scripts.
         The bootstrap lives in /static/challenge.js so the same-origin
         rule allows it to load, and it can import the WASM glue. -->
    <script type="module" src="/static/challenge.js"></script>
</body>
</html>"#)
}
