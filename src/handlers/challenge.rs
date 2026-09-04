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

/// Escape a value for interpolation into an HTML attribute.
/// The request path is attacker-controlled, and the challenge page is served
/// before any session exists, so this is a pre-auth injection boundary. The
/// browser decodes the entities back to the original value in the DOM, so
/// escaping changes nothing the JavaScript sees, only what the markup means.
fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn build_challenge_html(
    nonce: &str,
    nonce_sig: &str,
    destination: &str,
) -> String {
    // These three ride into HTML attributes on a pre-session page, so each
    // one is escaped at the boundary. The page then reads back the original
    // value from the decoded DOM attribute, unchanged.
    let nonce = escape_attr(nonce);
    let nonce_sig = escape_attr(nonce_sig);
    let destination = escape_attr(destination);

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matthew Hebert · verifying</title>
    <!-- Open Graph: a shared link lands on this gate, so the preview must
         speak for the page behind it, not for the puzzle. og:url keeps the
         path the visitor was heading to, read from data-destination. -->
    <meta property="og:title" content="Matthew Hebert">
    <meta property="og:description" content="A website written from the raw TCP socket up, by one person, in the open. A few seconds of proof of work opens it.">
    <meta property="og:url" content="https://mhebert.dev{destination}">
    <!-- External stylesheet: CSP style-src 'self' forbids inline <style>. -->
    <link rel="stylesheet" href="/static/challenge.css">
    <!-- Favicon is self-hosted like every other byte on this site. Without a
         real icon the browser falls back to /favicon.ico and 404s on every
         load, polluting the audit log. -->
    <link rel="icon" href="/static/favicon.ico">
</head>
<body>
    <!-- Hidden via the #challenge-data rule in challenge.css, NOT an
         inline style attribute. CSP style-src 'self' forbids those. -->
    <div id="challenge-data"
         data-nonce="{nonce}"
         data-nonce-sig="{nonce_sig}"
         data-destination="{destination}">
    </div>

    <div class="container">
        <p class="status" id="status">Proving this browser is a person, not a script.</p>
        <p class="hint">
            The puzzle costs your browser a few seconds and never asks who you
            are. Behind it is a site written by one person, from the raw TCP
            socket up, and the code is open.
        </p>
        <p class="error" id="error">
            This site proves you are a person with a WebAssembly puzzle, and
            this browser cannot run it. A current browser solves it in a few
            seconds.
        </p>
    </div>

    <!-- External module: CSP script-src 'self' forbids inline scripts.
         The bootstrap lives in /static/challenge.js so the same-origin
         rule allows it to load, and it can import the WASM glue. -->
    <script type="module" src="/static/challenge.js"></script>
</body>
</html>"#)
}
