use crate::http::{Request, Response};
use crate::middleware::pow;

/// Serve the PoW challenge page to an unverified visitor.
/// This is the only page served without a valid session cookie.
/// Returns a complete HTML page with the challenge nonce embedded
/// and a reference to the WASM bundle that solves it.
pub fn serve(request: &Request) -> Response {
    // Generate a fresh challenge nonce for this page load.
    // Each load gets a unique nonce — prevents pre-computation.
    // If challenge generation fails (SESSION_SECRET not set),
    // return 500 rather than serving a page the visitor cannot solve.
    let (nonce, nonce_sig) = match pow::generate_challenge() {
        Some(c) => c,
        None => {
            return Response {
                status: 500,
                reason: "Internal Server Error",
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                )],
                body: b"Server configuration error.".to_vec(),
            };
        }
    };

    // Determine the page the visitor was trying to reach.
    // After solving the challenge they will be redirected there.
    // Defaults to / if no referrer or original path is available.
    let destination = extract_destination(request);

    // Build the challenge page HTML.
    // The nonce and signature are embedded directly in the HTML
    // so the WASM module can read them from the DOM without
    // making an additional network request.
    // The WASM bundle is loaded from /static/pow_challenge.wasm
    // via same-origin request only — enforced by the CSP in
    // middleware/headers.rs (script-src 'self').
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

/// Extract the destination path from the request.
/// Used to redirect the visitor to their intended page after
/// solving the challenge.
fn extract_destination(request: &Request) -> String {
    // Use the request path as the destination.
    // Validate it starts with / to prevent open redirect.
    let path = &request.path;
    if path.starts_with('/') && !path.contains("//") {
        path.clone()
    } else {
        "/".to_string()
    }
}

/// Build the challenge page HTML.
/// Minimal, functional, intentionally unstyled at this stage.
/// The nonce and signature are embedded as data attributes on
/// a dedicated element so the WASM can locate them via the DOM API.
///
/// WASM load strategy: WebAssembly.instantiateStreaming() streams
/// compilation in parallel with download — most efficient method.
/// Falls back gracefully if the browser does not support WASM.
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
    <title>Verifying — Matthew Hebert</title>
    <style>
        body {{
            font-family: system-ui, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #0f1117;
            color: #e2e8f0;
        }}
        .container {{
            text-align: center;
            max-width: 400px;
            padding: 2rem;
        }}
        .status {{
            font-size: 0.9rem;
            color: #94a3b8;
            margin-top: 1rem;
        }}
        .error {{
            color: #f87171;
            display: none;
        }}
    </style>
</head>
<body>
    <!-- Challenge data — read by the WASM module -->
    <div id="challenge-data"
         data-nonce="{nonce}"
         data-nonce-sig="{nonce_sig}"
         data-destination="{destination}"
         style="display:none">
    </div>

    <div class="container">
        <p class="status" id="status">Verifying your browser...</p>
        <p class="error" id="error">
            Your browser does not support WebAssembly.
            Please update your browser to access this site.
        </p>
    </div>

    <script type="module">
        // Check WASM support before attempting to load.
        if (typeof WebAssembly === 'undefined') {{
            document.getElementById('status').style.display = 'none';
            document.getElementById('error').style.display = 'block';
        }} else {{
            // Load and instantiate the PoW WASM module.
            // The module reads the challenge data from the DOM,
            // computes the proof of work, and submits the solution
            // to POST /pow/verify automatically.
            WebAssembly.instantiateStreaming(
                fetch('/static/pow_challenge.wasm'),
                {{}}
            ).then(result => {{
                const {{ solve }} = result.instance.exports;
                solve();
            }}).catch(err => {{
                document.getElementById('status').textContent =
                    'Verification failed. Please refresh the page.';
                console.error('WASM load error:', err);
            }});
        }}
    </script>
</body>
</html>"#,
        nonce = nonce,
        nonce_sig = nonce_sig,
        destination = destination,
    )
}
