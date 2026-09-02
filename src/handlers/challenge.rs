use crate::http::{Request, Response};

/// Serve the PoW challenge page.
/// Returns an HTML page containing the WASM bundle that
/// computes the proof of work in the visitor's browser.
/// Stub — full implementation after WASM component is built.
pub fn serve(_request: &Request) -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: b"<html><body>PoW challenge stub</body></html>".to_vec(),
    }
}
