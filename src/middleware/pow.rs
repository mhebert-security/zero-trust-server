use crate::http::{Request, Response};

/// Verify a PoW solution submitted via POST /pow/verify.
/// Stub — full implementation in next commit.
pub fn verify(_request: &Request) -> Response {
    Response {
        status: 200,
        reason: "OK",
        headers: Vec::new(),
        body: b"PoW verification stub".to_vec(),
    }
}
