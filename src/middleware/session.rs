use crate::http::Request;

/// Returns true if the request carries a valid session cookie.
/// Stub — full implementation in next commit.
pub fn is_valid(_request: &Request) -> bool {
    // Temporary: treat all requests as unverified.
    // This means every request gets the PoW challenge until
    // session.rs is fully implemented.
    false
}
