use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{constant_time_eq, hmac_sha256, to_hex};
use crate::http::Request;

/// Session duration in seconds — 24 hours.
/// → Open question: review this value before production.
const SESSION_DURATION_SECS: u64 = 86400;

/// Cookie name used for the session token.
const SESSION_COOKIE_NAME: &str = "zts";

/// A parsed, verified session token.
/// Only constructed by `verify_token()` after successful HMAC check.
/// The existence of this struct is proof the token is valid.
pub struct Session {
    #[allow(dead_code)]
    pub expires_at: u64,
}

/// Check whether an incoming request carries a valid session cookie.
/// Called by router.rs before dispatching to any content handler.
/// Returns true only if the cookie is present, well-formed,
/// cryptographically valid, and not expired.
pub fn is_valid(request: &Request) -> bool {
    let Some(secret) = get_secret() else {
        // No secret configured — fail closed.
        // A server with no HMAC secret cannot issue or verify
        // sessions. Treat all requests as unverified.
        // This is the secure default — fail closed, not open.
        eprintln!("WARNING: SESSION_SECRET not set. \
                   All requests will receive the PoW challenge.");
        return false;
    };

    // Extract the session cookie value from request headers.
    let Some(cookie_value) = extract_cookie(request, SESSION_COOKIE_NAME) else {
        return false;
    };

    // Verify the token — HMAC check + expiry check.
    verify_token(&cookie_value, &secret).is_some()
}

/// Issue a new signed session cookie.
/// Called by pow.rs after successful `PoW` verification.
/// Returns the Set-Cookie header value ready to include in a response.
pub fn issue_cookie() -> Option<String> {
    let secret = get_secret()?;

    let expires_at = current_unix_time() + SESSION_DURATION_SECS;

    // Payload: just the expiry timestamp.
    // Simple, auditable, contains no sensitive information.
    let payload = expires_at.to_string();

    // Sign the payload with HMAC-SHA256.
    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    let signature_hex = to_hex(&signature);

    // Cookie format: payload.signature
    // Both components are needed to verify — payload provides
    // the data, signature proves authenticity.
    let token = format!("{payload}.{signature_hex}");

    // Set-Cookie header value with security flags.
    // Path=/ is REQUIRED: without it, RFC 6265 §5.1.4 derives the cookie
    // path from the request URI (/pow/verify → /pow), so the browser would
    // not send the cookie on the redirect to / and the gate would loop.
    // Secure: only sent over HTTPS (enforced by our TLS layer).
    // HttpOnly: not accessible to JavaScript — prevents XSS theft.
    // SameSite=Strict: not sent on cross-site requests — prevents CSRF.
    Some(format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; \
         SameSite=Strict; Max-Age={SESSION_DURATION_SECS}"
    ))
}

/// A parsed session token that passed HMAC verification and expiry.
/// Carries the raw signature bytes so the per-session request counter can
/// key on the token without re-hashing it.
struct VerifiedToken {
    expires_at: u64,
    /// The 32 HMAC-SHA256 bytes that prove the token is server-issued.
    signature: [u8; 32],
}

/// The raw HMAC signature bytes of the request's valid session cookie.
/// The bytes identify that session uniquely to the metrics counters. Some
/// only when the presented token verifies and is unexpired, which is exactly
/// when `is_valid` returns true, so the request counter advances on the same
/// requests the session column records as "yes".
pub fn session_key(request: &Request) -> Option<[u8; 32]> {
    let secret = get_secret()?;
    let cookie_value = extract_cookie(request, SESSION_COOKIE_NAME)?;
    verified_token(&cookie_value, &secret).map(|t| t.signature)
}

/// Verify a session token string.
/// Returns Some(Session) if valid, None if invalid or expired.
/// Performs constant-time HMAC comparison to prevent timing attacks.
fn verify_token(token: &str, secret: &str) -> Option<Session> {
    verified_token(token, secret).map(|t| Session {
        expires_at: t.expires_at,
    })
}

/// Verify a token string and return the verified parts.
fn verified_token(token: &str, secret: &str) -> Option<VerifiedToken> {
    // Split on the last '.' to separate payload from signature.
    let dot_pos = token.rfind('.')?;
    let payload = &token[..dot_pos];
    let provided_signature_hex = &token[dot_pos + 1..];

    // Recompute the expected HMAC from the payload and secret.
    let signature = hmac_sha256(
        secret.as_bytes(),
        payload.as_bytes(),
    );
    let expected_hex = to_hex(&signature);

    // Constant-time comparison.
    // Prevents timing side-channel attacks.
    // An attacker cannot determine how many bytes of their forged
    // signature match the real one by measuring response time.
    if !constant_time_eq(
        expected_hex.as_bytes(),
        provided_signature_hex.as_bytes(),
    ) {
        return None;
    }

    // Parse the expiry timestamp from the payload.
    let expires_at: u64 = payload.parse().ok()?;

    // Check expiry.
    if current_unix_time() >= expires_at {
        return None; // Session expired.
    }

    Some(VerifiedToken {
        expires_at,
        signature,
    })
}

/// Extract a named cookie value from the Cookie request header.
/// Returns None if the header is absent or the cookie is not found.
/// `pub` so the admin middleware can read its own `zts-admin` cookie through
/// the same parser instead of duplicating it; the enclosing module is private,
/// so this stays crate-internal either way.
pub fn extract_cookie(request: &Request, name: &str) -> Option<String> {
    let cookie_header = request.headers.get("cookie")?;

    // Cookie header format: name=value; name2=value2
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }

    None
}

/// Read the HMAC secret from the `SESSION_SECRET` environment variable.
/// Returns None if the variable is not set or is empty.
/// The server fails closed when the secret is missing.
fn get_secret() -> Option<String> {
    match std::env::var("SESSION_SECRET") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Current Unix timestamp in seconds.
fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same `SESSION_SECRET` literal the router tests use, so env-dependent
    /// tests in different modules of this crate cannot cross-invalidate each
    /// other when they run concurrently in one test binary (env is a
    /// process-global; concurrent `set_var` to a *different* value would race).
    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn set_secret() {
        // edition 2024 makes env mutation unsafe — this is the established
        // idiom across router.rs tests.
        unsafe { std::env::set_var("SESSION_SECRET", TEST_SECRET) }
    }

    /// A genuine token verifies; the same token with ONE bit of its HMAC
    /// signature flipped must not. Proves the signature — not just the
    /// payload format — gates the session, and that `constant_time_eq` is not
    /// vacuously accepting a single-bit mismatch.
    #[test]
    fn single_bit_flip_in_hmac_signature_is_rejected() {
        set_secret();
        let cookie = issue_cookie().expect("secret configured → cookie issued");
        let token = cookie
            .strip_prefix("zts=")
            .and_then(|t| t.split(';').next())
            .expect("well-formed Set-Cookie header");
        let secret = get_secret().expect("secret set above");

        // Baseline: the genuine token verifies.
        assert!(verify_token(token, &secret).is_some());

        // Flip exactly one bit (bit 0 of the signature's first byte) and
        // rebuild the token with the tampered signature.
        let (payload, sig_hex) = token.split_once('.').expect("payload.signature");
        let mut sig = decode_hex(sig_hex);
        sig[0] ^= 0x01;
        let forged = format!("{}.{}", payload, to_hex(&sig));

        assert_ne!(forged, token);
        assert!(
            verify_token(&forged, &secret).is_none(),
            "a one-bit-forged signature must not verify"
        );
    }

    /// A valid cookie yields exactly the signature bytes that signed it (so
    /// the metrics counter key is stable per token), and a forged cookie
    /// yields nothing.
    #[test]
    fn session_key_is_the_tokens_raw_signature_bytes() {
        set_secret();
        let cookie = issue_cookie().expect("secret configured → cookie issued");
        let token = cookie
            .strip_prefix("zts=")
            .and_then(|t| t.split(';').next())
            .expect("well-formed Set-Cookie header");
        let (_, sig_hex) = token.split_once('.').expect("payload.signature");

        let key = session_key(&request_with_cookie(&cookie))
            .expect("a valid cookie yields a session key");
        assert_eq!(to_hex(&key), sig_hex, "key is the token's raw HMAC bytes");

        let forged = request_with_cookie(&format!("zts=forged.{sig_hex}"));
        assert!(session_key(&forged).is_none(), "a forged payload yields no key");
    }

    fn request_with_cookie(cookie: &str) -> Request {
        use std::collections::HashMap;
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), cookie.to_string());
        Request {
            method: crate::http::Method::Get,
            path: "/".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string has even length");
        s.as_bytes()
            .chunks(2)
            .map(|c| (hex_val(c[0]) << 4) | hex_val(c[1]))
            .collect()
    }

    fn hex_val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("not an ascii hex digit: {b:#04x}"),
        }
    }
}
