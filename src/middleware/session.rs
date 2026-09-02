use std::time::{SystemTime, UNIX_EPOCH};

use crate::http::Request;

/// Session duration in seconds — 24 hours.
/// → Open question: review this value before production.
const SESSION_DURATION_SECS: u64 = 86400;

/// Cookie name used for the session token.
const SESSION_COOKIE_NAME: &str = "zts";

/// A parsed, verified session token.
/// Only constructed by verify_token() after successful HMAC check.
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
    let secret = match get_secret() {
        Some(s) => s,
        None => {
            // No secret configured — fail closed.
            // A server with no HMAC secret cannot issue or verify
            // sessions. Treat all requests as unverified.
            // This is the secure default — fail closed, not open.
            eprintln!("WARNING: SESSION_SECRET not set. \
                       All requests will receive the PoW challenge.");
            return false;
        }
    };

    // Extract the session cookie value from request headers.
    let cookie_value = match extract_cookie(request, SESSION_COOKIE_NAME) {
        Some(v) => v,
        None => return false,
    };

    // Verify the token — HMAC check + expiry check.
    verify_token(&cookie_value, &secret).is_some()
}

/// Issue a new signed session cookie.
/// Called by pow.rs after successful PoW verification.
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
    let token = format!("{}.{}", payload, signature_hex);

    // Set-Cookie header value with security flags.
    // Secure: only sent over HTTPS (enforced by our TLS layer).
    // HttpOnly: not accessible to JavaScript — prevents XSS theft.
    // SameSite=Strict: not sent on cross-site requests — prevents CSRF.
    Some(format!(
        "{}={}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_COOKIE_NAME,
        token,
        SESSION_DURATION_SECS,
    ))
}

/// Verify a session token string.
/// Returns Some(Session) if valid, None if invalid or expired.
/// Performs constant-time HMAC comparison to prevent timing attacks.
fn verify_token(token: &str, secret: &str) -> Option<Session> {
    // Split on the last '.' to separate payload from signature.
    let dot_pos = token.rfind('.')?;
    let payload = &token[..dot_pos];
    let provided_signature_hex = &token[dot_pos + 1..];

    // Recompute the expected HMAC from the payload and secret.
    let expected_signature = hmac_sha256(
        secret.as_bytes(),
        payload.as_bytes(),
    );
    let expected_hex = to_hex(&expected_signature);

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

    Some(Session { expires_at })
}

/// Extract a named cookie value from the Cookie request header.
/// Returns None if the header is absent or the cookie is not found.
fn extract_cookie<'a>(request: &'a Request, name: &str) -> Option<String> {
    let cookie_header = request.headers.get("cookie")?;

    // Cookie header format: name=value; name2=value2
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }

    None
}

/// Read the HMAC secret from the SESSION_SECRET environment variable.
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

/// HMAC-SHA256 implementation using only std.
/// No external crate — pure Rust against the FIPS 198-1 specification.
///
/// HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
/// where K' is the key padded to the block size,
/// opad = 0x5c repeated, ipad = 0x36 repeated.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const OPAD: u8 = 0x5c;
    const IPAD: u8 = 0x36;

    // If key is longer than block size, hash it first.
    let mut k_prime = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        k_prime[..32].copy_from_slice(&hashed);
    } else {
        k_prime[..key.len()].copy_from_slice(key);
    }

    // Inner hash: H((K' XOR ipad) || message)
    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    for b in &k_prime {
        inner_input.push(b ^ IPAD);
    }
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    // Outer hash: H((K' XOR opad) || inner_hash)
    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    for b in &k_prime {
        outer_input.push(b ^ OPAD);
    }
    outer_input.extend_from_slice(&inner_hash);

    sha256(&outer_input)
}

/// SHA-256 implementation against the FIPS 180-4 specification.
/// Pure Rust, no external crate.
fn sha256(message: &[u8]) -> [u8; 32] {
    // Initial hash values — first 32 bits of fractional parts
    // of square roots of first 8 primes.
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Round constants — first 32 bits of fractional parts
    // of cube roots of first 64 primes.
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Pre-processing: padding the message.
    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80); // Append bit '1' as byte 0x80
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    // Append original length as 64-bit big-endian
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk.
    for chunk in padded.chunks(64) {
        // Prepare message schedule.
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7)
                ^ w[i-15].rotate_right(18)
                ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17)
                ^ w[i-2].rotate_right(19)
                ^ (w[i-2] >> 10);
            w[i] = w[i-16]
                .wrapping_add(s0)
                .wrapping_add(w[i-7])
                .wrapping_add(s1);
        }

        // Compression function.
        let [mut a, mut b, mut c, mut d,
             mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6)
                ^ e.rotate_right(11)
                ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2)
                ^ a.rotate_right(13)
                ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g  = f;
            f  = e;
            e  = d.wrapping_add(temp1);
            d  = c;
            c  = b;
            b  = a;
            a  = temp1.wrapping_add(temp2);
        }

        // Add compressed chunk to current hash value.
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // Produce final hash — concatenate h0..h7 as big-endian bytes.
    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..(i + 1) * 4]
            .copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Encode a byte slice as a lowercase hex string.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Constant-time byte slice comparison.
/// Returns true if both slices are equal.
/// Takes the same amount of time regardless of where they differ,
/// preventing timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR each byte pair — 0 if equal, non-zero if different.
    // OR all results — 0 if all pairs were equal.
    // This forces the CPU to evaluate every byte pair
    // regardless of early differences.
    let result: u8 = a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    result == 0
}
