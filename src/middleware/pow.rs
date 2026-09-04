use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::crypto::{constant_time_eq, hmac_hex, sha256, to_hex};
use crate::http::{Request, Response};
use crate::middleware::session;

/// Number of leading zero bits required in a valid `PoW` solution.
/// At difficulty 20, a browser must compute ~1 million SHA-256
/// hashes on average. At WASM speeds (~10M hashes/sec) this
/// takes ~100ms — imperceptible to a human, expensive at scale.
/// → Open question: make this configurable via environment variable
const DIFFICULTY: u32 = 20;

/// How long a challenge nonce is valid in seconds.
/// After this window, the challenge must be re-requested.
const CHALLENGE_TTL_SECS: u64 = 300; // 5 minutes

/// Max /pow/verify submissions allowed per IP inside the rate window.
/// A real solve costs the browser roughly a million SHA-256 hashes, so no
/// honest client posts more than a handful per minute. Ten leaves room for a
/// retry after a stalled page while stopping a single IP from hammering the
/// endpoint at TCP speed. The eleventh attempt in a window answers 429.
const VERIFY_RATE_LIMIT: u32 = 10;

/// Width of the per-IP /pow/verify rate window.
const VERIFY_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Cap on tracked IPs before stale windows are swept.
/// A scanner spraying many source addresses opens one window each; without a
/// bound the table would grow forever. Past the cap, each new submission
/// drops the windows that have already fully elapsed.
const MAX_TRACKED_IPS: usize = 4096;

/// Per-IP submission counters for /pow/verify, keyed by client address.
/// Each value is (submissions, window start). `OnceLock` because
/// `HashMap::new` is not const: the first verify request builds the map, and
/// every later request reuses it. The mutex serializes the one-thread-per-
/// connection workers.
static VERIFY_LIMITS: OnceLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> = OnceLock::new();

/// A parsed `PoW` solution submission from the browser.
struct PowSubmission {
    /// The server-issued challenge nonce.
    nonce: String,
    /// The HMAC signature over the nonce, proving server issued it.
    nonce_sig: String,
    /// The candidate value the browser found that satisfies difficulty.
    candidate: u64,
}

/// Verify a `PoW` solution submitted via POST /pow/verify.
/// Called by router.rs when method=POST, path=/pow/verify, with the client's
/// address so the endpoint can enforce its per-IP budget.
///
/// On success: returns a 302 redirect with a session cookie.
/// On failure: returns a 400 or 403 with no cookie, or 429 when the client
/// has spent its allowance (see `VERIFY_RATE_LIMIT`).
pub fn verify(request: &Request, peer: Option<IpAddr>) -> Response {
    // Per-IP budget, checked before parsing: a client that spams malformed
    // bodies still spends its allowance, so the cap cannot be dodged by never
    // sending a well-formed submission. A request with no resolvable peer
    // skips the check — a socket without an address is not a real client.
    if let Some(ip) = peer
        && rate_limited(ip)
    {
        return too_many_submissions();
    }

    // Parse the submission from the request body.
    let Some(submission) = parse_submission(&request.body) else {
        return bad_submission();
    };

    // Verify the nonce was issued by this server.
    // Prevents forged challenges submitted directly to /pow/verify.
    if !verify_nonce_signature(&submission.nonce, &submission.nonce_sig) {
        return bad_submission();
    }

    // Verify the nonce has not expired.
    if nonce_is_expired(&submission.nonce) {
        return expired_challenge();
    }

    // Verify the candidate satisfies the difficulty requirement.
    // This is the actual PoW check — does SHA-256(nonce + candidate)
    // have DIFFICULTY leading zero bits?
    if !solution_is_valid(&submission.nonce, submission.candidate) {
        return bad_submission();
    }

    // Valid solution — issue a session cookie and redirect.
    let Some(cookie) = session::issue_cookie() else {
        // SESSION_SECRET not configured — server misconfiguration.
        // Return 500 rather than silently granting access.
        return Response {
            status: 500,
            reason: "Internal Server Error",
            headers: Vec::new(),
            body: b"The server is misconfigured. Try again in a few minutes.".to_vec(),
        };
    };

    // 302 redirect to the index page.
    // The session cookie grants access on the next request.
    Response {
        status: 302,
        reason: "Found",
        headers: vec![
            ("Location".to_string(), "/".to_string()),
            ("Set-Cookie".to_string(), cookie),
        ],
        body: Vec::new(),
    }
}

/// Generate a new challenge for the browser to solve.
/// Returns (nonce, signature) — both are sent to the browser
/// in the challenge page. The browser submits them back with
/// its solution so the server can verify authenticity.
pub fn generate_challenge() -> Option<(String, String)> {
    let secret = std::env::var("SESSION_SECRET").ok()?;

    // Nonce format: timestamp.random_hex
    // Timestamp allows expiry checking.
    // Random bytes prevent pre-computation.
    let timestamp = current_unix_time();
    let random = generate_random_hex();
    let nonce = format!("{timestamp}.{random}");

    // Sign the nonce so we can verify it was server-issued.
    let signature = hmac_hex(secret.as_bytes(), nonce.as_bytes());

    Some((nonce, signature))
}

/// Parse the `PoW` submission from the POST body.
/// Expected format: `nonce=...&nonce_sig=...&candidate=...`
/// Returns None if any field is missing or malformed.
fn parse_submission(body: &[u8]) -> Option<PowSubmission> {
    let body_str = std::str::from_utf8(body).ok()?;

    let mut nonce = None;
    let mut nonce_sig = None;
    let mut candidate = None;

    for pair in body_str.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "nonce"      => nonce      = Some(v.to_string()),
                "nonce_sig"  => nonce_sig  = Some(v.to_string()),
                "candidate"  => candidate  = v.parse::<u64>().ok(),
                _            => {} // ignore unknown fields
            }
        }
    }

    Some(PowSubmission {
        nonce: nonce?,
        nonce_sig: nonce_sig?,
        candidate: candidate?,
    })
}

/// Verify the nonce HMAC signature.
/// Proves the nonce was generated by this server.
fn verify_nonce_signature(nonce: &str, provided_sig: &str) -> bool {
    let Ok(secret) = std::env::var("SESSION_SECRET") else {
        return false;
    };

    let expected = hmac_hex(secret.as_bytes(), nonce.as_bytes());

    // Constant-time comparison — same reasoning as in session.rs.
    constant_time_eq(expected.as_bytes(), provided_sig.as_bytes())
}

/// Check whether the nonce has exceeded its TTL.
/// Nonce format: `timestamp.random_hex` — parse the timestamp.
fn nonce_is_expired(nonce: &str) -> bool {
    let Some((timestamp_str, _)) = nonce.split_once('.') else {
        return true; // malformed nonce, treat as expired
    };

    let issued_at: u64 = match timestamp_str.parse() {
        Ok(t) => t,
        Err(_) => return true,
    };

    current_unix_time().saturating_sub(issued_at) > CHALLENGE_TTL_SECS
}

/// Verify the `PoW` solution satisfies the difficulty requirement.
/// Computes SHA-256(nonce + "." + candidate) and checks that the
/// result has at least DIFFICULTY leading zero bits.
fn solution_is_valid(nonce: &str, candidate: u64) -> bool {
    let input = format!("{nonce}.{candidate}");
    let hash = sha256(input.as_bytes());

    // Count leading zero bits across the hash bytes.
    let mut zero_bits = 0u32;
    for byte in &hash {
        if *byte == 0 {
            zero_bits += 8;
        } else {
            // Count leading zeros in this byte.
            zero_bits += byte.leading_zeros();
            break;
        }
    }

    zero_bits >= DIFFICULTY
}

/// 400 response for a malformed or invalid submission.
fn bad_submission() -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        headers: Vec::new(),
        body: b"That proof of work did not verify. Reload the page for a fresh challenge.".to_vec(),
    }
}

/// 403 response for an expired challenge.
fn expired_challenge() -> Response {
    Response {
        status: 403,
        reason: "Forbidden",
        headers: Vec::new(),
        body: b"That challenge expired. Reload the page for a fresh one.".to_vec(),
    }
}

/// Record one /pow/verify submission from `ip` and report whether the client
/// is now over its allowance.
/// Returns true when the submission must be refused (429). A window opens on
/// a client's first submission and closes `VERIFY_RATE_WINDOW` later; a
/// submission that arrives after the close opens a fresh window.
fn rate_limited(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut table = verify_limits();

    // Sweep expired windows only once the table is full, so steady traffic
    // does not pay an O(n) pass per submission.
    if table.len() >= MAX_TRACKED_IPS {
        table.retain(|_, &mut (_, start)| now.duration_since(start) < VERIFY_RATE_WINDOW);
    }

    match table.entry(ip) {
        Entry::Occupied(mut entry) => {
            let (count, start) = entry.get_mut();
            if now.duration_since(*start) >= VERIFY_RATE_WINDOW {
                // Previous window has fully elapsed: this submission opens a
                // fresh one instead of counting against the old budget.
                *count = 1;
                *start = now;
                false
            } else if *count >= VERIFY_RATE_LIMIT {
                true
            } else {
                *count += 1;
                false
            }
        }
        Entry::Vacant(entry) => {
            entry.insert((1, now));
            false
        }
    }
}

/// Lock the shared per-IP table, treating a poisoned mutex as unlocked.
fn verify_limits() -> std::sync::MutexGuard<'static, HashMap<IpAddr, (u32, Instant)>> {
    VERIFY_LIMITS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// 429 response when a client has spent its per-IP allowance.
fn too_many_submissions() -> Response {
    Response {
        status: 429,
        reason: "Too Many Requests",
        headers: Vec::new(),
        body: b"Too many solve attempts. Wait a minute and try again.".to_vec(),
    }
}

/// Current Unix timestamp in seconds.
fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
}

/// Generate 16 random bytes and return them as a hex string, read from
/// /dev/urandom. Pure std — no rand crate.
fn generate_random_hex() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .expect("Cannot open /dev/urandom")
        .read_exact(&mut buf)
        .expect("Cannot read from /dev/urandom");
    to_hex(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, Request};
    use std::collections::HashMap;

    /// Same `SESSION_SECRET` literal as the router/session tests, so
    /// env-dependent tests across modules of this crate (which share one
    /// test process) never race on a *different* value.
    const TEST_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn set_secret() {
        // edition 2024 makes env mutation unsafe — established idiom.
        unsafe { std::env::set_var("SESSION_SECRET", TEST_SECRET) }
    }

    /// Brute-force a candidate that satisfies the CURRENT difficulty for a
    /// given server-issued nonce, using the module's own validity check.
    fn solve(nonce: &str) -> u64 {
        // Expected 2^DIFFICULTY ≈ 1M tries at difficulty 20; the cap exists
        // only to guarantee termination in a pathological tail.
        const MAX_TRIES: u64 = 1 << 25;
        for candidate in 0..MAX_TRIES {
            if solution_is_valid(nonce, candidate) {
                return candidate;
            }
        }
        panic!("no candidate satisfied difficulty {DIFFICULTY} within {MAX_TRIES} tries");
    }

    fn post_request(nonce: &str, sig: &str, candidate: u64) -> Request {
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        Request {
            method: Method::Post,
            path: "/pow/verify".to_string(),
            headers,
            body: format!("nonce={nonce}&nonce_sig={sig}&candidate={candidate}").into_bytes(),
        }
    }

    /// Dedicated source addresses so the limiter's shared map never sees two
    /// tests writing the same key concurrently (test threads run in parallel).
    const REPLAY_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    /// Documents known gap #14: `pow::verify` is stateless — no record of
    /// used nonces is kept, so replaying the SAME valid submission within the
    /// nonce TTL (300s) succeeds twice, minting a second session cookie.
    /// This is the intended current behavior (the cost is paid per solve, and
    /// a replayed solve re-verifies cheaply); the note in `09_security_audit`
    /// tracks it as accepted-until-volume-justifies-a-used-nonce-cache.
    #[test]
    fn same_valid_submission_verifies_twice_replay_window() {
        set_secret();
        let (nonce, sig) = generate_challenge().expect("secret configured → challenge issued");
        let candidate = solve(&nonce);

        let first = verify(&post_request(&nonce, &sig, candidate), Some(REPLAY_IP));
        let second = verify(&post_request(&nonce, &sig, candidate), Some(REPLAY_IP));

        assert_eq!(first.status, 302, "first submission must succeed");
        assert_eq!(second.status, 302, "replayed submission also succeeds — gap #14");
        let has_cookie = |r: &Response| r.headers.iter().any(|(n, _)| n == "Set-Cookie");
        assert!(has_cookie(&first), "first response sets a session cookie");
        assert!(has_cookie(&second), "replayed response sets another session cookie");
    }

    /// A client inside its allowance keeps getting 302s; the first submission
    /// past the allowance gets 429. Exercises the full handler path with a
    /// dedicated source address so no other test shares its budget.
    #[test]
    fn verify_exhausts_per_ip_allowance_then_returns_429() {
        set_secret();
        let source = ip(10, 55, 0, 1);
        let (nonce, sig) = generate_challenge().expect("secret configured → challenge issued");
        let candidate = solve(&nonce);

        // Each call replays the same valid solve (gap #14: used nonces are not
        // tracked), so the loop is only counting submissions against the IP.
        for _ in 0..VERIFY_RATE_LIMIT {
            let response = verify(&post_request(&nonce, &sig, candidate), Some(source));
            assert_eq!(response.status, 302, "within the allowance, verify grants a session");
        }

        let over = verify(&post_request(&nonce, &sig, candidate), Some(source));
        assert_eq!(over.status, 429, "past the allowance, verify answers 429");
    }

    /// A client whose window has fully elapsed is not throttled: the budget
    /// resets when the old window closes. The entry's start is pushed back
    /// past `VERIFY_RATE_WINDOW` to simulate the clock moving on without a
    /// sixty-second sleep in the test.
    #[test]
    fn expired_window_resets_a_clients_allowance() {
        let source = ip(10, 55, 0, 2);
        assert!(!rate_limited(source), "first submission opens the window");
        for _ in 1..VERIFY_RATE_LIMIT {
            assert!(!rate_limited(source), "submissions inside the window are allowed");
        }
        assert!(rate_limited(source), "the submission at the limit is refused");

        // Age the entry out by one full window.
        {
            let mut table = verify_limits();
            let (_, start) = table.get_mut(&source).expect("entry exists for the aged client");
            let older = start
                .checked_sub(VERIFY_RATE_WINDOW)
                .expect("the window start stays within the monotonic clock");
            *start = older;
            // The mutation is done; release the guard before the block ends so
            // a parallel test never waits on a guard held for no further work.
            drop(table);
        }

        assert!(!rate_limited(source), "a fresh window opens once the old one closes");
    }
}
