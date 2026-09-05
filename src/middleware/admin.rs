//! Authentication for the operator dashboard at /admin.
//!
//! A separate signed cookie, `zts-admin`, gates the dashboard. It is
//! deliberately independent of the visitor session (`zts`) that the proof of
//! work issues: the dashboard is a private maintenance surface, and its
//! authentication must not share a secret, a signing key, or a lifetime with
//! the public gate.
//!
//!   - The cookie is signed with `ZTS_ADMIN_SECRET`, a distinct environment
//!     variable required at startup alongside `SESSION_SECRET`.
//!   - It is issued only by POST /admin/login, after the submitted password
//!     matches `ZTS_ADMIN_PASSWORD` (compared in constant time).
//!   - Password attempts are throttled per IP (see the limits below), so the
//!     login door cannot be hammered at TCP speed even against a password
//!     that resists a timing side channel.
//!   - It expires after four hours.
//!
//! Both secrets fail closed: if the environment variable is absent or empty,
//! no cookie can be issued and no request is authorized.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::{constant_time_eq, hmac_sha256, to_hex};
use crate::http::Request;
use crate::middleware::session;

/// Cookie name for the admin session.
const ADMIN_COOKIE_NAME: &str = "zts-admin";

/// Admin session duration — 4 hours, a working window with a defined end.
const ADMIN_SESSION_DURATION_SECS: u64 = 4 * 60 * 60;

/// Max password attempts allowed per IP inside the window on /admin/login.
/// Ten tolerates a few wrong guesses (an operator mistypes) while capping
/// online guessing against the dashboard at two attempts a minute.
const MAX_LOGIN_ATTEMPTS: u32 = 10;

/// Width of the per-IP /admin/login attempt window.
const LOGIN_RATE_WINDOW: Duration = Duration::from_secs(300);

/// Cap on tracked IPs before stale windows are swept. The admin login draws
/// only the operator, so even a scanner spraying source addresses cannot fill
/// more than this many slots before the sweeps run.
const MAX_TRACKED_LOGIN_IPS: usize = 256;

/// Per-IP password-attempt counters for /admin/login, keyed by client address.
/// Same shape as the /pow/verify limiter in pow.rs: each value is
/// (attempts, window start), shared behind a mutex across the worker threads.
static LOGIN_LIMITS: OnceLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> = OnceLock::new();

/// Issue a new signed admin cookie after a successful login.
/// Returns the Set-Cookie header value, or None when `ZTS_ADMIN_SECRET` is
/// not configured (the server fails closed rather than minting an
/// unsigned-able session).
pub fn issue_cookie() -> Option<String> {
    let secret = admin_secret()?;

    let expires_at = current_unix_time() + ADMIN_SESSION_DURATION_SECS;

    // Payload is just the expiry timestamp, same scheme as the zts session
    // cookie: it holds nothing about who the operator is.
    let payload = expires_at.to_string();
    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    let token = format!("{payload}.{}", to_hex(&signature));

    Some(format!(
        "{ADMIN_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; \
         SameSite=Strict; Max-Age={ADMIN_SESSION_DURATION_SECS}"
    ))
}

/// Whether the request carries a valid, unexpired admin cookie.
pub fn is_authorized(request: &Request) -> bool {
    let Some(secret) = admin_secret() else {
        return false; // No secret configured — fail closed.
    };
    let Some(cookie_value) = session::extract_cookie(request, ADMIN_COOKIE_NAME) else {
        return false;
    };
    verify_token(&cookie_value, &secret).is_some()
}

/// Whether a submitted login password matches `ZTS_ADMIN_PASSWORD`.
/// Constant-time comparison so response time does not leak how many
/// characters matched.
pub fn check_password(provided: &str) -> bool {
    let Ok(expected) = std::env::var("ZTS_ADMIN_PASSWORD") else {
        return false; // Not configured — no password can match.
    };
    if expected.is_empty() {
        return false;
    }
    constant_time_eq(provided.as_bytes(), expected.as_bytes())
}

/// Record one password attempt from `ip` and report whether the client is now
/// over its allowance. Mirrors the /pow/verify limiter: a window opens on the
/// first attempt and closes `LOGIN_RATE_WINDOW` later; an attempt after the
/// close opens a fresh window. Returns true when the attempt must be refused.
pub fn login_attempt_denied(ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut table = login_limits();

    // Sweep expired windows only once the table is full, so the operator's
    // rare logins never pay an O(n) pass.
    if table.len() >= MAX_TRACKED_LOGIN_IPS {
        table.retain(|_, &mut (_, start)| now.duration_since(start) < LOGIN_RATE_WINDOW);
    }

    match table.entry(ip) {
        Entry::Occupied(mut entry) => {
            let (count, start) = entry.get_mut();
            if now.duration_since(*start) >= LOGIN_RATE_WINDOW {
                *count = 1;
                *start = now;
                false
            } else if *count >= MAX_LOGIN_ATTEMPTS {
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

/// Clear the attempt budget for `ip`, called on a successful login so earlier
/// wrong guesses in the same window never punish the correct password.
pub fn login_succeeded(ip: IpAddr) {
    login_limits().remove(&ip);
}

/// Lock the shared per-IP login table, treating a poisoned mutex as unlocked.
fn login_limits() -> std::sync::MutexGuard<'static, HashMap<IpAddr, (u32, Instant)>> {
    LOGIN_LIMITS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Verify an admin token string against the secret.
fn verify_token(token: &str, secret: &str) -> Option<()> {
    let dot_pos = token.rfind('.')?;
    let payload = &token[..dot_pos];
    let provided_signature_hex = &token[dot_pos + 1..];

    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    let expected_hex = to_hex(&signature);
    if !constant_time_eq(expected_hex.as_bytes(), provided_signature_hex.as_bytes()) {
        return None;
    }

    let expires_at: u64 = payload.parse().ok()?;
    if current_unix_time() >= expires_at {
        return None;
    }
    Some(())
}

/// Read `ZTS_ADMIN_SECRET`, or None when it is absent or empty.
fn admin_secret() -> Option<String> {
    match std::env::var("ZTS_ADMIN_SECRET") {
        Ok(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Current Unix time in seconds.
fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Method, Request};
    use std::collections::HashMap;

    /// Fixed values every test module sets, so tests in this crate that
    /// touch the same env variables concurrently cannot race on a *different*
    /// value (env is process-global).
    const TEST_ADMIN_SECRET: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const TEST_ADMIN_PASSWORD: &str = "correct horse battery staple";

    fn set_admin_env() {
        // edition 2024 makes env mutation unsafe — established idiom.
        unsafe {
            std::env::set_var("ZTS_ADMIN_SECRET", TEST_ADMIN_SECRET);
            std::env::set_var("ZTS_ADMIN_PASSWORD", TEST_ADMIN_PASSWORD);
        }
    }

    fn request_with_cookie(cookie: &str) -> Request {
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), cookie.to_string());
        Request {
            method: Method::Get,
            path: "/admin".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn issued_cookie_authorizes_the_request() {
        set_admin_env();
        let cookie = issue_cookie().expect("admin secret configured → cookie issued");
        let value = cookie.split(';').next().expect("name=value form").to_string();
        assert!(is_authorized(&request_with_cookie(&value)));
    }

    #[test]
    fn one_bit_flip_in_the_signature_revokes_authorization() {
        set_admin_env();
        let cookie = issue_cookie().expect("admin secret configured → cookie issued");
        let value = cookie.split(';').next().expect("name=value form");
        let token = value.strip_prefix("zts-admin=").expect("admin cookie name");
        let (payload, sig_hex) = token.split_once('.').expect("payload.signature");

        // Flip the low bit of the signature's first byte.
        let mut sig: Vec<u8> = (0..sig_hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&sig_hex[i..i + 2], 16).expect("hex digits")
            })
            .collect();
        sig[0] ^= 0x01;
        let forged_hex = to_hex(&sig);
        let forged = format!("zts-admin={payload}.{forged_hex}");

        assert_ne!(value, forged);
        assert!(!is_authorized(&request_with_cookie(&forged)),
            "a forged admin cookie must not authorize");
    }

    #[test]
    fn no_cookie_and_wrong_cookie_are_not_authorized() {
        set_admin_env();
        assert!(!is_authorized(&request_with_cookie("")));
        assert!(!is_authorized(&request_with_cookie("zts-admin=garbage")));
    }

    #[test]
    fn password_matches_exactly_and_in_constant_time_shape() {
        set_admin_env();
        assert!(check_password(TEST_ADMIN_PASSWORD));
        assert!(!check_password("wrong password"));
        assert!(!check_password(""));
    }

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 90, 0, d))
    }

    /// The login limiter allows a full window of attempts, refuses the one at
    /// the limit, and budgets each IP independently.
    #[test]
    fn login_attempts_are_rate_limited_per_ip() {
        let source = ip(1);
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            assert!(!login_attempt_denied(source), "attempts inside the window are allowed");
        }
        assert!(login_attempt_denied(source), "the attempt at the limit is refused");

        let other = ip(2);
        assert!(!login_attempt_denied(other), "each IP budgets independently");
    }

    /// A successful login clears the IP's budget, so an operator who mistypes
    /// a few times is not locked out after finally getting it right.
    #[test]
    fn successful_login_resets_the_ip_budget() {
        let source = ip(3);
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            let _ = login_attempt_denied(source);
        }
        assert!(login_attempt_denied(source), "the budget is spent");
        login_succeeded(source);
        assert!(!login_attempt_denied(source), "success clears the prior attempts");
    }

    /// A fully elapsed window resets the budget: the entry's start is pushed
    /// back past `LOGIN_RATE_WINDOW` to simulate the clock moving on without a
    /// five-minute sleep in the test.
    #[test]
    fn login_window_expiry_resets_the_budget() {
        let source = ip(4);
        for _ in 0..MAX_LOGIN_ATTEMPTS {
            let _ = login_attempt_denied(source);
        }
        assert!(login_attempt_denied(source), "the budget is spent");

        {
            let mut table = login_limits();
            let (_, start) = table.get_mut(&source).expect("entry exists for the aged client");
            let older = start
                .checked_sub(LOGIN_RATE_WINDOW)
                .expect("the window start stays within the monotonic clock");
            *start = older;
            drop(table);
        }

        assert!(!login_attempt_denied(source), "a fresh window opens once the old one closes");
    }
}
