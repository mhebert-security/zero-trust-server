//! Canary tokens planted in 404 responses.
//!
//! Every 404 the TLS listener serves mints a fresh token: 16 random bytes,
//! hex encoded, embedded as a data attribute on an invisible span in the
//! response body and recorded on that request's audit line (the rightmost
//! column). Later, any request whose headers or body carry a token the
//! server already issued trips a CANARY alert.
//!
//! A canary token is a tripwire for response-body capture. An honest browser
//! renders a 404 page and never sends its text back. A token that returns in
//! a later request means someone stored the body and echoed it: a proxy that
//! logs responses, a script that read the DOM, a stored script that
//! exfiltrates page text. Each of those leaves exactly this trace, and the
//! alert names the token so the operator can search the journal for the miss
//! that seeded it (the audit line that minted the token carries the same
//! value in its canary column).
//!
//! Bounds: the token table is capped (`MAX_ISSUED`). Under a miss flood the
//! oldest token is evicted, so memory stays flat no matter how many 404s
//! arrive. There is no time sweep: a token lives until newer misses push it
//! out, so a canary that an attacker discovers weeks later still fires. The
//! plaintext listener's 404 (redirect.rs) is out of scope: it never reaches
//! the session gate and writes no audit line, so a token there could not be
//! correlated back to anything.
//!
//! How a minted token reaches the audit line: the audit context is assembled
//! in the connection handler after routing, while the token is minted deep in
//! the content handlers at the moment the 404 body is built. Rather than
//! thread the value through every handler signature, `mint` leaves it in a
//! thread-local slot and the handler reads it with [`take_pending`] when it
//! assembles the audit line. The channel is race-free because each connection
//! is served start to finish on one worker thread: routing, audit assembly,
//! and the write all happen on the thread that minted, microseconds apart,
//! and the thread serves exactly one request before it exits.

use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::crypto::to_hex;
use crate::http::Request;

/// Bytes of randomness per token. 16 bytes encodes to 32 lowercase hex
/// characters, short enough to sit unnoticed in a page and long enough that a
/// guess at a live token is hopeless.
const TOKEN_BYTES: usize = 16;

/// Maximum tokens held for replay detection. Each 404 mints one; past this
/// cap the oldest token is evicted, so a scanner that floods the server with
/// misses cannot grow the table without bound. At the site's real miss rate
/// tokens live long after the moment that matters.
const MAX_ISSUED: usize = 8192;

/// Issued tokens, shared by all worker threads. Membership is by the raw
/// token bytes; `order` records FIFO issue order so the cap can evict the
/// oldest. `OnceLock` + `Mutex`, the same shape as the consumed-nonce and
/// rate-limit tables elsewhere.
static ISSUED: OnceLock<Mutex<IssuedStore>> = OnceLock::new();

// The token minted while building the response now being audited on this
// thread. See the module docs for why a thread-local is the honest channel.
thread_local! {
    static PENDING: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Issued-token membership with FIFO eviction at a fixed cap.
struct IssuedStore {
    present: HashSet<[u8; TOKEN_BYTES]>,
    /// Issue order, front is oldest, popped when the cap is exceeded.
    order: VecDeque<[u8; TOKEN_BYTES]>,
    cap: usize,
}

impl IssuedStore {
    fn with_cap(cap: usize) -> Self {
        Self {
            present: HashSet::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    /// Record a token as issued, evicting the oldest when the cap is reached.
    /// Re-issuing a token already present is a no-op.
    fn insert(&mut self, token: [u8; TOKEN_BYTES]) {
        if self.present.insert(token) {
            self.order.push_back(token);
            while self.order.len() > self.cap {
                if let Some(oldest) = self.order.pop_front() {
                    self.present.remove(&oldest);
                }
            }
        }
    }

    fn contains(&self, token: &[u8; TOKEN_BYTES]) -> bool {
        self.present.contains(token)
    }
}

/// Lock the shared token table, treating a poisoned mutex as unlocked.
fn issued() -> MutexGuard<'static, IssuedStore> {
    ISSUED
        .get_or_init(|| Mutex::new(IssuedStore::with_cap(MAX_ISSUED)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Mint a fresh canary token: 16 bytes from the operating system's entropy
/// source, hex encoded, recorded for replay detection, and left pending for
/// the current request's audit line.
pub fn mint() -> String {
    let token = random_token();
    issued().insert(token);
    let hex = to_hex(&token);
    PENDING.with(|slot| {
        *slot.borrow_mut() = Some(hex.clone());
    });
    hex
}

/// Read and clear the token minted for the request being audited on this
/// thread, if the response was a 404. Callers pair this with the response
/// status so a non-404 response never picks up a stray value.
pub fn take_pending() -> Option<String> {
    PENDING.with(|slot| slot.borrow_mut().take())
}

/// Search a request's headers, body, and request line for any issued canary
/// token. Returns the canonical lowercase hex of the first token found.
///
/// A replay can place the token anywhere a harvested page text would travel:
/// a header the exfil script controls, the body of a POST, or the query
/// string of a GET. All three are searched. The scan is cheap because it only
/// looks at runs of hex digits: prose and JSON contain almost none, and a
/// hostile all-hex body costs one membership check per 32-character window.
pub fn scan(request: &Request) -> Option<String> {
    let table = issued();
    let is_issued = |key: &[u8; TOKEN_BYTES]| table.contains(key);
    if let Some(hit) = find_issued(&request.body, &is_issued) {
        return Some(hit);
    }
    for value in request.headers.values() {
        if let Some(hit) = find_issued(value.as_bytes(), &is_issued) {
            return Some(hit);
        }
    }
    if let Some(hit) = find_issued(request.path.as_bytes(), &is_issued) {
        return Some(hit);
    }
    None
}

/// The 16 entropy bytes of a new token.
fn random_token() -> [u8; TOKEN_BYTES] {
    use std::io::Read;
    let mut token = [0u8; TOKEN_BYTES];
    let mut entropy = std::fs::File::open("/dev/urandom")
        .expect("open /dev/urandom to mint a canary token");
    entropy
        .read_exact(&mut token)
        .expect("read canary token entropy");
    token
}

/// Search `bytes` for a run of exactly 32 hex characters that decodes to a
/// token `is_issued` recognizes. Returns the canonical lowercase hex of the
/// first match.
///
/// Every 32-character window of a hex run is checked once, at the moment its
/// end passes: slide across the slice and, whenever at least 32 hex
/// characters stand behind the current position, examine the window that
/// ends there. The position just past the slice acts as a terminator so a
/// run that reaches the last byte still gets its final window.
fn find_issued(
    bytes: &[u8],
    is_issued: &dyn Fn(&[u8; TOKEN_BYTES]) -> bool,
) -> Option<String> {
    const HEX_LEN: usize = TOKEN_BYTES * 2;
    if bytes.len() < HEX_LEN {
        return None;
    }
    let mut run_start: Option<usize> = None;
    for i in 0..=bytes.len() {
        let at = if i < bytes.len() { bytes[i] } else { 0 };
        if is_hex(at) && run_start.is_none() {
            run_start = Some(i);
        }
        // Only a window whose 32 characters all lie inside the run (its start
        // is at or past `run_start`) is examined, so a non-hex byte can never
        // leak into a candidate.
        if run_start.is_some_and(|start| i >= start + HEX_LEN)
            && let Some(decoded) = decode_token(&bytes[i - HEX_LEN..i])
            && is_issued(&decoded)
        {
            return Some(to_hex(&decoded));
        }
        if !is_hex(at) {
            run_start = None;
        }
    }
    None
}

/// Decode 32 lowercase or uppercase hex characters back into the 16 token
/// bytes, or None when any character is not a hex digit.
fn decode_token(hex: &[u8]) -> Option<[u8; TOKEN_BYTES]> {
    if hex.len() != TOKEN_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; TOKEN_BYTES];
    for (idx, pair) in hex.chunks_exact(2).enumerate() {
        out[idx] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

/// The value of one hex character, or None when it is not a hex digit.
const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

const fn is_hex(b: u8) -> bool {
    nibble(b).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Method;
    use std::collections::HashMap;

    /// Build a GET request for a scan test.
    fn request(path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
        let headers: HashMap<String, String> = headers
            .iter()
            .map(|&(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Request {
            method: Method::Get,
            path: path.to_string(),
            headers,
            body: body.to_vec(),
        }
    }

    /// A fixed, distinct 16-byte token from a counter, so tests that plant
    /// many tokens never depend on the entropy source.
    fn seeded_token(n: u8) -> [u8; TOKEN_BYTES] {
        let mut t = [0u8; TOKEN_BYTES];
        t[0] = n;
        t
    }

    #[test]
    fn decode_roundtrips_encode_and_accepts_uppercase() {
        let bytes = seeded_token(0xab);
        let hex = to_hex(&bytes);
        assert_eq!(hex.len(), 32);
        assert_eq!(decode_token(hex.as_bytes()).expect("decode"), bytes);
        assert_eq!(
            decode_token(hex.to_uppercase().as_bytes()).expect("case-insensitive decode"),
            bytes
        );
        assert!(decode_token(&hex.as_bytes()[..30]).is_none(), "wrong length");
        assert!(decode_token(&b"z0".repeat(16)).is_none(), "non-hex digit");
    }

    #[test]
    fn find_issued_spots_a_token_anywhere_in_a_stream() {
        let token = to_hex(&seeded_token(7));
        let issued = |candidate: &[u8; TOKEN_BYTES]| {
            candidate == &seeded_token(7)
        };
        // Buried mid-sentence, spanning a boundary where hex meets prose.
        let haystack = format!("prose before {token} and after");
        assert_eq!(
            find_issued(haystack.as_bytes(), &issued).as_deref(),
            Some(token.as_str()),
            "a token inside prose is found"
        );
        // A longer hex run that contains the token near its end still fires.
        let long_run = format!("{}{}", "ab".repeat(8), token);
        assert!(find_issued(long_run.as_bytes(), &issued).is_some());
        // A token that was never issued is ignored.
        let other = to_hex(&seeded_token(9));
        let haystack = format!("value={other}");
        assert_eq!(find_issued(haystack.as_bytes(), &issued), None);
        // Nothing but prose: no candidates, no panic.
        assert_eq!(find_issued(b"all quiet here", &issued), None);
        // A run shorter than 32 hex digits cannot match.
        assert_eq!(find_issued(b"deadbeef", &issued), None);
    }

    #[test]
    fn issued_store_evicts_the_oldest_at_capacity() {
        let mut store = IssuedStore::with_cap(2);
        store.insert(seeded_token(1));
        store.insert(seeded_token(2));
        store.insert(seeded_token(3));
        assert!(!store.contains(&seeded_token(1)), "oldest is evicted first");
        assert!(store.contains(&seeded_token(2)));
        assert!(store.contains(&seeded_token(3)));
        // Re-issuing a live token does not disturb order or membership.
        store.insert(seeded_token(2));
        assert!(store.contains(&seeded_token(2)));
    }

    #[test]
    fn a_minted_canary_is_reported_and_scanned_back() {
        let token = mint();
        assert_eq!(token.len(), 32, "token is 32 hex chars");
        assert!(token.bytes().all(|b| nibble(b).is_some()), "token is hex");
        let second = mint();
        assert_ne!(token, second, "each 404 mints a fresh token");

        // take_pending reports the most recent mint on this thread.
        assert_eq!(take_pending().as_deref(), Some(second.as_str()));

        // The token planted in a header, in a body, and in a query string is
        // each found again, in canonical lowercase form.
        for source in [
            request("/", &[("Cookie", &format!("session={token}"))], b""),
            request("/", &[], format!("{{'body':'{token}'}}").as_bytes()),
            request(&format!("/callback?ref={token}"), &[], b""),
        ] {
            assert_eq!(
                scan(&source).as_deref(),
                Some(token.as_str()),
                "a later request that echoes the token is detected"
            );
        }

        // A request with no planted token is clean, even when it carries
        // plenty of other hex.
        let clean = request("/", &[("X-Trace", "cafebabe")], b"a1b2c3d4e5f67890");
        assert_eq!(scan(&clean), None);
    }
}
