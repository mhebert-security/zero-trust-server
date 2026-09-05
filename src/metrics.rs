//! Process-wide metrics for the operator dashboard at /admin.
//!
//! The server keeps no database and reads no files for these numbers. Each
//! connection handler writes into one shared state at the same moment it
//! builds the audit line, and the dashboard reads a snapshot of that state
//! when it renders. "Since restart" therefore means what it says: every
//! counter lives in memory and resets when the process does.
//!
//! What is tracked:
//!   - request totals by path since restart,
//!   - proof-of-work solve times (a ring buffer of the last 10,000),
//!   - per-session request counters and last-seen times, keyed on the raw
//!     HMAC bytes of the visitor session token,
//!   - process uptime.
//!
//! Testability: the arithmetic lives on [`Metrics`], so tests build a fresh
//! instance and never touch the process global. Production writes go through
//! [`global`], initialised once in `main()` so the uptime clock starts at
//! process start rather than at the first request.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// How many solve events the ring buffer holds. Matches the Part 2 spec: the
/// dashboard's solve distribution is computed from the last 10,000 solves.
const SOLVE_RING_CAP: usize = 10_000;

/// Cap on distinct request paths tracked separately. A scanner spraying
/// unique paths must not grow the table without bound; past the cap, further
/// unseen paths roll into one "(other)" bucket.
const MAX_DISTINCT_PATHS: usize = 256;

/// Cap on tracked session keys before a sweep of idle ones runs. The zts
/// cookie expires 24 hours after issue, so a key that has seen no request in
/// a day can never be valid again and is dead weight.
const MAX_TRACKED_SESSIONS: usize = 100_000;

/// Seconds a session key must be idle before a sweep drops it. Matches the
/// session lifetime, plus nothing: an idle day means an expired cookie.
const SESSION_SWEEP_IDLE_SECS: u64 = 86_400;

/// Width of the "active session" window on the dashboard.
const ACTIVE_SESSION_WINDOW_SECS: u64 = 3_600;

/// The shared state behind one [`Metrics`] handle. Every field is a
/// monotonic-now or wall-clock figure written under the single mutex.
struct State {
    /// When the process started (the moment `Metrics::new` ran in main).
    started: Instant,
    /// Requests by path since restart, plus the overflow bucket.
    requests: HashMap<String, u64>,
    requests_other: u64,
    /// Last `SOLVE_RING_CAP` successful solve times in milliseconds.
    solves: VecDeque<u64>,
    /// Requests per session token, keyed on the token's HMAC signature bytes.
    request_counts: HashMap<[u8; 32], u64>,
    /// Unix seconds of the last request per session token, for the
    /// active-in-the-last-hour count. Shares keys with `request_counts`.
    last_seen: HashMap<[u8; 32], u64>,
}

/// A process-global [`Metrics`], behind a `OnceLock` (like the per-IP
/// /pow/verify table in pow.rs): created once at startup, shared by all
/// worker threads.
static GLOBAL: OnceLock<Metrics> = OnceLock::new();

/// Handle to the process-wide metrics state.
///
/// Methods lock the inner state per call. The connection handlers call the
/// `record_*` methods while building an audit line; the dashboard reads a
/// [`Snapshot`] to render.
pub struct Metrics {
    state: Mutex<State>,
}

/// One coherent read of the metrics state for the dashboard.
pub struct Snapshot {
    /// Every request on the TLS listener since restart, all paths combined.
    pub total_requests: u64,
    /// Per-path request totals, largest first. May carry a final "(other)"
    /// row for paths past the distinct-path cap.
    pub path_counts: Vec<(String, u64)>,
    /// Solve distribution over the ring buffer, if any solves are recorded.
    pub solves: Option<SolveStats>,
    /// Distinct session tokens seen in the last hour.
    pub active_sessions: u64,
    /// Seconds since process start.
    pub uptime_secs: u64,
}

/// The solve-time distribution the dashboard shows.
pub struct SolveStats {
    /// Solves in the buffer (never more than `SOLVE_RING_CAP`).
    pub count: usize,
    /// The middle recorded solve time in milliseconds.
    pub median_ms: u64,
    /// The 95th percentile solve time in milliseconds.
    pub p95_ms: u64,
    /// The slowest recorded solve time in milliseconds.
    pub max_ms: u64,
}

impl Metrics {
    /// A fresh, empty metrics state. Tests build their own; production uses
    /// [`global`].
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                started: Instant::now(),
                requests: HashMap::new(),
                requests_other: 0,
                solves: VecDeque::with_capacity(SOLVE_RING_CAP),
                request_counts: HashMap::new(),
                last_seen: HashMap::new(),
            }),
        }
    }

    /// Count one served request on the TLS listener, bucketed by path.
    pub fn record_request(&self, path: &str) {
        let mut state = self.lock();
        match state.requests.get_mut(path) {
            Some(count) => *count += 1,
            None => {
                if state.requests.len() >= MAX_DISTINCT_PATHS {
                    state.requests_other += 1;
                } else {
                    state.requests.insert(path.to_string(), 1);
                }
            }
        }
    }

    /// Record one successful proof-of-work solve time in milliseconds,
    /// dropping the oldest solve when the ring buffer is full.
    pub fn record_solve(&self, ms: u64) {
        let mut state = self.lock();
        if state.solves.len() == SOLVE_RING_CAP {
            state.solves.pop_front();
        }
        state.solves.push_back(ms);
    }

    /// Count one request for a valid session, returning the request's number
    /// within that session (1 for the first request carrying the token).
    /// Also stamps the session's last-seen time for the active count.
    pub fn record_valid_request(&self, key: [u8; 32]) -> u64 {
        self.record_valid_request_at(key, unix_secs())
    }

    /// [`record_valid_request`] with an explicit clock, so tests can age a
    /// session without sleeping.
    fn record_valid_request_at(&self, key: [u8; 32], now: u64) -> u64 {
        let mut state = self.lock();
        Self::sweep_sessions(&mut state, now);
        // The entry borrow must end before last_seen is touched, so the
        // increment happens in its own scope and hands out its result.
        let count = {
            let entry = state.request_counts.entry(key).or_insert(0);
            *entry += 1;
            *entry
        };
        state.last_seen.insert(key, now);
        count
    }

    /// Distinct session tokens seen within the last hour, at an explicit
    /// clock so tests can age a session without sleeping. The dashboard reads
    /// the same figure from [`Snapshot`], computed under the snapshot lock.
    #[cfg(test)]
    fn active_sessions_at(&self, now: u64) -> u64 {
        let state = self.lock();
        count_active(&state, now)
    }

    /// A read-consistent snapshot for the dashboard. Sorting and percentile
    /// math happen on copies taken under the lock, so the state is never held
    /// across the work.
    pub fn snapshot(&self) -> Snapshot {
        let state = self.lock();

        let mut path_counts: Vec<(String, u64)> = state
            .requests
            .iter()
            .map(|(path, count)| (path.clone(), *count))
            .collect();
        if state.requests_other > 0 {
            path_counts.push(("(other)".to_string(), state.requests_other));
        }
        path_counts.sort_by(|a, b| b.1.cmp(&a.1));

        let total_requests: u64 = path_counts.iter().map(|(_, count)| count).sum();

        let solves = if state.solves.is_empty() {
            None
        } else {
            let mut sorted: Vec<u64> = state.solves.iter().copied().collect();
            sorted.sort_unstable();
            let count = sorted.len();
            let median = sorted[(count - 1) / 2];
            let p95 = sorted[p95_index(count)];
            let max = *sorted.last().expect("non-empty, checked above");
            Some(SolveStats {
                count,
                median_ms: median,
                p95_ms: p95,
                max_ms: max,
            })
        };

        let active_sessions = count_active(&state, unix_secs());

        Snapshot {
            total_requests,
            path_counts,
            solves,
            active_sessions,
            uptime_secs: state.started.elapsed().as_secs(),
        }
    }

    /// Drop sessions idle past the sweep threshold, but only once the table
    /// is full, so steady traffic does not pay an O(n) pass per request.
    /// Mirrors the lazy sweep in pow.rs's per-IP table. An associated function
    /// because it touches only the state, never the handle.
    fn sweep_sessions(state: &mut State, now: u64) {
        if state.request_counts.len() < MAX_TRACKED_SESSIONS {
            return;
        }
        let oldest_live = now.saturating_sub(SESSION_SWEEP_IDLE_SECS);
        state.last_seen.retain(|_, &mut seen| seen >= oldest_live);
        state
            .request_counts
            .retain(|key, _| state.last_seen.contains_key(key));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide metrics handle, created on first use.
pub fn global() -> &'static Metrics {
    GLOBAL.get_or_init(Metrics::new)
}

/// Force the global into existence at startup so its uptime clock starts
/// when the process does, not at the first request.
pub fn init_at_startup() {
    let _ = global();
}

/// 0-based index of the 95th percentile of `n` ascending values, by nearest
/// rank. `n` is non-zero (checked by the caller).
const fn p95_index(n: usize) -> usize {
    // ceil(0.95 * n), then to 0-based: rank - 1.
    (95 * n).div_ceil(100).saturating_sub(1)
}

/// Count sessions whose last request fell inside the active window. A plain
/// function so a caller that already holds the lock (snapshot) can reuse it
/// without re-acquiring the same mutex.
fn count_active(state: &State, now: u64) -> u64 {
    let window_start = now.saturating_sub(ACTIVE_SESSION_WINDOW_SECS);
    state
        .last_seen
        .values()
        .filter(|&&seen| seen >= window_start)
        .count() as u64
}

/// Current Unix time in seconds.
fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_metrics() -> Metrics {
        Metrics::new()
    }

    #[test]
    fn solve_distribution_matches_known_values() {
        let m = new_metrics();
        for ms in 1..=100 {
            m.record_solve(ms);
        }
        let stats = m.snapshot().solves.expect("solves recorded");
        assert_eq!(stats.count, 100);
        assert_eq!(stats.median_ms, 50);
        assert_eq!(stats.p95_ms, 95);
        assert_eq!(stats.max_ms, 100);
    }

    #[test]
    fn solve_ring_buffer_drops_the_oldest_at_capacity() {
        let m = new_metrics();
        for ms in 1..=SOLVE_RING_CAP as u64 + 10 {
            m.record_solve(ms);
        }
        let stats = m.snapshot().solves.expect("solves recorded");
        assert_eq!(stats.count, SOLVE_RING_CAP, "buffer holds exactly its cap");
        assert_eq!(stats.max_ms, SOLVE_RING_CAP as u64 + 10, "newest survives");
    }

    #[test]
    fn empty_snapshot_has_no_solve_stats() {
        let snapshot = new_metrics().snapshot();
        assert!(snapshot.solves.is_none());
        assert_eq!(snapshot.total_requests, 0);
    }

    #[test]
    fn request_paths_cap_into_an_other_bucket() {
        let m = new_metrics();
        for i in 0..(MAX_DISTINCT_PATHS + 50) {
            m.record_request(&format!("/scanned-{i}"));
        }
        let snapshot = m.snapshot();
        assert_eq!(
            snapshot.total_requests,
            (MAX_DISTINCT_PATHS + 50) as u64,
            "every request is counted"
        );
        let distinct_rows = snapshot.path_counts.len();
        assert_eq!(
            distinct_rows,
            MAX_DISTINCT_PATHS + 1,
            "256 paths plus the overflow bucket"
        );
        let sum: u64 = snapshot.path_counts.iter().map(|(_, c)| c).sum();
        assert_eq!(sum, snapshot.total_requests);
    }

    #[test]
    fn known_paths_accumulate_in_order() {
        let m = new_metrics();
        m.record_request("/");
        m.record_request("/about");
        m.record_request("/");
        let snapshot = m.snapshot();
        assert_eq!(snapshot.total_requests, 3);
        assert_eq!(snapshot.path_counts[0], ("/".to_string(), 2));
        assert_eq!(snapshot.path_counts[1], ("/about".to_string(), 1));
    }

    #[test]
    fn session_counter_counts_within_a_session() {
        let m = new_metrics();
        let key = [7u8; 32];
        let now = 1_000_000;
        assert_eq!(m.record_valid_request_at(key, now), 1);
        assert_eq!(m.record_valid_request_at(key, now + 30), 2);
        assert_eq!(m.record_valid_request_at(key, now + 90), 3);

        // A second, distinct session starts at its own 1.
        let other = [9u8; 32];
        assert_eq!(m.record_valid_request_at(other, now + 120), 1);
    }

    #[test]
    fn active_session_window_expires_idle_tokens() {
        let m = new_metrics();
        let key = [7u8; 32];
        let now = 1_000_000;
        m.record_valid_request_at(key, now);
        // Still within the one-hour window just under the edge.
        assert_eq!(m.active_sessions_at(now + 3_599), 1);
        // Just past the hour, the token is no longer active.
        assert_eq!(m.active_sessions_at(now + 3_601), 0);
    }

    #[test]
    fn p95_index_matches_nearest_rank() {
        // 100 values → rank 95 (0-based 94). 1 value → rank 1 (0-based 0).
        assert_eq!(p95_index(100), 94);
        assert_eq!(p95_index(1), 0);
        assert_eq!(p95_index(99), 94); // ceil(94.05)
    }
}
