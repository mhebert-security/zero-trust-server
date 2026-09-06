//! Structured per-request audit log.
//!
//! Every served request writes exactly one TAB-separated line to stdout
//! (the NixOS unit sends stdout to journald — see configuration.nix
//! StandardOutput=journal), parseable without a log parser:
//!
//! ```text
//! audit  <unix_ms>  <listener>  <peer>  <method>  <path>  <status>
//!        <session>  <latency_ms>  <pow_solve_ms>  <request_count_this_session>
//! ```
//!
//! Fields are separated by a single TAB. journald already stamps arrival
//! time on the line, but the leading `unix_ms` keeps the record self-contained
//! and sortable if it is ever piped elsewhere. The `session` column is
//! yes/no for
//! requests that reached the session gate, and "na" where no session decision
//! was possible (a request rejected before routing, a public pre-gate route,
//! or the plaintext redirect/ACME listener which has no gate). Latency is
//! connection-handler start → last byte written.
//!
//! The last two columns were appended on the right (2026-09-05) so parsers
//! that read the original nine fields keep working unchanged. `pow_solve_ms`
//! is the milliseconds between challenge issue and solve arrival for a
//! successful POST /pow/verify, and "-" for every other request.
//! `request_count_this_session` is the running count of requests made with
//! the presented valid session (1 for the first such request), and "-" where
//! no valid session was presented.
//!
//! The two-phase shape mirrors how the pieces are known: a request's method,
//! path and peer are understood where the request is read, but its status and
//! latency exist only after routing and the write complete. The connection
//! handlers build an [`AuditCtx`] at request-understood time and call
//! [`AuditCtx::finish`] once the last byte is written.
//!
//! Why structured: this line is the ONLY per-request record the server keeps.
//! Free-form lines made incident reconstruction a grep-for-a-needle exercise;
//! this format makes `journalctl -u zero-trust-server | grep audit` +
//! `cut -f4,5,7,8` actual analysis.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::http::Method;

/// Request-derived audit fields, captured where the request is understood.
///
/// Consumed (via [`finish`](AuditCtx::finish)) by the send path once the
/// response status and write latency are known, emitting the one audit line.
pub struct AuditCtx {
    /// Which listener served it: "tls" or "http80".
    pub listener: &'static str,
    pub peer: String,
    pub method: String,
    pub path: String,
    /// Some(true/false) when the session gate ran; None where no session
    /// decision exists, as for a request rejected before routing, a public
    /// pre-gate route such as /health, or the plaintext listener. The audit
    /// line renders None as "na".
    pub session: Option<bool>,
    /// Milliseconds between challenge issue and solve arrival, present only
    /// for a solved POST /pow/verify. None renders as "-".
    pub pow_solve_ms: Option<u64>,
    /// This request's number within its valid session (1 = first request
    /// carrying the token), present only where a valid session was presented
    /// and the gate ruled yes. None renders as "-".
    pub request_count: Option<u64>,
}

impl AuditCtx {
    /// Complete and emit the audit line, pairing the response status with the
    /// wall time from request start to last byte written, which only the send
    /// path knows. It cannot validate those inputs, and a failing stdout
    /// panics the print, which aborts the process under the release profile's
    /// `panic = "abort"`.
    pub fn finish(&self, status: u16, elapsed: Duration) {
        println!("{}", self.line(status, ms_u64(elapsed)));
    }

    /// Build the TAB-separated line, without printing. Split out so tests can
    /// assert on the record shape.
    fn line(&self, status: u16, latency_ms: u64) -> String {
        let session = match self.session {
            Some(true) => "yes",
            Some(false) => "no",
            None => "na",
        };
        format!(
            "audit\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            unix_ms(),
            self.listener,
            sanitize(&self.peer),
            sanitize(&self.method),
            sanitize(&self.path),
            status,
            session,
            latency_ms,
            field_or_hyphen(self.pow_solve_ms),
            field_or_hyphen(self.request_count),
        )
    }
}

/// Return the wire name (GET, HEAD, or POST) for a parsed method. The
/// match is exhaustive and cannot fail; adding a new method without a
/// matching arm is a compile error, which is the point.
pub const fn method_name(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
    }
}

/// Read the first space-delimited token of a raw request line as the
/// method name, for requests rejected before they parsed. Returns "-"
/// when the buffer is empty or the token is missing or over length, so
/// hostile input cannot panic or forge a field.
pub fn method_token(buf: &[u8]) -> String {
    let space = buf.iter().position(|&b| b == b' ');
    let token = space.map_or(buf, |i| &buf[..i]);
    token_string(token)
}

/// Read the second space-delimited token of a raw request line as the
/// path, for requests rejected before they parsed. Returns "-" when the
/// token is absent or over length; a present token may still carry
/// control characters, which `sanitize` scrubs at emit time.
pub fn path_token(buf: &[u8]) -> String {
    let first = buf.iter().position(|&b| b == b' ');
    let token = first.map_or(buf, |i| {
        let rest = &buf[i + 1..];
        rest.iter()
            .position(|&b| b == b' ')
            .map_or(rest, |j| &rest[..j])
    });
    token_string(token)
}

/// Lossy-UTF-8 + length-cap a raw token; the caller sanitizes control chars
/// at emit time.
fn token_string(token: &[u8]) -> String {
    const MAX_TOKEN: usize = 2048;
    if token.is_empty() || token.len() > MAX_TOKEN {
        return "-".to_string();
    }
    String::from_utf8_lossy(token).into_owned()
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// A `Duration` in whole milliseconds, narrowed to `u64` for the audit line.
///
/// `as_millis()` yields a `u128`; the spans measured here are per-request
/// wall-clock times that stay far below a second, and `u64` cannot overflow
/// until ≈584 million years of milliseconds — the cast cannot actually
/// truncate, so this one narrowing lives here (callers pass a `Duration`,
/// never a pre-truncated integer).
#[allow(clippy::cast_possible_truncation)]
const fn ms_u64(elapsed: Duration) -> u64 {
    elapsed.as_millis() as u64
}

/// Render an optional integer audit field as its value, or "-" when absent.
/// The hyphen is the record's "not applicable" token, matching the missing
/// method/path tokens above.
fn field_or_hyphen(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// Replace control characters so a hostile path/host header can never forge
/// an extra log line or field.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || c == '\t' {
            out.push('?');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(session: Option<bool>) -> AuditCtx {
        AuditCtx {
            listener: "tls",
            peer: "1.2.3.4:1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            session,
            pow_solve_ms: None,
            request_count: None,
        }
    }

    #[test]
    fn tokens_from_a_normal_request_line() {
        let buf = b"HEAD /health HTTP/1.1\r\nHost: mhebert.dev\r\n\r\n";
        assert_eq!(method_token(buf), "HEAD");
        assert_eq!(path_token(buf), "/health");
    }

    #[test]
    fn tokens_from_malformed_input_never_panic() {
        assert_eq!(method_token(b""), "-");
        assert_eq!(path_token(b""), "-");
        // No space anywhere: whole buffer is the token, so over the cap → "-".
        assert_eq!(method_token(&[b'a'; 9000]), "-");
        assert_eq!(path_token(&[b'a'; 9000]), "-");
    }

    #[test]
    fn method_without_space_is_best_effort() {
        // "not http" — no method/space structure; parse rejects it, audit
        // still reports the first token so the bad request line is findable.
        let buf = b"not http\r\n\r\n";
        assert_eq!(method_token(buf), "not");
        // Second token runs to the buffer end (control chars → '?' at emit).
        assert_eq!(path_token(buf), "http\r\n\r\n");
    }

    #[test]
    fn session_renders_yes_no_na() {
        assert!(ctx(Some(true)).line(200, 1).contains("\tyes\t"));
        assert!(ctx(Some(false)).line(200, 1).contains("\tno\t"));
        assert!(ctx(None).line(200, 1).contains("\tna\t"));
    }

    #[test]
    fn hostile_peer_cannot_forge_a_field() {
        // A peer string with a tab or newline must come out as '?', never as
        // a real field separator or a second log line.
        let c = AuditCtx {
            listener: "http80",
            peer: "1.2.3.4\r\naudit\tFAKE".to_string(),
            method: "GET".to_string(),
            path: "/x".to_string(),
            session: None,
            pow_solve_ms: None,
            request_count: None,
        };
        let line = c.line(301, 2);
        assert_eq!(line.matches('\n').count(), 0);
        assert!(!line.contains('\r'));
        assert_eq!(line.split('\t').count(), 11);
    }

    #[test]
    fn appended_fields_default_to_hyphen() {
        // A plain request has no solve timing and no session count; both
        // rightmost columns read "-" so the record stays TAB-shape-stable.
        let line = ctx(Some(true)).line(200, 3);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11);
        assert_eq!(fields[9], "-");
        assert_eq!(fields[10], "-");
    }

    #[test]
    fn pow_solve_and_session_count_render_when_present() {
        // A solved /pow/verify and a counted session request each fill their
        // column, proving the two new fields sit in the last two positions.
        let mut c = ctx(Some(true));
        c.pow_solve_ms = Some(412);
        c.request_count = Some(7);
        let line = c.line(302, 5);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 11);
        assert_eq!(fields[9], "412");
        assert_eq!(fields[10], "7");
    }
}
