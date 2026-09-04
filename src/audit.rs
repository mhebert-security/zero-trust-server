//! Structured per-request audit log.
//!
//! Every served request writes exactly one TAB-separated line to stdout
//! (the NixOS unit sends stdout to journald — see configuration.nix
//! StandardOutput=journal), parseable without a log parser:
//!
//!   audit  <unix_ms>  <listener>  <peer>  <method>  <path>  <status>  <session>  <latency_ms>
//!
//! Fields are separated by a single TAB. journald already stamps arrival
//! time on the line, but the leading unix_ms keeps the record self-contained
//! and sortable if it is ever piped elsewhere. <session> is yes/no for
//! requests that reached the session gate, and "na" where no session decision
//! was possible (a request rejected before routing, a public pre-gate route,
//! or the plaintext redirect/ACME listener which has no gate). Latency is
//! connection-handler start → last byte written.
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

use std::time::{SystemTime, UNIX_EPOCH};

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
    /// decision exists (request rejected before routing, a public pre-gate
    /// route such as /health, or the plaintext listener) — rendered "na".
    pub session: Option<bool>,
}

impl AuditCtx {
    /// Complete and emit the audit line: status + elapsed time (request start
    /// → last byte written) are only known here.
    pub fn finish(&self, status: u16, latency_ms: u64) {
        println!("{}", self.line(status, latency_ms));
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
            "audit\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            unix_ms(),
            self.listener,
            sanitize(&self.peer),
            sanitize(&self.method),
            sanitize(&self.path),
            status,
            session,
            latency_ms,
        )
    }
}

/// Human-readable name for a parsed method.
pub fn method_name(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
    }
}

/// Best-effort method token from a raw request buffer, for requests that were
/// rejected before they parsed into a Request (the first space-delimited token
/// of the request line). Never fails — hostile input yields "-".
pub fn method_token(buf: &[u8]) -> String {
    let space = buf.iter().position(|&b| b == b' ');
    let token = match space {
        Some(i) => &buf[..i],
        None => buf,
    };
    token_string(token)
}

/// Best-effort path token from a raw request buffer (the second
/// space-delimited token of the request line), for the same rejected-request
/// case as [`method_token`]. "-" when absent or over-length.
pub fn path_token(buf: &[u8]) -> String {
    let first = buf.iter().position(|&b| b == b' ');
    let token = match first {
        Some(i) => {
            let rest = &buf[i + 1..];
            match rest.iter().position(|&b| b == b' ') {
                Some(j) => &rest[..j],
                None => rest,
            }
        }
        None => buf,
    };
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
        };
        let line = c.line(301, 2);
        assert_eq!(line.matches("\n").count(), 0);
        assert!(!line.contains("\r"));
        assert_eq!(line.split('\t').count(), 9);
    }
}
