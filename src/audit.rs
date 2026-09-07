//! Structured per-request audit log.
//!
//! Every served request writes exactly one TAB-separated line to stdout
//! (the NixOS unit sends stdout to journald; see configuration.nix
//! StandardOutput=journal), parseable without a log parser:
//!
//! ```text
//! audit  <unix_ms>  <listener>  <peer>  <method>  <path>  <status>
//!        <session>  <latency_ms>  <pow_solve_ms>  <request_count_this_session>
//!        <canary>
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
//! The last three columns were appended on the right (2026-09-05 and
//! 2026-09-06) so parsers that read the original nine fields keep working
//! unchanged. `pow_solve_ms`
//! is the milliseconds between challenge issue and solve arrival for a
//! successful POST /pow/verify, and "-" for every other request.
//! `request_count_this_session` is the running count of requests made with
//! the presented valid session (1 for the first such request), and "-" where
//! no valid session was presented. `canary` is the token a 404 planted,
//! present only on that 404's own line so a later CANARY alert (see below)
//! can be correlated back to the miss that seeded it, and "-" for every
//! other response.
//!
//! A request that echoes a planted canary token back in its headers or body
//! writes a second, alert-only line with the `canary` prefix (see
//! [`canary_alert`]), in addition to its own `audit` line. The per-request
//! journal keeps its one-line invariant; the alert is a separate stream a
//! parser can filter on the prefix.
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
//!
//! ## Optional JSON mirror on stderr
//!
//! With the `structured-telemetry` Cargo feature enabled, each stdout line
//! (audit or canary) is mirrored as a single JSON object on stderr. The
//! stdout TAB stream is unchanged; the mirror is an opt-in feed for a
//! telemetry pipeline. The JSON carries the same data the TAB line carries,
//! never more, and never a session token or secret. Attribute names follow
//! the OpenTelemetry semantic conventions where one exists, and the
//! server-specific fields use the `zts.*` namespace. The mapping is
//! documented in the deployment runbook (§6). Each object sits on one line
//! with no embedded newline, so journald stores one event per record.

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
    /// The canary token a 404 planted, present only on that 404's own line so
    /// a later CANARY alert can be correlated back to the miss that seeded
    /// it. None (every non-404 response) renders as "-".
    pub canary: Option<String>,
}

impl AuditCtx {
    /// Complete and emit the audit line, pairing the response status with the
    /// wall time from request start to last byte written, which only the send
    /// path knows. It cannot validate those inputs, and a failing stdout
    /// panics the print, which aborts the process under the release profile's
    /// `panic = "abort"`.
    pub fn finish(&self, status: u16, elapsed: Duration) {
        let now_ms = unix_ms();
        let latency_ms = ms_u64(elapsed);
        println!("{}", self.tab_line(status, latency_ms, now_ms));
        #[cfg(feature = "structured-telemetry")]
        eprintln!("{}", self.structured_line(status, latency_ms, now_ms));
    }

    /// Build the TAB-separated line, without printing. Split out so tests can
    /// assert on the record shape.
    #[cfg(test)]
    fn line(&self, status: u16, latency_ms: u64) -> String {
        self.tab_line(status, latency_ms, unix_ms())
    }

    /// The TAB record body. `now_ms` is captured once per [`finish`], so the
    /// stdout TAB line and (under the `structured-telemetry` feature) the
    /// stderr JSON mirror stamp the same instant and cannot diverge.
    fn tab_line(&self, status: u16, latency_ms: u64, now_ms: u128) -> String {
        format!(
            "audit\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            now_ms,
            self.listener,
            sanitize(&self.peer),
            sanitize(&self.method),
            sanitize(&self.path),
            status,
            session_token(self.session),
            latency_ms,
            field_or_hyphen(self.pow_solve_ms),
            field_or_hyphen(self.request_count),
            canary_or_hyphen(self.canary.as_deref()),
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

/// Render the session column: "yes" or "no" where the session gate ran, and
/// "na" where no session decision exists. One definition feeds both the TAB
/// line and the JSON mirror, so the two never disagree.
const fn session_token(session: Option<bool>) -> &'static str {
    match session {
        Some(true) => "yes",
        Some(false) => "no",
        None => "na",
    }
}

/// Render an optional integer audit field as its value, or "-" when absent.
/// The hyphen is the record's "not applicable" token, matching the missing
/// method/path tokens above.
fn field_or_hyphen(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// Render the optional canary column as its token, or "-" when the response
/// was not a 404 and planted none.
fn canary_or_hyphen(value: Option<&str>) -> String {
    value.map_or_else(|| "-".to_string(), str::to_string)
}

/// Emit a CANARY alert: a request echoed back a canary token a 404 planted.
///
/// The line names the listener, the peer, and the request that carried the
/// token, plus the token itself, so an operator can search the journal for
/// the original miss (its audit line holds the same value in the rightmost
/// column). The `canary` prefix keeps the alert a separate stream from the
/// per-request `audit` lines; the token is lowercase hex, already safe to
/// print, but the request-derived fields are scrubbed like any audit field.
pub fn canary_alert(listener: &str, peer: &str, method: &str, path: &str, token: &str) {
    let now_ms = unix_ms();
    println!(
        "canary\t{}\t{}\t{}\t{}\t{}\t{}",
        now_ms,
        listener,
        sanitize(peer),
        sanitize(method),
        sanitize(path),
        token,
    );
    #[cfg(feature = "structured-telemetry")]
    eprintln!(
        "{}",
        structured_canary(listener, peer, method, path, token, now_ms)
    );
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

// ---------------------------------------------------------------------------
// Structured telemetry mirror (feature "structured-telemetry")
//
// Every stdout record above is also emitted, under the feature flag, as a
// single JSON object on stderr. The two streams stay in lockstep because
// they are written from the same instant in the same call. Nothing in this
// section compiles unless the feature is on.

#[cfg(feature = "structured-telemetry")]
impl AuditCtx {
    /// Build the stderr JSON mirror of the stdout TAB record. `now_ms` is the
    /// same instant the TAB line was stamped with, so the two cannot diverge.
    /// Keys that name an `OpenTelemetry` semantic convention keep the
    /// convention's dotted form; server-specific fields use the `zts.*`
    /// namespace (see the module doc and the deployment runbook §6).
    fn structured_line(&self, status: u16, latency_ms: u64, now_ms: u128) -> String {
        let (peer_address, peer_port) = split_peer(&self.peer);
        let (scheme, server_port) = scheme_and_port(self.listener);
        json_record(
            now_ms,
            "INFO",
            "audit",
            &[
                attr_str("zts.listener", self.listener),
                attr_str("http.request.method", &self.method),
                attr_str("url.path", &self.path),
                attr_num("http.response.status_code", u64::from(status)),
                attr_str("network.peer.address", &peer_address),
                attr_opt_num("network.peer.port", peer_port),
                attr_str("url.scheme", scheme),
                attr_num("server.port", server_port),
                attr_str("zts.session", session_token(self.session)),
                attr_num("zts.latency_ms", latency_ms),
                attr_opt_num("zts.pow.solve_ms", self.pow_solve_ms),
                attr_opt_num("zts.session.request_count", self.request_count),
                attr_opt_str("zts.canary", self.canary.as_deref()),
            ],
        )
    }
}

/// Build the stderr JSON mirror of a canary alert line. `OpenTelemetry`
/// severity WARN marks it as an alert, distinct from the INFO audit records
/// that carry the same attribute vocabulary.
#[cfg(feature = "structured-telemetry")]
fn structured_canary(
    listener: &str,
    peer: &str,
    method: &str,
    path: &str,
    token: &str,
    now_ms: u128,
) -> String {
    let (peer_address, peer_port) = split_peer(peer);
    let (scheme, server_port) = scheme_and_port(listener);
    json_record(
        now_ms,
        "WARN",
        "canary",
        &[
            attr_str("zts.listener", listener),
            attr_str("http.request.method", method),
            attr_str("url.path", path),
            attr_str("network.peer.address", &peer_address),
            attr_opt_num("network.peer.port", peer_port),
            attr_str("url.scheme", scheme),
            attr_num("server.port", server_port),
            attr_str("zts.canary", token),
        ],
    )
}

/// Wrap the audit fields into one stderr JSON record. Keys are the caller's;
/// this joins them after the shared record fields.
#[cfg(feature = "structured-telemetry")]
fn json_record(now_ms: u128, severity: &str, body: &str, attributes: &[String]) -> String {
    format!(
        "{{\"timestamp\":{timestamp},\"severity_text\":{severity},\"body\":{body},\"attributes\":{{{attrs}}}}}",
        timestamp = json_string(&rfc3339_utc(now_ms)),
        severity = json_string(severity),
        body = json_string(body),
        attrs = attributes.join(","),
    )
}

/// A quoted, escaped JSON string attribute.
#[cfg(feature = "structured-telemetry")]
fn attr_str(key: &str, value: &str) -> String {
    format!("\"{key}\":{}", json_string(value))
}

/// A JSON integer attribute.
#[cfg(feature = "structured-telemetry")]
fn attr_num(key: &str, value: u64) -> String {
    format!("\"{key}\":{value}")
}

/// A JSON integer attribute that reads `null` when the field is not
/// applicable, keeping every audit record's schema identical.
#[cfg(feature = "structured-telemetry")]
fn attr_opt_num(key: &str, value: Option<u64>) -> String {
    value.map_or_else(
        || format!("\"{key}\":null"),
        |number| format!("\"{key}\":{number}"),
    )
}

/// A JSON string attribute that reads `null` when the field is not
/// applicable, as above.
#[cfg(feature = "structured-telemetry")]
fn attr_opt_str(key: &str, value: Option<&str>) -> String {
    value.map_or_else(
        || format!("\"{key}\":null"),
        |text| format!("\"{key}\":{}", json_string(text)),
    )
}

/// Quote a value as a JSON string, escaping what the format requires so a
/// request-derived field can never close the object or inject a newline into
/// the stream. Control characters become `\uXXXX`; quotes and backslashes get
/// their escapes; everything else passes through as UTF-8.
#[cfg(feature = "structured-telemetry")]
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str("\\u");
                let digits = format!("{:04x}", u32::from(c));
                out.push_str(&digits);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Split a peer's `SocketAddr` string into its address and port for the
/// `network.peer.*` attributes. Where the socket had no resolvable address the
/// stored peer is "unknown", which has no port. IPv6 addresses are bracketed
/// by `SocketAddr`'s `Display`; the brackets are stripped here.
#[cfg(feature = "structured-telemetry")]
fn split_peer(peer: &str) -> (String, Option<u64>) {
    let Some((address, port)) = peer.rsplit_once(':') else {
        return (peer.to_string(), None);
    };
    if address.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return (peer.to_string(), None);
    }
    let address = address
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(address);
    (address.to_string(), port.parse().ok())
}

/// Map a listener name to the URL scheme and the port a client reached it on.
/// The TLS listener is the only https one; the plaintext listener ("http80")
/// is http. The service binds 8443/8080 and nftables REDIRECTs 443/80 onto
/// them, so the ports clients reach are 443 and 80 (runbook quick facts).
#[cfg(feature = "structured-telemetry")]
fn scheme_and_port(listener: &str) -> (&'static str, u64) {
    if listener == "http80" {
        ("http", 80)
    } else {
        ("https", 443)
    }
}

/// Render an epoch-milliseconds instant as an RFC 3339 UTC timestamp with
/// millisecond precision, the form the `OpenTelemetry` log model expects.
#[cfg(feature = "structured-telemetry")]
fn rfc3339_utc(epoch_ms: u128) -> String {
    let seconds = i64::try_from(epoch_ms / 1000)
        .expect("epoch milliseconds stay inside i64 for any plausible clock");
    let millis = epoch_ms % 1000;
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Days since 1970-01-01 to a (year, month, day) civil date. Howard Hinnant's
/// `civil_from_days`, the inverse of `days_from_civil`: no leap-year table and
/// no loop, exact over the whole range the epoch can produce here.
#[cfg(feature = "structured-telemetry")]
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097); // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = u32::try_from(day_of_year - (153 * month_prime + 2) / 5 + 1)
        .expect("civil day of month is 1..=31 by construction");
    let month = u32::try_from(if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    })
    .expect("civil month is 1..=12 by construction");
    if month <= 2 {
        (year + 1, month, day)
    } else {
        (year, month, day)
    }
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
            canary: None,
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
            canary: None,
        };
        let line = c.line(301, 2);
        assert_eq!(line.matches('\n').count(), 0);
        assert!(!line.contains('\r'));
        assert_eq!(line.split('\t').count(), 12);
    }

    #[test]
    fn appended_fields_default_to_hyphen() {
        // A plain request has no solve timing, no session count, and no
        // canary; the three rightmost columns read "-" so the record stays
        // TAB-shape-stable.
        let line = ctx(Some(true)).line(200, 3);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[9], "-");
        assert_eq!(fields[10], "-");
        assert_eq!(fields[11], "-");
    }

    #[test]
    fn pow_solve_and_session_count_render_when_present() {
        // A solved /pow/verify and a counted session request each fill their
        // column, proving the new fields sit in the last positions.
        let mut c = ctx(Some(true));
        c.pow_solve_ms = Some(412);
        c.request_count = Some(7);
        let line = c.line(302, 5);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[9], "412");
        assert_eq!(fields[10], "7");
        assert_eq!(fields[11], "-", "a 302 plants no canary");
    }

    #[test]
    fn a_404_canary_renders_in_the_rightmost_column() {
        let mut c = ctx(None);
        c.canary = Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string());
        let line = c.line(404, 9);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[11], "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn structured_line_maps_every_tab_field_with_otel_names() {
        let mut c = ctx(Some(true));
        c.peer = "203.0.113.7:5555".to_string();
        c.method = "POST".to_string();
        c.path = "/pow/verify".to_string();
        c.pow_solve_ms = Some(412);
        c.request_count = Some(7);
        let record = c.structured_line(302, 5, 0);
        assert!(record.starts_with('{') && record.ends_with('}'));
        assert!(!record.contains('\n'), "one event, one line: {record}");
        assert!(record.contains(r#""timestamp":"1970-01-01T00:00:00.000Z""#));
        assert!(record.contains(r#""severity_text":"INFO""#));
        assert!(record.contains(r#""body":"audit""#));
        assert!(record.contains(r#""zts.listener":"tls""#));
        assert!(record.contains(r#""http.request.method":"POST""#));
        assert!(record.contains(r#""url.path":"/pow/verify""#));
        assert!(record.contains(r#""http.response.status_code":302"#));
        assert!(record.contains(r#""network.peer.address":"203.0.113.7""#));
        assert!(record.contains(r#""network.peer.port":5555"#));
        assert!(record.contains(r#""url.scheme":"https""#));
        assert!(record.contains(r#""server.port":443"#));
        assert!(record.contains(r#""zts.session":"yes""#));
        assert!(record.contains(r#""zts.latency_ms":5"#));
        assert!(record.contains(r#""zts.pow.solve_ms":412"#));
        assert!(record.contains(r#""zts.session.request_count":7"#));
        assert!(record.contains(r#""zts.canary":null"#));
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn structured_line_uses_http_scheme_and_null_absent_fields() {
        let mut c = ctx(None);
        c.listener = "http80";
        let record = c.structured_line(503, 2, 0);
        assert!(record.contains(r#""url.scheme":"http""#));
        assert!(record.contains(r#""server.port":80"#));
        assert!(record.contains(r#""zts.session":"na""#));
        assert!(record.contains(r#""zts.pow.solve_ms":null"#));
        assert!(record.contains(r#""zts.session.request_count":null"#));
        assert!(record.contains(r#""zts.canary":null"#));
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn hostile_fields_are_json_escaped_not_injected() {
        // A path carrying a quote, a newline, and a tab must be escaped into
        // one valid JSON string, never allowed to break out of the record or
        // split the stream into extra lines.
        let mut c = ctx(None);
        c.method = "GET".to_string();
        c.path = "/p\"\n\t".to_string();
        let record = c.structured_line(200, 1, 0);
        assert!(!record.contains('\n'), "no raw newline: {record}");
        assert!(!record.contains('\r'), "no raw carriage return: {record}");
        assert!(record.contains(r#""url.path":"/p\"\n\t""#));
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn canary_json_carries_token_and_warn_severity() {
        let record = structured_canary(
            "tls",
            "[2001:db8::1]:443",
            "GET",
            "/",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            0,
        );
        assert!(!record.contains('\n'), "one event, one line: {record}");
        assert!(record.contains(r#""severity_text":"WARN""#));
        assert!(record.contains(r#""body":"canary""#));
        assert!(record.contains(r#""network.peer.address":"2001:db8::1""#));
        assert!(record.contains(r#""network.peer.port":443"#));
        assert!(record.contains(r#""url.scheme":"https""#));
        assert!(record.contains(r#""zts.canary":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6""#));
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn rfc3339_stamps_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(86_400_000), "1970-01-02T00:00:00.000Z");
        // 2000-01-01 00:00:00 UTC and the 2000 leap day that follows.
        assert_eq!(rfc3339_utc(946_684_800_000), "2000-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_utc(951_782_400_123), "2000-02-29T00:00:00.123Z");
        assert_eq!(rfc3339_utc(951_868_800_000), "2000-03-01T00:00:00.000Z");
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn split_peer_handles_v4_v6_and_unknown() {
        assert_eq!(
            split_peer("1.2.3.4:443"),
            ("1.2.3.4".to_string(), Some(443))
        );
        assert_eq!(
            split_peer("[2001:db8::1]:443"),
            ("2001:db8::1".to_string(), Some(443))
        );
        assert_eq!(split_peer("unknown"), ("unknown".to_string(), None));
        // A peer that never came from SocketAddr's Display falls back whole.
        assert_eq!(
            split_peer("garbage:port"),
            ("garbage:port".to_string(), None)
        );
    }

    #[cfg(feature = "structured-telemetry")]
    #[test]
    fn scheme_and_port_follow_the_listener() {
        assert_eq!(scheme_and_port("tls"), ("https", 443));
        assert_eq!(scheme_and_port("http80"), ("http", 80));
    }
}
