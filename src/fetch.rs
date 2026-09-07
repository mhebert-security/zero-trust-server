//! The outbound half of the news fetcher: HTTPS transport and feed parsing.
//!
//! Zero trust meets egress here. The fetcher's only destination is the
//! catalog in feeds.rs, so every request is checked twice before a byte
//! moves: the URL must name an allowlisted host, and the TLS handshake must
//! verify that host's certificate against Mozilla's roots. Redirects are
//! never followed, so a feed cannot steer this process toward a host the
//! catalog never named. Every socket is bounded by time (a read or write
//! that stalls for ten seconds is dropped) and by size (a response that
//! exceeds its budget aborts mid-read, never buffered whole first).
//!
//! The transport is deliberately thin. This module speaks just enough HTTP
//! to fetch a feed: one GET per feed, no redirects, no compression (the
//! request asks for `identity` and a feed that answers with gzip anyway is
//! treated as a failure, not silently inflated). The NVD 2.0 API is the one
//! exception to the single GET: it orders by publish date ascending and
//! rejects an ordering parameter, so the newest records sit at the end of
//! the list and take a count request plus one more for the last page.
//! Parsing is split by content: feeds.rs marks the two JSON feeds, the CISA
//! KEV catalog and the NVD 2.0 API, by their URLs, and each is read with a
//! narrow JSON walker. Every other feed is RSS or Atom XML read with
//! quick-xml. Dates arrive as RFC 2822, RFC 3339, or a bare YYYY-MM-DD and
//! are normalized to Unix seconds here, in one place.
//!
//! Nothing in this module panics and nothing prints. Every failure is a
//! [`FetchError`] value; the fetcher binary decides what to log.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quick_xml::escape;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::feeds::{Category, Feed};
use crate::store::NewsItem;

/// Applied to connect, read, and write alike. A feed host that needs longer
/// than this to answer a byte is not worth waiting on.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The response budget for a normal feed. A kilobyte over this and the read
/// aborts rather than buffering further.
const DEFAULT_BODY_LIMIT: usize = 1024 * 1024;

/// The response budget for the CISA KEV catalog alone.
///
/// The general cap above cannot hold the KEV JSON: the catalog weighed
/// roughly 1.7 MB when this was written, and it grows every time CISA adds
/// an exploited vulnerability. It is the largest response in the catalog by
/// an order of magnitude, so the megabyte cap would truncate every pass.
/// This budget exists only for the KEV URL; the NVD API and every XML feed
/// keep the megabyte cap. It is a deviation from a flat one-megabyte cap,
/// scoped as narrowly as the feeds.rs catalog will allow.
const KEV_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Seconds of CVE history the NVD query covers, matching the store's
/// retention: cleanup prunes items older than seven days. The pass returns
/// the newest CVEs in the window, so the width only matters when a run was
/// missed for days at a time; a narrow window would then leave a gap.
const NVD_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;

/// How many CVEs one NVD pass keeps, the page size the catalog names too.
const NVD_PAGE: i64 = 20;

/// Declared to every feed server so the connection identifies itself.
pub const USER_AGENT: &str = "mhebert-cyber-news/1.0";

/// How much of an item's body text is worth keeping. Feeds can carry full
/// article HTML in the description slot; a reader wants the first lines, not
/// a license to copy the article.
const MAX_DESCRIPTION_CHARS: usize = 1000;

/// A feed fetch failed. The fetcher logs the `Display` text and moves on.
#[derive(Debug)]
pub enum FetchError {
    /// The URL did not start with https://.
    NotHttps,
    /// The URL could not be split into host and path.
    MalformedUrl(String),
    /// The URL's host is not one of the ten in feeds.rs.
    HostNotAllowed(String),
    /// The hostname did not resolve.
    Dns(io::Error),
    /// Every address on the host refused a connection within the timeout.
    Connect(io::Error),
    /// A socket or TLS-layer I/O failure (timeouts surface here too).
    Io(io::Error),
    /// The TLS configuration, handshake, or certificate verification failed.
    Tls(String),
    /// The feed answered with a status other than 200. Redirects land here
    /// as well; they are never followed.
    HttpStatus(u16),
    /// The body ran past its budget and the read was aborted.
    BodyTooLarge { limit: usize },
    /// The HTTP framing was not well formed, or the body was truncated.
    Protocol(String),
    /// The feed gzip-compressed a response that asked for identity.
    ContentEncoding(String),
    /// The feed body (XML or the narrow JSON catalogs) did not parse.
    Parse(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::NotHttps => write!(f, "feed url is not https"),
            FetchError::MalformedUrl(url) => write!(f, "malformed feed url: {url}"),
            FetchError::HostNotAllowed(host) => {
                write!(f, "host {host} is not on the allowlist")
            }
            FetchError::Dns(e) => write!(f, "dns lookup failed: {e}"),
            FetchError::Connect(e) => write!(f, "connection failed: {e}"),
            FetchError::Io(e) => write!(f, "io error: {e}"),
            FetchError::Tls(e) => write!(f, "tls error: {e}"),
            FetchError::HttpStatus(code) => {
                write!(f, "feed answered http {code} (redirects are not followed)")
            }
            FetchError::BodyTooLarge { limit } => {
                write!(f, "response exceeded the {limit} byte budget; read aborted")
            }
            FetchError::Protocol(e) => write!(f, "malformed http response: {e}"),
            FetchError::ContentEncoding(enc) => {
                write!(f, "feed sent {enc}, but only identity was accepted")
            }
            FetchError::Parse(e) => write!(f, "could not parse feed body: {e}"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FetchError::Dns(e) | FetchError::Connect(e) | FetchError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FetchError {
    fn from(e: io::Error) -> Self {
        FetchError::Io(e)
    }
}

/// Fetch one feed and parse its body into store-ready items.
///
/// The transport, TLS verification, size budget, and parsing all happen
/// here. A feed that fails at any stage returns the reason as a value; the
/// caller logs it and keeps walking the catalog. The NVD API needs two GETs,
/// so it is routed to [`fetch_nvd_feed`]; every other feed is a single GET.
pub fn fetch_feed(feed: &Feed) -> Result<Vec<NewsItem>, FetchError> {
    if is_nvd_api(feed.url) {
        return fetch_nvd_feed(feed);
    }
    let body = get_body(feed.url)?;
    if is_kev_catalog(feed.url) {
        parse_kev_catalog(&body, feed)
    } else {
        parse_xml_feed(&body, feed)
    }
}

/// Fetch the NVD 2.0 API and parse its newest CVEs.
///
/// NVD orders results by publish date, ascending, and rejects an ordering
/// parameter, so the newest records sit at the end of the list, not the
/// front. Two GETs find them: one asks for a single record to learn how many
/// CVEs the trailing window holds, the second pages to the last page of that
/// window. The window must roll with the clock, or every pass would ask for
/// the same fixed week and the store would stop growing after the first run,
/// so the dates are computed here rather than fixed in the catalog.
fn fetch_nvd_feed(feed: &Feed) -> Result<Vec<NewsItem>, FetchError> {
    let now = now_secs();
    let endpoint = feed.url.split('?').next().unwrap_or(feed.url);
    let window = nvd_window_query(now);

    let count_url = format!("{endpoint}?resultsPerPage=1{window}");
    let count_body = get_body(&count_url)?;
    let total = nvd_total_results(&count_body)?;
    if total == 0 {
        return Ok(Vec::new());
    }

    let take = total.min(NVD_PAGE);
    let page_url = format!(
        "{endpoint}?resultsPerPage={take}{window}&startIndex={}",
        total - take
    );
    let page_body = get_body(&page_url)?;
    parse_nvd_api(&page_body, feed)
}

/// The rolling date window for one NVD request, as query parameters. NVD
/// wants RFC 3339 timestamps with milliseconds and requires both ends.
fn nvd_window_query(now: i64) -> String {
    format!(
        "&pubStartDate={}&pubEndDate={}",
        format_utc_rfc3339(now - NVD_WINDOW_SECS),
        format_utc_rfc3339(now)
    )
}

/// The top-level `totalResults` count in an NVD response.
fn nvd_total_results(document: &str) -> Result<i64, FetchError> {
    let key = "\"totalResults\"";
    let Some(start) = document.find(key) else {
        return Err(FetchError::Parse("nvd: no totalResults".into()));
    };
    let mut i = start + key.len();
    skip_space(document, &mut i);
    if !document[i..].starts_with(':') {
        return Err(FetchError::Parse("nvd: malformed totalResults".into()));
    }
    i += 1;
    skip_space(document, &mut i);
    let digits = document[i..]
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 {
        return Err(FetchError::Parse("nvd: malformed totalResults".into()));
    }
    document[i..i + digits]
        .parse::<i64>()
        .map_err(|_| FetchError::Parse("nvd: totalResults out of range".into()))
}

/// Format a Unix timestamp as an RFC 3339 UTC string with millisecond
/// precision, the shape NVD's date parameters take.
fn format_utc_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = secs_of_day % 3_600 / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000")
}

/// Civil date for a count of days since the Unix epoch.
///
/// The inverse of `days_from_civil`, integer only like the rest of this
/// module's date math. Non-negative timestamps only; the fetcher never asks
/// about times before 1970.
fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// One verified GET, returned as the response body text.
///
/// Everything a fetch shares: the allowlist check against the host the URL
/// names, the TLS handshake that verifies it, the single GET, the status and
/// content-encoding checks, and the read under the body budget. The caller
/// decides how the body parses.
fn get_body(url: &str) -> Result<String, FetchError> {
    let (host, path) = parse_url(url)?;
    if !host_is_allowed(&host) {
        return Err(FetchError::HostNotAllowed(host));
    }

    let budget = body_budget(url);
    let socket = connect(&host)?;
    let mut tls = tls_client(&host, socket)?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: application/atom+xml, application/rss+xml, application/xml;q=0.9, text/xml;q=0.9, application/json;q=0.8, */*;q=0.1\r\n\
         Accept-Encoding: identity\r\n\
         Connection: close\r\n\r\n"
    );
    tls.write_all(request.as_bytes())?;
    tls.flush()?;

    // Everything after the request is a read, so hand the stream to a
    // buffered reader and do not write again.
    let mut reader = BufReader::new(tls);
    let head = read_response_head(&mut reader)?;
    if head.status != 200 {
        return Err(FetchError::HttpStatus(head.status));
    }
    if let Some(encoding) = header(&head.headers, "content-encoding")
        && encoding != "identity"
    {
        return Err(FetchError::ContentEncoding(encoding.to_string()));
    }

    let body = read_body(&mut reader, &head.headers, budget)?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Split an https url into its (lowercased) host and its request path.
fn parse_url(url: &str) -> Result<(String, String), FetchError> {
    let rest = url.strip_prefix("https://").ok_or(FetchError::NotHttps)?;
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        return Err(FetchError::MalformedUrl(url.to_string()));
    }
    let path = if host_end < rest.len() {
        rest[host_end..].to_string()
    } else {
        "/".to_string()
    };
    Ok((host.to_ascii_lowercase(), path))
}

/// Whether a host is named by the catalog. The catalog is the whole egress
/// surface, so this comparison is against feeds::FEEDS, not a config file.
fn host_is_allowed(host: &str) -> bool {
    crate::feeds::FEEDS.iter().any(|feed| {
        parse_url(feed.url)
            .map(|(allowed, _)| allowed == host)
            .unwrap_or(false)
    })
}

/// The read budget for a feed's response. Only the KEV JSON catalog is big
/// enough to need the larger allowance; see `KEV_BODY_LIMIT`.
fn body_budget(url: &str) -> usize {
    if is_kev_catalog(url) {
        KEV_BODY_LIMIT
    } else {
        DEFAULT_BODY_LIMIT
    }
}

/// Whether a url points at the CISA KEV JSON catalog.
fn is_kev_catalog(url: &str) -> bool {
    url.ends_with("known_exploited_vulnerabilities.json")
}

/// Whether a url points at the NVD 2.0 REST search API.
fn is_nvd_api(url: &str) -> bool {
    url.starts_with("https://services.nvd.nist.gov/rest/json/cves/2.0")
}

/// Resolve the host and open a TCP connection with every timeout applied.
fn connect(host: &str) -> Result<TcpStream, FetchError> {
    let addresses = (host, 443u16).to_socket_addrs().map_err(FetchError::Dns)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(socket) => {
                socket.set_read_timeout(Some(IO_TIMEOUT))?;
                socket.set_write_timeout(Some(IO_TIMEOUT))?;
                socket.set_nodelay(true)?;
                return Ok(socket);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(FetchError::Connect(
        last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no addresses to try")
        }),
    ))
}

/// Layer a verified TLS client connection over the socket.
///
/// Verification is on by default and cannot be switched off here: the
/// certificate must chain to Mozilla's roots and match the host name. No
/// dangerous options are so much as imported.
fn tls_client(
    host: &str,
    socket: TcpStream,
) -> Result<StreamOwned<ClientConnection, TcpStream>, FetchError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| FetchError::Tls(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();

    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| FetchError::MalformedUrl(host.to_string()))?;
    let connection =
        ClientConnection::new(Arc::new(config), name).map_err(|e| FetchError::Tls(e.to_string()))?;
    Ok(StreamOwned::new(connection, socket))
}

/// One parsed response head: the status line and the headers.
struct ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
}

/// Read and parse the status line and header block of an HTTP response.
fn read_response_head(reader: &mut impl BufRead) -> Result<ResponseHead, FetchError> {
    let status_line = read_line_capped(reader, 16 * 1024)?;
    let status_line =
        std::str::from_utf8(&status_line).map_err(|_| FetchError::Protocol("status line is not ascii".into()))?;
    let mut parts = status_line.split_whitespace();
    if !parts.next().is_some_and(|version| version.starts_with("HTTP/")) {
        return Err(FetchError::Protocol("no http status line".into()));
    }
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| FetchError::Protocol("no status code".into()))?;

    let mut headers = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        let line = read_line_capped(reader, 16 * 1024)?;
        if line.is_empty() {
            break;
        }
        header_bytes += line.len();
        if header_bytes > 64 * 1024 {
            return Err(FetchError::Protocol("header block too large".into()));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| FetchError::Protocol("header is not ascii".into()))?;
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Ok(ResponseHead { status: code, headers })
}

/// Look up a single-valued response header by its lowercased name.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Read the response body under the size budget, honoring how the head said
/// it is framed: chunked, a known content length, or close-delimited.
fn read_body(
    reader: &mut impl BufRead,
    headers: &[(String, String)],
    limit: usize,
) -> Result<Vec<u8>, FetchError> {
    if header(headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return read_chunked_body(reader, limit);
    }
    if let Some(length) = header(headers, "content-length") {
        let length = length
            .trim()
            .parse::<u64>()
            .map_err(|_| FetchError::Protocol("bad content-length".into()))?;
        if usize::try_from(length).map(|n| n > limit).unwrap_or(true) {
            return Err(FetchError::BodyTooLarge { limit });
        }
        let mut body = Vec::new();
        read_exact_into(reader, length, &mut body)?;
        return Ok(body);
    }
    // Connection: close was requested, so the server ends the body by
    // closing the socket.
    read_to_capped(reader, limit)
}

/// Read until EOF, aborting the moment the byte budget is crossed.
fn read_to_capped(reader: &mut impl Read, limit: usize) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > limit {
            return Err(FetchError::BodyTooLarge { limit });
        }
    }
}

/// Read exactly `count` bytes into `out`.
fn read_exact_into(reader: &mut impl Read, mut count: u64, out: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 8192];
    while count > 0 {
        let want = usize::try_from(count).unwrap_or(chunk.len()).min(chunk.len());
        reader.read_exact(&mut chunk[..want])?;
        out.extend_from_slice(&chunk[..want]);
        count -= u64::try_from(want).expect("want fits in u64");
    }
    Ok(())
}

/// Decode a chunked transfer-encoded body under the byte budget.
fn read_chunked_body(reader: &mut impl BufRead, limit: usize) -> Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    loop {
        let size_line = read_line_capped(reader, 1024)?;
        let hex = size_line
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(&size_line);
        let hex = std::str::from_utf8(hex)
            .map_err(|_| FetchError::Protocol("chunk size is not ascii".into()))?;
        let size = u64::from_str_radix(hex.trim(), 16)
            .map_err(|_| FetchError::Protocol("bad chunk size".into()))?;
        if size == 0 {
            // Final zero chunk: consume the trailer block up to the empty line.
            loop {
                let line = read_line_capped(reader, 16 * 1024)?;
                if line.is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len().saturating_add(usize::try_from(size).unwrap_or(usize::MAX)) > limit {
            return Err(FetchError::BodyTooLarge { limit });
        }
        read_exact_into(reader, size, &mut body)?;
        // Each chunk is followed by CRLF; read it off so framing stays in step.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).map_err(|_| {
            FetchError::Protocol("body ended mid-chunk".into())
        })?;
    }
}

/// Read one CRLF- or LF-terminated line, without the newline, bounded in
/// length so a runaway header cannot grow memory without limit.
fn read_line_capped(reader: &mut impl BufRead, cap: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte)?;
        if read == 0 {
            return Ok(line);
        }
        match byte[0] {
            b'\n' => return Ok(line),
            b'\r' => {}
            _ => {
                line.push(byte[0]);
                if line.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "line exceeds the cap",
                    ));
                }
            }
        }
    }
}

/// Parse an RSS 2.0 or Atom document into store-ready items.
fn parse_xml_feed(document: &str, feed: &Feed) -> Result<Vec<NewsItem>, FetchError> {
    let mut reader = Reader::from_str(document);

    // Text trimming is deliberately left off. quick-xml reports an entity
    // reference as its own event, so "a &amp; b" arrives as three events and
    // trimming each one would eat the spaces that join them. Whitespace is
    // normalized later, per field.

    // RSS and Atom share no common grammar beyond XML, so the root element
    // picks the branch. Until the root shows up, channel and feed elements
    // under other names are ignored.
    let mut kind = None;
    let mut items = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                "rss" => kind = Some(XmlKind::Rss),
                "feed" => kind = Some(XmlKind::Atom),
                "item" if kind == Some(XmlKind::Rss) => {
                    if let Some(item) = rss_item(&mut reader, feed)? {
                        items.push(item);
                    }
                }
                "entry" if kind == Some(XmlKind::Atom) => {
                    if let Some(item) = atom_entry(&mut reader, feed)? {
                        items.push(item);
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(FetchError::Parse(format!("xml: {e}"))),
            _ => {}
        }
    }
    Ok(items)
}

/// Which XML dialect a document uses. RSS items and Atom entries are
/// collected differently, so the root element decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlKind {
    Rss,
    Atom,
}

/// Collect one RSS `<item>` subtree into a [`NewsItem`].
///
/// Consumes events up to and including the closing `</item>`. An item needs
/// a title and a link to be worth storing; anything less is dropped.
fn rss_item(reader: &mut Reader<&[u8]>, feed: &Feed) -> Result<Option<NewsItem>, FetchError> {
    let now = now_secs();
    let mut title = String::new();
    let mut link = String::new();
    let mut teaser = String::new();
    let mut full_text = String::new();
    let mut date = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                "title" => title = inner_text(reader, "title")?,
                "link" => link = inner_text(reader, "link")?,
                "pubDate" => date = inner_text(reader, "pubDate")?,
                "description" => teaser = inner_text(reader, "description")?,
                // content:encoded (its local name, without the prefix)
                // carries the full article. The teaser wins when present;
                // the full text is the fallback body.
                "encoded" => full_text = inner_text(reader, "encoded")?,
                _ => {}
            },
            Ok(Event::End(element)) if element.local_name().as_ref() == "item" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(FetchError::Parse(format!("rss xml: {e}"))),
            _ => {}
        }
    }

    let title = trim_text(&title);
    let link = trim_text(&link);
    if title.is_empty() || link.is_empty() {
        return Ok(None);
    }
    let description = if teaser.is_empty() { full_text } else { teaser };
    let published = parse_date(&trim_text(&date)).unwrap_or(now);
    Ok(Some(news_item(
        feed,
        &title,
        &link,
        &description,
        published,
        now,
    )))
}

/// Collect one Atom `<entry>` subtree into a [`NewsItem`].
///
/// Atom places the link in a `href` attribute rather than element text, and
/// can carry both `summary` and `content`; the first non-empty body text
/// wins. Publication time prefers `published`, falling back to `updated`.
fn atom_entry(reader: &mut Reader<&[u8]>, feed: &Feed) -> Result<Option<NewsItem>, FetchError> {
    let now = now_secs();
    let mut title = String::new();
    let mut href = None;
    let mut rel_seen = String::new();
    let mut description = String::new();
    let mut published = String::new();
    let mut updated = String::new();
    let mut alternate_href: Option<String> = None;
    let mut any_href: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => match element.local_name().as_ref() {
                "title" => title = inner_text(reader, "title")?,
                "published" => published = inner_text(reader, "published")?,
                "updated" => updated = inner_text(reader, "updated")?,
                "summary" if description.is_empty() => {
                    description = inner_text(reader, "summary")?;
                }
                "content" if description.is_empty() => {
                    description = inner_text(reader, "content")?;
                }
                "link" => {
                    let (h, rel) = link_attributes(&element);
                    href = Some(h);
                    rel_seen = rel;
                }
                _ => {}
            },
            Ok(Event::Empty(element)) if element.local_name().as_ref() == "link" => {
                let (h, rel) = link_attributes(&element);
                href = Some(h);
                rel_seen = rel;
            }
            Ok(Event::End(element)) if element.local_name().as_ref() == "entry" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(FetchError::Parse(format!("atom xml: {e}"))),
            _ => {}
        }
        // The href from the most recent link Start applies to whichever
        // link we are inside. Prefer an alternate or untyped link (the
        // article), never self or the feed's own url.
        if let Some(h) = href.take() {
            if rel_seen.is_empty() || rel_seen == "alternate" {
                alternate_href.get_or_insert(h);
            } else {
                any_href.get_or_insert(h);
            }
            rel_seen.clear();
        }
    }

    let title = trim_text(&title);
    let link = trim_text(&alternate_href.unwrap_or_else(|| any_href.unwrap_or_default()));
    if title.is_empty() || link.is_empty() {
        return Ok(None);
    }
    let date = trim_text(&published);
    let date = if date.is_empty() { trim_text(&updated) } else { date };
    let published = parse_date(&date).unwrap_or(now);
    Ok(Some(news_item(
        feed,
        &title,
        &link,
        &description,
        published,
        now,
    )))
}

/// Read the `href` and `rel` attributes off an Atom link element.
fn link_attributes(element: &quick_xml::events::BytesStart<'_>) -> (String, String) {
    let mut href = String::new();
    let mut rel = String::new();
    for attribute in element.attributes() {
        let Ok(attribute) = attribute else { continue };
        match attribute.key.local_name().as_ref() {
            "href" => href = unescape_text(&attribute.value),
            "rel" => rel = attribute.value.trim().to_string(),
            _ => {}
        }
    }
    (href, rel)
}

/// Read the text of one element, flattened across any markup inside it.
///
/// Consumes events up to and including the element's own closing tag, whose
/// name is `target`. Nested tags inside (markup inside an Atom `content`,
/// say) contribute their text but not their names, and the nesting depth is
/// tracked so a closing tag of the nested element does not end the read
/// early. An RSS description that is really HTML reads back as plain prose.
fn inner_text(reader: &mut Reader<&[u8]>, target: &str) -> Result<String, FetchError> {
    let mut out = String::new();
    let mut depth = 0usize;
    loop {
        match reader.read_event() {
            Ok(Event::Text(text)) => out.push_str(&unescape_text(&text)),
            Ok(Event::CData(text)) => out.push_str(&text),
            // XML entity references surface as GeneralRef events carrying
            // the bare body ("lt", "#233", "#x27"). quick-xml does not
            // resolve them without a DTD, so they are decoded here.
            Ok(Event::GeneralRef(reference)) => {
                out.push_str(&decode_entity_reference(reference.as_ref()));
            }
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::Empty(_)) => {}
            Ok(Event::End(element)) if element.local_name().as_ref() == target && depth == 0 => {
                return Ok(out);
            }
            Ok(Event::End(_)) if depth > 0 => depth -= 1,
            Ok(Event::Eof) => return Ok(out),
            Err(e) => return Err(FetchError::Parse(format!("xml text: {e}"))),
            _ => {}
        }
    }
}

/// Decode XML entities, keeping the raw text when an entity is unknown.
fn unescape_text(text: &str) -> String {
    match escape::unescape(text) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => text.to_string(),
    }
}

/// Decode one XML entity reference body into the character it names.
///
/// The body is what quick-xml reports between the ampersand and semicolon.
/// The five predefined XML entities and the decimal/hex numeric references
/// are resolved; an unrecognized named entity (feeds occasionally carry
/// HTML leftovers like `&rsquo;`) is kept verbatim so no text is silently
/// dropped.
fn decode_entity_reference(body: &str) -> String {
    match body {
        "amp" => return "&".to_string(),
        "lt" => return "<".to_string(),
        "gt" => return ">".to_string(),
        "quot" => return "\"".to_string(),
        "apos" => return "'".to_string(),
        _ => {}
    }
    if let Some(ch) = body
        .strip_prefix("#x")
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .and_then(char::from_u32)
    {
        return ch.to_string();
    }
    if let Some(ch) = body
        .strip_prefix('#')
        .and_then(|decimal| decimal.parse::<u32>().ok())
        .and_then(char::from_u32)
    {
        return ch.to_string();
    }
    format!("&{body};")
}

/// Trim surrounding whitespace.
fn trim_text(text: &str) -> String {
    text.trim().to_string()
}

/// Assemble the stored form of an item from parsed feed content.
fn news_item(feed: &Feed, title: &str, link: &str, description: &str, published: i64, now: i64) -> NewsItem {
    NewsItem {
        id: 0,
        title: trim_text(title),
        url: trim_text(link),
        description: clean_text(description),
        published,
        source: feed.source_name.to_string(),
        category: feed.category.as_str().to_string(),
        fetched_at: now,
    }
}

/// Strip markup tags, collapse whitespace, and cap the description length.
fn clean_text(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut in_tag = false;
    for ch in text.chars() {
        if in_tag {
            if ch == '>' {
                in_tag = false;
            }
        } else if ch == '<' {
            in_tag = true;
        } else {
            plain.push(ch);
        }
    }
    let joined = plain.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.chars().take(MAX_DESCRIPTION_CHARS).collect()
}

/// Parse the CISA KEV JSON catalog into store-ready CVE items.
///
/// The catalog is one JSON object whose `vulnerabilities` array holds one
/// object per CVE. This parser is intentionally narrow: it walks the array
/// and lifts the string fields it needs, skipping everything else. It is not
/// a general JSON parser and does not claim to be one.
fn parse_kev_catalog(document: &str, feed: &Feed) -> Result<Vec<NewsItem>, FetchError> {
    let now = now_secs();
    let mut items = Vec::new();

    let key = "\"vulnerabilities\"";
    let Some(start) = document.find(key) else {
        return Err(FetchError::Parse("kev: no vulnerabilities key".into()));
    };
    let mut i = start + key.len();
    skip_space(document, &mut i);
    if document[i..].starts_with(':') {
        i += 1;
    }
    skip_space(document, &mut i);
    if document[i..].starts_with('[') {
        i += 1;
    } else {
        return Err(FetchError::Parse("kev: no vulnerabilities array".into()));
    }

    loop {
        skip_space(document, &mut i);
        // A comma between objects, or trailing punctuation, is not a field.
        if document[i..].starts_with(',') {
            i += 1;
            continue;
        }
        match document[i..].chars().next() {
            Some(']') => break,
            Some('{') => {
                let fields = json_object_strings(document, &mut i)?;
                if let Some(cve_id) = fields.get("cveID") {
                    let title = fields
                        .get("vulnerabilityName")
                        .filter(|t| !t.is_empty())
                        .cloned()
                        .unwrap_or_else(|| cve_id.clone());
                    let description = fields
                        .get("shortDescription")
                        .filter(|d| !d.is_empty())
                        .cloned()
                        .or_else(|| fields.get("requiredAction").cloned())
                        .unwrap_or_default();
                    let published = fields
                        .get("dateAdded")
                        .and_then(|date| parse_date(date))
                        .unwrap_or(now);
                    items.push(NewsItem {
                        id: 0,
                        title,
                        url: format!("https://nvd.nist.gov/vuln/detail/{cve_id}"),
                        description: clean_text(&description),
                        published,
                        source: feed.source_name.to_string(),
                        category: Category::Cve.as_str().to_string(),
                        fetched_at: now,
                    });
                }
            }
            _ => {
                return Err(FetchError::Parse("kev: malformed catalog".into()));
            }
        }
    }
    Ok(items)
}

/// The piece of one NVD CVE record the aggregator keeps.
struct NvdRecord {
    id: String,
    published: Option<String>,
    description: String,
}

/// Parse the NVD 2.0 CVE search response into store-ready CVE items.
///
/// The response nests every CVE two levels down: a `vulnerabilities` array,
/// then one object per CVE, then a `cve` object that carries the id, the
/// descriptions array, and the publish time. This walker is as narrow as the
/// KEV one above: it lifts those three fields and walks past everything else
/// (references, weaknesses, metrics) without buffering it. The item title is
/// the CVE id and the url is the NVD detail page, so the store keys each row
/// on a stable value across runs.
fn parse_nvd_api(document: &str, feed: &Feed) -> Result<Vec<NewsItem>, FetchError> {
    let now = now_secs();
    let mut items = Vec::new();

    let key = "\"vulnerabilities\"";
    let Some(start) = document.find(key) else {
        return Err(FetchError::Parse("nvd: no vulnerabilities key".into()));
    };
    let mut i = start + key.len();
    skip_space(document, &mut i);
    if document[i..].starts_with(':') {
        i += 1;
    }
    skip_space(document, &mut i);
    if document[i..].starts_with('[') {
        i += 1;
    } else {
        return Err(FetchError::Parse("nvd: no vulnerabilities array".into()));
    }

    loop {
        skip_space(document, &mut i);
        // A comma between elements, or trailing punctuation, is not a field.
        if document[i..].starts_with(',') {
            i += 1;
            continue;
        }
        match document[i..].chars().next() {
            Some(']') => break,
            Some('{') => {
                if let Some(record) = nvd_element(document, &mut i)? {
                    items.push(nvd_news_item(&record, feed, now));
                }
            }
            _ => return Err(FetchError::Parse("nvd: malformed response".into())),
        }
    }
    Ok(items)
}

/// Build the stored item from one parsed NVD record.
fn nvd_news_item(record: &NvdRecord, feed: &Feed, now: i64) -> NewsItem {
    let published = record
        .published
        .as_deref()
        .and_then(parse_date)
        .unwrap_or(now);
    news_item(
        feed,
        &record.id,
        &format!("https://nvd.nist.gov/vuln/detail/{}", record.id),
        &record.description,
        published,
        now,
    )
}

/// Read one `vulnerabilities` element. The CVE record sits under a `cve`
/// key, so that object is the only member descended into; the rest of the
/// element (cveTags and anything new NVD adds) is skipped. An element with
/// no `cve` object yields None.
fn nvd_element(document: &str, i: &mut usize) -> Result<Option<NvdRecord>, FetchError> {
    // The cursor sits on the element's opening brace.
    *i += 1;
    let mut record = None;
    loop {
        skip_space(document, i);
        if document[*i..].starts_with(',') {
            *i += 1;
            continue;
        }
        if document[*i..].starts_with('}') {
            *i += 1;
            return Ok(record);
        }
        let key =
            json_string(document, i).ok_or_else(|| FetchError::Parse("nvd: bad key".into()))?;
        skip_space(document, i);
        if !document[*i..].starts_with(':') {
            return Err(FetchError::Parse("nvd: missing colon".into()));
        }
        *i += 1;
        skip_space(document, i);
        if key == "cve" && document[*i..].starts_with('{') {
            record = Some(nvd_cve_object(document, i)?);
        } else {
            skip_any_json_value(document, i)?;
        }
    }
}

/// Read one `cve` object, lifting the id, the publish time, and the
/// descriptions. Every other member (references, weaknesses, metrics) is
/// walked past whole.
fn nvd_cve_object(document: &str, i: &mut usize) -> Result<NvdRecord, FetchError> {
    // The cursor sits on the cve object's opening brace.
    *i += 1;
    let mut id = None;
    let mut published = None;
    let mut descriptions: Vec<(String, String)> = Vec::new();
    loop {
        skip_space(document, i);
        if document[*i..].starts_with(',') {
            *i += 1;
            continue;
        }
        if document[*i..].starts_with('}') {
            *i += 1;
            break;
        }
        let key =
            json_string(document, i).ok_or_else(|| FetchError::Parse("nvd: bad key".into()))?;
        skip_space(document, i);
        if !document[*i..].starts_with(':') {
            return Err(FetchError::Parse("nvd: missing colon".into()));
        }
        *i += 1;
        skip_space(document, i);
        match key.as_str() {
            "id" => {
                if let Some(value) = optional_string(document, i)? {
                    id = Some(value);
                }
            }
            "published" => {
                if let Some(value) = optional_string(document, i)? {
                    published = Some(value);
                }
            }
            "descriptions" => {
                if document[*i..].starts_with('[') {
                    read_nvd_descriptions(document, i, &mut descriptions)?;
                } else {
                    skip_any_json_value(document, i)?;
                }
            }
            _ => skip_any_json_value(document, i)?,
        }
    }
    let id = id.ok_or_else(|| FetchError::Parse("nvd: cve has no id".into()))?;
    let description = descriptions
        .iter()
        .find(|(lang, _)| lang == "en")
        .or_else(|| descriptions.first())
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    Ok(NvdRecord {
        id,
        published,
        description,
    })
}

/// Read the `descriptions` array into (lang, value) pairs. A description
/// with no text is dropped.
fn read_nvd_descriptions(
    document: &str,
    i: &mut usize,
    out: &mut Vec<(String, String)>,
) -> Result<(), FetchError> {
    // The cursor sits on the array's opening bracket.
    *i += 1;
    loop {
        skip_space(document, i);
        if document[*i..].starts_with(',') {
            *i += 1;
            continue;
        }
        match document[*i..].chars().next() {
            Some(']') => {
                *i += 1;
                return Ok(());
            }
            Some('{') => {
                let fields = json_object_strings(document, i).map_err(|_| {
                    FetchError::Parse("nvd: malformed description".into())
                })?;
                if let Some(value) = fields.get("value").filter(|text| !text.is_empty()) {
                    let lang = fields.get("lang").cloned().unwrap_or_default();
                    out.push((lang, value.clone()));
                }
            }
            _ => return Err(FetchError::Parse("nvd: malformed descriptions".into())),
        }
    }
}

/// Read a member value that should be a string. A value that is not a string
/// is skipped whole and None is returned, so an absent or mistyped field is
/// not fatal.
fn optional_string(document: &str, i: &mut usize) -> Result<Option<String>, FetchError> {
    skip_space(document, i);
    if document[*i..].starts_with('"') {
        json_string(document, i)
            .map(Some)
            .ok_or_else(|| FetchError::Parse("nvd: unterminated string".into()))
    } else {
        skip_any_json_value(document, i)?;
        Ok(None)
    }
}

/// Skip one JSON value of any shape, quotes respected. Scalars are handled
/// by skip_json_scalar, which also eats a trailing comma.
fn skip_any_json_value(document: &str, i: &mut usize) -> Result<(), FetchError> {
    skip_space(document, i);
    match document[*i..].chars().next() {
        Some('"') => {
            if json_string(document, i).is_none() {
                return Err(FetchError::Parse("nvd: unterminated string".into()));
            }
            Ok(())
        }
        Some('{') | Some('[') => skip_json_value(document, i),
        Some(_) => {
            skip_json_scalar(document, i);
            Ok(())
        }
        None => Err(FetchError::Parse("nvd: truncated value".into())),
    }
}

/// Skip JSON whitespace from the cursor onward.
fn skip_space(document: &str, i: &mut usize) {
    while document[*i..].starts_with(|c: char| c.is_whitespace()) {
        *i += 1;
    }
}

/// Read one JSON string value starting at the cursor, which must sit on the
/// opening quote. Advances past the closing quote. Handles the backslash
/// escapes that actually appear in the KEV catalog.
fn json_string(document: &str, i: &mut usize) -> Option<String> {
    let rest = &document[*i..];
    if !rest.starts_with('"') {
        return None;
    }
    *i += 1;
    let mut out = String::new();
    let mut chars = document[*i..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => {
                *i += offset + 1;
                return Some(out);
            }
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    match escaped {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000c}'),
                        'u' => {
                            let hex = document[*i + offset + 2..].get(..4)?;
                            if let Some(c) = u32::from_str_radix(hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                            {
                                out.push(c);
                            }
                            chars.next();
                            chars.next();
                            chars.next();
                            chars.next();
                        }
                        other => out.push(other),
                    }
                }
            }
            _ => out.push(ch),
        }
    }
    None
}

/// Collect the top-level string fields of one JSON object into a map.
///
/// The cursor must sit on the opening brace. Nested objects and arrays are
/// skipped whole; only strings directly under this object are kept, which is
/// all the KEV catalog needs.
fn json_object_strings(
    document: &str,
    i: &mut usize,
) -> Result<std::collections::HashMap<String, String>, FetchError> {
    let mut fields = std::collections::HashMap::new();
    skip_space(document, i);
    if !document[*i..].starts_with('{') {
        return Err(FetchError::Parse("kev: expected object".into()));
    }
    *i += 1;
    loop {
        skip_space(document, i);
        // A comma between members is not a key. Values are consumed without
        // their trailing comma, so it is skipped here where the next member
        // is expected.
        if document[*i..].starts_with(',') {
            *i += 1;
            continue;
        }
        if document[*i..].starts_with('}') {
            *i += 1;
            return Ok(fields);
        }
        let key = json_string(document, i).ok_or_else(|| FetchError::Parse("kev: bad key".into()))?;
        skip_space(document, i);
        if !document[*i..].starts_with(':') {
            return Err(FetchError::Parse("kev: missing colon".into()));
        }
        *i += 1;
        skip_space(document, i);
        match document[*i..].chars().next() {
            Some('"') => {
                if let Some(value) = json_string(document, i) {
                    fields.insert(key, value);
                }
            }
            Some('{') => skip_json_value(document, i)?,
            Some('[') => skip_json_value(document, i)?,
            Some(_) => skip_json_scalar(document, i),
            None => return Err(FetchError::Parse("kev: truncated object".into())),
        }
    }
}

/// Skip one nested JSON object or array, quotes respected.
fn skip_json_value(document: &str, i: &mut usize) -> Result<(), FetchError> {
    let mut depth = 0usize;
    let rest = &document[*i..];
    let mut chars = rest.char_indices();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => {
                // Hand the string off to json_string to skip it properly,
                // then resync the cursor.
                *i += offset;
                if json_string(document, i).is_none() {
                    return Err(FetchError::Parse("kev: unterminated string".into()));
                }
                chars = document[*i..].char_indices();
            }
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    *i += offset + 1;
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    Err(FetchError::Parse("kev: unterminated value".into()))
}

/// Skip a JSON scalar (number, true, false, null) from the cursor. A trailing
/// comma is consumed too; a brace is left for the caller to close.
fn skip_json_scalar(document: &str, i: &mut usize) {
    let rest = &document[*i..];
    let at = rest.find([',', '}', ']']).unwrap_or(rest.len());
    *i += at;
    if document[*i..].starts_with(',') {
        *i += 1;
    }
}

/// Current Unix timestamp in seconds.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
        .try_into()
        .expect("Unix time fits in i64 until the year 2262")
}

/// Parse a feed date into a Unix timestamp.
///
/// Feeds rarely agree on a format. RFC 3339 (`2026-09-07T12:00:00Z`) rules
/// Atom, RFC 2822 (`Tue, 07 Sep 2026 12:00:00 +0000`) rules RSS, and the KEV
/// catalog uses a bare date (`2026-09-07`). All three are accepted; anything
/// else yields `None` and the caller stamps the item with fetch time.
fn parse_date(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if text.contains('T') {
        return parse_rfc3339(text).or_else(|| parse_rfc2822(text));
    }
    // YYYY-MM-DD has exactly two hyphens and starts with a digit.
    if text.matches('-').count() == 2
        && text.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && let Some(ts) = parse_ymd(text)
    {
        return Some(ts);
    }
    parse_rfc2822(text)
}

/// Parse RFC 3339, e.g. `2026-09-07T12:34:56.000Z` or `...+02:00`.
fn parse_rfc3339(text: &str) -> Option<i64> {
    let date_end = text.find('T')?;
    let (y, mo, d) = parse_date_part(&text[..date_end])?;
    let rest = &text[date_end + 1..];

    // Locate the timezone: Z, or a signed hh:mm, or nothing.
    let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let time_part = &rest[..zone_at];
    let zone = &rest[zone_at..];

    // RFC 3339 allows fractional seconds; they do not matter at second
    // resolution, so drop them before the clock fields are read.
    let time_part = time_part.split('.').next().unwrap_or(time_part);

    let (h, mi, s) = parse_time_part(time_part)?;
    let offset = if zone.is_empty() || zone.eq_ignore_ascii_case("Z") {
        0
    } else {
        parse_zone_offset(zone)?
    };
    Some(civil_seconds(y, mo, d, h, mi, s).saturating_sub(offset))
}

/// Parse RFC 2822, e.g. `Tue, 07 Sep 2026 12:34:56 +0000`.
fn parse_rfc2822(text: &str) -> Option<i64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let mut i = 0;
    // Skip the optional weekday token ("Tue," or "Tue").
    if weekday_of(parts[i].trim_end_matches(',')) {
        i += 1;
    }
    let day = i64::from(parts.get(i)?.parse::<u32>().ok()?);
    let month = month_of(parts.get(i + 1)?)?;
    let mut year = parts.get(i + 2)?.parse::<i64>().ok()?;
    // RFC 2822 allows a two-digit year; map it into the 20th/21st century
    // the way mail readers always have.
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let (h, mi, s) = parse_time_part(parts.get(i + 3)?).unwrap_or((0, 0, 0));
    let offset = parts
        .get(i + 4)
        .and_then(|zone| parse_zone_offset(zone))
        .unwrap_or(0);
    Some(civil_seconds(year, month, day, h, mi, s).saturating_sub(offset))
}

/// Parse a bare `YYYY-MM-DD` calendar date as midnight UTC.
fn parse_ymd(text: &str) -> Option<i64> {
    let (y, mo, d) = parse_date_part(text)?;
    Some(civil_seconds(y, mo, d, 0, 0, 0))
}

/// Split and validate a `YYYY-MM-DD` date.
fn parse_date_part(text: &str) -> Option<(i64, i64, i64)> {
    let mut fields = text.split('-');
    let y = fields.next()?.parse::<i64>().ok()?;
    let mo = fields.next()?.parse::<i64>().ok()?;
    let d = fields.next()?.parse::<i64>().ok()?;
    if fields.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, mo, d))
}

/// Parse `hh:mm:ss` or `hh:mm` (RFC 2822 allows omitting seconds).
fn parse_time_part(text: &str) -> Option<(i64, i64, i64)> {
    let fields: Vec<&str> = text.split(':').collect();
    if !(2..=3).contains(&fields.len()) {
        return None;
    }
    let h = fields[0].parse::<i64>().ok()?;
    let mi = fields[1].parse::<i64>().ok()?;
    let s = fields.get(2).map(|f| f.parse::<i64>().ok()).unwrap_or(Some(0))?;
    if !(0..24).contains(&h) || !(0..60).contains(&mi) || !(0..60).contains(&s) {
        return None;
    }
    Some((h, mi, s))
}

/// Parse a timezone suffix into an offset in seconds east of UTC.
///
/// Numeric forms (`+0000`, `-0500`, `+02:00`) are the rule in feeds. GMT and
/// UTC mean zero; the North American abbreviations map to their daylight
/// variants on the assumption that a feed printing `EST` in July is rare and
/// not worth a table. An unrecognized word yields `None`, which the caller
/// treats as UTC.
fn parse_zone_offset(text: &str) -> Option<i64> {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 4 {
        return match text.to_ascii_uppercase().as_str() {
            "Z" | "GMT" | "UTC" => Some(0),
            // Offsets east of UTC are positive; these zones sit west.
            "EST" => Some(-5 * 3600),
            "EDT" => Some(-4 * 3600),
            "CST" => Some(-6 * 3600),
            "CDT" => Some(-5 * 3600),
            "MST" => Some(-7 * 3600),
            "MDT" => Some(-6 * 3600),
            "PST" => Some(-8 * 3600),
            "PDT" => Some(-7 * 3600),
            _ => None,
        };
    }
    let sign: i64 = if text.starts_with('-') { -1 } else { 1 };
    let hours = digits[..2].parse::<i64>().ok()?;
    let minutes = digits[2..].parse::<i64>().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Whether `token` is a three-letter English weekday abbreviation.
fn weekday_of(token: &str) -> bool {
    matches!(
        token,
        "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun"
    )
}

/// The month number (1-12) of a three-letter English month abbreviation.
fn month_of(token: &str) -> Option<i64> {
    Some(match token {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days from the Unix epoch to a proleptic Gregorian civil date, using the
/// days-from-civil algorithm (Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719_468
}

/// Unix seconds for a fully resolved civil date-time.
fn civil_seconds(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A fake feed for parse tests.
    fn feed(category: Category) -> Feed {
        Feed {
            url: "https://example.com/feed.xml",
            source_name: "Example",
            category,
        }
    }

    fn xml_feed(body: &str, category: Category) -> Vec<NewsItem> {
        parse_xml_feed(body, &feed(category)).expect("xml parses")
    }

    #[test]
    fn url_splits_into_host_and_path() {
        assert_eq!(
            parse_url("https://krebsonsecurity.com/feed/").expect("parses"),
            ("krebsonsecurity.com".to_string(), "/feed/".to_string())
        );
        assert_eq!(
            parse_url("https://www.cisa.gov/sites/default/files/kev.json?x=1").expect("parses"),
            (
                "www.cisa.gov".to_string(),
                "/sites/default/files/kev.json?x=1".to_string()
            )
        );
        assert_eq!(
            parse_url("https://isc.sans.edu/rssfeed.xml").expect("parses").0,
            "isc.sans.edu"
        );
        assert!(matches!(parse_url("http://insecure.example/"), Err(FetchError::NotHttps)));
    }

    #[test]
    fn every_catalog_host_is_its_own_allowlist_entry() {
        for feed in crate::feeds::FEEDS {
            let (host, _) = parse_url(feed.url).expect("catalog urls parse");
            assert!(
                host_is_allowed(&host),
                "feed host {host} must pass the allowlist"
            );
        }
    }

    #[test]
    fn a_host_outside_the_catalog_is_refused_before_any_connection() {
        // The catalog in feeds.rs is the whole egress surface. A forged Feed
        // pointing elsewhere must be refused before fetch_feed resolves a
        // name or opens a socket, so this test needs no network: the guard
        // answers first.
        let foreign = Feed {
            url: "https://not-in-the-catalog.example/feed.xml",
            source_name: "Foreign",
            category: Category::Cve,
        };
        assert!(!host_is_allowed("not-in-the-catalog.example"));
        assert!(matches!(
            fetch_feed(&foreign),
            Err(FetchError::HostNotAllowed(host)) if host == "not-in-the-catalog.example"
        ));
    }

    #[test]
    fn only_the_kev_url_gets_the_larger_budget() {
        assert_eq!(body_budget("https://x/feed.xml"), DEFAULT_BODY_LIMIT);
        assert_eq!(
            body_budget("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
            KEV_BODY_LIMIT
        );
    }

    #[test]
    fn response_head_parses_status_and_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 12\r\n\r\n";
        let mut cursor = Cursor::new(raw);
        let head = read_response_head(&mut cursor).expect("head parses");
        assert_eq!(head.status, 200);
        assert_eq!(header(&head.headers, "content-type"), Some("text/xml"));
        assert_eq!(header(&head.headers, "content-length"), Some("12"));
    }

    #[test]
    fn body_reads_by_content_length_chunked_and_close() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = Cursor::new(raw);
        let head = read_response_head(&mut cursor).expect("head");
        assert_eq!(
            read_body(&mut cursor, &head.headers, 1024).expect("body"),
            b"hello"
        );

        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut cursor = Cursor::new(raw);
        let head = read_response_head(&mut cursor).expect("head");
        assert_eq!(
            read_body(&mut cursor, &head.headers, 1024).expect("chunked body"),
            b"hello world"
        );

        let raw = b"HTTP/1.1 200 OK\r\n\r\nopen-ended body, no length";
        let mut cursor = Cursor::new(raw);
        let head = read_response_head(&mut cursor).expect("head");
        assert_eq!(
            read_body(&mut cursor, &head.headers, 1024).expect("close-delimited body"),
            b"open-ended body, no length"
        );
    }

    #[test]
    fn body_aborts_when_it_exceeds_the_budget() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nway too much content for four bytes";
        let mut cursor = Cursor::new(raw);
        let head = read_response_head(&mut cursor).expect("head");
        let error = read_body(&mut cursor, &head.headers, 4).expect_err("budget trip");
        assert!(matches!(error, FetchError::BodyTooLarge { .. }));
    }

    #[test]
    fn rss_items_are_extracted() {
        let body = r#"<?xml version="1.0"?>
<rss version="2.0"><channel><title>Example</title>
<item><title>Router botnet grows</title>
<link>https://example.com/stories/1</link>
<description>&lt;p&gt;New variant spreads&lt;/p&gt;</description>
<pubDate>Tue, 01 Sep 2026 12:00:00 +0000</pubDate></item>
<item><title>No link here, dropped</title></item>
</channel></rss>"#;
        let items = xml_feed(body, Category::Breach);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Router botnet grows");
        assert_eq!(items[0].url, "https://example.com/stories/1");
        assert_eq!(items[0].description, "New variant spreads");
        assert_eq!(items[0].category, "Breach");
        assert_eq!(items[0].source, "Example");
    }

    #[test]
    fn atom_entries_are_extracted_and_prefer_the_alternate_link() {
        let body = r#"<feed xmlns="http://www.w3.org/2005/Atom"><title>Example</title>
<entry><title>Side channel in firmware</title>
<link rel="self" href="https://example.com/feed"/>
<link rel="alternate" href="https://example.com/stories/2"/>
<summary type="html">&lt;b&gt;Research&lt;/b&gt; notes a leak</summary>
<updated>2026-09-07T08:30:00Z</updated></entry>
</feed>"#;
        let items = xml_feed(body, Category::Research);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].url, "https://example.com/stories/2");
        assert_eq!(items[0].description, "Research notes a leak");
        assert_eq!(items[0].category, "Research");
    }

    #[test]
    fn content_encoded_backs_an_empty_description() {
        let body = r#"<rss version="2.0"><channel>
<item><title>Full text</title><link>https://example.com/a</link>
<description>Short teaser</description>
<content:encoded xmlns:content="http://purl.org/rss/1.0/modules/content/"><![CDATA[<p>Long article body here.</p>]]></content:encoded>
<pubDate>Mon, 07 Sep 2026 09:00:00 GMT</pubDate></item>
</channel></rss>"#;
        let items = xml_feed(body, Category::ThreatIntel);
        assert_eq!(items[0].description, "Short teaser", "teaser wins");
    }

    #[test]
    fn kev_catalog_parses_into_cve_items() {
        let body = r#"{
  "title": "KEV",
  "vulnerabilities": [
    {
      "cveID": "CVE-2026-0001",
      "vendorProject": "Acme",
      "product": "Widget",
      "vulnerabilityName": "Acme Widget RCE",
      "dateAdded": "2026-09-01",
      "shortDescription": "Acme Widget has an RCE.",
      "requiredAction": "Apply vendor patch.",
      "cwes": ["CWE-78"]
    },
    {
      "cveID": "CVE-2026-0002",
      "vendorProject": "Beta",
      "product": "Gadget",
      "vulnerabilityName": "Beta Gadget LPE",
      "dateAdded": "2026-09-02",
      "requiredAction": "Mitigate per CISA.",
      "cwes": []
    }
  ]
}"#;
        let items = parse_kev_catalog(body, &feed(Category::Cve)).expect("kev parses");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Acme Widget RCE");
        assert_eq!(items[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2026-0001");
        assert_eq!(items[0].description, "Acme Widget has an RCE.");
        assert_eq!(items[0].category, "Cve");
        assert_eq!(items[1].description, "Mitigate per CISA.", "requiredAction fallback");
    }

    #[test]
    fn nvd_api_response_parses_into_cve_items() {
        let body = r#"{
  "resultsPerPage": 20,
  "startIndex": 0,
  "totalResults": 340,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-09-07T12:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2026-7777",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2026-09-07T08:00:00.000",
        "lastModified": "2026-09-07T09:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
          { "lang": "es", "value": "Primera descripcion." },
          { "lang": "en", "value": "The widget parser lets a remote user run code." }
        ],
        "references": [{ "url": "https://example.com/advisory" }]
      },
      "cveTags": []
    },
    {
      "cve": {
        "id": "CVE-2026-7778",
        "published": "2026-09-07T10:00:00.000",
        "descriptions": [
          { "lang": "es", "value": "Solo descripcion." }
        ]
      }
    }
  ]
}"#;
        let items = parse_nvd_api(body, &feed(Category::Cve)).expect("nvd api parses");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "CVE-2026-7777", "the cve id is the title");
        assert_eq!(items[0].url, "https://nvd.nist.gov/vuln/detail/CVE-2026-7777");
        assert_eq!(
            items[0].description,
            "The widget parser lets a remote user run code.",
            "the english description wins over the spanish one"
        );
        assert_eq!(items[0].category, "Cve");
        assert_eq!(
            items[0].published,
            civil_seconds(2026, 9, 7, 8, 0, 0),
            "published parses from rfc 3339 with fractional seconds"
        );
        assert_eq!(
            items[1].description,
            "Solo descripcion.",
            "without english the first description is kept"
        );
    }

    #[test]
    fn json_feeds_route_by_url_and_only_kev_gets_the_large_budget() {
        let kev =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        let nvd = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20";
        let xml = "https://www.schneier.com/feed/atom/";
        assert!(is_kev_catalog(kev));
        assert!(is_nvd_api(nvd));
        assert!(!is_kev_catalog(nvd), "nvd keeps the default budget");
        assert!(!is_nvd_api(xml));
        assert_eq!(body_budget(kev), KEV_BODY_LIMIT);
        assert_eq!(
            body_budget(nvd),
            DEFAULT_BODY_LIMIT,
            "twenty records fit under the default cap"
        );
    }

    #[test]
    fn nvd_total_results_reads_the_count() {
        let body = r#"{"resultsPerPage":1,"startIndex":0,"totalResults":2546,"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":{"id":"CVE-2026-0001"}}]}"#;
        assert_eq!(nvd_total_results(body).unwrap(), 2546);
        assert!(
            nvd_total_results(r#"{"vulnerabilities":[]}"#).is_err(),
            "a response with no totalResults fails"
        );
    }

    #[test]
    fn utc_rfc3339_formats_civil_time() {
        assert_eq!(format_utc_rfc3339(0), "1970-01-01T00:00:00.000");
        assert_eq!(
            format_utc_rfc3339(civil_seconds(2026, 9, 7, 14, 30, 5)),
            "2026-09-07T14:30:05.000"
        );
        assert_eq!(
            format_utc_rfc3339(civil_seconds(2026, 2, 28, 23, 59, 59)),
            "2026-02-28T23:59:59.000",
            "leap year boundary stays aligned"
        );
    }

    #[test]
    fn nvd_window_query_spans_seven_days() {
        let now = civil_seconds(2026, 9, 7, 12, 0, 0);
        assert_eq!(
            nvd_window_query(now),
            "&pubStartDate=2026-08-31T12:00:00.000&pubEndDate=2026-09-07T12:00:00.000"
        );
    }

    #[test]
    fn rfc3339_timestamps_parse() {
        assert_eq!(
            parse_date("2026-09-07T12:34:56Z"),
            Some(civil_seconds(2026, 9, 7, 12, 34, 56))
        );
        assert_eq!(
            parse_date("2026-09-07T14:34:56+02:00"),
            Some(civil_seconds(2026, 9, 7, 12, 34, 56))
        );
        assert_eq!(
            parse_date("2026-09-07T12:34:56.250Z"),
            Some(civil_seconds(2026, 9, 7, 12, 34, 56))
        );
    }

    #[test]
    fn rfc2822_timestamps_parse() {
        assert_eq!(
            parse_date("Tue, 01 Sep 2026 12:00:00 +0000"),
            Some(civil_seconds(2026, 9, 1, 12, 0, 0))
        );
        assert_eq!(
            parse_date("Mon, 07 Sep 2026 09:00:00 GMT"),
            Some(civil_seconds(2026, 9, 7, 9, 0, 0))
        );
        assert_eq!(
            parse_date("1 Sep 2026 08:00:00 -0500"),
            Some(civil_seconds(2026, 9, 1, 13, 0, 0))
        );
    }

    #[test]
    fn bare_and_missing_dates_fall_back_sensibly() {
        assert_eq!(
            parse_date("2026-09-07"),
            Some(civil_seconds(2026, 9, 7, 0, 0, 0))
        );
        assert_eq!(parse_date("no date here"), None);
        assert_eq!(parse_date(""), None);
    }
}
