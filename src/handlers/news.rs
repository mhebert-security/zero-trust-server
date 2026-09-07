//! The /news page handler.
//!
//! This handler follows the pattern of every other protected page: the router
//! runs the session check before dispatch (router.rs Step 1), and a visitor
//! without a valid session gets the PoW challenge there, never here. By the
//! time this code runs, the visitor is verified.
//!
//! What remains is the read path. The handler opens the shared SQLite store at
//! the path the operator configures (CYBER_NEWS_DB_PATH, else the production
//! default), pulls the last 24 hours of items, and hands them to the renderer.
//! The fetcher wrote those rows on its own six-hour timer; this process only
//! ever reads them. A store that will not open, or a read that fails, answers
//! 500 rather than a page full of nothing.

use crate::http::{Request, Response};
use crate::{renderer, store};

/// The production store location, used when CYBER_NEWS_DB_PATH names none.
/// Mirrors the fetcher's default so the two processes agree by default.
const DEFAULT_DB_PATH: &str = "/var/lib/cyber-news/news.db";

/// How much recent history the page shows: the last day, newest first.
const HOURS: u64 = 24;

/// Serve the cyber-news page to a verified visitor.
pub fn page(_request: &Request) -> Response {
    render_from(&db_path())
}

/// Build the page from a specific store path, so tests can point at a temp
/// database without touching the environment.
fn render_from(path: &str) -> Response {
    let conn = match store::init_db(path) {
        Ok(conn) => conn,
        Err(_) => return internal_error(),
    };
    let items = match store::get_recent(&conn, HOURS) {
        Ok(items) => items,
        Err(_) => return internal_error(),
    };

    Response {
        status: 200,
        reason: "OK",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: renderer::render_news_page(&items).into_bytes(),
    }
}

/// Resolve the store path from the environment, falling back to production.
fn db_path() -> String {
    resolve_db_path(std::env::var("CYBER_NEWS_DB_PATH").ok())
}

/// The path resolution itself, lifted out of the env read so it is testable
/// without mutating process-global state. An unset or empty variable means
/// the production default.
fn resolve_db_path(env: Option<String>) -> String {
    env.filter(|path| !path.is_empty())
        .unwrap_or_else(|| DEFAULT_DB_PATH.to_string())
}

/// A short 500 in the site's voice; the store may be missing or locked.
fn internal_error() -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        body: b"The news store could not be opened. Try again in a few minutes.".to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Method;
    use crate::middleware::session;
    use crate::store::NewsItem;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch")
            .as_secs()
            .try_into()
            .expect("fits in i64")
    }

    fn item(title: &str, url: &str, category: &str, published: i64) -> NewsItem {
        NewsItem {
            id: 0,
            title: title.to_string(),
            url: url.to_string(),
            description: "Body text.".to_string(),
            published,
            source: "Test Source".to_string(),
            category: category.to_string(),
            fetched_at: 0,
        }
    }

    /// A store path unique to this test, in the temp dir. SQLite writes -wal
    /// and -shm siblings beside a WAL database, so removal covers all three.
    fn temp_db(tag: &str) -> PathBuf {
        let name = format!(
            "cyber-news-{tag}-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before Unix epoch")
                .as_nanos()
        );
        std::env::temp_dir().join(name)
    }

    fn remove_db(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::remove_file(Path::new(&name));
        }
    }

    /// A GET request for /news carrying a freshly minted session cookie.
    fn news_request_with_session() -> crate::http::Request {
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let cookie = session::issue_cookie().expect("cookie");
        let zts = cookie.split(';').next().unwrap().to_string();
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), zts);
        crate::http::Request {
            method: Method::Get,
            path: "/news".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    #[test]
    fn without_a_session_the_challenge_answers_not_the_page() {
        // No cookie at all: routing short-circuits at the session gate and
        // serves the PoW challenge, exactly as it does for / and /about. The
        // secret must be set so the challenge can render, mirroring the other
        // gate tests.
        unsafe { std::env::set_var("SESSION_SECRET", "0123456789abcdef0123456789abcdef") }
        let request = crate::http::Request {
            method: Method::Get,
            path: "/news".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        let routed = crate::router::handle(&request, None);
        assert_eq!(routed.session, Some(false), "/news is PoW gated");
        let body = String::from_utf8(routed.response.body).expect("utf-8");
        assert!(
            body.contains("Proving this browser is a person"),
            "the challenge page answers, not the news page"
        );
        assert!(!body.contains("cyber news"));
    }

    #[test]
    fn with_a_session_the_route_serves_the_recent_items() {
        // One env var points the handler at a temp store; this is the only
        // test in the binary that reads it, so there is no cross-test race.
        let path = temp_db("route");
        unsafe { std::env::set_var("CYBER_NEWS_DB_PATH", path.to_str().expect("utf-8")) }
        let conn = store::init_db(path.to_str().expect("utf-8")).expect("open");
        let recent_published = now() - 3600;
        store::insert_item(&conn, &item("A fresh headline", "https://example.com/1", "Cve", recent_published))
            .expect("insert recent");
        store::insert_item(
            &conn,
            &item(
                "A stale headline",
                "https://example.com/2",
                "Research",
                now() - 30 * 3600,
            ),
        )
        .expect("insert stale");
        drop(conn);

        let routed = crate::router::handle(&news_request_with_session(), None);
        let resp = &routed.response;
        assert_eq!(resp.status, 200);
        assert_eq!(routed.session, Some(true));
        assert!(
            resp.headers
                .iter()
                .any(|(n, _)| n == "Content-Security-Policy"),
            "the page gets the full header set from the router"
        );
        assert!(
            resp.headers
                .iter()
                .any(|(n, v)| n == "Content-Type" && v == "text/html; charset=utf-8")
        );
        let body = String::from_utf8(resp.body.clone()).expect("utf-8");
        assert!(body.contains("<h1 class=\"page-title\">cyber news</h1>"));
        assert!(body.contains("A fresh headline"));
        assert!(
            !body.contains("A stale headline"),
            "get_recent(24) keeps only the last day"
        );
        remove_db(&path);
    }

    #[test]
    fn render_from_builds_a_page_from_a_seeded_store() {
        let path = temp_db("render");
        let conn = store::init_db(path.to_str().expect("utf-8")).expect("open");
        store::insert_item(
            &conn,
            &item("In the window", "https://example.com/a", "Breach", now() - 1800),
        )
        .expect("insert");
        drop(conn);

        let resp = render_from(path.to_str().expect("utf-8"));
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body).expect("utf-8");
        assert!(body.contains("In the window"));
        assert!(body.contains("cyber news"));
        remove_db(&path);
    }

    #[test]
    fn render_from_answers_500_when_the_store_cannot_open() {
        // A path whose parent directory does not exist cannot be opened by
        // SQLite, so the handler must answer 500, never an empty page.
        let missing = temp_db("missing").join("no-such-dir").join("news.db");
        let resp = render_from(missing.to_str().expect("utf-8"));
        assert_eq!(resp.status, 500);
        assert_eq!(resp.reason, "Internal Server Error");
        let body = String::from_utf8(resp.body).expect("utf-8");
        assert!(body.contains("news store could not be opened"));
    }

    #[test]
    fn the_page_head_declares_the_favicon_like_every_other_page() {
        // content.rs pins the same rule for the committed pages; the news page
        // is generated, so the check lives here against the real renderer.
        let path = temp_db("favicon");
        let conn = store::init_db(path.to_str().expect("utf-8")).expect("open");
        store::insert_item(
            &conn,
            &item("Any", "https://example.com/fav", "Ot", now()),
        )
        .expect("insert");
        drop(conn);

        let body = String::from_utf8(render_from(path.to_str().expect("utf-8")).body).expect("utf-8");
        assert!(
            body.contains(r#"<link rel="icon" href="/static/favicon.ico">"#),
            "the generated page declares the favicon"
        );
        remove_db(&path);
    }

    #[test]
    fn resolve_db_path_uses_the_env_then_falls_back() {
        assert_eq!(
            resolve_db_path(None),
            "/var/lib/cyber-news/news.db",
            "no env var means the production default"
        );
        assert_eq!(
            resolve_db_path(Some(String::new())),
            "/var/lib/cyber-news/news.db",
            "an empty env var is treated as unset"
        );
        assert_eq!(
            resolve_db_path(Some("/tmp/cyber-news/test.db".to_string())),
            "/tmp/cyber-news/test.db"
        );
    }
}
