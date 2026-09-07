//! SQLite persistence behind the /news route and the feed fetcher.
//!
//! The two processes never talk to each other. The fetcher (a standalone
//! binary on a six-hour systemd timer) opens this store and writes items; the
//! zero-trust server opens the same file and reads the last 24 hours when a
//! verified visitor asks for /news. The schema is the whole contract between
//! them, so it lives here, in one place. This module makes no network calls.
//!
//! rusqlite is a deliberate exception to the standard-library rule, on the
//! same grounds as rustls: SQLite is an embedded, in-process store that needs
//! no server, and a transactional relational store is not tractable to hand
//! roll the way HTTP parsing and routing are. The bundled feature compiles
//! the SQLite amalgamation at build time, so the binary links with no system
//! SQLite development package.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// One news item as it is stored and read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsItem {
    pub id: i64,
    pub title: String,
    pub url: String,
    pub description: String,
    /// Publication time as a Unix timestamp in seconds. i64, not u64, because
    /// that is SQLite's INTEGER and rusqlite's native binding type; the value
    /// never approaches the signed limit.
    pub published: i64,
    /// The feed's display name (the publication, not the reader).
    pub source: String,
    /// Canonical category name; see `feeds::Category::as_str`.
    pub category: String,
    /// When this row was inserted, as a Unix timestamp in seconds.
    pub fetched_at: i64,
}

/// Open the store, creating the file if it does not exist, and ensure the
/// schema is present. Idempotent: safe to call on every process start and on
/// every /news request.
///
/// The parent directory must already exist; SQLite will not create it. The
/// fetcher's install path does, and callers that want a file elsewhere
/// create the directory first.
pub fn init_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;

    // Busy timeout first, before any statement: the fetcher may be mid-write
    // while the server opens the same file, and SQLite answers a lock it
    // cannot take by waiting up to this long instead of failing instantly.
    conn.busy_timeout(Duration::from_secs(5))?;

    // Prefer WAL so a reader never blocks the writer and vice versa. If the
    // underlying filesystem rejects it the connection keeps the default
    // journal and the busy timeout still arbitrates contention, so a WAL
    // refusal is not worth failing the whole open over.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS items (
             id          INTEGER PRIMARY KEY AUTOINCREMENT,
             title       TEXT    NOT NULL,
             url         TEXT    NOT NULL UNIQUE,
             description TEXT    NOT NULL DEFAULT '',
             published   INTEGER NOT NULL,
             source      TEXT    NOT NULL,
             category    TEXT    NOT NULL,
             fetched_at  INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_items_published
             ON items (published);",
    )?;

    Ok(conn)
}

/// Insert one item, ignoring a duplicate. A duplicate is any row that already
/// holds the same `url`, which is what makes re-fetching a feed idempotent:
/// the six-hour timer can read the same item many times and the table never
/// gains a second copy. Returns the number of rows written, 0 for a
/// duplicate. `id` and `fetched_at` on the input are ignored; the row gets
/// its own id and the current time.
pub fn insert_item(conn: &Connection, item: &NewsItem) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT OR IGNORE INTO items
             (title, url, description, published, source, category, fetched_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            item.title,
            item.url,
            item.description,
            item.published,
            item.source,
            item.category,
            current_unix_time(),
        ],
    )
}

/// Items published within the last `hours`, newest first. Rows newer than the
/// top of the query are deliberately not clipped: a feed whose clock runs a
/// little ahead of the server still shows its items once the timestamps pass.
pub fn get_recent(conn: &Connection, hours: u64) -> rusqlite::Result<Vec<NewsItem>> {
    let cutoff = recent_cutoff(hours);
    let mut stmt = conn.prepare(
        "SELECT id, title, url, description, published, source, category, fetched_at
         FROM items
         WHERE published >= ?1
         ORDER BY published DESC, id DESC",
    )?;
    let rows = stmt.query_map(params![cutoff], row_to_item)?;
    rows.collect()
}

/// Delete every item published more than `days` ago. Returns how many rows
/// went. Runs after each fetch pass so the store holds a rolling window, not
/// the full history of every feed.
pub fn cleanup(conn: &Connection, days: u64) -> rusqlite::Result<usize> {
    let cutoff = current_unix_time().saturating_sub(period_secs(days, 86400));
    conn.execute("DELETE FROM items WHERE published < ?1", params![cutoff])
}

/// Map one result row onto a [`NewsItem`]. Shared by every read so column
/// order has exactly one home.
fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<NewsItem> {
    Ok(NewsItem {
        id: row.get(0)?,
        title: row.get(1)?,
        url: row.get(2)?,
        description: row.get(3)?,
        published: row.get(4)?,
        source: row.get(5)?,
        category: row.get(6)?,
        fetched_at: row.get(7)?,
    })
}

/// Current Unix timestamp in seconds.
fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
        .try_into()
        .expect("Unix time fits in i64 until the year 2262")
}

/// The oldest `published` value `get_recent` still returns, given a window
/// in hours. Converts without an `as` cast: a window too large to express in
/// seconds becomes the full i64 range, so an absurdly large window degrades
/// to "everything", never to a wrap.
fn recent_cutoff(hours: u64) -> i64 {
    current_unix_time().saturating_sub(period_secs(hours, 3600))
}

/// A count of units converted to seconds, clamped to the i64 range so the
/// caller's saturating arithmetic stays well-defined.
fn period_secs(units: u64, secs_per_unit: u64) -> i64 {
    i64::try_from(units.saturating_mul(secs_per_unit)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway item with everything but the id and fetched_at set. The
    /// caller overrides title, url, and published where a test needs to.
    fn item(title: &str, url: &str, published: i64) -> NewsItem {
        NewsItem {
            id: 0,
            title: title.to_string(),
            url: url.to_string(),
            description: String::new(),
            published,
            source: "Test Source".to_string(),
            category: "Research".to_string(),
            fetched_at: 0,
        }
    }

    /// A store path unique to this test, in the temp dir. SQLite writes
    /// -wal and -shm siblings beside a WAL database, so removal is best
    /// effort over all three names rather than exact.
    fn temp_db(tag: &str) -> std::path::PathBuf {
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

    fn remove_db(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::remove_file(std::path::Path::new(&name));
        }
    }

    #[test]
    fn init_db_creates_schema_and_insert_read_round_trips() {
        let path = temp_db("roundtrip");
        let conn = init_db(path.to_str().expect("utf-8 temp path")).expect("open");
        let published = current_unix_time() - 100;
        let written =
            insert_item(&conn, &item("Round trip", "https://example.com/1", published))
                .expect("insert");
        assert_eq!(written, 1);

        let recent = get_recent(&conn, 24).expect("read");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].title, "Round trip");
        assert_eq!(recent[0].url, "https://example.com/1");
        assert_eq!(recent[0].published, published);
        assert_eq!(recent[0].source, "Test Source");
        assert_eq!(recent[0].category, "Research");
        assert!(recent[0].fetched_at >= published, "fetched_at is set by insert");
        drop(conn);
        remove_db(&path);
    }

    #[test]
    fn reinserting_the_same_url_is_ignored() {
        let path = temp_db("dedupe");
        let conn = init_db(path.to_str().expect("utf-8 temp path")).expect("open");
        insert_item(&conn, &item("First", "https://example.com/same", current_unix_time()))
            .expect("first insert");
        let second =
            insert_item(&conn, &item("Second", "https://example.com/same", current_unix_time()))
                .expect("second insert");
        assert_eq!(second, 0, "a duplicate url must not write a row");
        assert_eq!(get_recent(&conn, 24).expect("read").len(), 1);
        drop(conn);
        remove_db(&path);
    }

    #[test]
    fn get_recent_returns_only_the_window() {
        let path = temp_db("window");
        let conn = init_db(path.to_str().expect("utf-8 temp path")).expect("open");
        let now = current_unix_time();
        insert_item(&conn, &item("Fresh", "https://example.com/fresh", now - 3600))
            .expect("insert fresh");
        insert_item(
            &conn,
            &item("Stale", "https://example.com/stale", now - 25 * 3600),
        )
        .expect("insert stale");

        let recent = get_recent(&conn, 24).expect("read");
        assert_eq!(recent.len(), 1, "only the item inside 24 hours returns");
        assert_eq!(recent[0].title, "Fresh");
        drop(conn);
        remove_db(&path);
    }

    #[test]
    fn cleanup_removes_only_rows_older_than_the_keep_window() {
        let path = temp_db("cleanup");
        let conn = init_db(path.to_str().expect("utf-8 temp path")).expect("open");
        let now = current_unix_time();
        insert_item(&conn, &item("Recent", "https://example.com/recent", now)).expect("insert");
        insert_item(
            &conn,
            &item("Ancient", "https://example.com/ancient", now - 8 * 86400),
        )
        .expect("insert");

        let removed = cleanup(&conn, 7).expect("cleanup");
        assert_eq!(removed, 1, "exactly the item older than 7 days goes");
        let remaining = get_recent(&conn, 24 * 30).expect("read");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].title, "Recent");
        drop(conn);
        remove_db(&path);
    }
}
