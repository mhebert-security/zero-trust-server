//! The standalone news fetcher.
//!
//! A systemd timer (deploy/cyber-news-fetcher.timer) runs this binary every
//! six hours. It walks the fixed catalog in feeds.rs, fetches and parses each
//! feed through fetch.rs, and writes every item to the SQLite store that
//! store.rs owns. The zero-trust server never runs this code; it reads the
//! same database when a verified visitor asks for /news. The store file is
//! the whole interface between the two processes.
//!
//! The database path resolves from the first command-line argument, then the
//! CYBER_NEWS_DB_PATH environment variable, then the production default. A
//! feed that fails is logged and skipped, never fatal: ten feeds, each
//! independent, and the timer will come around again in six hours.

use std::env;
use std::fs;
use std::path::Path;
use std::process;

// store.rs and feeds.rs are shared with the zero-trust server binary, which
// owns the halves this fetcher never touches: the read path (get_recent) and
// the page-facing vocabulary (Category::ALL and its labels) serve the /news
// route, not the write path. The allow is on the include, not the shared
// source, so each binary only silences the dead code that belongs to the
// other.
#[path = "../store.rs"]
#[allow(dead_code)] // get_recent and helpers serve the server's /news read.
mod store;
#[path = "../feeds.rs"]
#[allow(dead_code)] // ALL and label render the /news tabs in the server.
mod feeds;
#[path = "../fetch.rs"]
mod fetch;

/// The production store location, used when neither an argument nor the
/// environment names one.
const DEFAULT_DB_PATH: &str = "/var/lib/cyber-news/news.db";

/// How many days of history the store keeps after each pass.
const KEEP_DAYS: u64 = 7;

fn main() {
    let db_path = resolve_db_path();

    // SQLite will not create the parent directory. The service install
    // creates the production one; creating it here keeps manual and test
    // runs (against a temp path) working without extra setup.
    if let Some(parent) = Path::new(&db_path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("news: cannot create {}: {e}", parent.display());
        process::exit(1);
    }

    let conn = match store::init_db(&db_path) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("news: cannot open store at {db_path}: {e}");
            process::exit(1);
        }
    };

    let mut feeds_fetched = 0usize;
    let mut items_inserted = 0usize;
    for feed in feeds::FEEDS {
        match fetch::fetch_feed(&feed) {
            Ok(items) => {
                feeds_fetched += 1;
                let mut new_in_feed = 0usize;
                for item in &items {
                    match store::insert_item(&conn, item) {
                        Ok(written) => new_in_feed += written,
                        Err(e) => {
                            eprintln!(
                                "news: insert into store failed for {}: {e}",
                                feed.source_name
                            );
                        }
                    }
                }
                items_inserted += new_in_feed;
                println!(
                    "news: {}: {} item(s) parsed, {} new",
                    feed.source_name,
                    items.len(),
                    new_in_feed
                );
            }
            Err(e) => {
                eprintln!("news: {} ({}): {e}; skipped", feed.source_name, feed.url);
            }
        }
    }

    match store::cleanup(&conn, KEEP_DAYS) {
        Ok(removed) => println!("news: cleanup removed {removed} item(s) older than {KEEP_DAYS} days"),
        Err(e) => eprintln!("news: cleanup failed: {e}"),
    }

    println!(
        "news: done: {feeds_fetched}/{} feed(s) fetched, {items_inserted} new item(s) in {db_path}",
        feeds::FEEDS.len()
    );
}

/// Resolve the store path from the argument, the environment, or the default.
fn resolve_db_path() -> String {
    if let Some(path) = env::args_os().nth(1) {
        return path.to_string_lossy().into_owned();
    }
    if let Ok(path) = env::var("CYBER_NEWS_DB_PATH")
        && !path.is_empty()
    {
        return path;
    }
    DEFAULT_DB_PATH.to_string()
}
