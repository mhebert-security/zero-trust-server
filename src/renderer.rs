//! HTML for the /news page, built as one string with no template engine.
//!
//! The store hands this renderer the items it read back (handlers/news.rs
//! calls get_recent and passes the rows over). The category tabs come from
//! feeds.rs, the same vocabulary the fetcher writes and store.rs persists, so
//! the page can never label an item with a bucket the catalog does not know.
//!
//! The page is a normal `.page` document like the other gated pages: it links
//! the shared stylesheet and the favicon, and its feed-specific styles live in
//! static/news.css. The CSP allows style-src 'self' only, so nothing here is
//! styled inline and there is no inline <style> block. Tab filtering is pure
//! CSS, no JavaScript: each tab label checks a hidden radio input, and a
//! :has() selector hides every item whose category class does not match the
//! checked radio.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::feeds::Category;
use crate::markdown::{escape_attr, escape_text};
use crate::store::NewsItem;

/// Render the complete /news page for the given items, newest first.
pub fn render_news_page(items: &[NewsItem]) -> String {
    render_news_page_at(items, unix_now())
}

/// The page at a fixed moment, so tests can pin the clock.
fn render_news_page_at(items: &[NewsItem], now: i64) -> String {
    // The header stamps when the store was last written, which is the newest
    // fetched_at among the rows. An empty page falls back to now.
    let updated = items.iter().map(|item| item.fetched_at).max().unwrap_or(now);
    let updated_iso = iso8601_utc(updated);
    let updated_ago = time_ago(updated, now);

    let mut body = String::new();
    body.push_str("<h1 class=\"page-title\">cyber news</h1>\n");
    body.push_str(&format!(
        "<p class=\"news-updated\">last updated \
         <time datetime=\"{updated_iso}\">{updated_ago}</time></p>\n"
    ));

    if items.is_empty() {
        body.push_str(
            "<p class=\"news-empty\">No items in the last 24 hours. \
             The six-hour fetcher will be back around to fill this page.</p>\n",
        );
    } else {
        body.push_str(&tabs_markup());
        body.push_str("<ol class=\"news\">\n");
        for item in items {
            body.push_str(&item_markup(item, now));
        }
        body.push_str("</ol>\n");
    }

    page_shell(&body)
}

/// The tab bar and its hidden radio controls.
///
/// The radios are inputs of one group (`news-filter`), "All" checked by
/// default. Each label is bound to one radio with `for`; static/news.css keys
/// off the checked id to light the label and filter the list below.
fn tabs_markup() -> String {
    let mut out = String::from(
        "<div class=\"tabs\" role=\"group\" aria-label=\"Filter news by category\">\n",
    );
    out.push_str(&radio_markup("tab-all", true));
    for category in Category::ALL {
        out.push_str(&radio_markup(&tab_id(category.as_str()), false));
    }
    out.push_str("<label class=\"tab\" for=\"tab-all\">All</label>\n");
    for category in Category::ALL {
        out.push_str(&format!(
            "<label class=\"tab\" for=\"{}\">{}</label>\n",
            tab_id(category.as_str()),
            category.label()
        ));
    }
    out.push_str("</div>\n");
    out
}

/// One hidden radio. The visible control is the label bound to it.
fn radio_markup(id: &str, checked: bool) -> String {
    let selected = if checked { " checked" } else { "" };
    format!(
        "<input type=\"radio\" class=\"news-tab\" name=\"news-filter\" id=\"{id}\"{selected}>\n"
    )
}

/// One feed item card.
fn item_markup(item: &NewsItem, now: i64) -> String {
    // A headline with nothing to show degrades to its own URL rather than a
    // blank line, so the list never carries an unreadable entry.
    let headline = if item.title.trim().is_empty() {
        item.url.clone()
    } else {
        item.title.clone()
    };
    let class = match known_category(&item.category) {
        Some(category) => format!(" cat-{}", category.as_str().to_ascii_lowercase()),
        None => String::new(),
    };
    let label = known_category(&item.category)
        .map(|c| c.label().to_string())
        .unwrap_or_else(|| item.category.clone());
    let published_iso = iso8601_utc(item.published);
    let published_ago = time_ago(item.published, now);

    let mut card = String::new();
    card.push_str(&format!(
        "<li class=\"news-item{class}\">\n\
         <div class=\"news-row\">\n\
         <a class=\"news-title\" href=\"{url}\" rel=\"noopener noreferrer\">{title}</a>\n\
         <time class=\"news-time\" datetime=\"{published_iso}\">{published_ago}</time>\n\
         </div>\n",
        class = class,
        url = escape_attr(&item.url),
        title = escape_text(&headline),
        published_iso = published_iso,
        published_ago = published_ago,
    ));
    if !item.description.is_empty() {
        card.push_str(&format!(
            "<p class=\"news-desc\">{}</p>\n",
            escape_text(&item.description)
        ));
    }
    card.push_str(&format!(
        "<div class=\"news-meta\">\n\
         <span class=\"news-source\">{source}</span>\n\
         <span class=\"badge\">{label}</span>\n\
         </div>\n\
         </li>\n",
        source = escape_text(&item.source),
        label = escape_text(&label),
    ));
    card
}

/// Wrap the feed body in the shared interior-page shell, mirroring writeup.rs
/// and the committed static pages so /news reads as part of the site.
fn page_shell(body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matthew Hebert · cyber news</title>
    <meta name="description" content="Cyber news and vulnerability intel, gathered from ten sources every six hours.">
    <meta property="og:title" content="Matthew Hebert · cyber news">
    <meta property="og:description" content="Cyber news and vulnerability intel, gathered from ten sources every six hours.">
    <meta property="og:url" content="https://mhebert.dev/news">
    <link rel="icon" href="/static/favicon.ico">
    <link rel="stylesheet" href="/static/style.css">
    <link rel="stylesheet" href="/static/news.css">
</head>
<body class="page">
    <header class="page-head">
        <a class="wordmark" href="/">mhebert<span class="dot">.</span>dev</a>
        <nav class="nav" aria-label="Site">
            <a href="/">index</a>
            <a href="/projects">projects</a>
            <a href="/about">about</a>
            <a href="/writing">writing</a>
            <a href="/news" aria-current="page">news</a>
            <a href="/contact">contact</a>
        </nav>
    </header>

    <main>
{body}    </main>

    <footer class="page-footer">
        served by <code>zero-trust-server</code> · HTTP/1.1 from raw sockets · rustls TLS 1.3 · a proof of work gate · <a href="/transparency">what this server records</a>
    </footer>
</body>
</html>
"#,
        body = body
    )
}

/// The radio id and item class both derive from the canonical token, so the
/// DOM the renderer emits always matches the selectors in static/news.css.
fn tab_id(token: &str) -> String {
    format!("tab-{}", token.to_ascii_lowercase())
}

/// The category the token names, if the catalog still has that bucket.
fn known_category(token: &str) -> Option<Category> {
    Category::ALL.into_iter().find(|c| c.as_str() == token)
}

/// "5s ago", "3m ago", "2h ago", "4d ago", "3w ago". Compact because it is a
/// caption under a headline, and it always ends in "ago" so it reads the same
/// way at every granularity.
fn time_ago(timestamp: i64, now: i64) -> String {
    let delta = now.saturating_sub(timestamp).max(0);
    match delta {
        0..=59 => format!("{delta}s ago"),
        60..=3599 => format!("{}m ago", delta / 60),
        3600..=86_399 => format!("{}h ago", delta / 3600),
        86_400..=604_799 => format!("{}d ago", delta / 86_400),
        _ => format!("{}w ago", delta / 604_800),
    }
}

/// Current Unix timestamp in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_secs()
        .try_into()
        .expect("Unix time fits in i64 until the year 2262")
}

/// A timestamp as RFC 3339 UTC, e.g. `2026-09-07T12:00:00Z`, for <time>
/// datetime attributes. Uses the inverse of the Hinnant days_from_civil
/// conversion, the same civil calendar arithmetic the fetcher already uses.
fn iso8601_utc(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    let seconds_of_day = timestamp.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3600,
        seconds_of_day % 3600 / 60,
        seconds_of_day % 60
    )
}

/// Days since 1970-01-01 to a civil (year, month, day). Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NewsItem;

    /// A fixed moment: 2024-01-01T00:00:00Z.
    const NOW: i64 = 1_704_067_200;

    fn item(title: &str, url: &str, category: &str, published: i64, fetched_at: i64) -> NewsItem {
        NewsItem {
            id: 0,
            title: title.to_string(),
            url: url.to_string(),
            description: "The body of the item.".to_string(),
            published,
            source: "Test Source".to_string(),
            category: category.to_string(),
            fetched_at,
        }
    }

    fn sample_items() -> Vec<NewsItem> {
        vec![
            item(
                "A CVE writeup",
                "https://example.com/cve",
                "Cve",
                NOW - 90,
                NOW - 60,
            ),
            item(
                "A breach notice",
                "https://example.com/breach",
                "Breach",
                NOW - 3600,
                NOW - 120,
            ),
        ]
    }

    #[test]
    fn page_contains_shell_chrome_and_no_executable_markup() {
        let html = render_news_page_at(&sample_items(), NOW);

        // The page is one of the gated interior pages: favicon, both
        // stylesheets, the wordmark, the shared footer, and a current nav item.
        for needle in [
            "<title>Matthew Hebert · cyber news</title>",
            r#"<link rel="icon" href="/static/favicon.ico">"#,
            r#"<link rel="stylesheet" href="/static/style.css">"#,
            r#"<link rel="stylesheet" href="/static/news.css">"#,
            r#"<a class="wordmark" href="/">mhebert<span class="dot">.</span>dev</a>"#,
            r#"<a href="/news" aria-current="page">news</a>"#,
            r#"served by <code>zero-trust-server</code>"#,
            "<h1 class=\"page-title\">cyber news</h1>",
            "<ol class=\"news\">",
        ] {
            assert!(html.contains(needle), "missing: {needle}");
        }

        // The CSP forbids inline styles and the page ships no script, so
        // neither may appear anywhere in the emitted document.
        assert!(!html.contains("<script"));
        assert!(!html.contains("<style"));
        assert!(!html.contains("style="));
        assert!(!html.contains("javascript:"));
    }

    #[test]
    fn every_catalog_category_gets_a_tab_and_the_dom_matches_the_stylesheet() {
        let html = render_news_page_at(&sample_items(), NOW);
        let css = include_str!("../static/news.css");

        // All, then the five categories, in the same order as the tabs.
        let mut tokens = vec!["All"];
        for category in Category::ALL {
            tokens.push(category.label());
        }
        for label in &tokens {
            assert!(html.contains(label), "tab label missing: {label}");
        }

        // The DOM ids the renderer emits and the selectors the stylesheet
        // writes must agree, or a tab would filter nothing.
        for category in Category::ALL {
            let id = format!("tab-{}", category.as_str().to_ascii_lowercase());
            let class = format!(".cat-{}", category.as_str().to_ascii_lowercase());
            assert!(
                html.contains(&format!("id=\"{id}\"")),
                "radio id missing: {id}"
            );
            assert!(
                html.contains(&format!("for=\"{id}\"")),
                "label target missing: {id}"
            );
            assert!(css.contains(&class), "stylesheet lacks filter: {class}");
        }
        assert!(html.contains("id=\"tab-all\" checked"), "All is the default tab");
        assert!(css.contains(".cat-cve"), "stylesheet covers every category");
    }

    #[test]
    fn items_render_linked_headline_meta_and_relative_time() {
        let html = render_news_page_at(&sample_items(), NOW);

        assert!(html.contains("A CVE writeup"));
        assert!(
            html.contains(r#"<a class="news-title" href="https://example.com/cve" rel="noopener noreferrer">A CVE writeup</a>"#)
        );
        assert!(html.contains("<span class=\"news-source\">Test Source</span>"));
        assert!(html.contains("<span class=\"badge\">CVE</span>"));
        assert!(html.contains("<span class=\"badge\">Breach</span>"));
        assert!(html.contains(">1m ago</time>"), "90s rounds to 1m ago");
        assert!(html.contains(">1h ago</time>"), "3600s rounds to 1h ago");
        assert!(
            html.contains("<li class=\"news-item cat-cve\">"),
            "item carries the class its tab filters on"
        );
        assert!(
            html.contains("<li class=\"news-item cat-breach\">"),
            "second item carries its category class"
        );
    }

    #[test]
    fn untrusted_text_is_escaped_before_it_reaches_the_page() {
        let hostile = item(
            "Sneaky & <script>alert(1)</script> headline",
            "https://example.com/?q=\" onmouseover=\"x",
            "Research",
            NOW,
            NOW,
        );
        let html = render_news_page_at(&[hostile], NOW);

        assert!(html.contains("Sneaky &amp; &lt;script&gt;alert(1)&lt;/script&gt; headline"));
        assert!(!html.contains("<script>alert"));
        assert!(
            html.contains("https://example.com/?q=&quot; onmouseover=&quot;x"),
            "attribute context escapes quotes"
        );
        // Escaping neutralizes the quote that would have opened a second
        // attribute; the word may remain as inert text, the quote must not.
        assert!(!html.contains("\" onmouseover=\""));
        assert!(!html.contains("href=\"https://example.com/?q=\" onmouseover="));
    }

    #[test]
    fn a_category_the_catalog_does_not_know_falls_back_to_its_token() {
        let stray = item(
            "Orphaned row",
            "https://example.com/orphan",
            "SomeOldBucket",
            NOW,
            NOW,
        );
        let html = render_news_page_at(&[stray], NOW);

        assert!(html.contains("<span class=\"badge\">SomeOldBucket</span>"));
        assert!(
            html.contains("<li class=\"news-item\">"),
            "an unknown category gets no filter class, so it shows only under All"
        );
    }

    #[test]
    fn an_empty_page_still_stands_up() {
        let html = render_news_page_at(&[], NOW);
        assert!(html.contains("No items in the last 24 hours."));
        assert!(!html.contains("class=\"news-item\""));

        // The production entry point uses the live clock but must never panic
        // on an empty read.
        let live = render_news_page(&[]);
        assert!(live.contains("cyber news"));
    }

    #[test]
    fn the_updated_stamp_comes_from_the_newest_fetched_at() {
        let html = render_news_page_at(&sample_items(), NOW);
        // The first item carries fetched_at NOW - 60, the newest in the set.
        assert!(html.contains(">1m ago</time>"), "updated reads 1m ago");
        assert!(
            html.contains("datetime=\"2023-12-31T23:59:00Z\""),
            "updated datetime is RFC 3339 UTC"
        );
    }

    #[test]
    fn time_ago_uses_compact_units() {
        assert_eq!(time_ago(NOW, NOW), "0s ago");
        assert_eq!(time_ago(NOW - 45, NOW), "45s ago");
        assert_eq!(time_ago(NOW - 600, NOW), "10m ago");
        assert_eq!(time_ago(NOW - 7200, NOW), "2h ago");
        assert_eq!(time_ago(NOW - 200_000, NOW), "2d ago");
        assert_eq!(time_ago(NOW - 4_000_000, NOW), "6w ago");
        // A timestamp from the future never reads negative.
        assert_eq!(time_ago(NOW + 60, NOW), "0s ago");
    }

    #[test]
    fn iso8601_utc_formats_known_epochs() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_704_067_200), "2024-01-01T00:00:00Z");
        // A leap year boundary stays correct through the civil conversion.
        assert_eq!(iso8601_utc(1_583_020_800), "2020-03-01T00:00:00Z");
    }
}
