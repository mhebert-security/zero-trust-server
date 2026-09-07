//! The fixed catalog of cyber-news sources and their categories.
//!
//! This module is the fetcher's only notion of where news comes from. There
//! is no configuration file and no database of feeds: the list below is the
//! entire egress surface, which is the point. A zero-trust fetcher that reads
//! its destinations from an operator-editable file would let a compromise of
//! that file steer it anywhere. Here a code change is the only way to add a
//! source, and it is reviewable in the same diff as the allowlist that gates
//! it (fetch.rs). The canonical `Category::as_str` token stored per item is
//! also the value renderer.rs maps back to a badge, so the vocabulary of the
//! store and the page is pinned to this file.

/// The five buckets every item is filed under. Names are deliberately
/// lowercase-safe on disk via `as_str` while reading as code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Known exploited vulnerabilities and CVE disclosures.
    Cve,
    /// Incidents, disclosure notices, and attacker activity.
    Breach,
    /// Threat intelligence, campaigns, and adversary behavior.
    ThreatIntel,
    /// Operational technology and industrial control system advisories.
    Ot,
    /// Analysis, research, and commentary.
    Research,
}

impl Category {
    /// All categories in the order the page tabs should show them.
    pub const ALL: [Category; 5] = [
        Category::Cve,
        Category::Breach,
        Category::ThreatIntel,
        Category::Ot,
        Category::Research,
    ];

    /// The canonical token stored in SQLite and understood by renderer.rs.
    /// Changing one of these strings silently orphans existing rows and
    /// breaks the badge mapping, so the unit tests below pin them.
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Cve => "Cve",
            Category::Breach => "Breach",
            Category::ThreatIntel => "ThreatIntel",
            Category::Ot => "Ot",
            Category::Research => "Research",
        }
    }

    /// The human label shown on the page tab and on each item's badge.
    pub const fn label(self) -> &'static str {
        match self {
            Category::Cve => "CVE",
            Category::Breach => "Breach",
            Category::ThreatIntel => "Threat Intel",
            Category::Ot => "OT",
            Category::Research => "Research",
        }
    }
}

/// One news source: where to fetch it, what to call it, and its bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Feed {
    pub url: &'static str,
    pub source_name: &'static str,
    pub category: Category,
}

/// The sources this aggregator follows. Ten entries, all HTTPS. The fetcher
/// walks this list in order, never follows a redirect, and connects only to
/// the allowlisted host that the URL itself names (fetch.rs enforces that).
pub const FEEDS: [Feed; 10] = [
    // NVD retired its RSS exports; the 2.0 REST search API is the current
    // public read path. It answers JSON, which fetch.rs reads with a narrow
    // walker rather than the XML parser. Twenty results per pass keeps the
    // response small and the list of CVEs current.
    Feed {
        url: "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20",
        source_name: "NVD",
        category: Category::Cve,
    },
    Feed {
        url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        source_name: "CISA KEV",
        category: Category::Cve,
    },
    Feed {
        url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        source_name: "CISA ICS",
        category: Category::Ot,
    },
    Feed {
        url: "https://www.bleepingcomputer.com/feed/",
        source_name: "BleepingComputer",
        category: Category::Breach,
    },
    Feed {
        url: "https://krebsonsecurity.com/feed/",
        source_name: "Krebs on Security",
        category: Category::Breach,
    },
    Feed {
        url: "https://feeds.feedburner.com/TheHackersNews",
        source_name: "The Hacker News",
        category: Category::ThreatIntel,
    },
    Feed {
        url: "https://www.darkreading.com/rss.xml",
        source_name: "Dark Reading",
        category: Category::ThreatIntel,
    },
    Feed {
        url: "https://isc.sans.edu/rssfeed.xml",
        source_name: "SANS ISC",
        category: Category::Research,
    },
    Feed {
        url: "https://www.schneier.com/feed/atom/",
        source_name: "Schneier on Security",
        category: Category::Research,
    },
    Feed {
        url: "https://www.reddit.com/r/netsec/.rss",
        source_name: "r/netsec",
        category: Category::Research,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_category_has_a_canonical_token_and_a_label() {
        // The canonical tokens are a store and page contract; the labels are
        // what a visitor reads. Both must be present, distinct per category,
        // and non-empty for every category.
        let mut tokens = HashSet::new();
        let mut labels = HashSet::new();
        for category in Category::ALL {
            let token = category.as_str();
            let label = category.label();
            assert!(!token.is_empty());
            assert!(!label.is_empty());
            assert!(tokens.insert(token), "duplicate token: {token}");
            assert!(labels.insert(label), "duplicate label: {label}");
        }
    }

    #[test]
    fn the_tokens_are_the_ones_the_page_and_store_expect() {
        // Pin the exact strings so a rename that would strand existing rows
        // or break the renderer's badge mapping fails this test instead of
        // silently corrupting the store.
        let tokens: Vec<&str> = Category::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            tokens,
            vec!["Cve", "Breach", "ThreatIntel", "Ot", "Research"]
        );
    }

    #[test]
    fn feed_list_is_complete_distinct_and_https() {
        // The source list is the whole egress surface: ten entries, every
        // url distinct and https, every name distinct.
        assert_eq!(FEEDS.len(), 10);
        let mut urls = HashSet::new();
        let mut names = HashSet::new();
        for feed in FEEDS {
            assert!(
                feed.url.starts_with("https://"),
                "every feed is https: {}",
                feed.url
            );
            assert!(urls.insert(feed.url), "duplicate feed url: {}", feed.url);
            assert!(
                names.insert(feed.source_name),
                "duplicate source name: {}",
                feed.source_name
            );
        }
    }

    #[test]
    fn feed_list_covers_every_category() {
        let used: HashSet<Category> = FEEDS.iter().map(|f| f.category).collect();
        for category in Category::ALL {
            assert!(used.contains(&category), "no feed in {category:?}");
        }
    }
}
