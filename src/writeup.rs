//! Project writeups: Markdown files read at startup, served as HTML pages.
//!
//! The four project writeups live as plain Markdown under `content/` (the
//! directory is configurable via `WRITEUPS_DIR` and defaults to `content`,
//! relative to the working directory). `main.rs` calls [`init`] once at
//! startup; from then on the store is immutable and the handler at
//! `/projects/<slug>` answers from it. A writeup that cannot be read is a
//! startup error, not a silent 404, so a deployment that forgets the
//! Markdown fails loudly instead of shipping a projects page with dead
//! links.
//!
//! Each file starts with an H1 that names the page and becomes the `<title>`
//! and `.page-title`; the first paragraph after it becomes the meta and
//! Open Graph description, so it must be plain prose with no inline markup.
//! The rest of the file is rendered by [`crate::markdown`] into a fragment
//! and wrapped in the shared page shell (nav, footer, security posture),
//! which is built here so the Markdown stays content only.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::markdown;

/// A loaded, rendered project writeup.
#[derive(Debug)]
pub struct Writeup {
    /// The slug that routes to this page, from the file name without ".md".
    pub slug: String,
    /// The page name from the leading H1 (also shown as `.page-title`).
    #[allow(dead_code)] // metadata read by tests; the page itself is the html
    pub title: String,
    /// Plain-text description for the meta and Open Graph tags.
    #[allow(dead_code)] // metadata read by tests; embedded in the html
    pub description: String,
    /// The complete HTML document, ready to serve.
    pub html: String,
}

/// The process-wide store, populated once by [`init`].
static WRITEUPS: OnceLock<Vec<Writeup>> = OnceLock::new();

/// Load every `.md` file under `dir` and make the store live.
/// Fails (with the io error) if the directory cannot be read; callers treat
/// that as fatal. Returns the number of writeups loaded.
pub fn init(dir: &Path) -> Result<usize, String> {
    let pages = load(dir)?;
    let count = pages.len();
    WRITEUPS
        .set(pages)
        .map_err(|_| "writeup store already initialized".to_string())?;
    Ok(count)
}

/// Read and render every `.md` file under `dir`, sorted by slug. Pure so the
/// tests can drive it with a scratch directory.
pub fn load(dir: &Path) -> Result<Vec<Writeup>, String> {
    let read_dir = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

    let mut pages: Vec<Writeup> = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("error reading {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(slug) = name.strip_suffix(".md") else {
            continue;
        };
        if slug.is_empty() {
            continue;
        }
        let source =
            fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        pages.push(build_page(slug, &source));
    }

    pages.sort_by(|a, b| a.slug.cmp(&b.slug));
    Ok(pages)
}

/// The live writeup for `slug`, if the store holds one.
pub fn get(slug: &str) -> Option<&'static Writeup> {
    WRITEUPS
        .get()?
        .iter()
        .find(|page| page.slug == slug)
}

/// Build a [`Writeup`] from Markdown source, extracting the leading H1 as
/// the page name and the first paragraph as the description.
fn build_page(slug: &str, source: &str) -> Writeup {
    let lines: Vec<&str> = source.lines().collect();

    // The page name is the first non-blank line when it is an H1 ("# name").
    // Anything else falls back to the slug so a content file without a
    // leading heading still names itself.
    let mut body_start = 0;
    let mut title = slug.to_string();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(name) = h1_text(line) {
            title = name.trim().to_string();
            body_start = idx + 1;
        } else {
            body_start = idx;
        }
        break;
    }

    // The description is the first paragraph of the body, kept as plain
    // text. It must be prose without inline markup to read cleanly in a
    // <meta> tag.
    let mut lead: Vec<&str> = Vec::new();
    for line in &lines[body_start..] {
        let text = line.trim();
        if text.is_empty() {
            if lead.is_empty() {
                continue; // blanks between the title and the lead are padding
            }
            break;
        }
        lead.push(text);
    }
    let raw = plain_text(&lead.join(" "));
    let description = if raw.is_empty() {
        "A project writeup on mhebert.dev.".to_string()
    } else {
        raw.chars().take(160).collect()
    };

    let body = lines[body_start..].join("\n");
    let body_html = markdown::render(&body);
    let html = page_shell(slug, &title, &description, &body_html);

    Writeup {
        slug: slug.to_string(),
        title,
        description,
        html,
    }
}

/// The name from a leading H1 line ("# name"), if the line is exactly that.
fn h1_text(line: &str) -> Option<&str> {
    let t = line.trim();
    let rest = t.strip_prefix('#')?;
    if rest.starts_with('#') {
        return None; // "## heading" is not the page name
    }
    let name = rest.trim();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Reduce a Markdown paragraph to plain text for the meta description:
/// code markers and emphasis are dropped, links keep their label.
fn plain_text(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '`' | '*' | '_' | '#' => i += 1,
            '[' => {
                // "[label](href)" keeps its label; an unmatched "[" is kept.
                if let Some(close) = chars[i + 1..].iter().position(|&c| c == ']') {
                    let label_end = i + 1 + close;
                    if chars.get(label_end + 1) == Some(&'(') {
                        for c in &chars[i + 1..label_end] {
                            out.push(*c);
                        }
                        i = label_end + 1;
                        while i < chars.len() && chars[i] != ')' {
                            i += 1;
                        }
                        i += 1;
                        continue;
                    }
                }
                out.push('[');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Wrap a rendered body fragment in the shared interior-page shell. The
/// shell mirrors static/about.html so writeups read as part of the site, and
/// it must declare the favicon and stylesheet like every other gated page.
fn page_shell(slug: &str, title: &str, description: &str, body: &str) -> String {
    let title_esc = markdown::escape_text(title);
    let description_attr = markdown::escape_attr(description);
    let title_attr = markdown::escape_attr(title);
    let slug_attr = markdown::escape_attr(slug);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Matthew Hebert · {title_esc}</title>
    <meta name="description" content="{description_attr}">
    <meta property="og:title" content="Matthew Hebert · {title_attr}">
    <meta property="og:description" content="{description_attr}">
    <meta property="og:url" content="https://mhebert.dev/projects/{slug_attr}">
    <link rel="icon" href="/static/favicon.ico">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body class="page">
    <header class="page-head">
        <a class="wordmark" href="/">mhebert<span class="dot">.</span>dev</a>
        <nav class="nav" aria-label="Site">
            <a href="/">index</a>
            <a href="/projects" aria-current="page">projects</a>
            <a href="/about">about</a>
            <a href="/writing">writing</a>
            <a href="/contact">contact</a>
        </nav>
    </header>

    <main>
        <h1 class="page-title">{title_esc}</h1>
        <div class="writeup">
{body}        </div>
    </main>

    <footer class="page-footer">
        served by <code>zero-trust-server</code> · HTTP/1.1 from raw sockets · rustls TLS 1.3 · a proof of work gate · <a href="/transparency">what this server records</a>
    </footer>
</body>
</html>
"#
    )
}

/// The fixture page used by the shared test store, kept identical across
/// runs so whichever test seeds first, the others read the same content.
#[cfg(test)]
const FIXTURE_SAMPLE: &str = "# sample

This is the sample writeup lead.

## A section

Paragraph with **bold** and [a link](https://example.com/).

- one
- two

`inline code` stays escaped: <tag>.
";

/// A second fixture page, to exercise ordering and independent slugs.
#[cfg(test)]
const FIXTURE_SECOND: &str = "# second

Another lead paragraph.
";

/// Populate the global writeup store from a synthetic fixture, once per test
/// process. Idempotent, so handler and routing tests in other modules can
/// serve /projects/<slug> without touching the real content directory.
#[cfg(test)]
pub fn seed_test_pages() {
    static SEED: OnceLock<()> = OnceLock::new();
    SEED.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "zts-writeup-fixture-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("sample.md"), FIXTURE_SAMPLE).expect("fixture write");
        fs::write(dir.join("second.md"), FIXTURE_SECOND).expect("fixture write");
        let _ = init(&dir);
        let _ = fs::remove_dir_all(&dir);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("zts-writeup-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn load_builds_pages_sorted_with_shell_and_meta() {
        let dir = scratch("build");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("second.md"), FIXTURE_SECOND).expect("fixture write");
        fs::write(dir.join("sample.md"), FIXTURE_SAMPLE).expect("fixture write");

        let pages = load(&dir).expect("fixture directory loads");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].slug, "sample", "pages sort by slug");
        assert_eq!(pages[1].slug, "second");
        let page = &pages[0];
        assert_eq!(page.title, "sample");
        assert_eq!(page.description, "This is the sample writeup lead.");
        assert!(page.html.contains("<title>Matthew Hebert · sample</title>"));
        assert!(page.html.contains(r#"<link rel="icon" href="/static/favicon.ico">"#));
        assert!(page.html.contains(r#"<link rel="stylesheet" href="/static/style.css">"#));
        assert!(page.html.contains("aria-current=\"page\""));
        assert!(page.html.contains("served by <code>zero-trust-server</code>"));
        assert!(page.html.contains("<h2>A section</h2>"));
        assert!(!page.html.contains("<blockquote>"), "no stray blockquote");
        assert!(page.html.contains("<li>two</li>"));
        assert!(page.html.contains("&lt;tag&gt;"), "inline code is escaped");
    }

    #[test]
    fn load_fails_cleanly_on_a_missing_directory() {
        let dir = scratch("missing");
        let _ = fs::remove_dir_all(&dir);
        let err = load(&dir).expect_err("a missing directory is an error");
        assert!(err.contains("cannot read"), "error names the failure");
    }

    #[test]
    fn build_falls_back_to_slug_when_no_leading_h1() {
        let page = build_page("sluggy", "## A section\n\nNo leading H1 here.");
        assert_eq!(page.title, "sluggy");
        assert!(page.html.contains("<h2>A section</h2>"));
    }

    #[test]
    fn the_real_content_directory_loads_and_renders_every_writeup() {
        // The four shipped Markdown files must parse with the renderer and
        // assemble into complete pages, so a content typo or an unsupported
        // construct fails the suite at build time instead of on the live
        // site. The slug set must match the projects page cards exactly.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("content");
        let pages = load(&dir).expect("content directory loads");
        let expected = [
            "modbus-dnp3-traffic-analysis",
            "sigma-detections-attck",
            "yara-rules-malware-detection",
            "zero-trust-server",
        ];
        assert_eq!(pages.len(), expected.len(), "content has one file per project");
        let slugs: Vec<&str> = pages.iter().map(|p| p.slug.as_str()).collect();
        assert_eq!(slugs, expected, "writeups sort to the projects page order");
        for page in &pages {
            assert!(page.html.contains(r#"<link rel="icon" href="/static/favicon.ico">"#),
                "{} declares the favicon", page.slug);
            assert!(page.html.contains("<div class=\"writeup\">"),
                "{} wraps its body in the prose container", page.slug);
            assert!(page.html.contains("served by <code>zero-trust-server</code>"),
                "{} carries the footer", page.slug);
            assert!(!page.description.is_empty(),
                "{} has a meta description", page.slug);
        }
    }

    #[test]
    fn get_returns_pages_from_the_seeded_store() {
        seed_test_pages();
        let page = get("sample").expect("fixture store holds sample");
        assert_eq!(page.title, "sample");
        assert!(page.html.contains("A section"));
        assert!(get("nope").is_none(), "unknown slug is a miss");
    }
}
