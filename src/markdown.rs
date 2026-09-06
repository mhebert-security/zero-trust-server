//! Minimal Markdown renderer, std only.
//!
//! Turns the project writeups (Markdown files read at startup, see
//! `writeup.rs`) into an HTML body fragment. This is a deliberate subset,
//! not a `CommonMark` implementation: enough shape to write a real page, no
//! dependency to audit. The block grammar covers `ATX` headings, paragraphs
//! (soft-wrapped source lines join into one paragraph), bullet and ordered
//! lists, fenced code blocks, blockquotes, and thematic breaks. The inline
//! grammar covers `code` spans, `*emphasis*`, `**strong**`, and
//! `[text](url)` links whose href is restricted to http(s) and same-site
//! paths.
//!
//! The output is a fragment, never a full document: the shared page shell
//! belongs to `writeup.rs`. Every text node and code node is HTML-escaped,
//! and link destinations that fail the scheme check are emitted as plain
//! text, so a typo cannot turn into an executable `javascript:` href.
//!
//! `escape_text` and `escape_attr` are exported for the shell builder, which
//! interpolates operator-supplied titles and descriptions into a document.

/// Render a Markdown source string to an HTML fragment.
#[must_use]
pub fn render(source: &str) -> String {
    let mut out = String::new();
    let lines: Vec<&str> = source.split('\n').collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];

        // Blank lines carry no content; they separate blocks.
        if line.trim().is_empty() {
            i += 1;
            continue;
        }

        // Fenced code block. Consume every line up to the closing fence.
        if let Some(lang) = fence_language(line) {
            i += 1;
            let mut code = String::new();
            while i < lines.len() && !is_fence_close(lines[i]) {
                code.push_str(lines[i]);
                code.push('\n');
                i += 1;
            }
            if i < lines.len() {
                i += 1; // the closing fence
            }
            out.push_str("<pre><code");
            if !lang.is_empty() {
                out.push_str(" class=\"language-");
                out.push_str(lang);
                out.push('"');
            }
            out.push('>');
            out.push_str(&escape_text(&code));
            out.push_str("</code></pre>\n");
            continue;
        }

        // ATX heading.
        if let Some((level, text)) = atx_heading(line) {
            let heading =
                format!("<h{level}>{}</h{level}>\n", render_inline(text));
            out.push_str(&heading);
            i += 1;
            continue;
        }

        // Thematic break.
        if is_thematic_break(line) {
            out.push_str("<hr>\n");
            i += 1;
            continue;
        }

        // Blockquote. Consecutive ">" lines, blank ">" lines split
        // paragraphs inside the quote.
        if starts_quote(line) {
            let mut inner: Vec<&str> = Vec::new();
            while i < lines.len() && starts_quote(lines[i]) {
                inner.push(quote_text(lines[i]));
                i += 1;
            }
            out.push_str(&render_quote(&inner));
            continue;
        }

        // Lists. One marker per line, a blank line ends the list.
        if let Some(kind) = list_item_kind(line) {
            out.push_str(&render_list(&lines, &mut i, kind));
            continue;
        }

        // Paragraph. Consume ordinary lines until a blank line or the start
        // of another block; the source's soft wraps join with single spaces.
        let mut para: Vec<&str> = Vec::new();
        while i < lines.len()
            && !lines[i].trim().is_empty()
            && !is_block_start(lines[i])
        {
            para.push(lines[i].trim());
            i += 1;
        }
        if !para.is_empty() {
            out.push_str("<p>");
            out.push_str(&render_inline(&para.join(" ")));
            out.push_str("</p>\n");
        }
    }

    out
}

/// HTML-escape text destined for element content (no markup interpreted).
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

/// HTML-escape text destined for a double-quoted attribute value.
pub fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Is this line the start of any block other than a paragraph?
fn is_block_start(line: &str) -> bool {
    fence_language(line).is_some()
        || atx_heading(line).is_some()
        || is_thematic_break(line)
        || starts_quote(line)
        || list_item_kind(line).is_some()
}

/// The info string of a fenced code block opener, or None.
/// The info string is sanitised to a safe class token.
fn fence_language(line: &str) -> Option<&str> {
    let t = line.trim();
    if !(t.starts_with("```") || t.starts_with("~~~")) {
        return None;
    }
    let rest = &t[3..];
    let lang = rest.trim();
    if lang.is_empty() {
        Some("")
    } else {
        lang.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '#')))
            .next()
            .filter(|tok| !tok.is_empty())
    }
}

fn is_fence_close(line: &str) -> bool {
    fence_language(line).is_some()
}

/// `(level, text)` for an ATX heading line.
fn atx_heading(line: &str) -> Option<(usize, &str)> {
    let t = line.trim();
    let hashes = t.bytes().take_while(|&b| b == b'#').count();
    if !(1..=6).contains(&hashes) {
        return None;
    }
    let rest = &t[hashes..];
    let text = rest.trim();
    if text.is_empty() && hashes == 6 {
        return None; // "######" with nothing after is a break candidate, not a heading
    }
    Some((hashes, text))
}

fn is_thematic_break(line: &str) -> bool {
    let t = line.trim();
    let Some(c) = t.chars().next() else {
        return false;
    };
    matches!(c, '-' | '*' | '_')
        && t.chars().all(|x| x == c)
        && t.chars().count() >= 3
}

fn starts_quote(line: &str) -> bool {
    line.trim_start().starts_with('>')
}

/// The content of a blockquote line, with the leading ">" removed.
fn quote_text(line: &str) -> &str {
    let t = line.trim_start().strip_prefix('>').unwrap_or(line);
    t.trim()
}

/// Render a run of blockquote content lines. Blank entries split paragraphs.
fn render_quote(inner: &[&str]) -> String {
    let mut out = String::from("<blockquote>\n");
    for group in inner.split(|l| l.is_empty()) {
        if group.is_empty() {
            continue;
        }
        out.push_str("<p>");
        out.push_str(&render_inline(&group.join(" ")));
        out.push_str("</p>\n");
    }
    out.push_str("</blockquote>\n");
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Bullet,
    Ordered,
}

fn list_item_kind(line: &str) -> Option<ListKind> {
    let t = line.trim_start();
    if t.starts_with("- ") || t.starts_with("* ") {
        return Some(ListKind::Bullet);
    }
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 && t.as_bytes().get(digits) == Some(&b'.') {
        let rest = t[digits + 1..].trim_start();
        if !rest.is_empty() {
            return Some(ListKind::Ordered);
        }
    }
    None
}

/// Render one list block, consuming its lines. A line that is not the same
/// list kind ends the list.
fn render_list(lines: &[&str], i: &mut usize, kind: ListKind) -> String {
    let tag = match kind {
        ListKind::Bullet => "ul",
        ListKind::Ordered => "ol",
    };
    let mut out = String::from("<");
    out.push_str(tag);
    out.push_str(">\n");
    while *i < lines.len() && list_item_kind(lines[*i]) == Some(kind) {
        let t = lines[*i].trim_start();
        let text = match kind {
            ListKind::Bullet => t[2..].trim(),
            ListKind::Ordered => t[t.find('.').map_or(0, |d| d + 1)..].trim(),
        };
        out.push_str("<li>");
        out.push_str(&render_inline(text));
        out.push_str("</li>\n");
        *i += 1;
    }
    out.push_str("</");
    out.push_str(tag);
    out.push_str(">\n");
    out
}

/// Render inline markup (code, emphasis, strong, links) with escaping.
fn render_inline(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut buf = String::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '`' => {
                // Code span: run to the next backtick; an unterminated run
                // is literal text.
                if let Some(close) = find_char(&chars, i + 1, '`') {
                    flush_text(&mut buf, &mut out);
                    let code: String = chars[i + 1..close].iter().collect();
                    out.push_str("<code>");
                    out.push_str(&escape_text(&code));
                    out.push_str("</code>");
                    i = close + 1;
                } else {
                    buf.push('`');
                    i += 1;
                }
            }
            '*' => {
                // Strong when doubled; a delimiter without a closer is
                // literal.
                let strong = chars.get(i + 1) == Some(&'*');
                let delim_len = if strong { 2 } else { 1 };
                let close = if strong {
                    find_strong(&chars, i + delim_len)
                } else {
                    find_em(&chars, i + delim_len)
                };
                if let Some(close) = close {
                    flush_text(&mut buf, &mut out);
                    let inner: String = chars[i + delim_len..close].iter().collect();
                    let tag = if strong { "strong" } else { "em" };
                    out.push('<');
                    out.push_str(tag);
                    out.push('>');
                    out.push_str(&render_inline(&inner));
                    out.push_str("</");
                    out.push_str(tag);
                    out.push('>');
                    i = close + delim_len;
                } else {
                    buf.push('*');
                    i += 1;
                }
            }
            '[' => {
                // Link when a well-formed, scheme-safe "[text](href)"
                // follows; otherwise the text is literal.
                if let Some((label, href, next)) = link_at(&chars, i) {
                    flush_text(&mut buf, &mut out);
                    out.push_str("<a href=\"");
                    out.push_str(&escape_attr(&href));
                    out.push_str("\">");
                    out.push_str(&escape_text(&label));
                    out.push_str("</a>");
                    i = next;
                } else {
                    buf.push('[');
                    i += 1;
                }
            }
            _ => {
                buf.push(c);
                i += 1;
            }
        }
    }

    flush_text(&mut buf, &mut out);
    out
}

/// Move buffered plain text into `out`, escaped.
fn flush_text(buf: &mut String, out: &mut String) {
    if !buf.is_empty() {
        out.push_str(&escape_text(buf));
        buf.clear();
    }
}

fn find_char(chars: &[char], mut from: usize, needle: char) -> Option<usize> {
    while from < chars.len() {
        if chars[from] == needle {
            return Some(from);
        }
        from += 1;
    }
    None
}

/// First "**" at or after `from`.
fn find_strong(chars: &[char], mut from: usize) -> Option<usize> {
    while from + 1 < chars.len() {
        if chars[from] == '*' && chars[from + 1] == '*' {
            return Some(from);
        }
        from += 1;
    }
    None
}

/// First lone "*" at or after `from` (not the first half of "**").
fn find_em(chars: &[char], mut from: usize) -> Option<usize> {
    while from < chars.len() {
        if chars[from] == '*' && chars.get(from + 1) != Some(&'*') {
            return Some(from);
        }
        from += 1;
    }
    None
}

/// If `chars[from]` opens a "[label](href)" link, return it with the index
/// just past the closing paren. The label is plain text (no nested markup).
fn link_at(chars: &[char], from: usize) -> Option<(String, String, usize)> {
    let close = find_char(chars, from + 1, ']')?;
    if chars.get(close + 1) != Some(&'(') {
        return None;
    }
    let open = close + 1;
    let close_paren = find_char(chars, open + 1, ')')?;
    let label: String = chars[from + 1..close].iter().collect();
    let href: String = chars[open + 1..close_paren].iter().collect();
    if label.trim().is_empty() || !is_safe_href(&href) {
        return None;
    }
    Some((label.trim().to_string(), href.trim().to_string(), close_paren + 1))
}

/// Accept http(s) absolute links and same-site "/" paths. Reject every other
/// scheme (javascript:, data:, file:) and any href with whitespace, control
/// characters, or quote characters that would let markup escape an attribute.
fn is_safe_href(href: &str) -> bool {
    if href.is_empty() || href.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(c, '"' | '\'' | '<' | '>' | '\\')
    }) {
        return false;
    }
    if href.starts_with('/') {
        return !href.starts_with("//") && !href.starts_with("/\\");
    }
    let lower = href.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_paragraph_is_escaped_and_wrapped() {
        assert_eq!(render("Plain text."), "<p>Plain text.</p>\n");
        assert_eq!(
            render("a < b & c"),
            "<p>a &lt; b &amp; c</p>\n"
        );
    }

    #[test]
    fn wrapped_source_lines_join_into_one_paragraph() {
        assert_eq!(
            render("first line\nsecond line"),
            "<p>first line second line</p>\n"
        );
    }

    #[test]
    fn blank_lines_separate_paragraphs() {
        assert_eq!(
            render("one\n\ntwo"),
            "<p>one</p>\n<p>two</p>\n"
        );
    }

    #[test]
    fn atx_headings_render_at_their_level() {
        assert_eq!(render("# Title"), "<h1>Title</h1>\n");
        assert_eq!(render("## Section"), "<h2>Section</h2>\n");
        assert_eq!(render("#### Deep"), "<h4>Deep</h4>\n");
    }

    #[test]
    fn emphasis_and_strong_render_and_escape() {
        assert_eq!(render("*x* and **y**"), "<p><em>x</em> and <strong>y</strong></p>\n");
        assert_eq!(render("**a**"), "<p><strong>a</strong></p>\n");
    }

    #[test]
    fn unterminated_emphasis_stays_literal() {
        assert_eq!(render("not *emphasised"), "<p>not *emphasised</p>\n");
    }

    #[test]
    fn code_spans_escape_their_content() {
        assert_eq!(
            render("run `cargo test`"),
            "<p>run <code>cargo test</code></p>\n"
        );
        assert_eq!(
            render("`a<b && c`"),
            "<p><code>a&lt;b &amp;&amp; c</code></p>\n"
        );
    }

    #[test]
    fn fenced_code_is_escaped_and_classed() {
        let md = "```rust\nfn main() { if a < b {}\n}\n```";
        let html = render(md);
        assert!(html.contains(r#"<pre><code class="language-rust">"#));
        assert!(html.contains("fn main() { if a &lt; b {}"));
        assert!(html.contains("</code></pre>"));
    }

    #[test]
    fn unschemed_fence_has_no_class() {
        let html = render("```\nraw\n```");
        assert!(html.contains("<pre><code>raw\n</code></pre>"));
    }

    #[test]
    fn safe_links_render_plain_labels() {
        let html = render("[repo](https://github.com/me/r)");
        assert_eq!(
            html,
            "<p><a href=\"https://github.com/me/r\">repo</a></p>\n"
        );
    }

    #[test]
    fn same_site_link_is_allowed() {
        let html = render("[transparency](/transparency)");
        assert!(html.contains("<a href=\"/transparency\">"));
    }

    #[test]
    fn unsafe_schemes_stay_literal_text() {
        for md in [
            "[x](javascript:alert(1))",
            "[x](data:text/html,hi)",
            "[x](file:///etc/passwd)",
            "[x](https://ok.example/a b)",
        ] {
            let html = render(md);
            assert!(!html.contains("<a"), "{md} must not become an anchor");
            assert!(html.contains(']'), "{md} text is preserved");
        }
    }

    #[test]
    fn bullet_list_renders() {
        assert_eq!(
            render("- alpha\n- beta"),
            "<ul>\n<li>alpha</li>\n<li>beta</li>\n</ul>\n"
        );
    }

    #[test]
    fn ordered_list_renders() {
        assert_eq!(
            render("1. first\n2. second"),
            "<ol>\n<li>first</li>\n<li>second</li>\n</ol>\n"
        );
    }

    #[test]
    fn blockquote_joins_wrapped_lines() {
        let html = render("> the write that\n> can stop a line");
        assert!(html.contains("<blockquote>"));
        assert!(html.contains("<p>the write that can stop a line</p>"));
        assert!(html.contains("</blockquote>"));
    }

    #[test]
    fn thematic_break_renders() {
        assert_eq!(render("---"), "<hr>\n");
    }

    #[test]
    fn escape_text_and_attr_differ_on_quotes() {
        assert_eq!(escape_text("a\"b"), "a\"b");
        assert_eq!(escape_attr("a\"b"), "a&quot;b");
    }
}
