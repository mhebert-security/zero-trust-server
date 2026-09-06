# Agent Workflow & Project Protocol

## Authorship

Do not add yourself as a contributor, co-author, or collaborator anywhere
in this repository. This includes commit messages, git trailers, AUTHORS
files, README attribution, and any other form of credit. All commits are
authored solely by the repository owner. Claude is a tool, not a contributor.

## Memory & Architectural Source of Truth
- The obsidian-vault MCP tool (using @modelcontextprotocol/server-filesystem) is your persistent external memory bank and architectural source of truth.
- Allowed root: /home/splayingcow/Obsidian.
- Canonical project notes: 03_Security/00_active/07_zero_trust_website/ (flat structure — 00_overview through 08_substack_seeds)
- Implementation log: 03_Security/00_active/07_zero_trust_website/01_implementation_log.md
- Always consult relevant Obsidian notes before planning or modifying code.
- Treat constraints, schemas, and design patterns found in Obsidian as hard project requirements.

## Obsidian Write Protocols
- Mandatory Execution: Do not describe or propose note updates in chat without executing them. You MUST call the filesystem MCP tools (read_file, write_file, edit_file, list_directory) to directly inspect, update, or append to the actual .md files in the vault.
- Auto-Sync: Every time a task, refactor, or test suite is completed, automatically append a dated status entry under an ## Implementation Log header in the corresponding project note.
- Log Structure: Every vault update must document:
  - Files created or modified.
  - Dependencies or configurations introduced.
  - Test and security scan results.
  - Remaining security considerations, known follow-ups, or deployment status.
- Verification: Always verify that the tool call confirms the write succeeded on disk.

## External Documentation & Web Retrieval
- Use the fetch MCP tool whenever dealing with unfamiliar library APIs, third-party crate updates, or external RFC/spec documentation.
- When live vulnerability lookups or CVE advisories are required, search via available search tools before drafting mitigations.

## Visual Documentation & Screenshots
- Whenever frontend UI, challenge flows, or layout changes are made, run:
  node scripts/capture-stage.js <stage-name>
  (e.g. challenge for the pre-solve PoW gate screen, verified for the post-auth state; the script also honors CAPTURE_URL / CAPTURE_NAME env overrides for non-local targets and custom filenames).
- All screenshots must output to /home/splayingcow/Obsidian/08_Assets/screenshots/.
- When appending to the project note in Obsidian, embed captured screenshots using standard wikilinks:
  ![[08_Assets/screenshots/<file>.png]] (or ![[<file>.png]])

## Verification, Testing & Static Security Analysis
Before declaring any task complete or committing:
1. Run local build and unit tests via the bash tool (cargo check and cargo test).
2. Run a static security audit using Semgrep via bash:
   semgrep scan --config auto src/
3. If Semgrep or the compiler flags errors, insecure functions, or memory safety issues, resolve them immediately.
4. Update the Obsidian tracking note once all tests and security scans pass cleanly.
5. Trigger the GitHub Remote Push Protocol to push changes upstream.

## GitHub Remote Push Protocol
- Autonomous Checkpoints: Once a task passes compilation, tests, Semgrep analysis, and Obsidian logging:
  1. Inspect the working tree:
     git status --short
  2. If there are no modified or staged files, do nothing.
  3. Otherwise, stage all relevant changes, ensuring credentials, keys, or local environment files are ignored:
     git add <changed-files>
  4. Create a concise conventional commit describing what was completed:
     git commit -m "feat/fix: <summary of task>"
  5. Push the commit upstream to GitHub:
     git push origin HEAD
- Never leave a finished task uncommitted or unpushed to GitHub if verification and vault logging passed.

## Execution Rules
- Execute tool calls autonomously without asking for routine permissions.
- When presenting completed work, explicitly state which Obsidian notes were read and updated, cite Semgrep scan findings, and report the resulting GitHub commit hash and push status.

## Prose Standard

All user-facing copy, documentation, comments intended to be read by humans,
and any generated written content must meet the following standard.

### Non-Fiction Craft
Follow the principles in "On Writing Well" (Zinsser), "The Elements of Style"
(Strunk & White), and "Several Short Sentences About Writing" (Klinkenborg).

- Cut every word that restates what the sentence before it already said.
- Active voice by default. Passive only when the agent is genuinely unknown.
- Concrete nouns and strong verbs. Never "is performed" when "rejects" will do.
- No em dashes, en dashes, or hyphens used as clause separators. Restructure
  the sentence instead.
- No filler openers. Begin with the substance.
- Short paragraphs. Three sentences is a paragraph.

### Fiction Craft
Draw warmth and weight from the following:

- Hemingway: the iceberg. Say the essential thing and trust the reader to feel
  what is beneath it. Do not explain the emotion; render the fact that carries it.
- Carver: economy with emotional charge. Every detail chosen deliberately.
  Nothing decorative.
- Le Guin ("Steering the Craft"): rhythm and sentence variety as meaning.
  A sequence of identical structures deadens the reader.
- Chekhov: precision of observation over generality. The specific detail
  is always more alive than the category it belongs to.
- Nabokov: exact words for exact things. Vagueness is a failure of attention,
  not a style.

### Application
These principles apply to: HTML copy, README files, error messages visible to
users, log annotations, commit messages, and any prose generated on request.
They do not apply to inline code comments whose audience is the compiler or a
linter, or to structured data formats.

When rewriting existing copy, read the result aloud internally. Any sentence
that stumbles gets one more pass before it ships.

## Site / product follow-ups

### Observability
- Log rotation — the audit stream goes to stdout, captured by journald, and
  production already bounds it (services.journald: SystemMaxUse 512M,
  MaxRetentionSec 60day, MaxFileSec 1week). Logrotate does not apply. Prefer
  30-day retention? Edit configuration.nix. See 10_runbook.md §7.
- UptimeRobot → Pushover alert — set a 2-minute check interval and route
  failures to your phone. You'll know about a crash before any user does.

### Content / portfolio
- Substack cross-link — add a visible link from the About page (or a nav item)
  to your Substack once the first post is live. The site and the publication
  should point at each other.
