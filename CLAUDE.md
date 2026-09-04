# Agent Workflow & Project Protocol

## Memory & Architectural Source of Truth
- The obsidian-vault MCP tool (using @modelcontextprotocol/server-filesystem) is your persistent external memory bank and architectural source of truth.
- Allowed root: /home/splayingcow/Obsidian.
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
