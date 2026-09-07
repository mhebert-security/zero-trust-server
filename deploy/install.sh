#!/bin/bash
# Install the cyber-news fetcher and its systemd units.
#
# Copies the service and timer into /etc/systemd/system, installs the compiled
# binary where the service expects it, and enables and starts the timer. Run
# as root on a plain systemd machine. On the NixOS host the units are declared
# in configuration.nix instead; this script is the portable path for anywhere
# else.
#
# The binary comes from $FETCHER_BIN if given, else the native release build,
# else the musl release build. Nothing is installed until a binary is found.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "install.sh must run as root." >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT="cyber-news-fetcher"
BIN_DEST="/usr/local/bin/cyber_news_fetcher"
STORE_DIR="/var/lib/cyber-news"

# Locate the compiled binary. An explicit path wins; then the native and musl
# release outputs of this repo, in that order.
if [[ -n "${FETCHER_BIN:-}" ]]; then
    BIN_SRC="$FETCHER_BIN"
else
    ROOT="$(cd "$HERE/.." && pwd)"
    if [[ -x "$ROOT/target/release/cyber_news_fetcher" ]]; then
        BIN_SRC="$ROOT/target/release/cyber_news_fetcher"
    elif [[ -x "$ROOT/target/x86_64-unknown-linux-musl/release/cyber_news_fetcher" ]]; then
        BIN_SRC="$ROOT/target/x86_64-unknown-linux-musl/release/cyber_news_fetcher"
    else
        echo "No compiled fetcher found. Build it first, then rerun:" >&2
        echo "  cargo build --release" >&2
        exit 1
    fi
fi

# The service runs unprivileged and may write only the store directory. Create
# the system user and the directory it owns once; later runs reuse both.
if ! id -u cyber-news >/dev/null 2>&1; then
    useradd --system --home-dir "$STORE_DIR" --shell /usr/sbin/nologin cyber-news
fi
mkdir -p "$STORE_DIR"
chown cyber-news:cyber-news "$STORE_DIR"

install -m 0755 "$BIN_SRC" "$BIN_DEST"
install -m 0644 "$HERE/$UNIT.service" /etc/systemd/system/
install -m 0644 "$HERE/$UNIT.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now "$UNIT.timer"
echo "$UNIT.timer installed and started. Runs every six hours."
