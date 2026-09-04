#!/bin/bash
# Deploy the zero-trust server to production.
# → GitHub issue #8: no longer SSHes as root. Defaults to the restricted
#   `deploy` user, which may only write /opt/zero-trust-server (setgid dir)
#   and run `sudo systemctl stop|start zero-trust-server` (see the sudoers
#   rule in configuration.nix). Pass DEPLOY_USER=root during the one-time
#   server migration, before the `deploy` user exists.
set -euo pipefail

HOST="188.245.239.118"
PORT="2222"
REMOTE_DIR="/opt/zero-trust-server"
DEPLOY_USER="${DEPLOY_USER:-deploy}"

# Run a command on the server. Non-root users need sudo for systemctl.
remote() {
    if [[ "$DEPLOY_USER" == "root" ]]; then
        ssh -p "$PORT" "root@$HOST" "$@"
    else
        ssh -p "$PORT" "${DEPLOY_USER}@$HOST" "sudo $*"
    fi
}

echo "Building release binary..."
cargo build --release --target x86_64-unknown-linux-musl

echo "Stopping service (as $DEPLOY_USER)..."
remote systemctl stop zero-trust-server

echo "Ensuring directory exists and is writable by $DEPLOY_USER..."
ssh -p "$PORT" "${DEPLOY_USER}@$HOST" "mkdir -p $REMOTE_DIR"

echo "Copying binary to server..."
scp -P "$PORT" \
    target/x86_64-unknown-linux-musl/release/zero-trust-server \
    "${DEPLOY_USER}@$HOST:$REMOTE_DIR/zero-trust-server"

echo "Marking binary executable..."
# Plain scp drops the exec bit (0644). chmod here is safe: the file is owned
# by $DEPLOY_USER (scp wrote it) and the service runs as an unprivileged user
# that only needs read+execute via world bits.
ssh -p "$PORT" "${DEPLOY_USER}@$HOST" "chmod 0755 $REMOTE_DIR/zero-trust-server"

echo "Copying static files to server..."
# Replace the remote static dir deterministically.
# NOTE: do NOT use `scp -r static/ dest:/opt/zero-trust-server/static` here —
# if the destination already exists (it does after the first deploy), scp
# nests the source folder inside it -> /static/static/, and the server's
# path guard (content.rs rejects filenames containing '/') makes those files
# unservable. A tar stream over ssh gives exact, idempotent mirror semantics.
tar -C static -cf - . | ssh -p "$PORT" "${DEPLOY_USER}@$HOST" \
    "rm -rf $REMOTE_DIR/static && \
     mkdir -p $REMOTE_DIR/static && \
     tar -C $REMOTE_DIR/static -xf -"

# The one-time NixOS migration (root-owned /etc/nixos + nftables + new
# systemd unit) must upload the binary BEFORE `nixos-rebuild switch`, then let
# the switch start the service under the new unit's env. NO_START=1 skips the
# start + smoke so deploy.sh can be the upload half of that sequence.
if [[ "${NO_START:-0}" == "1" ]]; then
    echo "NO_START=1 — not starting service (NixOS switch will)."
    exit 0
fi

echo "Starting service..."
remote systemctl start zero-trust-server

# Smoke test: the TLS listener binds 0.0.0.0:8443 (post-redirect), reachable
# directly on loopback. Expect the challenge page (200). Skip with SMOKE=0.
# Run via plain ssh, NOT sudo (curl is not a sudo-allowed command).
if [[ "${SMOKE:-1}" == "1" ]]; then
    echo "Smoke-testing https://127.0.0.1:8443/ ..."
    sleep 1
    code=$(ssh -p "$PORT" "${DEPLOY_USER}@$HOST" \
        "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/")
    echo "HTTP $code"
    if [[ "$code" != "200" ]]; then
        echo "Smoke test failed — check: remote systemctl status zero-trust-server" >&2
        exit 1
    fi
fi

echo "Done."
