#!/bin/bash
set -e

echo "Building release binary..."
cargo build --release --target x86_64-unknown-linux-musl

echo "Creating directory on server..."
ssh -p 2222 root@188.245.239.118 "mkdir -p /opt/zero-trust-server"

echo "Copying binary to server..."
scp -P 2222 \
    target/x86_64-unknown-linux-musl/release/zero-trust-server \
    root@188.245.239.118:/opt/zero-trust-server/zero-trust-server

echo "Copying static files to server..."
scp -P 2222 -r \
    static/ \
    root@188.245.239.118:/opt/zero-trust-server/static

echo "Done — binary and static files deployed."
echo "Systemd service restart will be added once the service is configured."
