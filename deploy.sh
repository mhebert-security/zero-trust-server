#!/bin/bash
set -e

echo "Building release binary..."
cargo build --release --target x86_64-unknown-linux-musl

echo "Stopping service..."
ssh -p 2222 root@188.245.239.118 "systemctl stop zero-trust-server"

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

echo "Starting service..."
ssh -p 2222 root@188.245.239.118 "systemctl start zero-trust-server"

echo "Done."