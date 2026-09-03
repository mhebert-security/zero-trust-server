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
# Replace the remote static dir deterministically.
# NOTE: do NOT use `scp -r static/ dest:/opt/zero-trust-server/static` here —
# if the destination already exists (it does after the first deploy), scp
# nests the source folder inside it -> /static/static/, and the server's
# path guard (content.rs rejects filenames containing '/') makes those files
# unservable. A tar stream over ssh gives exact, idempotent mirror semantics.
tar -C static -cf - . | ssh -p 2222 root@188.245.239.118 \
    "rm -rf /opt/zero-trust-server/static && \
     mkdir -p /opt/zero-trust-server/static && \
     tar -C /opt/zero-trust-server/static -xf -"

echo "Starting service..."
ssh -p 2222 root@188.245.239.118 "systemctl start zero-trust-server"

echo "Done."