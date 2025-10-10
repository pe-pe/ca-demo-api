#!/usr/bin/env bash
set -euo pipefail

CA_DIR=/app/ca

if [ -f "$CA_DIR/ca.key.pem" ] && [ -f "$CA_DIR/ca.cert.pem" ]; then
    echo "CA already initialized, skipping"
    exit 0
fi
echo "Initializing CA..."
mkdir -p "$CA_DIR"
cd "$CA_DIR"

# generate a new self-signed CA cert
openssl req -x509 -newkey rsa:4096 -days 365 \
-nodes -subj "/CN=Demo CA" \
-keyout ca.key.pem -out ca.cert.pem > /dev/null 2>&1
