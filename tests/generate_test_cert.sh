#!/bin/bash

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

openssl req -x509 -newkey rsa:2048 \
    -keyout "$PROJECT_ROOT/test_key.pem" \
    -out "$PROJECT_ROOT/test_cert.pem" \
    -days 365 \
    -nodes \
    -subj "/CN=localhost"

echo "[+] Test certificate generated successfully"
