#!/usr/bin/env bash
# Start the local MongoDB used by the ForensIQ backend.
#
# Why TLS: server/db.py passes tlsCAFile=certifi's bundle to motor, which turns
# TLS on unconditionally. A plaintext mongod cannot be reached by that client,
# so this script runs mongod with a self-signed local certificate and the
# backend connects with tlsAllowInvalidCertificates=true. Nothing here is
# production configuration, and the certificates live in the git-ignored
# cli_agent/.runtime/ directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TLS_DIR="$REPO_ROOT/cli_agent/.runtime/mongo-tls"
CONTAINER=forensiq-mongo

if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "mongo already running ($CONTAINER, 127.0.0.1:27017)"
    exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    docker start "$CONTAINER" >/dev/null
    echo "started existing $CONTAINER"
    exit 0
fi

mkdir -p "$TLS_DIR"
if [[ ! -f "$TLS_DIR/server.pem" ]]; then
    (
        cd "$TLS_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
            -days 365 -subj "/CN=ForensIQ Local Dev CA" >/dev/null 2>&1
        openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
            -subj "/CN=localhost" >/dev/null 2>&1
        printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > san.cnf
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
            -out server.crt -days 365 -extfile san.cnf >/dev/null 2>&1
        cat server.crt server.key > server.pem
        chmod 644 server.pem ca.pem
    )
    echo "generated local TLS certificate in $TLS_DIR"
fi

docker run -d --name "$CONTAINER" -p 127.0.0.1:27017:27017 \
    -v "$TLS_DIR:/tls:ro" mongo:7 \
    --tlsMode requireTLS \
    --tlsCertificateKeyFile /tls/server.pem \
    --tlsCAFile /tls/ca.pem \
    --tlsAllowConnectionsWithoutCertificates \
    --bind_ip_all >/dev/null

echo "mongo started ($CONTAINER, 127.0.0.1:27017)"
