#!/usr/bin/env bash
# Bootstrap the Docker MySQL 8.0 SSL test environment.
# Usage: ./docker/bootstrap.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building and starting MySQL 8.0 SSL container..."
docker compose up -d --build

echo "==> Waiting for MySQL to become healthy..."
attempts=0
max_attempts=40
while [ $attempts -lt $max_attempts ]; do
    status=$(docker inspect --format='{{.State.Health.Status}}' myzql-ssl-test 2>/dev/null || echo "not_found")
    if [ "$status" = "healthy" ]; then
        echo "==> MySQL is healthy."
        break
    fi
    attempts=$((attempts + 1))
    printf "    waiting... (%d/%d, status=%s)\n" "$attempts" "$max_attempts" "$status"
    sleep 3
done

if [ "$status" != "healthy" ]; then
    echo "ERROR: MySQL did not become healthy after $max_attempts attempts." >&2
    docker logs myzql-ssl-test --tail 30 >&2
    exit 1
fi

# Verify TLS and replication user work
echo "==> Verifying TLS connection with replication user..."
docker exec myzql-ssl-test mysql \
    -u myzql_repl_user -pReplPass2025 \
    --ssl-mode=REQUIRED \
    -e "SELECT 'TLS OK' AS status, @@ssl_cipher AS cipher;" 2>/dev/null

echo "==> Checking binlog files..."
docker exec myzql-ssl-test mysql \
    -u myzql_repl_user -pReplPass2025 \
    --ssl-mode=REQUIRED \
    -e "SHOW BINARY LOGS;" 2>/dev/null

echo ""
echo "Docker MySQL SSL test environment is ready."
echo "  Host: 127.0.0.1:23306"
echo "  User: myzql_repl_user / ReplPass2025"
echo "  DB:   testdb"
echo ""
echo "Run the connector:"
echo "  ./zig-out/bin/myzql_binlog_connector config.docker-ssl.json"
