#!/usr/bin/env bash
# Tear down the Docker MySQL 8.0 SSL test environment.
# Usage: ./docker/teardown.sh [--volumes]
#
# Options:
#   --volumes   Also remove the persistent MySQL data volume.
#               Without this flag the volume is kept so binlog
#               state survives across bootstrap cycles.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

REMOVE_VOLUMES=""
for arg in "$@"; do
    case "$arg" in
        --volumes) REMOVE_VOLUMES="--volumes" ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

echo "==> Stopping and removing containers..."
docker compose down $REMOVE_VOLUMES

if [ -n "$REMOVE_VOLUMES" ]; then
    echo "==> Persistent volume removed."
else
    echo "==> Persistent volume kept (pass --volumes to remove)."
fi

echo "Done."
