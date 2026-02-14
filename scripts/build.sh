#!/usr/bin/env bash
#
# build.sh - Build wrapper that uses the patched stdlib with matching Zig
#
# This script uses local-zig-lib/ if present, along with the Zig binary
# that was used to create it (stored in .zig-path during setup).
#
# Usage: ./scripts/build.sh [BUILD_ARGS...]
#
# Examples:
#   ./scripts/build.sh                           # Default build
#   ./scripts/build.sh -Doptimize=ReleaseSafe   # Release build
#   ./scripts/build.sh run -- config.json        # Build and run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOCAL_LIB_DIR="$PROJECT_DIR/local-zig-lib"
ZIG_PATH_FILE="$LOCAL_LIB_DIR/.zig-path"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd "$PROJECT_DIR"

# Check if local patched lib exists
if [[ -d "$LOCAL_LIB_DIR/lib" ]]; then
    # Get the Zig binary that matches the stdlib
    if [[ -f "$ZIG_PATH_FILE" ]]; then
        ZIG_BIN=$(cat "$ZIG_PATH_FILE")
        if [[ ! -x "$ZIG_BIN" ]]; then
            echo -e "${RED}[ERROR]${NC} Zig binary not found: $ZIG_BIN"
            echo "Re-run setup: ./scripts/setup-zig-lib.sh /path/to/zig"
            exit 1
        fi
    else
        echo -e "${YELLOW}[WARN]${NC} No .zig-path file found, using system zig"
        echo "The stdlib was created by a previous version of setup-zig-lib.sh"
        echo "If build fails with @Int errors, re-run: ./scripts/setup-zig-lib.sh /path/to/zig-0.16"
        ZIG_BIN="zig"
    fi

    echo -e "${GREEN}[BUILD]${NC} Using: $ZIG_BIN"
    echo -e "${GREEN}[BUILD]${NC} Stdlib: local-zig-lib/lib"
    exec "$ZIG_BIN" build --zig-lib-dir "$LOCAL_LIB_DIR/lib" "$@"
else
    echo -e "${YELLOW}[BUILD]${NC} Patched stdlib not found."
    echo
    echo "TLS 1.3 with MySQL requires a patched Zig stdlib."
    echo "Run the setup script first:"
    echo
    echo "  ./scripts/setup-zig-lib.sh /path/to/zig-0.16"
    echo
    exit 1
fi
