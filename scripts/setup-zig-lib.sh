#!/usr/bin/env bash
#
# setup-zig-lib.sh - Prepare a patched Zig stdlib for TLS 1.3 MySQL support
#
# This script creates a local copy of Zig's standard library and applies
# the TLS CertificateRequest patch required for MySQL 8.0+ SSL connections.
#
# Usage: ./scripts/setup-zig-lib.sh [ZIG_PATH]
#
# Arguments:
#   ZIG_PATH  Path to zig executable (default: searches PATH)
#
# After running this script, build with:
#   zig build --zig-lib-dir local-zig-lib/lib

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOCAL_LIB_DIR="$PROJECT_DIR/local-zig-lib"
PATCH_FILE="$PROJECT_DIR/patches/zig-tls-certificate-request.patch"

# Required Zig version (patch is tested against this)
REQUIRED_VERSION="0.16.0-dev.2349"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Find Zig executable
find_zig() {
    if [[ -n "${1:-}" ]]; then
        echo "$1"
    elif command -v zig &>/dev/null; then
        command -v zig
    else
        log_error "Zig not found. Install Zig 0.16.x or specify path: $0 /path/to/zig"
        exit 1
    fi
}

# Get Zig version
get_zig_version() {
    "$1" version 2>/dev/null || echo "unknown"
}

# Get Zig lib directory
get_zig_lib_dir() {
    # Parse zig env output for lib_dir
    "$1" env 2>/dev/null | grep '\.lib_dir' | sed 's/.*= *"\([^"]*\)".*/\1/' | head -1
}

# Check if patch is already applied
is_patch_applied() {
    local client_zig="$1/lib/std/crypto/tls/Client.zig"
    if [[ -f "$client_zig" ]]; then
        grep -q "client_cert_requested" "$client_zig" 2>/dev/null
    else
        return 1
    fi
}

main() {
    local zig_path
    zig_path=$(find_zig "${1:-}")

    log_info "Using Zig: $zig_path"

    local version
    version=$(get_zig_version "$zig_path")
    log_info "Zig version: $version"

    # Version check (warning only)
    if [[ "$version" != *"0.16"* ]]; then
        log_warn "Expected Zig 0.16.x, got: $version"
        log_warn "Patch may not apply cleanly to other versions"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi

    # Check if patch file exists
    if [[ ! -f "$PATCH_FILE" ]]; then
        log_error "Patch file not found: $PATCH_FILE"
        exit 1
    fi

    # Check if already set up
    if is_patch_applied "$LOCAL_LIB_DIR"; then
        log_info "Patch already applied in $LOCAL_LIB_DIR"
        log_info "To rebuild from scratch, run: rm -rf $LOCAL_LIB_DIR"
        exit 0
    fi

    # Get source lib directory
    local src_lib_dir
    src_lib_dir=$(get_zig_lib_dir "$zig_path")

    # Handle relative paths from zig env
    if [[ "$src_lib_dir" != /* ]]; then
        src_lib_dir="$(dirname "$zig_path")/$src_lib_dir"
    fi

    if [[ ! -d "$src_lib_dir" ]]; then
        log_error "Zig lib directory not found: $src_lib_dir"
        exit 1
    fi

    log_info "Source lib: $src_lib_dir"

    # Clean and create local lib directory
    rm -rf "$LOCAL_LIB_DIR"
    mkdir -p "$LOCAL_LIB_DIR"

    log_info "Copying stdlib to $LOCAL_LIB_DIR..."
    cp -R "$src_lib_dir" "$LOCAL_LIB_DIR/"

    log_info "Applying TLS CertificateRequest patch..."
    cd "$LOCAL_LIB_DIR"

    # Apply patch (strip leading a/ b/ from paths)
    if patch -p1 < "$PATCH_FILE"; then
        log_info "Patch applied successfully!"
    else
        log_error "Patch failed to apply"
        log_warn "This might happen if Zig version differs significantly from 0.16.0-dev.2349"
        exit 1
    fi

    cd "$PROJECT_DIR"

    # Save the Zig path for build.sh to use (compiler must match stdlib)
    local zig_abs_path
    zig_abs_path=$(cd "$(dirname "$zig_path")" && pwd)/$(basename "$zig_path")
    echo "$zig_abs_path" > "$LOCAL_LIB_DIR/.zig-path"

    echo
    log_info "Setup complete!"
    echo
    echo "Build with:"
    echo "  $zig_abs_path build --zig-lib-dir local-zig-lib/lib"
    echo
    echo "Or use the wrapper script:"
    echo "  ./scripts/build.sh"
}

main "$@"
