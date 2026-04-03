#!/usr/bin/env bash
# SDK Generation Script for PalAuth
#
# Currently the SDKs are hand-written thin wrappers over the OpenAPI spec.
# This script documents the generation process and validates the spec.
#
# Prerequisites:
#   npm install -g @redocly/cli
#
# Usage:
#   ./sdk/generate.sh validate    # Validate OpenAPI spec
#   ./sdk/generate.sh build       # Build TypeScript SDKs
#   ./sdk/generate.sh all         # Validate + build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC="$ROOT_DIR/api/openapi.yaml"

validate() {
    echo "==> Validating OpenAPI spec..."
    if command -v npx &> /dev/null; then
        npx --yes @redocly/cli lint "$SPEC" --skip-rule no-unused-components
    else
        echo "npx not found. Install Node.js to validate the spec."
        exit 1
    fi
    echo "==> OpenAPI spec is valid."
}

build_ts() {
    echo "==> Building TypeScript client SDK..."
    cd "$ROOT_DIR/sdk/typescript/client"
    if [ -f "node_modules/.package-lock.json" ]; then
        npx tsc
    else
        echo "    Run 'npm install' in sdk/typescript/client/ first."
    fi

    echo "==> Building TypeScript server SDK..."
    cd "$ROOT_DIR/sdk/typescript/server"
    if [ -f "node_modules/.package-lock.json" ]; then
        npx tsc
    else
        echo "    Run 'npm install' in sdk/typescript/server/ first."
    fi
}

case "${1:-all}" in
    validate)
        validate
        ;;
    build)
        build_ts
        ;;
    all)
        validate
        build_ts
        ;;
    *)
        echo "Usage: $0 {validate|build|all}"
        exit 1
        ;;
esac
