#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/wasm"

WASM_PACK_VERSION="0.13.1"

needs_install=true
if command -v wasm-pack &>/dev/null; then
    current=$(wasm-pack --version | awk '{print $2}')
    if [ "$current" = "$WASM_PACK_VERSION" ]; then
        needs_install=false
    else
        echo "wasm-pack $current found, but $WASM_PACK_VERSION is required. Reinstalling..."
    fi
fi

if [ "$needs_install" = true ]; then
    cargo install wasm-pack --version "$WASM_PACK_VERSION" --locked --force
fi

echo "Building sanct-wasm for web..."
wasm-pack build \
    --target web \
    --out-dir "$OUT_DIR" \
    "$ROOT_DIR/crates/sanct-wasm"

rm -f "$OUT_DIR/.gitignore"

echo "Done! Output in wasm/"
