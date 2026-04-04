#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/wasm"

if ! command -v wasm-pack &>/dev/null; then
    echo "wasm-pack not found. Installing..."
    cargo install wasm-pack
fi

echo "Building sanct-wasm for web..."
wasm-pack build \
    --target web \
    --out-dir "$OUT_DIR" \
    "$ROOT_DIR/crates/sanct-wasm"

rm -f "$OUT_DIR/.gitignore"

echo "Done! Output in wasm/"
