#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$ROOT_DIR/crates/sanct-swift"
SWIFT_DIR="$ROOT_DIR/swift"
BUILD_DIR="$ROOT_DIR/target/swift-build"
XCFRAMEWORK_NAME="SanctCryptoFFI"
SWIFT_MODULE_NAME="SanctCrypto"
LIB_NAME="libsanct_swift.a"

TARGETS_DEVICE=("aarch64-apple-ios")
TARGETS_SIM=("aarch64-apple-ios-sim" "x86_64-apple-ios")
TARGETS_MAC=("aarch64-apple-darwin" "x86_64-apple-darwin")
ALL_TARGETS=("${TARGETS_DEVICE[@]}" "${TARGETS_SIM[@]}" "${TARGETS_MAC[@]}")

echo "==> Ensuring rustup targets are installed"
for t in "${ALL_TARGETS[@]}"; do
    rustup target add "$t" >/dev/null
done

echo "==> Building staticlibs (release)"
for t in "${ALL_TARGETS[@]}"; do
    echo "    target: $t"
    cargo build --release --target "$t" -p sanct-swift
done

mkdir -p "$BUILD_DIR"
LIPO_IOS_SIM="$BUILD_DIR/ios-sim/$LIB_NAME"
LIPO_MAC="$BUILD_DIR/macos/$LIB_NAME"
mkdir -p "$BUILD_DIR/ios-sim" "$BUILD_DIR/macos"

echo "==> Lipo: iOS simulator (arm64 + x86_64)"
lipo -create \
    "$ROOT_DIR/target/aarch64-apple-ios-sim/release/$LIB_NAME" \
    "$ROOT_DIR/target/x86_64-apple-ios/release/$LIB_NAME" \
    -output "$LIPO_IOS_SIM"

echo "==> Lipo: macOS (arm64 + x86_64)"
lipo -create \
    "$ROOT_DIR/target/aarch64-apple-darwin/release/$LIB_NAME" \
    "$ROOT_DIR/target/x86_64-apple-darwin/release/$LIB_NAME" \
    -output "$LIPO_MAC"

IOS_DEVICE_LIB="$ROOT_DIR/target/aarch64-apple-ios/release/$LIB_NAME"

echo "==> Generating Swift bindings"
GEN_DIR="$BUILD_DIR/generated"
rm -rf "$GEN_DIR"
mkdir -p "$GEN_DIR"
cargo run --release -p sanct-swift --bin uniffi-bindgen -- generate \
    --library "$IOS_DEVICE_LIB" \
    --language swift \
    --out-dir "$GEN_DIR"

MODULEMAP_DIR="$BUILD_DIR/headers"
rm -rf "$MODULEMAP_DIR"
mkdir -p "$MODULEMAP_DIR"

cp "$GEN_DIR"/*.h "$MODULEMAP_DIR/"
MODULEMAP_SRC="$(ls "$GEN_DIR"/*.modulemap)"
cp "$MODULEMAP_SRC" "$MODULEMAP_DIR/module.modulemap"

XCF_OUT="$SWIFT_DIR/$XCFRAMEWORK_NAME.xcframework"
rm -rf "$XCF_OUT"

echo "==> Building xcframework"
xcodebuild -create-xcframework \
    -library "$IOS_DEVICE_LIB" -headers "$MODULEMAP_DIR" \
    -library "$LIPO_IOS_SIM"   -headers "$MODULEMAP_DIR" \
    -library "$LIPO_MAC"       -headers "$MODULEMAP_DIR" \
    -output "$XCF_OUT"

mkdir -p "$SWIFT_DIR/Sources/$SWIFT_MODULE_NAME"
cp "$GEN_DIR"/*.swift "$SWIFT_DIR/Sources/$SWIFT_MODULE_NAME/"

echo "Done."
echo "  XCFramework: $XCF_OUT"
echo "  Swift sources: $SWIFT_DIR/Sources/$SWIFT_MODULE_NAME"
