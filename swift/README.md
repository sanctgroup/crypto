# SanctCrypto (Swift)

Swift Package wrapping the `sanct-crypto` Rust library for iOS and macOS.

## Build

From the repo root:

```sh
./scripts/build-swift.sh
```

This will:

1. Compile `sanct-swift` as a static library for `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`, `aarch64-apple-darwin`, and `x86_64-apple-darwin`.
2. Lipo the simulator and macOS slices.
3. Generate Swift bindings via UniFFI (`uniffi-bindgen`).
4. Produce `swift/SanctCryptoFFI.xcframework` and copy generated `.swift` sources into `swift/Sources/SanctCrypto/`.

After running it once, the contents of `swift/` form a working Swift Package consumable via SPM:

```swift
.package(path: "../crypto/swift")
```

or (once published) by Git URL.

## Requirements

- Xcode 15+ (for `xcodebuild -create-xcframework`)
- Rust toolchain with the five Apple targets (`rustup target add ...` is automated by the script)

## API

The Swift API mirrors `sanct-wasm`:

- `generateSalt()`, `deriveMasterKey(password:salt:)`
- `generateIdentityKeys(masterKey:)`, `decryptPrivateKeys(masterKey:encryptedBundle:)`
- `encryptMessage`, `decryptMessage`, `sealForRecipient`, `sealMetadataForRecipient`, `encryptDraft`
- `encryptMetadata`, `decryptMetadata`, `computeSubjectHash`
- Recovery: `generateRecoveryPhrase`, `recoveryKeyFromPhrase`, `hashRecoveryKey`, `encryptBundleForRecovery`, `decryptBundleWithRecovery`
- PGP: `pgpGenerateKey`, `pgpImportKey`, `pgpExportKey`, `pgpKeyInfo`, `pgpEncryptToRecipients`, `pgpDecryptMessage`

Errors throw `SanctCryptoError`.
