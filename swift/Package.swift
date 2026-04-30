// swift-tools-version:5.9
import PackageDescription

// Updated by scripts/build-swift.sh on release. To update manually:
//   1. Build & zip: ./scripts/build-swift.sh <tag>
//   2. Upload swift/SanctCryptoFFI.xcframework.zip to GitHub release <tag>
//   3. The script rewrites the url + checksum below.
let releaseURL = "https://github.com/sanctgroup/crypto/releases/download/v0.1.0/SanctCryptoFFI.xcframework.zip"
let releaseChecksum = "654bd560105c32ceb738ad36cbb1d8aaf2f870db6a572a7faaa94e6505191177"

let package = Package(
    name: "SanctCrypto",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "SanctCrypto", targets: ["SanctCrypto"]),
    ],
    targets: [
        .binaryTarget(
            name: "SanctCryptoFFI",
            url: releaseURL,
            checksum: releaseChecksum
        ),
        .target(
            name: "SanctCrypto",
            dependencies: ["SanctCryptoFFI"],
            path: "Sources/SanctCrypto"
        ),
    ]
)
