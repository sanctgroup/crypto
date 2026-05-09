// swift-tools-version:5.9
import PackageDescription

// Updated by scripts/build-swift.sh on release. To update manually:
//   1. Build & zip: ./scripts/build-swift.sh <tag>
//   2. Upload swift/SanctCryptoFFI.xcframework.zip to GitHub release <tag>
//   3. The script rewrites the url + checksum below.
let releaseURL = "https://github.com/sanctgroup/crypto/releases/download/v0.2.0/SanctCryptoFFI.xcframework.zip"
let releaseChecksum = "400a6f38d26464e95ceafa915f6c4ed9d29f72157e302713ee9c33330e3c64dd"

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
