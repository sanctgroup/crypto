# Sanct's restricted rPGP build

This is a modified copy of rPGP 0.21.0, used only inside Sanct. Upstream source: https://github.com/rpgp/rpgp/tree/c2b192e52b2e7f99777196539ea79b37f1f9ff30. The published `pgp-0.21.0.crate` SHA-256 is `ae70f4d9325a391db30d115d6191a7bb67cec856aa0bba131290f0c4e09a532a`.

The RSA, ECDSA, NIST ECDH, Ed448, X448 and optional OpenPGP PQC providers, their adapters and their dependencies have been removed. Unsupported key generation and parameter decoding return a dedicated fatal DisabledAlgorithm error. Unlike the upstream Unsupported error, this error is not skipped by the composed-key parser. A bundle containing a removed provider is rejected as a whole so importing it cannot silently discard a subkey. Algorithm identifiers and opaque packet encodings remain where they do not need the removed providers. DSA and ElGamal parsing/public verification code remains, but Sanct's private-key policy permits only Ed25519/X25519 and their legacy forms.

This removes the dependency paths to RUSTSEC-2023-0071 (`rsa`) and RUSTSEC-2026-0387 (`crypto-bigint` before 0.7.6). These are provider removals, not fixes to those upstream libraries. The supported Curve25519 cryptographic operations and OpenPGP wire formats are retained from upstream. Sanct's separate hybrid ML-KEM implementation is unchanged.

The crate keeps the upstream package name and version so security scanners can continue to identify rPGP advisories. It is excluded from the workspace and cannot be published. The consuming Rust crates also disable registry publication so Cargo cannot replace this path dependency with the unrestricted crates.io package during publication. Native consumers should use this repository with its vendored source.

The vendored source omits upstream examples, tests, benchmarks, test-only attributes and comments. The error variants belonging to removed providers are removed; constant-time equality now imports `subtle` directly. Local modifications also replace the removed ECDH verification branches with an explicit error. No new cryptographic primitive is implemented here. Original license texts are preserved in LICENSE-MIT and LICENSE-APACHE.

Sanct's tests exercise legacy Curve25519 encryption/signing, RFC 9580 Ed25519/X25519 v4/v6 key import and encryption, signed-message verification, rejection of synthetic RSA/P-256 imports and unsupported provider generation, and compatibility with prior WASM bundles. `cargo-deny` bans RSA and affected crypto-bigint versions without advisory ignores. The checked-in fixture secret keys are disposable test material, never operational identities.

This copy must be reviewed when upstream rPGP changes or publishes a new advisory. Replacing it with an upstream release requires confirming that the banned dependencies remain absent, reviewing provider behavior, rerunning the native/WASM tests and updating the source provenance. A clean advisory scan does not substitute for a cryptographic audit.
