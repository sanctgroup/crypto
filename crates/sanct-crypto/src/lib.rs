pub mod envelope;
pub mod hybrid;
pub mod keys;
pub mod password;
pub mod pgp;
pub mod recovery;
pub mod symmetric;

#[cfg(feature = "wasm")]
pub mod wasm;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed (wrong key or tampered data)")]
    DecryptionFailed,

    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    #[error("Unsupported envelope version: {0}")]
    UnsupportedVersion(u8),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
