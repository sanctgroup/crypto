use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::CryptoError;

const NONCE_LEN: usize = 24;

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt_into(key, plaintext, Vec::new())
}

pub(crate) fn encrypt_into(
    key: &[u8],
    plaintext: &[u8],
    output: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::EncryptionFailed)?;

    let mut output = Zeroizing::new(output);
    output.reserve(NONCE_LEN + plaintext.len() + 16);
    output.extend_from_slice(&nonce);
    let payload_start = output.len();
    output.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&nonce.into(), b"", (&mut output[payload_start..]).into())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    output.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *output))
}

pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }
    if data.len() < NONCE_LEN + 16 {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;

    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0xABu8; 32];
        let plaintext = b"hello world, this is a test message for Sanct";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let encrypted = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0xABu8; 32];
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0xABu8; 32];
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_invalid_key_length() {
        assert!(encrypt(&[0u8; 16], b"test").is_err());
    }

    #[test]
    fn test_large_payload() {
        let key = [0xABu8; 32];
        let plaintext = vec![0x42u8; 1024 * 1024];
        let encrypted = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
