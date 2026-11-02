use chacha20poly1305::aead::{Aead, AeadInOut, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::CryptoError;

const NONCE_LEN: usize = 24;

pub fn encrypt(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt_into(key, aad, plaintext, Vec::new())
}

pub(crate) fn encrypt_into(
    key: &[u8],
    aad: &[u8],
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
        .encrypt_inout_detached(&nonce.into(), aad, (&mut output[payload_start..]).into())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    output.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *output))
}

pub fn decrypt(key: &[u8], aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_aad() {
        let key = [0xABu8; 32];
        let sealed = encrypt(&key, b"context", b"hello").unwrap();
        assert_eq!(decrypt(&key, b"context", &sealed).unwrap(), b"hello");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0xABu8; 32];
        let sealed = encrypt(&key, b"context", b"hello").unwrap();
        assert!(decrypt(&key, b"other", &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = encrypt(&[0xABu8; 32], b"context", b"hello").unwrap();
        assert!(decrypt(&[0xCDu8; 32], b"context", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0xABu8; 32];
        let mut sealed = encrypt(&key, b"context", b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(decrypt(&key, b"context", &sealed).is_err());
    }

    #[test]
    fn invalid_key_length_rejected() {
        assert!(encrypt(&[0u8; 16], b"", b"x").is_err());
        assert!(decrypt(&[0u8; 16], b"", &[0u8; 64]).is_err());
    }

    #[test]
    fn short_ciphertext_rejected() {
        assert!(decrypt(&[0u8; 32], b"", &[0u8; 10]).is_err());
    }
}
