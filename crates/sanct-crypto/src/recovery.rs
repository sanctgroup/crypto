use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

const RECOVERY_KEY_LEN: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase {
    pub phrase: String,
    pub keys: RecoveryKeys,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKeys {
    pub auth_key: [u8; RECOVERY_KEY_LEN],
    pub wrap_key: [u8; RECOVERY_KEY_LEN],
}

pub fn generate_recovery_phrase() -> Result<RecoveryPhrase, CryptoError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::fill(entropy.as_mut()).expect("OS randomness unavailable");

    let phrase = format_phrase(&entropy);
    let keys = derive_recovery_keys(&entropy)?;

    Ok(RecoveryPhrase { phrase, keys })
}

pub fn recovery_keys_from_phrase(phrase: &str) -> Result<RecoveryKeys, CryptoError> {
    let entropy = Zeroizing::new(parse_phrase(phrase)?);
    derive_recovery_keys(&entropy)
}

pub fn hash_recovery_auth_key(auth_key: &[u8]) -> Vec<u8> {
    Sha256::digest(auth_key).to_vec()
}

pub fn verify_recovery_auth_key(auth_key: &[u8], stored_hash: &[u8]) -> bool {
    if auth_key.len() != RECOVERY_KEY_LEN {
        return false;
    }
    let computed = Sha256::digest(auth_key);
    bool::from(computed.as_slice().ct_eq(stored_hash))
}

fn derive_recovery_keys(entropy: &[u8; 32]) -> Result<RecoveryKeys, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"sanct-recovery-split-v1"), entropy);
    let mut keys = RecoveryKeys {
        auth_key: [0u8; RECOVERY_KEY_LEN],
        wrap_key: [0u8; RECOVERY_KEY_LEN],
    };
    hk.expand(b"auth", &mut keys.auth_key)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"wrap", &mut keys.wrap_key)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    Ok(keys)
}

fn format_phrase(entropy: &[u8; 32]) -> String {
    let hex = hex_encode(entropy);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
        .to_uppercase()
}

fn parse_phrase(phrase: &str) -> Result<[u8; 32], CryptoError> {
    if phrase.len() > 256
        || phrase
            .chars()
            .any(|c| !c.is_ascii_hexdigit() && c != '-' && !c.is_ascii_whitespace())
    {
        return Err(CryptoError::InvalidCiphertext);
    }
    let cleaned = Zeroizing::new(
        phrase
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>(),
    );

    let cleaned = Zeroizing::new(cleaned.to_lowercase());
    if cleaned.len() != 64 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
    }
    Ok(bytes)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_reproduces_keys() {
        let generated = generate_recovery_phrase().unwrap();
        let derived = recovery_keys_from_phrase(&generated.phrase).unwrap();
        assert_eq!(generated.keys.auth_key, derived.auth_key);
        assert_eq!(generated.keys.wrap_key, derived.wrap_key);
        assert_ne!(derived.auth_key, derived.wrap_key);
    }

    #[test]
    fn hash_of_auth_key_verifies_and_reveals_nothing_about_wrap_key() {
        let generated = generate_recovery_phrase().unwrap();
        let stored = hash_recovery_auth_key(&generated.keys.auth_key);
        assert!(verify_recovery_auth_key(&generated.keys.auth_key, &stored));
        assert!(!verify_recovery_auth_key(&generated.keys.wrap_key, &stored));
        assert!(!verify_recovery_auth_key(&[0u8; 16], &stored));
    }

    #[test]
    fn malformed_phrases_rejected() {
        assert!(recovery_keys_from_phrase("not hex at all").is_err());
        assert!(recovery_keys_from_phrase("ABCD").is_err());
        assert!(recovery_keys_from_phrase(&"A".repeat(300)).is_err());
    }
}
