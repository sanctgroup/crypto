use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::symmetric;
use crate::CryptoError;

const RECOVERY_KEY_LEN: usize = 32;

pub struct RecoveryPhrase {
    pub phrase: String,
    pub recovery_key: [u8; RECOVERY_KEY_LEN],
}

pub fn generate_recovery_phrase() -> RecoveryPhrase {
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill(&mut entropy);

    let phrase = format_phrase(&entropy);
    let recovery_key = derive_recovery_key(&entropy);

    RecoveryPhrase {
        phrase,
        recovery_key,
    }
}

pub fn recovery_key_from_phrase(phrase: &str) -> Result<[u8; RECOVERY_KEY_LEN], CryptoError> {
    let entropy = parse_phrase(phrase)?;
    Ok(derive_recovery_key(&entropy))
}

pub fn hash_recovery_key(recovery_key: &[u8]) -> Vec<u8> {
    Sha256::digest(recovery_key).to_vec()
}

pub fn verify_recovery_key(recovery_key: &[u8], stored_hash: &[u8]) -> bool {
    let computed = Sha256::digest(recovery_key);
    constant_time_eq(computed.as_slice(), stored_hash)
}

pub fn encrypt_bundle_for_recovery(
    recovery_key: &[u8],
    private_bundle_plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    symmetric::encrypt(recovery_key, private_bundle_plaintext)
}

pub fn decrypt_bundle_with_recovery(
    recovery_key: &[u8],
    recovery_encrypted_bundle: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    symmetric::decrypt(recovery_key, recovery_encrypted_bundle)
}

fn derive_recovery_key(entropy: &[u8; 32]) -> [u8; RECOVERY_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(b"sanct-recovery-key-v1"), entropy);
    let mut key = [0u8; RECOVERY_KEY_LEN];
    hk.expand(b"recovery-master", &mut key)
        .expect("HKDF expand for 32 bytes cannot fail");
    key
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
    let cleaned: String = phrase.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    let cleaned = cleaned.to_lowercase();
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_parse_roundtrip() {
        let rp = generate_recovery_phrase();
        let recovered_key = recovery_key_from_phrase(&rp.phrase).unwrap();
        assert_eq!(rp.recovery_key, recovered_key);
    }

    #[test]
    fn phrase_format() {
        let rp = generate_recovery_phrase();
        let parts: Vec<&str> = rp.phrase.split('-').collect();
        assert_eq!(parts.len(), 16);
        for part in &parts {
            assert_eq!(part.len(), 4);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn verify_hash() {
        let rp = generate_recovery_phrase();
        let hash = hash_recovery_key(&rp.recovery_key);
        assert!(verify_recovery_key(&rp.recovery_key, &hash));
        assert!(!verify_recovery_key(&[0u8; 32], &hash));
    }

    #[test]
    fn encrypt_decrypt_bundle() {
        let rp = generate_recovery_phrase();
        let plaintext = b"secret private keys go here";
        let encrypted = encrypt_bundle_for_recovery(&rp.recovery_key, plaintext).unwrap();
        let decrypted = decrypt_bundle_with_recovery(&rp.recovery_key, &encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let rp = generate_recovery_phrase();
        let encrypted = encrypt_bundle_for_recovery(&rp.recovery_key, b"secret").unwrap();
        let wrong_key = [0u8; 32];
        assert!(decrypt_bundle_with_recovery(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn parse_with_spaces_and_dashes() {
        let rp = generate_recovery_phrase();
        let with_spaces = rp.phrase.replace('-', " ");
        let recovered = recovery_key_from_phrase(&with_spaces).unwrap();
        assert_eq!(rp.recovery_key, recovered);
    }

    #[test]
    fn parse_lowercase() {
        let rp = generate_recovery_phrase();
        let lower = rp.phrase.to_lowercase();
        let recovered = recovery_key_from_phrase(&lower).unwrap();
        assert_eq!(rp.recovery_key, recovered);
    }

    #[test]
    fn invalid_phrase_length() {
        assert!(recovery_key_from_phrase("ABCD-1234").is_err());
    }
}
