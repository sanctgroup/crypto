use hmac::{Hmac, Mac};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, B32};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hybrid::{MlKemKeyPair, X25519KeyPair};
use crate::symmetric;
use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityKeyBundle {
    pub x25519_public: Vec<u8>,
    pub mlkem768_public: Vec<u8>,
    pub encrypted_private_bundle: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeys {
    pub x25519_secret: Vec<u8>,
    pub mlkem768_secret: Vec<u8>,
    pub threading_key: Vec<u8>,
}

pub fn generate_identity_keys(master_key: &[u8]) -> Result<IdentityKeyBundle, CryptoError> {
    if master_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(master_key.len()));
    }

    let x25519_kp = X25519KeyPair::generate();
    let mlkem_kp = MlKemKeyPair::generate();
    let threading_key = derive_threading_key(master_key)?;

    let private_keys = PrivateKeys {
        x25519_secret: x25519_kp.secret.as_bytes().to_vec(),
        mlkem768_secret: mlkem_kp.decapsulation_key.as_bytes().to_vec(),
        threading_key: threading_key.to_vec(),
    };

    let private_bytes = Zeroizing::new(
        serde_json::to_vec(&private_keys).map_err(|e| CryptoError::Serialization(e.to_string()))?,
    );
    let encrypted_private_bundle = symmetric::encrypt(master_key, &private_bytes)?;

    Ok(IdentityKeyBundle {
        x25519_public: x25519_kp.public.as_bytes().to_vec(),
        mlkem768_public: mlkem_kp.encapsulation_key.as_bytes().to_vec(),
        encrypted_private_bundle,
    })
}

pub fn derive_lookup_public_keys(lookup_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(Some(b"sanct-directory-lookup-v1"), lookup_key);

    let mut x25519_seed = [0u8; 32];
    let mut mlkem_d = [0u8; 32];
    let mut mlkem_z = [0u8; 32];

    hk.expand(b"x25519-secret", &mut x25519_seed)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"mlkem-d", &mut mlkem_d)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"mlkem-z", &mut mlkem_z)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;

    let x25519 = X25519KeyPair::from_secret_bytes(&x25519_seed);
    let d = B32::from(mlkem_d);
    let z = B32::from(mlkem_z);
    let (_, ek) = MlKem768::generate_deterministic(&d, &z);

    Ok((x25519.public.as_bytes().to_vec(), ek.as_bytes().to_vec()))
}

pub fn decrypt_private_bundle(
    master_key: &[u8],
    encrypted_bundle: &[u8],
) -> Result<PrivateKeys, CryptoError> {
    let decrypted = Zeroizing::new(symmetric::decrypt(master_key, encrypted_bundle)?);
    let keys: PrivateKeys = serde_json::from_slice(&decrypted)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    Ok(keys)
}

fn derive_threading_key(master_key: &[u8]) -> Result<[u8; 32], CryptoError> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(b"sanct-threading-key-v1"), master_key);
    let mut key = [0u8; 32];
    hk.expand(b"threading-hmac", &mut key)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    Ok(key)
}

pub fn compute_subject_hash(threading_key: &[u8], subject: &str) -> Vec<u8> {
    let normalized = normalize_subject(subject);
    let mut mac = HmacSha256::new_from_slice(threading_key).expect("HMAC accepts any key length");
    mac.update(normalized.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

pub fn derive_server_threading_key(server_secret: &[u8], user_id: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(user_id);
    mac.finalize().into_bytes().into()
}

pub fn normalize_subject(s: &str) -> String {
    let mut normalized = s.trim();

    loop {
        let next = strip_prefix_ci(normalized, "re:")
            .or_else(|| strip_prefix_ci(normalized, "fwd:"))
            .or_else(|| strip_prefix_ci(normalized, "fw:"));

        match next {
            Some(rest) => normalized = rest.trim_start(),
            None => break,
        }
    }

    normalized.to_lowercase()
}

fn strip_prefix_ci<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_decrypt_roundtrip() {
        let master_key = [0xABu8; 32];
        let bundle = generate_identity_keys(&master_key).unwrap();

        assert_eq!(bundle.x25519_public.len(), 32);
        assert!(!bundle.mlkem768_public.is_empty());
        assert!(!bundle.encrypted_private_bundle.is_empty());

        let private_keys =
            decrypt_private_bundle(&master_key, &bundle.encrypted_private_bundle).unwrap();
        assert_eq!(private_keys.x25519_secret.len(), 32);
        assert!(!private_keys.mlkem768_secret.is_empty());
        assert_eq!(private_keys.threading_key.len(), 32);
    }

    #[test]
    fn test_wrong_master_key_fails() {
        let master_key = [0xABu8; 32];
        let wrong_key = [0xCDu8; 32];
        let bundle = generate_identity_keys(&master_key).unwrap();
        assert!(decrypt_private_bundle(&wrong_key, &bundle.encrypted_private_bundle).is_err());
    }

    #[test]
    fn test_subject_hash_deterministic() {
        let key = [42u8; 32];
        let h1 = compute_subject_hash(&key, "Hello World");
        let h2 = compute_subject_hash(&key, "Hello World");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_subject_hash_normalizes() {
        let key = [42u8; 32];
        let h1 = compute_subject_hash(&key, "Hello");
        let h2 = compute_subject_hash(&key, "Re: Hello");
        let h3 = compute_subject_hash(&key, "  RE: hello  ");
        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn test_subject_hash_different_keys() {
        let h1 = compute_subject_hash(&[1u8; 32], "Hello");
        let h2 = compute_subject_hash(&[2u8; 32], "Hello");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_end_to_end_encrypt_decrypt() {
        let master_key = [0x42u8; 32];
        let bundle = generate_identity_keys(&master_key).unwrap();
        let private_keys =
            decrypt_private_bundle(&master_key, &bundle.encrypted_private_bundle).unwrap();

        let plaintext = b"Top secret message from Sanct";

        let sealed = crate::envelope::SealedEnvelope::seal(
            &bundle.x25519_public,
            &bundle.mlkem768_public,
            plaintext,
        )
        .unwrap();

        let decrypted = sealed
            .open(&private_keys.x25519_secret, &private_keys.mlkem768_secret)
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_subject_hash_empty_string() {
        let key = [42u8; 32];
        let hash = compute_subject_hash(&key, "");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_subject_hash_unicode() {
        let key = [42u8; 32];
        let hash = compute_subject_hash(&key, "Re: Привет мир 🌍");
        assert_eq!(hash.len(), 32);
        let hash2 = compute_subject_hash(&key, "Re: こんにちは");
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_derive_server_threading_key() {
        let secret = b"server-secret-key-for-testing!!!";
        let k1 = derive_server_threading_key(secret, b"user-1");
        let k2 = derive_server_threading_key(secret, b"user-1");
        assert_eq!(k1, k2);
        let k3 = derive_server_threading_key(secret, b"user-2");
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_normalize_subject_chained_prefixes() {
        let normalized = normalize_subject("Re: Fwd: Re: Hello");
        assert_eq!(normalized, "hello");
    }
}
