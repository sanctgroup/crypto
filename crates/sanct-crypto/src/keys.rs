use hmac::{Hmac, KeyInit, Mac};
use ml_kem::{DecapsulationKey, KeyExport, MlKem768, Seed};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hybrid::{MlKemEncoding, MlKemKeyPair, X25519KeyPair};
use crate::signing;
use crate::symmetric;
use crate::CryptoError;

type HmacSha256 = Hmac<Sha256>;

const BUNDLE_AAD: &[u8] = b"sanct-private-bundle-v1";
const ACCOUNT_KEY_AAD_PREFIX: &[u8] = b"sanct-account-key-v1:";
const KEY_LEN: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityKeyBundle {
    pub x25519_public: Vec<u8>,
    pub mlkem768_public: Vec<u8>,
    pub ed25519_public: Vec<u8>,
    pub mldsa65_public: Vec<u8>,
    pub key_version: u32,
    pub encrypted_private_bundle: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreviousKeys {
    pub x25519_secret: Vec<u8>,
    pub mlkem768_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKeys {
    pub x25519_secret: Vec<u8>,
    pub mlkem768_secret: Vec<u8>,
    pub threading_key: Vec<u8>,
    pub data_key: Vec<u8>,
    pub ed25519_seed: Vec<u8>,
    pub mldsa65_seed: Vec<u8>,
    pub key_version: u32,
    pub previous: Vec<PreviousKeys>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapPurpose {
    Password,
    Recovery,
    Passkey,
}

impl WrapPurpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Password => b"password",
            Self::Recovery => b"recovery",
            Self::Passkey => b"passkey",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        match value {
            "password" => Ok(Self::Password),
            "recovery" => Ok(Self::Recovery),
            "passkey" => Ok(Self::Passkey),
            _ => Err(CryptoError::InvalidCiphertext),
        }
    }
}

pub fn generate_account_key() -> Zeroizing<[u8; KEY_LEN]> {
    random_key()
}

pub fn wrap_account_key(
    wrap_key: &[u8],
    account_key: &[u8],
    purpose: WrapPurpose,
) -> Result<Vec<u8>, CryptoError> {
    if account_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength(account_key.len()));
    }
    symmetric::encrypt(wrap_key, &account_key_aad(purpose), account_key)
}

pub fn unwrap_account_key(
    wrap_key: &[u8],
    wrapped: &[u8],
    purpose: WrapPurpose,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let account_key = Zeroizing::new(symmetric::decrypt(
        wrap_key,
        &account_key_aad(purpose),
        wrapped,
    )?);
    if account_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(account_key)
}

fn account_key_aad(purpose: WrapPurpose) -> Vec<u8> {
    [ACCOUNT_KEY_AAD_PREFIX, purpose.label()].concat()
}

pub fn generate_identity_keys(account_key: &[u8]) -> Result<IdentityKeyBundle, CryptoError> {
    if account_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength(account_key.len()));
    }

    let threading_key = random_key();
    let data_key = random_key();
    build_identity(
        account_key,
        1,
        &threading_key[..],
        &data_key[..],
        Vec::new(),
    )
}

pub fn rotate_identity_keys(
    account_key: &[u8],
    current: &PrivateKeys,
) -> Result<IdentityKeyBundle, CryptoError> {
    if account_key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength(account_key.len()));
    }

    let mut previous = Vec::with_capacity(current.previous.len() + 1);
    previous.push(PreviousKeys {
        x25519_secret: current.x25519_secret.clone(),
        mlkem768_secret: current.mlkem768_secret.clone(),
    });
    for entry in &current.previous {
        previous.push(PreviousKeys {
            x25519_secret: entry.x25519_secret.clone(),
            mlkem768_secret: entry.mlkem768_secret.clone(),
        });
    }

    let next_version = current
        .key_version
        .checked_add(1)
        .ok_or(CryptoError::KeyDerivation("key version overflow".into()))?;
    build_identity(
        account_key,
        next_version,
        &current.threading_key,
        &current.data_key,
        previous,
    )
}

fn build_identity(
    account_key: &[u8],
    key_version: u32,
    threading_key: &[u8],
    data_key: &[u8],
    previous: Vec<PreviousKeys>,
) -> Result<IdentityKeyBundle, CryptoError> {
    let x25519_kp = X25519KeyPair::generate();
    let mlkem_kp = MlKemKeyPair::generate();
    let ed25519_seed = random_key();
    let mldsa65_seed = random_key();
    let signing_public = signing::public_keys(&ed25519_seed[..], &mldsa65_seed[..])?;

    let private_keys = PrivateKeys {
        x25519_secret: x25519_kp.secret.as_bytes().to_vec(),
        mlkem768_secret: mlkem_kp.decapsulation_key.as_bytes().to_vec(),
        threading_key: threading_key.to_vec(),
        data_key: data_key.to_vec(),
        ed25519_seed: ed25519_seed.to_vec(),
        mldsa65_seed: mldsa65_seed.to_vec(),
        key_version,
        previous,
    };

    let private_bytes = Zeroizing::new(serialize_private_keys(&private_keys)?);
    let encrypted_private_bundle = symmetric::encrypt(account_key, BUNDLE_AAD, &private_bytes)?;

    Ok(IdentityKeyBundle {
        x25519_public: x25519_kp.public.as_bytes().to_vec(),
        mlkem768_public: mlkem_kp.encapsulation_key.as_bytes().to_vec(),
        ed25519_public: signing_public.ed25519.clone(),
        mldsa65_public: signing_public.mldsa65.clone(),
        key_version,
        encrypted_private_bundle,
    })
}

pub fn serialize_private_keys(keys: &PrivateKeys) -> Result<Vec<u8>, CryptoError> {
    serde_json::to_vec(keys).map_err(|e| CryptoError::Serialization(e.to_string()))
}

pub fn parse_private_keys(bytes: &[u8]) -> Result<PrivateKeys, CryptoError> {
    serde_json::from_slice(bytes).map_err(|e| CryptoError::Serialization(e.to_string()))
}

pub fn decrypt_private_bundle(
    account_key: &[u8],
    encrypted_bundle: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decrypted = Zeroizing::new(symmetric::decrypt(
        account_key,
        BUNDLE_AAD,
        encrypted_bundle,
    )?);
    parse_private_keys(&decrypted)?;
    Ok(decrypted)
}

fn random_key() -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).expect("OS randomness unavailable");
    key
}

pub fn derive_lookup_public_keys(lookup_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(Some(b"sanct-directory-lookup-v1"), lookup_key);

    let mut x25519_seed = Zeroizing::new([0u8; 32]);
    let mut mlkem_d = Zeroizing::new([0u8; 32]);
    let mut mlkem_z = Zeroizing::new([0u8; 32]);

    hk.expand(b"x25519-secret", x25519_seed.as_mut())
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"mlkem-d", mlkem_d.as_mut())
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"mlkem-z", mlkem_z.as_mut())
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;

    let x25519 = X25519KeyPair::from_secret_bytes(&x25519_seed);
    let mut seed = Seed::default();
    seed[..32].copy_from_slice(mlkem_d.as_ref());
    seed[32..].copy_from_slice(mlkem_z.as_ref());
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    seed.as_mut_slice().zeroize();
    let ek = dk.encapsulation_key();
    mlkem_d.zeroize();
    mlkem_z.zeroize();
    x25519_seed.zeroize();

    Ok((x25519.public.as_bytes().to_vec(), ek.to_bytes().to_vec()))
}

pub fn derive_lookup_signing_keys(
    lookup_key: &[u8],
) -> Result<signing::SigningPublicKeys, CryptoError> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(Some(b"sanct-directory-signing-lookup-v1"), lookup_key);
    let mut ed25519_seed = Zeroizing::new([0u8; KEY_LEN]);
    let mut mldsa65_seed = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(b"ed25519", ed25519_seed.as_mut())
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"mldsa65", mldsa65_seed.as_mut())
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    signing::public_keys(&ed25519_seed[..], &mldsa65_seed[..])
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
    fn identity_roundtrip() {
        let account_key = [0xABu8; 32];
        let bundle = generate_identity_keys(&account_key).unwrap();

        assert_eq!(bundle.x25519_public.len(), 32);
        assert_eq!(bundle.ed25519_public.len(), 32);
        assert_eq!(bundle.mldsa65_public.len(), 1952);
        assert_eq!(bundle.key_version, 1);

        let bytes = decrypt_private_bundle(&account_key, &bundle.encrypted_private_bundle).unwrap();
        let keys = parse_private_keys(&bytes).unwrap();
        assert_eq!(keys.x25519_secret.len(), 32);
        assert_eq!(keys.threading_key.len(), 32);
        assert_eq!(keys.data_key.len(), 32);
        assert_ne!(keys.threading_key, keys.data_key);
    }

    #[test]
    fn threading_key_does_not_depend_on_account_key() {
        let account_key = [0xABu8; 32];
        let one = generate_identity_keys(&account_key).unwrap();
        let two = generate_identity_keys(&account_key).unwrap();
        let one = parse_private_keys(
            &decrypt_private_bundle(&account_key, &one.encrypted_private_bundle).unwrap(),
        )
        .unwrap();
        let two = parse_private_keys(
            &decrypt_private_bundle(&account_key, &two.encrypted_private_bundle).unwrap(),
        )
        .unwrap();
        assert_ne!(one.threading_key, two.threading_key);
    }

    #[test]
    fn wrong_account_key_fails() {
        let bundle = generate_identity_keys(&[0xABu8; 32]).unwrap();
        assert!(decrypt_private_bundle(&[0xCDu8; 32], &bundle.encrypted_private_bundle).is_err());
    }

    #[test]
    fn account_key_wrap_is_bound_to_purpose() {
        let wrap = [1u8; 32];
        let account = generate_account_key();
        let wrapped = wrap_account_key(&wrap, &account[..], WrapPurpose::Password).unwrap();
        assert_eq!(
            &unwrap_account_key(&wrap, &wrapped, WrapPurpose::Password).unwrap()[..],
            &account[..]
        );
        assert!(unwrap_account_key(&wrap, &wrapped, WrapPurpose::Recovery).is_err());
        assert!(unwrap_account_key(&[2u8; 32], &wrapped, WrapPurpose::Password).is_err());
    }

    #[test]
    fn rotation_keeps_old_keys_and_stable_secrets() {
        let account_key = [0x11u8; 32];
        let first = generate_identity_keys(&account_key).unwrap();
        let first_keys = parse_private_keys(
            &decrypt_private_bundle(&account_key, &first.encrypted_private_bundle).unwrap(),
        )
        .unwrap();

        let second = rotate_identity_keys(&account_key, &first_keys).unwrap();
        assert_eq!(second.key_version, 2);
        assert_ne!(second.x25519_public, first.x25519_public);
        assert_ne!(second.ed25519_public, first.ed25519_public);

        let second_keys = parse_private_keys(
            &decrypt_private_bundle(&account_key, &second.encrypted_private_bundle).unwrap(),
        )
        .unwrap();
        assert_eq!(second_keys.threading_key, first_keys.threading_key);
        assert_eq!(second_keys.data_key, first_keys.data_key);
        assert_eq!(second_keys.previous.len(), 1);
        assert_eq!(
            second_keys.previous[0].x25519_secret,
            first_keys.x25519_secret
        );
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
