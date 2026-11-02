use argon2::{self, Argon2, Params};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

const MASTER_KEY_LEN: usize = 32;

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("OS randomness unavailable");
    salt
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PasswordKeys {
    pub auth_key: [u8; MASTER_KEY_LEN],
    pub wrap_key: [u8; MASTER_KEY_LEN],
}

pub fn derive_password_keys(password: &[u8], salt: &[u8]) -> Result<PasswordKeys, CryptoError> {
    let master = derive_master_key(password, salt)?;
    let hk = Hkdf::<Sha256>::new(Some(b"sanct-password-split-v1"), master.as_ref());
    let mut keys = PasswordKeys {
        auth_key: [0u8; MASTER_KEY_LEN],
        wrap_key: [0u8; MASTER_KEY_LEN],
    };
    hk.expand(b"auth", &mut keys.auth_key)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    hk.expand(b"wrap", &mut keys.wrap_key)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;
    Ok(keys)
}

fn derive_master_key(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CryptoError> {
    let params = Params::new(65536, 3, 1, Some(MASTER_KEY_LEN))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    let mut memory = Zeroizing::new(vec![
        argon2::Block::default();
        argon2.params().block_count()
    ]);
    argon2
        .hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_wrap_keys_are_independent() {
        let salt = [42u8; 32];
        let keys = derive_password_keys(b"test-password", &salt).unwrap();
        let master = derive_master_key(b"test-password", &salt).unwrap();
        assert_ne!(keys.auth_key, keys.wrap_key);
        assert_ne!(keys.auth_key, *master);
        assert_ne!(keys.wrap_key, *master);
        let again = derive_password_keys(b"test-password", &salt).unwrap();
        assert_eq!(keys.auth_key, again.auth_key);
        assert_eq!(keys.wrap_key, again.wrap_key);
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let salt = [42u8; 32];
        let key1 = derive_master_key(b"test-password", &salt).unwrap();
        let key2 = derive_master_key(b"test-password", &salt).unwrap();
        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [42u8; 32];
        let key1 = derive_master_key(b"password-a", &salt).unwrap();
        let key2 = derive_master_key(b"password-b", &salt).unwrap();
        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let key1 = derive_master_key(b"same-password", &[1u8; 32]).unwrap();
        let key2 = derive_master_key(b"same-password", &[2u8; 32]).unwrap();
        assert_ne!(&*key1, &*key2);
    }
}
