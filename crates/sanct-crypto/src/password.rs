use argon2::{self, Argon2, Params};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::CryptoError;

const MASTER_KEY_LEN: usize = 32;

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, CryptoError> {
    let params = Params::new(65536, 3, 1, Some(MASTER_KEY_LEN))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

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
