use crate::hybrid;
use crate::symmetric;
use crate::CryptoError;

const ENVELOPE_VERSION: u8 = 1;
const X25519_PUB_LEN: usize = 32;
const HEADER_LEN: usize = 1 + X25519_PUB_LEN + hybrid::MLKEM_CIPHERTEXT_LEN;

/// Wire format: `[version | x25519_ephemeral | mlkem_ct | nonce | ciphertext | tag]`
pub struct SealedEnvelope {
    pub version: u8,
    pub x25519_ephemeral_public: [u8; X25519_PUB_LEN],
    pub mlkem_ciphertext: [u8; hybrid::MLKEM_CIPHERTEXT_LEN],
    pub encrypted_payload: Vec<u8>,
}

impl SealedEnvelope {
    pub fn seal(
        recipient_x25519_public: &[u8],
        recipient_mlkem_public: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        let encap = hybrid::encapsulate(recipient_x25519_public, recipient_mlkem_public)?;
        let encrypted_payload = symmetric::encrypt(&encap.shared_secret, plaintext)?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            x25519_ephemeral_public: encap.x25519_ephemeral_public,
            mlkem_ciphertext: encap.mlkem_ciphertext,
            encrypted_payload,
        })
    }

    pub fn open(
        &self,
        x25519_private: &[u8],
        mlkem_private: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.version != ENVELOPE_VERSION {
            return Err(CryptoError::UnsupportedVersion(self.version));
        }

        let shared_secret = hybrid::decapsulate(
            x25519_private,
            mlkem_private,
            &self.x25519_ephemeral_public,
            &self.mlkem_ciphertext,
        )?;

        symmetric::decrypt(&shared_secret, &self.encrypted_payload)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.encrypted_payload.len());
        buf.push(self.version);
        buf.extend_from_slice(&self.x25519_ephemeral_public);
        buf.extend_from_slice(&self.mlkem_ciphertext);
        buf.extend_from_slice(&self.encrypted_payload);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < HEADER_LEN + 24 + 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let version = data[0];
        let x25519_ephemeral_public: [u8; X25519_PUB_LEN] = data[1..1 + X25519_PUB_LEN]
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let mlkem_ciphertext: [u8; hybrid::MLKEM_CIPHERTEXT_LEN] = data
            [1 + X25519_PUB_LEN..HEADER_LEN]
            .try_into()
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let encrypted_payload = data[HEADER_LEN..].to_vec();

        Ok(Self {
            version,
            x25519_ephemeral_public,
            mlkem_ciphertext,
            encrypted_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::{MlKemKeyPair, X25519KeyPair};
    use ml_kem::EncodedSizeUser;

    #[test]
    fn test_seal_open_roundtrip() {
        let x25519_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let plaintext = b"Hello from Sanct! This is an encrypted message.";

        let sealed = SealedEnvelope::seal(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
            plaintext,
        )
        .unwrap();

        let decrypted = sealed
            .open(
                x25519_kp.secret.as_bytes(),
                mlkem_kp.decapsulation_key.as_bytes().as_slice(),
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let x25519_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let plaintext = b"serialize me";

        let sealed = SealedEnvelope::seal(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
            plaintext,
        )
        .unwrap();

        let bytes = sealed.to_bytes();
        let restored = SealedEnvelope::from_bytes(&bytes).unwrap();

        let decrypted = restored
            .open(
                x25519_kp.secret.as_bytes(),
                mlkem_kp.decapsulation_key.as_bytes().as_slice(),
            )
            .unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let x25519_kp = X25519KeyPair::generate();
        let wrong_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let sealed = SealedEnvelope::seal(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
            b"secret",
        )
        .unwrap();

        let result = sealed.open(
            wrong_kp.secret.as_bytes(),
            mlkem_kp.decapsulation_key.as_bytes().as_slice(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_large_message() {
        let x25519_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let plaintext = vec![0xABu8; 1024 * 1024];

        let sealed = SealedEnvelope::seal(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
            &plaintext,
        )
        .unwrap();

        let decrypted = sealed
            .open(
                x25519_kp.secret.as_bytes(),
                mlkem_kp.decapsulation_key.as_bytes().as_slice(),
            )
            .unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_from_bytes_too_short() {
        let result = SealedEnvelope::from_bytes(&[0u8; 10]);
        assert!(matches!(result, Err(CryptoError::InvalidCiphertext)));
    }

    #[test]
    fn test_from_bytes_wrong_version() {
        let x25519_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let sealed = SealedEnvelope::seal(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
            b"version test",
        )
        .unwrap();

        let mut bytes = sealed.to_bytes();
        bytes[0] = 99;

        let restored = SealedEnvelope::from_bytes(&bytes).unwrap();
        let result = restored.open(
            x25519_kp.secret.as_bytes(),
            mlkem_kp.decapsulation_key.as_bytes().as_slice(),
        );
        assert!(matches!(result, Err(CryptoError::UnsupportedVersion(99))));
    }
}
