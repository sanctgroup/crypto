use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::CryptoError;

const SHARED_SECRET_LEN: usize = 32;
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

pub struct X25519KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

pub struct MlKemKeyPair {
    pub decapsulation_key: <MlKem768 as KemCore>::DecapsulationKey,
    pub encapsulation_key: <MlKem768 as KemCore>::EncapsulationKey,
}

impl MlKemKeyPair {
    pub fn generate() -> Self {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        Self {
            decapsulation_key: dk,
            encapsulation_key: ek,
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridEncapsulation {
    pub x25519_ephemeral_public: [u8; 32],
    pub mlkem_ciphertext: [u8; MLKEM_CIPHERTEXT_LEN],
    pub shared_secret: [u8; SHARED_SECRET_LEN],
}

pub fn encapsulate(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
) -> Result<HybridEncapsulation, CryptoError> {
    let x25519_ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let x25519_ephemeral_public = PublicKey::from(&x25519_ephemeral);
    let recipient_x25519 = PublicKey::from(
        <[u8; 32]>::try_from(recipient_x25519_public)
            .map_err(|_| CryptoError::InvalidKeyLength(recipient_x25519_public.len()))?,
    );
    let x25519_shared = x25519_ephemeral.diffie_hellman(&recipient_x25519);

    let mlkem_ek = ek_from_bytes(recipient_mlkem_public)?;
    let (mlkem_ciphertext, mlkem_shared) = mlkem_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut mlkem_ciphertext_bytes = [0u8; MLKEM_CIPHERTEXT_LEN];
    mlkem_ciphertext_bytes.copy_from_slice(mlkem_ciphertext.as_slice());

    let eph_pub_bytes = x25519_ephemeral_public.to_bytes();
    let combined = combine_shared_secrets_v2(
        x25519_shared.as_bytes(),
        mlkem_shared.as_slice(),
        &eph_pub_bytes,
        &mlkem_ciphertext_bytes,
    )?;

    Ok(HybridEncapsulation {
        x25519_ephemeral_public: eph_pub_bytes,
        mlkem_ciphertext: mlkem_ciphertext_bytes,
        shared_secret: combined,
    })
}

pub fn decapsulate(
    x25519_private: &[u8],
    mlkem_private: &[u8],
    x25519_ephemeral_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let (x25519_shared, mlkem_shared) = decapsulate_raw(
        x25519_private,
        mlkem_private,
        x25519_ephemeral_public,
        mlkem_ciphertext,
    )?;

    let mut mlkem_ct_bytes = [0u8; MLKEM_CIPHERTEXT_LEN];
    mlkem_ct_bytes.copy_from_slice(mlkem_ciphertext);

    combine_shared_secrets_v2(
        x25519_shared.as_ref(),
        mlkem_shared.as_ref(),
        x25519_ephemeral_public,
        &mlkem_ct_bytes,
    )
}

#[doc(hidden)]
pub fn decapsulate_v1(
    x25519_private: &[u8],
    mlkem_private: &[u8],
    x25519_ephemeral_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    let (x25519_shared, mlkem_shared) = decapsulate_raw(
        x25519_private,
        mlkem_private,
        x25519_ephemeral_public,
        mlkem_ciphertext,
    )?;
    combine_shared_secrets_v1(x25519_shared.as_ref(), mlkem_shared.as_ref())
}

type Ss = Zeroizing<[u8; SHARED_SECRET_LEN]>;

fn decapsulate_raw(
    x25519_private: &[u8],
    mlkem_private: &[u8],
    x25519_ephemeral_public: &[u8; 32],
    mlkem_ciphertext: &[u8],
) -> Result<(Ss, Ss), CryptoError> {
    let x25519_secret = StaticSecret::from(
        <[u8; 32]>::try_from(x25519_private)
            .map_err(|_| CryptoError::InvalidKeyLength(x25519_private.len()))?,
    );
    let x25519_ephemeral = PublicKey::from(*x25519_ephemeral_public);
    let x25519_shared = x25519_secret.diffie_hellman(&x25519_ephemeral);

    let mlkem_dk = dk_from_bytes(mlkem_private)?;
    let mlkem_ct = ct_from_bytes(mlkem_ciphertext)?;
    let mlkem_ss = mlkem_dk
        .decapsulate(&mlkem_ct)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let mut x_buf = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    x_buf.copy_from_slice(x25519_shared.as_bytes());
    let mut m_buf = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    m_buf.copy_from_slice(mlkem_ss.as_slice());

    Ok((x_buf, m_buf))
}

fn ek_from_bytes(bytes: &[u8]) -> Result<<MlKem768 as KemCore>::EncapsulationKey, CryptoError> {
    let arr = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(bytes.len()))?;
    Ok(<MlKem768 as KemCore>::EncapsulationKey::from_bytes(arr))
}

fn dk_from_bytes(bytes: &[u8]) -> Result<<MlKem768 as KemCore>::DecapsulationKey, CryptoError> {
    let arr = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(bytes.len()))?;
    Ok(<MlKem768 as KemCore>::DecapsulationKey::from_bytes(arr))
}

fn ct_from_bytes(bytes: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>, CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidCiphertext)
}

fn combine_shared_secrets_v1(
    x25519_shared: &[u8],
    mlkem_shared: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    if x25519_shared.len() != SHARED_SECRET_LEN || mlkem_shared.len() != SHARED_SECRET_LEN {
        return Err(CryptoError::KeyDerivation(
            "unexpected hybrid shared secret length".into(),
        ));
    }

    let mut ikm = Zeroizing::new([0u8; SHARED_SECRET_LEN * 2]);
    ikm[..SHARED_SECRET_LEN].copy_from_slice(x25519_shared);
    ikm[SHARED_SECRET_LEN..].copy_from_slice(mlkem_shared);

    let hk = Hkdf::<Sha256>::new(Some(b"sanct-hybrid-kem-v1"), ikm.as_ref());
    let mut output = [0u8; SHARED_SECRET_LEN];
    hk.expand(b"sanct-message-key", &mut output)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;

    Ok(output)
}

fn combine_shared_secrets_v2(
    x25519_shared: &[u8],
    mlkem_shared: &[u8],
    x25519_ephemeral_public: &[u8; 32],
    mlkem_ciphertext: &[u8; MLKEM_CIPHERTEXT_LEN],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    if x25519_shared.len() != SHARED_SECRET_LEN || mlkem_shared.len() != SHARED_SECRET_LEN {
        return Err(CryptoError::KeyDerivation(
            "unexpected hybrid shared secret length".into(),
        ));
    }

    const IKM_LEN: usize = SHARED_SECRET_LEN * 2 + 32 + MLKEM_CIPHERTEXT_LEN;
    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    let mut offset = 0;
    ikm[offset..offset + SHARED_SECRET_LEN].copy_from_slice(x25519_shared);
    offset += SHARED_SECRET_LEN;
    ikm[offset..offset + SHARED_SECRET_LEN].copy_from_slice(mlkem_shared);
    offset += SHARED_SECRET_LEN;
    ikm[offset..offset + 32].copy_from_slice(x25519_ephemeral_public);
    offset += 32;
    ikm[offset..offset + MLKEM_CIPHERTEXT_LEN].copy_from_slice(mlkem_ciphertext);

    let hk = Hkdf::<Sha256>::new(Some(b"sanct-hybrid-kem-v2"), ikm.as_ref());
    let mut output = [0u8; SHARED_SECRET_LEN];
    hk.expand(b"sanct-message-key", &mut output)
        .map_err(|_| CryptoError::KeyDerivation("HKDF expand failed".into()))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let x25519_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let encap = encapsulate(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
        )
        .unwrap();

        let decap = decapsulate(
            x25519_kp.secret.as_bytes(),
            mlkem_kp.decapsulation_key.as_bytes().as_slice(),
            &encap.x25519_ephemeral_public,
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        assert_eq!(encap.shared_secret, decap);
    }

    #[test]
    fn test_wrong_x25519_key_gives_different_secret() {
        let x25519_kp = X25519KeyPair::generate();
        let wrong_kp = X25519KeyPair::generate();
        let mlkem_kp = MlKemKeyPair::generate();

        let encap = encapsulate(
            x25519_kp.public.as_bytes(),
            mlkem_kp.encapsulation_key.as_bytes().as_slice(),
        )
        .unwrap();

        let decap = decapsulate(
            wrong_kp.secret.as_bytes(),
            mlkem_kp.decapsulation_key.as_bytes().as_slice(),
            &encap.x25519_ephemeral_public,
            &encap.mlkem_ciphertext,
        )
        .unwrap();

        assert_ne!(encap.shared_secret, decap);
    }
}
