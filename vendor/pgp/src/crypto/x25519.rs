use std::cmp::PartialEq;

use hkdf::HkdfExtract;
use log::debug;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{aes_kw, Decryptor},
    errors::{bail, ensure, Result},
    ser::Serialize,
    types::X25519PublicParams,
};

pub const KEY_LEN: usize = 32;

#[derive(Clone, derive_more::Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[debug("..")]
    secret: StaticSecret,
}

impl From<&SecretKey> for X25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: PublicKey::from(&value.secret),
        }
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.secret.as_bytes().eq(other.secret.as_bytes())
    }
}

impl Eq for SecretKey {}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let mut secret_key_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *secret_key_bytes);

        let secret = StaticSecret::from(*secret_key_bytes);
        SecretKey { secret }
    }

    pub fn try_from_bytes(secret: [u8; KEY_LEN]) -> Result<Self> {
        let secret = x25519_dalek::StaticSecret::from(secret);
        Ok(Self { secret })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.secret.as_bytes()
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let x = self.as_bytes();
        writer.write_all(x)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        KEY_LEN
    }
}

pub struct EncryptionFields<'a> {
    pub ephemeral_public_point: [u8; 32],

    pub recipient_public: [u8; 32],

    pub encrypted_session_key: &'a [u8],
}

impl Decryptor for SecretKey {
    type EncryptionFields<'a> = EncryptionFields<'a>;

    fn decrypt(&self, data: Self::EncryptionFields<'_>) -> Result<Zeroizing<Vec<u8>>> {
        debug!("X25519 decrypt");

        let shared_secret = {
            let their_public = x25519_dalek::PublicKey::from(data.ephemeral_public_point);

            let our_secret = &self.secret;

            let shared_secret = our_secret.diffie_hellman(&their_public);
            if !shared_secret.was_contributory() {
                bail!("All-zero x25519 shared secret");
            }

            shared_secret.to_bytes()
        };

        derive_session_key(
            data.ephemeral_public_point,
            data.recipient_public,
            shared_secret,
            data.encrypted_session_key,
        )
    }
}

pub fn derive_session_key(
    ephemeral: [u8; 32],
    recipient_public: [u8; 32],
    shared_secret: [u8; 32],
    encrypted_session_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let okm = hkdf(&ephemeral, &recipient_public, &shared_secret)?;

    let decrypted_key = aes_kw::unwrap(&*okm, encrypted_session_key)?;
    ensure!(!decrypted_key.is_empty(), "empty key is not valid");

    Ok(decrypted_key)
}

pub fn hkdf(
    ephemeral: &[u8; 32],
    recipient_public: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 16]>> {
    const INFO: &[u8] = b"OpenPGP X25519";

    let mut hkdf_extract = HkdfExtract::<Sha256>::new(None);
    hkdf_extract.input_ikm(ephemeral);
    hkdf_extract.input_ikm(recipient_public);
    hkdf_extract.input_ikm(shared_secret);

    let (_, hkdf) = hkdf_extract.finalize();

    let mut okm = Zeroizing::new([0u8; 16]);
    hkdf.expand(INFO, &mut (*okm))
        .expect("16 is a valid length for Sha256 to output");

    Ok(okm)
}

pub fn encrypt<R: CryptoRng + Rng>(
    mut rng: R,
    recipient_public: &x25519_dalek::PublicKey,
    plain: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    debug!("X25519 encrypt");

    const MAX_SIZE: usize = 255;
    ensure!(
        plain.len() <= MAX_SIZE,
        "unable to encrypt larger than {} bytes",
        MAX_SIZE
    );

    let (ephemeral_public, shared_secret) = {
        let mut ephemeral_secret_key_bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *ephemeral_secret_key_bytes);
        let our_secret = StaticSecret::from(*ephemeral_secret_key_bytes);

        let shared_secret = our_secret.diffie_hellman(recipient_public);

        let ephemeral_public = x25519_dalek::PublicKey::from(&our_secret);

        (ephemeral_public, shared_secret)
    };

    let okm = hkdf(
        ephemeral_public.as_bytes(),
        recipient_public.as_bytes(),
        shared_secret.as_bytes(),
    )?;

    let wrapped = aes_kw::wrap(&*okm, plain)?;

    Ok((ephemeral_public.to_bytes(), wrapped))
}
