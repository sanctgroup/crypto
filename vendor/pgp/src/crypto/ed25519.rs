use std::ops::Deref;

use rand::{CryptoRng, Rng};
use signature::{Signer as _, Verifier};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{bail, ensure, ensure_eq, Result},
    ser::Serialize,
    types::{Ed25519PublicParams, EddsaLegacyPublicParams, Mpi, SignatureBytes},
};

const MIN_HASH_LEN_BITS: usize = 256;

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum Mode {
    EdDSALegacy,

    Ed25519,
}

#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop, derive_more::Debug)]

pub struct SecretKey {
    #[debug("..")]
    secret: ed25519_dalek::SigningKey,
    #[zeroize(skip)]
    pub(crate) mode: Mode,
}

impl From<&SecretKey> for Ed25519PublicParams {
    fn from(value: &SecretKey) -> Self {
        debug_assert_eq!(value.mode, Mode::Ed25519);
        Self {
            key: value.secret.verifying_key(),
        }
    }
}

impl From<&SecretKey> for EddsaLegacyPublicParams {
    fn from(value: &SecretKey) -> Self {
        debug_assert_eq!(value.mode, Mode::EdDSALegacy);
        Self::Ed25519 {
            key: value.secret.verifying_key(),
        }
    }
}

impl Deref for SecretKey {
    type Target = ed25519_dalek::SigningKey;

    fn deref(&self) -> &Self::Target {
        &self.secret
    }
}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R, mode: Mode) -> Self {
        let mut bytes = Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
        rng.fill_bytes(&mut *bytes);
        let secret = ed25519_dalek::SigningKey::from_bytes(&bytes);

        SecretKey { secret, mode }
    }

    pub fn try_from_bytes(raw_secret: [u8; KEY_LEN], mode: Mode) -> Result<Self> {
        let secret = ed25519_dalek::SigningKey::from(raw_secret);
        Ok(Self { secret, mode })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.secret.as_bytes()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        let Some(digest_size) = hash.digest_size() else {
            bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
        };
        ensure_eq!(
            digest.len(),
            digest_size,
            "Unexpected digest length {} for hash algorithm {:?}",
            digest.len(),
            hash,
        );
        ensure!(
            digest_size * 8 >= MIN_HASH_LEN_BITS,
            "EdDSA signature: hash algorithm {:?} is too weak for Ed25519",
            hash,
        );

        let signature = self.secret.sign(digest);
        let bytes = signature.to_bytes();

        let sig = match self.mode {
            Mode::EdDSALegacy => {
                let r = Mpi::from_slice(&bytes[..32]);
                let s = Mpi::from_slice(&bytes[32..]);
                SignatureBytes::Mpis(vec![r, s])
            }
            Mode::Ed25519 => SignatureBytes::Native(bytes.to_vec().into()),
        };
        Ok(sig)
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self.mode {
            Mode::EdDSALegacy => {
                Mpi::from_slice(&self.secret.as_bytes()[..]).to_writer(writer)?;
            }
            Mode::Ed25519 => {
                let x = self.as_bytes();
                writer.write_all(x)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self.mode {
            Mode::EdDSALegacy => Mpi::from_slice(self.secret.as_bytes()).write_len(),
            Mode::Ed25519 => KEY_LEN,
        }
    }
}

pub fn verify(
    key: &ed25519_dalek::VerifyingKey,
    hash: HashAlgorithm,
    hashed: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    let Some(digest_size) = hash.digest_size() else {
        bail!("EdDSA signature: invalid hash algorithm: {:?}", hash);
    };
    ensure!(
        digest_size * 8 >= MIN_HASH_LEN_BITS,
        "EdDSA signature: hash algorithm {:?} is too weak for Ed25519",
        hash,
    );

    let sig = sig_bytes.try_into()?;

    Ok(key.verify(hashed, &sig)?)
}
