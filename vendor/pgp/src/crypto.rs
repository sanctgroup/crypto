use zeroize::Zeroizing;

use self::hash::HashAlgorithm;
use crate::types::SignatureBytes;

pub mod aead;
pub mod aes_kw;
pub mod sym;

pub mod dsa;
pub mod ecdh;

pub mod ed25519;

pub mod eddsa_legacy;
pub mod elgamal;

pub mod x25519;

pub mod checksum;
pub mod ecc_curve;
pub mod hash;
pub mod public_key;

pub trait Decryptor {
    type EncryptionFields<'a>;

    fn decrypt(
        &self,
        data: Self::EncryptionFields<'_>,
    ) -> crate::errors::Result<Zeroizing<Vec<u8>>>;
}

pub trait Signer {
    fn sign(&self, hash: HashAlgorithm, digest: &[u8]) -> crate::errors::Result<SignatureBytes>;
}
