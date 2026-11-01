pub use dsa::KeySize;
use dsa::{Components, Signature, SigningKey};
use num_bigint::BigUint;
use rand::{CryptoRng, Rng};
use signature::hazmat::PrehashVerifier;
use zeroize::Zeroize;

use crate::{
    crypto::{hash::HashAlgorithm, Signer},
    errors::{unimplemented_err, Result},
    ser::Serialize,
    types::{DsaPublicParams, Mpi, SignatureBytes},
};

#[derive(Clone, PartialEq, derive_more::Debug)]

pub struct SecretKey {
    #[debug("..")]
    key: dsa::SigningKey,
}

impl From<&SecretKey> for DsaPublicParams {
    fn from(value: &SecretKey) -> Self {
        Self {
            key: value.key.verifying_key().clone(),
        }
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {}
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SecretKey {}

impl Eq for SecretKey {}

impl SecretKey {
    pub fn generate<R: Rng + CryptoRng>(mut rng: R, key_size: KeySize) -> Self {
        let components = Components::generate(&mut rng, key_size);
        let signing_key = SigningKey::generate(&mut rng, components);

        SecretKey { key: signing_key }
    }

    pub(crate) fn try_from_mpi(pub_params: &DsaPublicParams, x: Mpi) -> Result<Self> {
        let secret = dsa::SigningKey::from_components(pub_params.key.clone(), x.into())?;
        Ok(Self { key: secret })
    }

    fn to_mpi(&self) -> Mpi {
        Mpi::from(self.key.x())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.x().to_bytes_be()
    }
}

impl Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.to_mpi().to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        self.to_mpi().write_len()
    }
}

impl Signer for SecretKey {
    fn sign(&self, hash_algorithm: HashAlgorithm, digest: &[u8]) -> Result<SignatureBytes> {
        let signing_key = &self.key;
        let signature = match hash_algorithm {
            HashAlgorithm::Md5 => signing_key.sign_prehashed_rfc6979::<md5::Md5>(digest),

            HashAlgorithm::Sha1 => signing_key.sign_prehashed_rfc6979::<sha1::Sha1>(digest),

            HashAlgorithm::Ripemd160 => {
                signing_key.sign_prehashed_rfc6979::<ripemd::Ripemd160>(digest)
            }
            HashAlgorithm::Sha256 => signing_key.sign_prehashed_rfc6979::<sha2::Sha256>(digest),
            HashAlgorithm::Sha384 => signing_key.sign_prehashed_rfc6979::<sha2::Sha384>(digest),
            HashAlgorithm::Sha512 => signing_key.sign_prehashed_rfc6979::<sha2::Sha512>(digest),
            HashAlgorithm::Sha224 => signing_key.sign_prehashed_rfc6979::<sha2::Sha224>(digest),
            HashAlgorithm::Sha3_256 => signing_key.sign_prehashed_rfc6979::<sha3::Sha3_256>(digest),
            HashAlgorithm::Sha3_512 => signing_key.sign_prehashed_rfc6979::<sha3::Sha3_512>(digest),
            _ => unimplemented_err!("hasher {:?}", hash_algorithm),
        }?;

        Ok(SignatureBytes::Mpis(vec![
            Mpi::from(signature.r()),
            Mpi::from(signature.s()),
        ]))
    }
}

pub fn verify(params: &DsaPublicParams, hashed: &[u8], r: BigUint, s: BigUint) -> Result<()> {
    let verifying_key = &params.key;
    let signature = Signature::from_components(r, s)?;
    verifying_key.verify_prehash(hashed, &signature)?;

    Ok(())
}
