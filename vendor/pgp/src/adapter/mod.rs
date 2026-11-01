use crate::{crypto::public_key::PublicKeyAlgorithm, types::PublicParams};
pub trait PublicKey {
    const PGP_ALGORITHM: PublicKeyAlgorithm;
    fn pgp_parameters(&self) -> PublicParams;
}
