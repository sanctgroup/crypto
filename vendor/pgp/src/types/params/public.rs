use std::io::{self, BufRead};

use bytes::Bytes;

use crate::{
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::{Error, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

mod dsa;
pub(crate) mod ecdh;

mod ed25519;

mod eddsa_legacy;
mod elgamal;

mod x25519;

pub use self::{
    dsa::DsaPublicParams, ecdh::EcdhPublicParams, ed25519::Ed25519PublicParams,
    eddsa_legacy::EddsaLegacyPublicParams, elgamal::ElgamalPublicParams,
    x25519::X25519PublicParams,
};

use super::PlainSecretParams;

#[derive(PartialEq, Eq, Clone, derive_more::Debug)]
pub enum PublicParams {
    DSA(DsaPublicParams),

    ECDH(EcdhPublicParams),
    Elgamal(ElgamalPublicParams),
    EdDSALegacy(EddsaLegacyPublicParams),
    Ed25519(Ed25519PublicParams),
    X25519(X25519PublicParams),

    Unknown {
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl TryFrom<&PlainSecretParams> for PublicParams {
    type Error = Error;

    fn try_from(secret: &PlainSecretParams) -> Result<Self, Self::Error> {
        match secret {
            PlainSecretParams::DSA(ref p) => Ok(Self::DSA(p.into())),

            PlainSecretParams::ECDH(ref p) => Ok(Self::ECDH(p.try_into()?)),
            PlainSecretParams::Elgamal(ref p) => Ok(Self::Elgamal(p.into())),
            PlainSecretParams::Ed25519(ref p) => Ok(Self::Ed25519(p.into())),
            PlainSecretParams::EdDSALegacy(ref p) => Ok(Self::EdDSALegacy(p.try_into()?)),
            PlainSecretParams::X25519(ref p) => Ok(Self::X25519(p.into())),

            PlainSecretParams::Unknown { pub_params, .. } => Ok(Self::Unknown {
                data: pub_params.clone(),
            }),
        }
    }
}

impl PublicParams {
    pub fn try_from_reader<B: BufRead>(
        typ: PublicKeyAlgorithm,
        len: Option<usize>,
        i: B,
    ) -> Result<PublicParams> {
        match typ {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::RSASign => return Err(crate::errors::Error::DisabledAlgorithm),
            PublicKeyAlgorithm::DSA => {
                let params = DsaPublicParams::try_from_reader(i)?;
                Ok(PublicParams::DSA(params))
            }
            PublicKeyAlgorithm::ECDSA => return Err(crate::errors::Error::DisabledAlgorithm),
            PublicKeyAlgorithm::ECDH => {
                let params = EcdhPublicParams::try_from_reader(i, len)?;
                Ok(PublicParams::ECDH(params))
            }
            PublicKeyAlgorithm::Elgamal => {
                let params = ElgamalPublicParams::try_from_reader(i, false)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::ElgamalEncrypt => {
                let params = ElgamalPublicParams::try_from_reader(i, true)?;
                Ok(PublicParams::Elgamal(params))
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                let params = EddsaLegacyPublicParams::try_from_reader(i, len)?;
                Ok(PublicParams::EdDSALegacy(params))
            }
            PublicKeyAlgorithm::Ed25519 => {
                let params = Ed25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::Ed25519(params))
            }
            PublicKeyAlgorithm::X25519 => {
                let params = X25519PublicParams::try_from_reader(i)?;
                Ok(PublicParams::X25519(params))
            }
            PublicKeyAlgorithm::Ed448 => return Err(crate::errors::Error::DisabledAlgorithm),
            PublicKeyAlgorithm::X448 => return Err(crate::errors::Error::DisabledAlgorithm),

            PublicKeyAlgorithm::DiffieHellman
            | PublicKeyAlgorithm::Private100
            | PublicKeyAlgorithm::Private101
            | PublicKeyAlgorithm::Private102
            | PublicKeyAlgorithm::Private103
            | PublicKeyAlgorithm::Private104
            | PublicKeyAlgorithm::Private105
            | PublicKeyAlgorithm::Private106
            | PublicKeyAlgorithm::Private107
            | PublicKeyAlgorithm::Private108
            | PublicKeyAlgorithm::Private109
            | PublicKeyAlgorithm::Private110
            | PublicKeyAlgorithm::Unknown(_) => unknown(i, len),
        }
    }

    pub fn hash_alg(&self) -> HashAlgorithm {
        match self {
            PublicParams::DSA(_) | PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => {
                HashAlgorithm::Sha256
            }

            PublicParams::Elgamal(_)
            | PublicParams::ECDH(_)
            | PublicParams::X25519(_)
            | PublicParams::Unknown { .. } => HashAlgorithm::Sha256,
        }
    }
}

fn unknown<B: BufRead>(mut i: B, len: Option<usize>) -> Result<PublicParams> {
    if let Some(pub_len) = len {
        let data = i.take_bytes(pub_len)?.freeze();
        Ok(PublicParams::Unknown { data })
    } else {
        let data = i.rest()?.freeze();
        Ok(PublicParams::Unknown { data })
    }
}

impl Serialize for PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PublicParams::DSA(params) => {
                params.to_writer(writer)?;
            }

            PublicParams::ECDH(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Elgamal(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::EdDSALegacy(params) => {
                params.to_writer(writer)?;
            }
            PublicParams::Ed25519(params) => {
                params.to_writer(writer)?;
            }

            PublicParams::X25519(params) => {
                params.to_writer(writer)?;
            }

            PublicParams::Unknown { ref data } => {
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            PublicParams::DSA(params) => {
                sum += params.write_len();
            }

            PublicParams::ECDH(params) => {
                sum += params.write_len();
            }
            PublicParams::Elgamal(params) => {
                sum += params.write_len();
            }
            PublicParams::EdDSALegacy(params) => {
                sum += params.write_len();
            }
            PublicParams::Ed25519(params) => {
                sum += params.write_len();
            }

            PublicParams::X25519(params) => {
                sum += params.write_len();
            }

            PublicParams::Unknown { ref data } => {
                sum += data.len();
            }
        }
        sum
    }
}
