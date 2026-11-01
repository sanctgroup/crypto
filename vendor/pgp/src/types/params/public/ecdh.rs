use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;

use crate::{
    crypto::{
        ecc_curve::{ecc_curve_from_oid, ECCCurve},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure_eq, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Mpi,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u8)]

pub enum EcdhKdfType {
    Native,

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    Replaced {
        replacement_fingerprint: [u8; 20],
    },
}

impl From<EcdhKdfType> for u8 {
    fn from(value: EcdhKdfType) -> Self {
        match value {
            EcdhKdfType::Native => 0x01,
            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            EcdhKdfType::Replaced { .. } => 0xff,
        }
    }
}

impl EcdhKdfType {
    const fn param_len(&self) -> u8 {
        match self {
            Self::Native => 0x03,
            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            Self::Replaced { .. } => 0x17,
        }
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]

pub enum EcdhPublicParams {
    Curve25519Legacy {
        p: x25519_dalek::PublicKey,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
        ecdh_kdf_type: EcdhKdfType,
    },

    Brainpool256 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    Brainpool384 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    Brainpool512 {
        p: Mpi,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },

    Unsupported {
        curve: ECCCurve,
        #[debug("{}", hex::encode(opaque))]
        opaque: Bytes,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
    },
}

impl Serialize for EcdhPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let oid = self.curve().oid();
        writer.write_u8(oid.len().try_into()?)?;
        writer.write_all(&oid)?;

        let tags = match self {
            Self::Curve25519Legacy {
                p,
                hash,
                alg_sym,
                ecdh_kdf_type,
            } => {
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                mpi.to_writer(writer)?;
                Some((hash, alg_sym, ecdh_kdf_type))
            }

            Self::Brainpool256 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Brainpool384 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Brainpool512 { p, hash, alg_sym } => {
                p.to_writer(writer)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
            Self::Unsupported {
                opaque,
                hash,
                alg_sym,
                ..
            } => {
                writer.write_all(opaque)?;
                Some((hash, alg_sym, &EcdhKdfType::Native))
            }
        };

        if let Some((hash, alg_sym, ecdh_kdf_type)) = tags {
            writer.write_u8(ecdh_kdf_type.param_len())?;
            writer.write_u8((*ecdh_kdf_type).into())?;

            writer.write_u8((*hash).into())?;
            writer.write_u8((*alg_sym).into())?;

            #[cfg(feature = "draft-wussler-openpgp-forwarding")]
            if let EcdhKdfType::Replaced {
                replacement_fingerprint,
            } = ecdh_kdf_type
            {
                writer.write_all(&replacement_fingerprint[..])?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 1;

        match self {
            Self::Curve25519Legacy {
                p,
                #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                ecdh_kdf_type,
                ..
            } => {
                sum += self.curve().oid().len();
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(p.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                sum += mpi.write_len();

                #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                if matches![ecdh_kdf_type, EcdhKdfType::Replaced { .. }] {
                    sum += 20
                }
            }

            Self::Brainpool256 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Brainpool384 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Brainpool512 { p, .. } => {
                sum += self.curve().oid().len();
                sum += p.write_len();
            }
            Self::Unsupported { curve, opaque, .. } => {
                let oid = curve.oid();
                sum += oid.len();
                sum += opaque.len();
            }
        };

        sum += 1 + 1 + 1 + 1;

        sum
    }
}

impl EcdhPublicParams {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Curve25519Legacy { .. } => ECCCurve::Curve25519Legacy,

            Self::Brainpool256 { .. } => ECCCurve::BrainpoolP256r1,
            Self::Brainpool384 { .. } => ECCCurve::BrainpoolP384r1,
            Self::Brainpool512 { .. } => ECCCurve::BrainpoolP512r1,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }

    pub fn try_from_reader<B: BufRead>(mut i: B, _len: Option<usize>) -> Result<Self> {
        let curve_len = i.read_u8()?;
        let curve_raw = i.take_bytes(curve_len.into())?;
        let curve = ecc_curve_from_oid(&curve_raw).ok_or_else(|| format_err!("invalid curve"))?;

        match curve {
            ECCCurve::Curve25519Legacy
            | ECCCurve::P256
            | ECCCurve::P384
            | ECCCurve::P521
            | ECCCurve::BrainpoolP256r1
            | ECCCurve::BrainpoolP384r1
            | ECCCurve::BrainpoolP512r1
            | ECCCurve::Unknown(_) => {
                let p = Mpi::try_from_reader(&mut i)?;

                let len_param = i.read_u8()?;

                let kdf_type = i.read_u8()?;

                let hash = i.read_u8().map(HashAlgorithm::from)?;

                let alg_sym = i.read_u8().map(SymmetricKeyAlgorithm::from)?;

                let ecdh_kdf_type = match kdf_type {
                    0x01 => EcdhKdfType::Native,

                    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                    0xff => {
                        crate::errors::ensure!(
                            curve == ECCCurve::Curve25519Legacy,
                            "unexpected curve for forwardee key {}",
                            curve
                        );

                        EcdhKdfType::Replaced {
                            replacement_fingerprint: i.read_arr()?,
                        }
                    }

                    typ => bail!("unexpected ECDH KDF type {}", typ),
                };

                ensure_eq!(
                    len_param,
                    ecdh_kdf_type.param_len(),
                    "unexpected length {} for kdf type {}",
                    len_param,
                    kdf_type
                );

                let params = Self::try_from_mpi(p, curve, hash, alg_sym, ecdh_kdf_type)?;
                Ok(params)
            }
            ECCCurve::Ed25519Legacy | ECCCurve::Secp256k1 => {
                bail!("Unsupported curve {:?}", curve)
            }
        }
    }

    fn try_from_mpi(
        p: Mpi,
        curve: ECCCurve,
        hash: HashAlgorithm,
        alg_sym: SymmetricKeyAlgorithm,
        ecdh_kdf_type: EcdhKdfType,
    ) -> Result<Self> {
        match curve {
            ECCCurve::Curve25519Legacy => {
                ensure_eq!(p.len(), 33, "invalid public key length");

                let public_key = &p.as_ref()[1..];

                let mut public_key_arr = [0u8; 32];
                public_key_arr[..].copy_from_slice(public_key);

                let p = x25519_dalek::PublicKey::from(public_key_arr);
                Ok(EcdhPublicParams::Curve25519Legacy {
                    p,
                    hash,
                    alg_sym,
                    ecdh_kdf_type,
                })
            }
            ECCCurve::P256 => return Err(crate::errors::Error::DisabledAlgorithm),
            ECCCurve::P384 => return Err(crate::errors::Error::DisabledAlgorithm),
            ECCCurve::P521 => return Err(crate::errors::Error::DisabledAlgorithm),
            ECCCurve::BrainpoolP256r1 => Ok(EcdhPublicParams::Brainpool256 { p, hash, alg_sym }),
            ECCCurve::BrainpoolP384r1 => Ok(EcdhPublicParams::Brainpool384 { p, hash, alg_sym }),
            ECCCurve::BrainpoolP512r1 => Ok(EcdhPublicParams::Brainpool512 { p, hash, alg_sym }),
            curve => {
                let opaque = Bytes::from(p.to_bytes()?);

                Ok(EcdhPublicParams::Unsupported {
                    curve,
                    opaque,
                    hash,
                    alg_sym,
                })
            }
        }
    }
}
