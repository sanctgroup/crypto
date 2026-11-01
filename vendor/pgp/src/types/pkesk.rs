use std::io::BufRead;

use byteorder::WriteBytesExt;
use bytes::Bytes;

use super::Mpi;
use crate::{
    crypto::{public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{unsupported_err, InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

#[derive(Clone, derive_more::Debug, Eq, PartialEq)]
pub enum PkeskBytes {
    Rsa {
        mpi: Mpi,
    },
    Elgamal {
        first: Mpi,
        second: Mpi,
    },
    Ecdh {
        public_point: Mpi,
        encrypted_session_key: Bytes,
    },
    X25519 {
        #[debug("{}", hex::encode(ephemeral))]
        ephemeral: [u8; 32],
        #[debug("{}", hex::encode(session_key))]
        session_key: Bytes,
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    X448 {
        #[debug("{}", hex::encode(ephemeral))]
        ephemeral: [u8; 56],
        #[debug("{}", hex::encode(session_key))]
        session_key: Bytes,
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },
    MlKem768X25519 {
        #[debug("{}", hex::encode(ecdh_ciphertext))]
        ecdh_ciphertext: [u8; 32],
        #[debug("{}", hex::encode(&ml_kem_ciphertext[..]))]
        ml_kem_ciphertext: Box<[u8; 1088]>,
        #[debug("{}", hex::encode(session_key))]
        session_key: Bytes,
        sym_alg: Option<SymmetricKeyAlgorithm>,
    },

    Other {
        #[debug("{}", hex::encode(key))]
        key: Bytes,
    },
}

impl PkeskBytes {
    pub fn try_from_reader<B: BufRead>(
        alg: &PublicKeyAlgorithm,
        version: u8,
        mut i: B,
    ) -> Result<Self> {
        match alg {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::RSAEncrypt => {
                let mpi = Mpi::try_from_reader(&mut i)?;
                Ok(PkeskBytes::Rsa { mpi })
            }
            PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalEncrypt => {
                let first = Mpi::try_from_reader(&mut i)?;
                let second = Mpi::try_from_reader(&mut i)?;
                Ok(PkeskBytes::Elgamal { first, second })
            }
            PublicKeyAlgorithm::ECDSA
            | PublicKeyAlgorithm::DSA
            | PublicKeyAlgorithm::DiffieHellman => {
                let key = i.rest()?.freeze();
                Ok(PkeskBytes::Other { key })
            }
            PublicKeyAlgorithm::ECDH => {
                let public_point = Mpi::try_from_reader(&mut i)?;
                let session_key_len = i.read_u8()?;
                let session_key = i.take_bytes(session_key_len.into())?.freeze();

                Ok(PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key: session_key,
                })
            }
            PublicKeyAlgorithm::X25519 => {
                let ephemeral_public = i.read_arr::<32>()?;

                let len = i.read_u8()?;
                if len == 0 {
                    return Err(InvalidInputSnafu.build());
                }

                let sym_alg = if version == 3 {
                    let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
                    Some(alg)
                } else {
                    None
                };

                let skey_len = if version == 3 { len - 1 } else { len };

                let esk = i.take_bytes(skey_len.into())?.freeze();

                Ok(PkeskBytes::X25519 {
                    ephemeral: ephemeral_public,
                    sym_alg,
                    session_key: esk,
                })
            }
            PublicKeyAlgorithm::X448 => {
                let ephemeral_public = i.read_arr::<56>()?;

                let len = i.read_u8()?;
                if len == 0 {
                    return Err(InvalidInputSnafu.build());
                }

                let sym_alg = if version == 3 {
                    let alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
                    Some(alg)
                } else {
                    None
                };

                let skey_len = if version == 3 { len - 1 } else { len };

                let session_key = i.take_bytes(skey_len.into())?.freeze();

                Ok(PkeskBytes::X448 {
                    ephemeral: ephemeral_public,
                    sym_alg,
                    session_key,
                })
            }
            PublicKeyAlgorithm::Unknown(_) => {
                let key = i.rest()?.freeze();
                Ok(PkeskBytes::Other { key })
            }

            _ => unsupported_err!("unsupported algorithm for ESK: {:?}", alg),
        }
    }
}

impl Serialize for PkeskBytes {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PkeskBytes::Rsa { mpi } => {
                mpi.to_writer(writer)?;
            }
            PkeskBytes::Elgamal { first, second } => {
                first.to_writer(writer)?;
                second.to_writer(writer)?;
            }
            PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            } => {
                public_point.to_writer(writer)?;

                writer.write_u8(encrypted_session_key.len().try_into()?)?;

                writer.write_all(encrypted_session_key)?;
            }
            PkeskBytes::X25519 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                writer.write_all(ephemeral)?;

                if let Some(sym_alg) = sym_alg {
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    writer.write_u8(session_key.len().try_into()?)?;
                }

                writer.write_all(session_key)?;
            }
            PkeskBytes::MlKem768X25519 {
                ecdh_ciphertext: ephemeral,
                sym_alg,
                session_key,
                ml_kem_ciphertext,
            } => {
                writer.write_all(ephemeral)?;
                writer.write_all(&ml_kem_ciphertext[..])?;

                if let Some(sym_alg) = sym_alg {
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    writer.write_u8(session_key.len().try_into()?)?;
                }

                writer.write_all(session_key)?;
            }

            PkeskBytes::X448 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                writer.write_all(ephemeral)?;

                if let Some(sym_alg) = sym_alg {
                    writer.write_u8((session_key.len() + 1).try_into()?)?;

                    writer.write_u8((*sym_alg).into())?;
                } else {
                    writer.write_u8(session_key.len().try_into()?)?;
                }

                writer.write_all(session_key)?;
            }
            PkeskBytes::Other { key } => {
                writer.write_all(key)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            PkeskBytes::Rsa { mpi } => {
                sum += mpi.write_len();
            }
            PkeskBytes::Elgamal { first, second } => {
                sum += first.write_len();
                sum += second.write_len();
            }
            PkeskBytes::Ecdh {
                public_point,
                encrypted_session_key,
            } => {
                sum += public_point.write_len();

                sum += 1;
                sum += encrypted_session_key.len();
            }
            PkeskBytes::X25519 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                sum += ephemeral.len();

                if sym_alg.is_some() {
                    sum += 1 + 1;
                } else {
                    sum += 1;
                }
                sum += session_key.len();
            }
            PkeskBytes::MlKem768X25519 {
                ecdh_ciphertext: ephemeral,
                sym_alg,
                session_key,
                ml_kem_ciphertext,
            } => {
                sum += ephemeral.len();
                sum += ml_kem_ciphertext.len();

                if sym_alg.is_some() {
                    sum += 1 + 1;
                } else {
                    sum += 1;
                }
                sum += session_key.len();
            }

            PkeskBytes::X448 {
                ephemeral,
                sym_alg,
                session_key,
            } => {
                sum += ephemeral.len();

                if sym_alg.is_some() {
                    sum += 1 + 1;
                } else {
                    sum += 1;
                }
                sum += session_key.len();
            }
            PkeskBytes::Other { key } => {
                sum += key.len();
            }
        }
        sum
    }
}
