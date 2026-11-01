use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;

use crate::{
    crypto::ecc_curve::{ecc_curve_from_oid, ECCCurve},
    errors::{ensure_eq, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Mpi,
};

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]

pub enum EddsaLegacyPublicParams {
    Ed25519 {
        key: ed25519_dalek::VerifyingKey,
    },

    Unsupported {
        curve: ECCCurve,
        #[debug("{}", hex::encode(opaque))]
        opaque: Bytes,
    },
}

impl EddsaLegacyPublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B, len: Option<usize>) -> Result<Self> {
        let curve_len = i.read_u8()?;

        let curve_raw = i.take_bytes(curve_len.into())?;
        let curve = ecc_curve_from_oid(&curve_raw).ok_or_else(|| format_err!("invalid curve"))?;

        match curve {
            ECCCurve::Ed25519Legacy => {
                let q = Mpi::try_from_reader(&mut i)?;
                ensure_eq!(q.len(), 33, "invalid Q (len)");
                ensure_eq!(q.as_ref()[0], 0x40, "invalid Q (prefix)");
                let public = &q.as_ref()[1..];

                let key: ed25519_dalek::VerifyingKey = public.try_into()?;
                Ok(Self::Ed25519 { key })
            }
            _ => {
                let opaque = if let Some(pub_len) = len {
                    i.take_bytes(pub_len)?.freeze()
                } else {
                    let p = Mpi::try_from_reader(&mut i)?;
                    Bytes::from(p.to_bytes()?)
                };

                Ok(Self::Unsupported { curve, opaque })
            }
        }
    }

    pub fn curve(&self) -> ECCCurve {
        match self {
            Self::Ed25519 { .. } => ECCCurve::Ed25519Legacy,
            Self::Unsupported { curve, .. } => curve.clone(),
        }
    }
}

impl Serialize for EddsaLegacyPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519Legacy.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;
                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                mpi.to_writer(writer)?;
            }
            Self::Unsupported { curve, opaque } => {
                let oid = curve.oid();
                writer.write_u8(oid.len().try_into()?)?;
                writer.write_all(&oid)?;

                writer.write_all(opaque)?;
            }
        }
        Ok(())
    }
    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            Self::Ed25519 { key } => {
                let oid = ECCCurve::Ed25519Legacy.oid();
                sum += 1;
                sum += oid.len();

                let mut mpi = Vec::with_capacity(33);
                mpi.push(0x40);
                mpi.extend_from_slice(key.as_bytes());
                let mpi = Mpi::from_slice(&mpi);
                sum += mpi.write_len();
            }
            Self::Unsupported { curve, opaque } => {
                let oid = curve.oid();
                sum += 1;
                sum += oid.len();
                sum += opaque.len();
            }
        }
        sum
    }
}
