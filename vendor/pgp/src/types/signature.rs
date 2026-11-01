use bytes::Bytes;
use log::debug;

use super::Mpi;
use crate::{errors::bail, ser::Serialize};

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum SignatureBytes {
    Mpis(Vec<Mpi>),

    Native(#[debug("{}", hex::encode(_0))] Bytes),
}

impl SignatureBytes {
    pub(crate) fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> crate::errors::Result<()> {
        use crate::ser::Serialize;

        match &self {
            SignatureBytes::Mpis(mpis) => {
                debug!("writing {} signature MPIs", mpis.len());

                for val in mpis {
                    val.to_writer(writer)?;
                }
            }
            SignatureBytes::Native(sig) => {
                writer.write_all(sig)?;
            }
        }

        Ok(())
    }

    pub(crate) fn write_len(&self) -> usize {
        match self {
            SignatureBytes::Mpis(mpis) => mpis.write_len(),
            SignatureBytes::Native(sig) => sig.len(),
        }
    }
}

impl<'a> TryFrom<&'a SignatureBytes> for &'a [Mpi] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a SignatureBytes) -> std::result::Result<Self, Self::Error> {
        match value {
            SignatureBytes::Mpis(mpis) => Ok(mpis),

            SignatureBytes::Native(_) => bail!("Native Sig can't be transformed into Mpis"),
        }
    }
}

impl<'a> TryFrom<&'a SignatureBytes> for &'a [u8] {
    type Error = crate::errors::Error;

    fn try_from(value: &'a SignatureBytes) -> std::result::Result<Self, Self::Error> {
        match value {
            SignatureBytes::Mpis(_) => bail!("Mpi-based Sig can't be transformed into &[u8]"),

            SignatureBytes::Native(native) => Ok(native),
        }
    }
}

impl From<Vec<Mpi>> for SignatureBytes {
    fn from(value: Vec<Mpi>) -> Self {
        SignatureBytes::Mpis(value)
    }
}

impl From<Bytes> for SignatureBytes {
    fn from(value: Bytes) -> Self {
        SignatureBytes::Native(value)
    }
}
