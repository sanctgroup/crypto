use std::io::{self, BufRead};

use byteorder::{BigEndian, WriteBytesExt};
use bytes::{Buf, Bytes};
use num_bigint::BigUint;

use crate::{
    errors::{InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

const MAX_EXTERN_MPI_BITS: u16 = 16384;

#[derive(Default, Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Mpi(#[debug("{}", hex::encode(_0))] Bytes);

impl Mpi {
    pub(crate) fn from_raw(bytes: Bytes) -> Self {
        Mpi(bytes)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let len_bits = i.read_be_u16()?;

        if len_bits > MAX_EXTERN_MPI_BITS {
            return Err(InvalidInputSnafu.build());
        }

        let len_bytes = (len_bits + 7) >> 3;

        let mut n = i.take_bytes(usize::from(len_bytes))?.freeze();
        let n_stripped = match leading_zeros_offset(&n) {
            Some(offset) => {
                n.advance(offset);
                n
            }
            None => Bytes::new(),
        };

        Ok(Mpi(n_stripped))
    }

    pub fn from_slice(raw: &[u8]) -> Self {
        Self(strip_leading_zeros(raw).to_vec().into())
    }
}

#[inline]
fn bit_size(val: &[u8]) -> usize {
    if val.is_empty() {
        0
    } else {
        (val.len() * 8) - val[0].leading_zeros() as usize
    }
}

#[inline]
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    match leading_zeros_offset(bytes) {
        Some(offset) => &bytes[offset..],
        None => &[],
    }
}

#[inline]
fn leading_zeros_offset(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|b| b != &0)
}

impl AsRef<[u8]> for Mpi {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Serialize for Mpi {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> Result<()> {
        let bytes = &self.0;
        let size = bit_size(bytes);
        w.write_u16::<BigEndian>(size as u16)?;
        w.write_all(bytes)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        2 + self.0.len()
    }
}

impl From<BigUint> for Mpi {
    fn from(other: BigUint) -> Self {
        Mpi(other.to_bytes_be().into())
    }
}

impl From<&BigUint> for Mpi {
    fn from(other: &BigUint) -> Self {
        Mpi(other.to_bytes_be().into())
    }
}

impl From<Mpi> for BigUint {
    fn from(other: Mpi) -> Self {
        BigUint::from_bytes_be(other.as_ref())
    }
}
