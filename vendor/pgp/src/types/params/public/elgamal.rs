use std::io::{self, BufRead};

use crate::{errors::Result, ser::Serialize, types::Mpi};

#[derive(Debug, PartialEq, Eq, Clone)]

pub struct ElgamalPublicParams {
    p: Mpi,
    g: Mpi,
    y: Mpi,

    encrypt_only: bool,
}

impl ElgamalPublicParams {
    pub(crate) fn is_encrypt_only(&self) -> bool {
        self.encrypt_only
    }

    pub fn try_from_reader<B: BufRead>(mut i: B, encrypt_only: bool) -> Result<Self> {
        let p = Mpi::try_from_reader(&mut i)?;

        let g = Mpi::try_from_reader(&mut i)?;

        let y = Mpi::try_from_reader(&mut i)?;

        let params = ElgamalPublicParams {
            p,
            g,
            y,
            encrypt_only,
        };

        Ok(params)
    }
}

impl Serialize for ElgamalPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.p.to_writer(writer)?;
        self.g.to_writer(writer)?;
        self.y.to_writer(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        sum += self.p.write_len();
        sum += self.g.write_len();
        sum += self.y.write_len();
        sum
    }
}
