use std::io::{self, BufRead};

use crate::{
    errors::{ensure, Result},
    ser::Serialize,
    types::Mpi,
};

#[derive(Debug, PartialEq, Clone)]

pub struct DsaPublicParams {
    pub key: dsa::VerifyingKey,
}

impl Eq for DsaPublicParams {}

impl DsaPublicParams {
    const MAX_L_BITS: usize = 4096;
    const MAX_N_BITS: usize = 256;

    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let p = Mpi::try_from_reader(&mut i)?;
        let q = Mpi::try_from_reader(&mut i)?;
        let g = Mpi::try_from_reader(&mut i)?;
        let y = Mpi::try_from_reader(&mut i)?;

        ensure!(
            p.len() * 8 <= Self::MAX_L_BITS,
            "p is too long ({} bytes)",
            p.len()
        );
        ensure!(
            q.len() * 8 <= Self::MAX_N_BITS,
            "q is too long ({} bytes)",
            q.len()
        );

        ensure!(g.len() <= p.len(), "g is longer than p ({} bytes)", g.len());
        ensure!(y.len() <= p.len(), "y is longer than p ({} bytes)", y.len());

        let params = DsaPublicParams::try_from_mpi(p, q, g, y)?;
        Ok(params)
    }

    pub(crate) fn try_from_mpi(p: Mpi, q: Mpi, g: Mpi, y: Mpi) -> Result<Self> {
        let components = dsa::Components::from_components(p.into(), q.into(), g.into())?;
        let key = dsa::VerifyingKey::from_components(components, y.into())?;

        Ok(DsaPublicParams { key })
    }
}

impl Serialize for DsaPublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        let c = self.key.components();
        let p: Mpi = c.p().into();
        p.to_writer(writer)?;
        let q: Mpi = c.q().into();
        q.to_writer(writer)?;
        let g: Mpi = c.g().into();
        g.to_writer(writer)?;
        let y: Mpi = self.key.y().into();
        y.to_writer(writer)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;

        let c = self.key.components();
        let p: Mpi = c.p().into();
        sum += p.write_len();
        let q: Mpi = c.q().into();
        sum += q.write_len();
        let g: Mpi = c.g().into();
        sum += g.write_len();
        let y: Mpi = self.key.y().into();
        sum += y.write_len();
        sum
    }
}
