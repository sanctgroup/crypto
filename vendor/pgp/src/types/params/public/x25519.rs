use std::io::{self, BufRead};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]

pub struct X25519PublicParams {
    pub key: x25519_dalek::PublicKey,
}

impl X25519PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let public_raw = i.read_arr::<32>()?;
        let public = x25519_dalek::PublicKey::from(public_raw);
        let params = Self { key: public };

        Ok(params)
    }
}

impl Serialize for X25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        32
    }
}
