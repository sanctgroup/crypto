use std::io::{self, BufRead};

use crate::{errors::Result, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Debug, PartialEq, Eq, Clone)]

pub struct Ed25519PublicParams {
    #[cfg_attr(
        test,
        proptest(strategy = "super::eddsa_legacy::tests::ed25519_pub_gen()")
    )]
    pub key: ed25519_dalek::VerifyingKey,
}

impl Ed25519PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let p = i.read_arr::<32>()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&p)?;
        let params = Self { key };

        Ok(params)
    }
}

impl Serialize for Ed25519PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.key.as_bytes()[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.key.as_bytes().len()
    }
}
