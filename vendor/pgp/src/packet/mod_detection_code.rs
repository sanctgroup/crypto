use std::io::{self, BufRead};

use crate::{
    errors::Result,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

#[derive(derive_more::Debug, Clone, PartialEq, Eq)]

pub struct ModDetectionCode {
    packet_header: PacketHeader,
    #[debug("{}", hex::encode(hash))]
    hash: [u8; 20],
}

impl ModDetectionCode {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let hash = input.read_arr::<20>()?;

        Ok(ModDetectionCode {
            packet_header,
            hash,
        })
    }
}

impl Serialize for ModDetectionCode {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.hash[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.hash.len()
    }
}

impl PacketTrait for ModDetectionCode {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
