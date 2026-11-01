use std::io::{self, BufRead};

use crate::{
    errors::{ensure_eq, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

const PGP: [u8; 3] = [0x50, 0x47, 0x50];

#[derive(Debug, Clone, PartialEq, Eq)]

pub struct Marker {
    packet_header: PacketHeader,
}

impl Marker {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let marker = input.read_arr::<3>()?;
        ensure_eq!(marker, PGP, "invalid input");

        Ok(Marker { packet_header })
    }
}

impl Serialize for Marker {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&PGP[..])?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        PGP.len()
    }
}

impl PacketTrait for Marker {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
