use std::io::{self, BufRead};

use log::warn;

use crate::{
    errors::Result,
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

#[derive(Debug, PartialEq, Eq, Clone)]

pub struct Trust {
    packet_header: PacketHeader,
}

impl Trust {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        warn!("Trust packet detected, ignoring");
        data.drain()?;

        Ok(Trust { packet_header })
    }
}

impl Serialize for Trust {
    fn to_writer<W: io::Write>(&self, _writer: &mut W) -> Result<()> {
        Ok(())
    }

    fn write_len(&self) -> usize {
        0
    }
}

impl PacketTrait for Trust {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
