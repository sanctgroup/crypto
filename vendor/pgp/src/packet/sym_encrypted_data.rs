use std::io::{self, BufRead};

use bytes::Bytes;

use super::PacketHeader;
use crate::{errors::Result, packet::PacketTrait, parsing_reader::BufReadParsing, ser::Serialize};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct SymEncryptedData {
    packet_header: PacketHeader,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl SymEncryptedData {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let data = input.rest()?;
        Ok(SymEncryptedData {
            packet_header,
            data: data.freeze(),
        })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl Serialize for SymEncryptedData {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.data.len()
    }
}

impl PacketTrait for SymEncryptedData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
