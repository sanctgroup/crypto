use std::io::{BufRead, Write};

use byteorder::WriteBytesExt;
use bytes::Bytes;

use crate::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        sym::SymmetricKeyAlgorithm,
    },
    errors::{ensure_eq, InvalidInputSnafu, Result},
    packet::{PacketHeader, PacketTrait},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::Tag,
};

const GNUPG_AEAD_VERSION_1: u8 = 0x01;

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Config {
    pub sym_alg: SymmetricKeyAlgorithm,
    pub aead: AeadAlgorithm,
    pub chunk_size: ChunkSize,
    #[debug("{}", hex::encode(iv))]
    pub iv: Bytes,
}

impl Config {
    pub fn try_from_reader<R: BufRead>(mut data: R) -> Result<Self> {
        let version = data.read_u8()?;
        ensure_eq!(
            version,
            GNUPG_AEAD_VERSION_1,
            "GnupgAead version {} is unsupported",
            version
        );

        let sym_alg = data.read_u8().map(SymmetricKeyAlgorithm::from)?;

        let aead = data.read_u8().map(AeadAlgorithm::from)?;
        ensure_eq!(
            aead,
            AeadAlgorithm::Ocb,
            "GnupgAead AEAD mode {:?} is unsupported",
            aead
        );

        let chunk_size = data
            .read_u8()?
            .try_into()
            .map_err(|_| InvalidInputSnafu.build())?;

        let iv = data.take_bytes(aead.iv_size())?.into();

        Ok(Self {
            sym_alg,
            aead,
            chunk_size,
            iv,
        })
    }
}

impl Serialize for Config {
    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(GNUPG_AEAD_VERSION_1)?;
        writer.write_u8(self.sym_alg.into())?;
        writer.write_u8(self.aead.into())?;
        writer.write_u8(self.chunk_size.into())?;
        writer.write_all(&self.iv)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        4 + self.iv.len()
    }
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct GnupgAeadData {
    packet_header: PacketHeader,
    config: Config,
    #[debug("{}", hex::encode(data))]
    data: Bytes,
}

impl GnupgAeadData {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut data: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::GnupgAeadData, "invalid tag");

        let config = Config::try_from_reader(&mut data)?;
        let data = data.rest()?;

        Ok(Self {
            packet_header,
            config,
            data: data.freeze(),
        })
    }
}

impl Serialize for GnupgAeadData {
    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.config.to_writer(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.config.write_len();
        sum += self.data.len();
        sum
    }
}

impl PacketTrait for GnupgAeadData {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
