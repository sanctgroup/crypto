use std::io::BufRead;

use bitfields::bitfield;
use byteorder::{BigEndian, WriteBytesExt};
use log::debug;

use crate::{
    errors::{bail, ensure, format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{PacketHeaderVersion, PacketLength, Tag},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PacketHeader {
    Old {
        header: OldPacketHeader,
        length: PacketLength,
    },
    New {
        header: NewPacketHeader,
        length: PacketLength,
    },
}

const MAX_PARTIAL_LEN: u32 = 2u32.pow(30);

impl PacketHeader {
    pub fn try_from_reader<R: BufRead>(mut r: R) -> std::io::Result<Self> {
        let header = r.read_u8()?;

        let first_two_bits = header & 0b1100_0000;
        match first_two_bits {
            0b1100_0000 => {
                let header = NewPacketHeader::from_bits(header);
                let length = PacketLength::try_from_reader(r)?;

                Ok(PacketHeader::New { header, length })
            }
            0b1000_0000 => {
                let header = OldPacketHeader::from_bits(header);
                let length = match header.length_type() {
                    0 => PacketLength::Fixed(r.read_u8()?.into()),

                    1 => PacketLength::Fixed(r.read_be_u16()?.into()),

                    2 => PacketLength::Fixed(r.read_be_u32()?),
                    3 => PacketLength::Indeterminate,
                    _ => unreachable!("old packet length type is only 2 bits"),
                };
                Ok(PacketHeader::Old { header, length })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown packet header version {header:b}"),
            )),
        }
    }

    pub fn from_parts(
        version: PacketHeaderVersion,
        tag: Tag,
        length: PacketLength,
    ) -> Result<Self> {
        match version {
            PacketHeaderVersion::Old => {
                let typ = match &length {
                    PacketLength::Fixed(len) => old_fixed_type(*len),
                    PacketLength::Indeterminate => 3,
                    PacketLength::Partial(_) => {
                        bail!("partial lengths are only supported in new style headers");
                    }
                };

                Ok(Self::Old {
                    header: OldPacketHeaderBuilder::new()
                        .checked_with_tag(tag.into())
                        .map_err(|_| {
                            format_err!("tag is not compatible with old packet headers: {:?}", tag)
                        })?
                        .with_length_type(typ)
                        .build(),
                    length,
                })
            }
            PacketHeaderVersion::New => {
                ensure!(
                    !matches!(length, PacketLength::Indeterminate),
                    "indeterminate packet length is only supported in old style headers"
                );
                if let PacketLength::Partial(l) = length {
                    ensure!(
                        l.count_ones() == 1,
                        "partial length must be a power of two: {}",
                        l
                    );
                    ensure!(
                        l <= MAX_PARTIAL_LEN,
                        "partial length must be less or equal than {}",
                        MAX_PARTIAL_LEN
                    );
                }

                Ok(Self::New {
                    header: NewPacketHeaderBuilder::new().with_tag(tag.into()).build(),
                    length,
                })
            }
        }
    }

    pub const fn version(&self) -> PacketHeaderVersion {
        match self {
            Self::Old { .. } => PacketHeaderVersion::Old,
            Self::New { .. } => PacketHeaderVersion::New,
        }
    }

    pub fn packet_length(&self) -> PacketLength {
        match self {
            Self::Old { length, .. } => *length,
            Self::New { length, .. } => *length,
        }
    }

    pub(crate) fn packet_length_mut(&mut self) -> &mut PacketLength {
        match self {
            Self::Old { ref mut length, .. } | Self::New { ref mut length, .. } => length,
        }
    }

    pub fn tag(&self) -> Tag {
        match self {
            Self::Old { header, .. } => header.tag().into(),
            Self::New { header, .. } => header.tag().into(),
        }
    }

    pub fn new_fixed(tag: Tag, length: u32) -> Self {
        let header = NewPacketHeaderBuilder::new().with_tag(tag.into()).build();
        PacketHeader::New {
            header,
            length: PacketLength::Fixed(length),
        }
    }
}

impl Serialize for PacketHeader {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        debug!("writing packet header {self:?}");

        match self {
            Self::New { header, length } => {
                writer.write_u8(header.into_bits())?;
                length.to_writer_new(writer)?;
            }
            Self::Old { header, length } => match length {
                PacketLength::Fixed(len) => {
                    writer.write_u8(header.into_bits())?;
                    if *len < 256 {
                        writer.write_u8(*len as u8)?;
                    } else if *len < 65536 {
                        writer.write_u16::<BigEndian>(*len as u16)?;
                    } else {
                        writer.write_u32::<BigEndian>(*len)?;
                    }
                }
                PacketLength::Indeterminate => {
                    writer.write_u8(header.into_bits())?;
                }
                PacketLength::Partial(_) => {
                    unreachable!("invalid state: partial lengths for old style packet header");
                }
            },
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Self::New { header: _, length } => match length {
                PacketLength::Fixed(len) => {
                    let mut sum = 1;
                    if *len < 192 {
                        sum += 1;
                    } else if *len < 8384 {
                        sum += 2;
                    } else {
                        sum += 5
                    }
                    sum
                }
                PacketLength::Indeterminate => {
                    unreachable!(
                        "invalid state: indeterminate lengths for new style packet header"
                    );
                }
                PacketLength::Partial(_len) => 1 + 1,
            },
            Self::Old { header: _, length } => match length {
                PacketLength::Fixed(len) => {
                    let mut sum = 1;
                    if *len < 256 {
                        sum += 1;
                    } else if *len < 65536 {
                        sum += 2;
                    } else {
                        sum += 4;
                    }
                    sum
                }
                PacketLength::Indeterminate => 1,
                PacketLength::Partial(_) => {
                    unreachable!("invalid state: partial lengths for old style packet header");
                }
            },
        }
    }
}

#[bitfield(u8, order = msb, debug = false)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OldPacketHeader {
    #[bits(1, default = true)]
    padding: bool,
    #[bits(1, default = false)]
    version: bool,
    #[bits(4)]
    tag: u8,
    #[bits(2)]
    length_type: u8,
}

impl std::fmt::Debug for OldPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OldPacketHeader")
            .field("padding", &(self.padding() as u8))
            .field("version", &(self.version() as u8))
            .field("tag", &Tag::from(self.tag()))
            .field("length_type", &self.length_type())
            .finish()
    }
}

#[bitfield(u8, order = msb, debug = false)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NewPacketHeader {
    #[bits(1, default = true)]
    padding: bool,
    #[bits(1, default = true)]
    version: bool,
    #[bits(6)]
    tag: u8,
}

impl std::fmt::Debug for NewPacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPacketHeader")
            .field("padding", &(self.padding() as u8))
            .field("version", &(self.version() as u8))
            .field("tag", &(Tag::from(self.tag())))
            .finish()
    }
}

fn old_fixed_type(len: u32) -> u8 {
    if len < 256 {
        0
    } else if len < 65536 {
        1
    } else {
        2
    }
}
