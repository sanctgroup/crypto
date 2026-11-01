use std::io::{self, BufRead};

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use crate::{errors::Result, parsing_reader::BufReadParsing};

#[derive(derive_more::Debug, PartialEq, Eq, Clone, Copy)]
pub enum PacketLength {
    Fixed(u32),
    Indeterminate,
    Partial(u32),
}

impl PacketLength {
    pub fn fixed_encoding_len(len: u32) -> usize {
        if len < 192 {
            1
        } else if len < 8384 {
            2
        } else {
            1 + 4
        }
    }

    pub fn try_from_reader<R: BufRead>(mut r: R) -> std::io::Result<Self> {
        let olen = r.read_u8()?;
        let len = match olen {
            0..=191 => PacketLength::Fixed(olen.into()),

            192..=223 => {
                let a = r.read_u8()?;
                let l = ((olen as u32 - 192) << 8) + 192 + a as u32;
                PacketLength::Fixed(l)
            }

            224..=254 => PacketLength::Partial(1 << (olen as usize & 0x1F)),

            255 => {
                let len = r.read_be_u32()?;
                PacketLength::Fixed(len)
            }
        };
        Ok(len)
    }

    pub fn maybe_len(&self) -> Option<u32> {
        match self {
            Self::Fixed(len) => Some(*len),
            Self::Indeterminate => None,
            Self::Partial(len) => Some(*len),
        }
    }

    pub fn to_writer_new<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            PacketLength::Fixed(len) => {
                if *len < 192 {
                    writer.write_u8(*len as u8)?;
                } else if *len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(*len)?;
                }
            }
            PacketLength::Indeterminate => {
                unreachable!("invalid state: indeterminate lengths for new style packet header");
            }
            PacketLength::Partial(len) => {
                debug_assert_eq!(len.count_ones(), 1);

                let n = len.trailing_zeros();
                let n = (224 + n) as u8;
                writer.write_u8(n)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[non_exhaustive]
pub enum Tag {
    PublicKeyEncryptedSessionKey = 1,
    Signature = 2,
    SymKeyEncryptedSessionKey = 3,
    OnePassSignature = 4,
    SecretKey = 5,
    PublicKey = 6,
    SecretSubkey = 7,
    CompressedData = 8,
    SymEncryptedData = 9,
    Marker = 10,
    LiteralData = 11,
    Trust = 12,
    UserId = 13,
    PublicSubkey = 14,
    UserAttribute = 17,
    SymEncryptedProtectedData = 18,
    ModDetectionCode = 19,
    GnupgAeadData = 20,
    Padding = 21,

    UnassignedCritical(UnassignedCriticalTag),

    UnassignedNonCritical(UnassignedNonCriticalTag),

    Experimental(ExperimentalTag),

    Invalid(InvalidTag),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct UnassignedCriticalTag(u8);

impl UnassignedCriticalTag {
    pub fn new(value: u8) -> Option<Self> {
        match value {
            22..=39 => Some(Self(value)),
            _ => None,
        }
    }
}

impl From<UnassignedCriticalTag> for u8 {
    fn from(val: UnassignedCriticalTag) -> Self {
        val.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct UnassignedNonCriticalTag(u8);

impl UnassignedNonCriticalTag {
    pub fn new(value: u8) -> Option<Self> {
        match value {
            40..=59 => Some(Self(value)),
            _ => None,
        }
    }
}

impl From<UnassignedNonCriticalTag> for u8 {
    fn from(val: UnassignedNonCriticalTag) -> Self {
        val.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct ExperimentalTag(u8);

impl ExperimentalTag {
    pub fn new(value: u8) -> Option<Self> {
        match value {
            60..=63 => Some(Self(value)),
            _ => None,
        }
    }
}

impl From<ExperimentalTag> for u8 {
    fn from(val: ExperimentalTag) -> Self {
        val.0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(transparent)]
pub struct InvalidTag(u8);

impl InvalidTag {
    pub fn new(value: u8) -> Option<Self> {
        match value {
            0 | 15 | 16 | 64.. => Some(Self(value)),
            _ => None,
        }
    }
}

impl From<InvalidTag> for u8 {
    fn from(val: InvalidTag) -> Self {
        val.0
    }
}

impl From<Tag> for u8 {
    fn from(value: Tag) -> Self {
        match value {
            Tag::PublicKeyEncryptedSessionKey => 1,
            Tag::Signature => 2,
            Tag::SymKeyEncryptedSessionKey => 3,
            Tag::OnePassSignature => 4,
            Tag::SecretKey => 5,
            Tag::PublicKey => 6,
            Tag::SecretSubkey => 7,
            Tag::CompressedData => 8,
            Tag::SymEncryptedData => 9,
            Tag::Marker => 10,
            Tag::LiteralData => 11,
            Tag::Trust => 12,
            Tag::UserId => 13,
            Tag::PublicSubkey => 14,

            Tag::UserAttribute => 17,
            Tag::SymEncryptedProtectedData => 18,
            Tag::ModDetectionCode => 19,
            Tag::GnupgAeadData => 20,
            Tag::Padding => 21,

            Tag::UnassignedCritical(id) => id.into(),
            Tag::UnassignedNonCritical(id) => id.into(),
            Tag::Experimental(id) => id.into(),

            Tag::Invalid(id) => id.into(),
        }
    }
}
impl From<u8> for Tag {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::PublicKeyEncryptedSessionKey,
            2 => Self::Signature,
            3 => Self::SymKeyEncryptedSessionKey,
            4 => Self::OnePassSignature,
            5 => Self::SecretKey,
            6 => Self::PublicKey,
            7 => Self::SecretSubkey,
            8 => Self::CompressedData,
            9 => Self::SymEncryptedData,
            10 => Self::Marker,
            11 => Self::LiteralData,
            12 => Self::Trust,
            13 => Self::UserId,
            14 => Self::PublicSubkey,

            17 => Self::UserAttribute,
            18 => Self::SymEncryptedProtectedData,
            19 => Self::ModDetectionCode,
            20 => Self::GnupgAeadData,
            21 => Self::Padding,
            22..=39 => Self::UnassignedCritical(UnassignedCriticalTag(value)),
            40..=59 => Self::UnassignedNonCritical(UnassignedNonCriticalTag(value)),
            60..=63 => Self::Experimental(ExperimentalTag(value)),

            0 | 15 | 16 | 64.. => Self::Invalid(InvalidTag(value)),
        }
    }
}

impl Tag {
    pub fn encode(self) -> u8 {
        0b1100_0000 | u8::from(self)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[derive(Default)]

pub enum PacketHeaderVersion {
    Old = 0,
    #[default]
    New = 1,
}

impl PacketHeaderVersion {
    pub fn write_header(self, writer: &mut impl io::Write, tag: Tag, len: usize) -> Result<()> {
        debug!("write_header {self:?} {tag:?} {len}");
        let tag: u8 = tag.into();
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    writer.write_u8(0b1000_0000 | (tag << 2))?;
                    writer.write_u8(len.try_into()?)?;
                } else if len < 65536 {
                    writer.write_u8(0b1000_0001 | (tag << 2))?;
                    writer.write_u16::<BigEndian>(len as u16)?;
                } else {
                    writer.write_u8(0b1000_0010 | (tag << 2))?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
            PacketHeaderVersion::New => {
                writer.write_u8(0b1100_0000 | tag)?;
                if len < 192 {
                    writer.write_u8(len.try_into()?)?;
                } else if len < 8384 {
                    writer.write_u8((((len - 192) >> 8) + 192) as u8)?;
                    writer.write_u8(((len - 192) & 0xFF) as u8)?;
                } else {
                    writer.write_u8(255)?;
                    writer.write_u32::<BigEndian>(len as u32)?;
                }
            }
        }

        Ok(())
    }

    pub fn header_len(self, len: usize) -> usize {
        match self {
            PacketHeaderVersion::Old => {
                if len < 256 {
                    2
                } else if len < 65536 {
                    3
                } else {
                    5
                }
            }
            PacketHeaderVersion::New => {
                if len < 192 {
                    2
                } else if len < 8384 {
                    3
                } else {
                    6
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum KeyVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,

    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

impl KeyVersion {
    pub const fn fingerprint_len(&self) -> Option<usize> {
        match self {
            KeyVersion::V2 | KeyVersion::V3 => Some(16),
            KeyVersion::V4 => Some(20),
            KeyVersion::V5 | KeyVersion::V6 => Some(32),
            KeyVersion::Other(_) => None,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for KeyVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum PkeskVersion {
    V3 = 3,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SkeskVersion {
    V4 = 4,

    V5 = 5,

    V6 = 6,

    #[num_enum(catch_all)]
    Other(u8),
}
