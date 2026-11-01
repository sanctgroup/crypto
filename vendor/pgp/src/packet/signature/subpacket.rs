use std::io::BufRead;

use byteorder::{BigEndian, WriteBytesExt};
use bytes::Bytes;
use smallvec::SmallVec;

use crate::{
    crypto::{
        aead::AeadAlgorithm, hash::HashAlgorithm, public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::Result,
    packet::{Features, KeyFlags, Notation, RevocationCode, Signature},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{CompressionAlgorithm, Duration, Fingerprint, KeyId, RevocationKey, Timestamp},
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SubpacketType {
    SignatureCreationTime,
    SignatureExpirationTime,
    ExportableCertification,
    TrustSignature,
    RegularExpression,
    Revocable,
    KeyExpirationTime,
    PreferredSymmetricAlgorithms,
    RevocationKey,
    IssuerKeyId,
    Notation,
    PreferredHashAlgorithms,
    PreferredCompressionAlgorithms,
    KeyServerPreferences,
    PreferredKeyServer,
    PrimaryUserId,
    PolicyURI,
    KeyFlags,
    SignersUserID,
    RevocationReason,
    Features,
    SignatureTarget,
    EmbeddedSignature,
    IssuerFingerprint,
    PreferredEncryptionModes,
    IntendedRecipientFingerprint,

    PreferredAead,
    Experimental(u8),
    Other(u8),
}

impl SubpacketType {
    pub fn as_u8(&self, is_critical: bool) -> u8 {
        let raw: u8 = match self {
            SubpacketType::SignatureCreationTime => 2,
            SubpacketType::SignatureExpirationTime => 3,
            SubpacketType::ExportableCertification => 4,
            SubpacketType::TrustSignature => 5,
            SubpacketType::RegularExpression => 6,
            SubpacketType::Revocable => 7,
            SubpacketType::KeyExpirationTime => 9,
            SubpacketType::PreferredSymmetricAlgorithms => 11,
            SubpacketType::RevocationKey => 12,
            SubpacketType::IssuerKeyId => 16,
            SubpacketType::Notation => 20,
            SubpacketType::PreferredHashAlgorithms => 21,
            SubpacketType::PreferredCompressionAlgorithms => 22,
            SubpacketType::KeyServerPreferences => 23,
            SubpacketType::PreferredKeyServer => 24,
            SubpacketType::PrimaryUserId => 25,
            SubpacketType::PolicyURI => 26,
            SubpacketType::KeyFlags => 27,
            SubpacketType::SignersUserID => 28,
            SubpacketType::RevocationReason => 29,
            SubpacketType::Features => 30,
            SubpacketType::SignatureTarget => 31,
            SubpacketType::EmbeddedSignature => 32,
            SubpacketType::IssuerFingerprint => 33,
            SubpacketType::PreferredEncryptionModes => 34,
            SubpacketType::IntendedRecipientFingerprint => 35,

            SubpacketType::PreferredAead => 39,
            SubpacketType::Experimental(n) => *n,
            SubpacketType::Other(n) => *n,
        };

        if is_critical {
            raw | 0b1000_0000
        } else {
            raw
        }
    }

    #[inline]
    pub fn from_u8(n: u8) -> (Self, bool) {
        let is_critical = (n >> 7) == 1;

        let n = n & 0b0111_1111;

        let m = match n {
            2 => SubpacketType::SignatureCreationTime,
            3 => SubpacketType::SignatureExpirationTime,
            4 => SubpacketType::ExportableCertification,
            5 => SubpacketType::TrustSignature,
            6 => SubpacketType::RegularExpression,
            7 => SubpacketType::Revocable,
            9 => SubpacketType::KeyExpirationTime,
            11 => SubpacketType::PreferredSymmetricAlgorithms,
            12 => SubpacketType::RevocationKey,
            16 => SubpacketType::IssuerKeyId,
            20 => SubpacketType::Notation,
            21 => SubpacketType::PreferredHashAlgorithms,
            22 => SubpacketType::PreferredCompressionAlgorithms,
            23 => SubpacketType::KeyServerPreferences,
            24 => SubpacketType::PreferredKeyServer,
            25 => SubpacketType::PrimaryUserId,
            26 => SubpacketType::PolicyURI,
            27 => SubpacketType::KeyFlags,
            28 => SubpacketType::SignersUserID,
            29 => SubpacketType::RevocationReason,
            30 => SubpacketType::Features,
            31 => SubpacketType::SignatureTarget,
            32 => SubpacketType::EmbeddedSignature,
            33 => SubpacketType::IssuerFingerprint,
            34 => SubpacketType::PreferredEncryptionModes,
            35 => SubpacketType::IntendedRecipientFingerprint,

            39 => SubpacketType::PreferredAead,
            100..=110 => SubpacketType::Experimental(n),
            _ => SubpacketType::Other(n),
        };

        (m, is_critical)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]

pub enum SubpacketLength {
    One(u8),
    Two(u16),
    Five(u32),
}

impl SubpacketLength {
    pub(crate) fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let olen = i.read_u8()?;
        let len = match olen {
            0..=191 => Self::One(olen),

            192..=254 => {
                let a = i.read_u8()?;
                let l = ((olen as u16 - 192) << 8) + 192 + a as u16;
                Self::Two(l)
            }
            255 => {
                let len = i.read_be_u32()?;
                Self::Five(len)
            }
        };
        Ok(len)
    }

    pub(crate) fn encode(len: u32) -> Self {
        match len {
            0..=191 => Self::One(len as u8),
            192..=16319 => Self::Two(len as u16),
            _ => Self::Five(len),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::One(l) => *l as _,
            Self::Two(l) => *l as _,
            Self::Five(l) => *l as _,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Serialize for SubpacketLength {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::One(l) => {
                debug_assert!(*l < 192, "Inconsistent SubpacketLength::One");
                writer.write_u8(*l)?;
            }
            Self::Two(l) => {
                let one = (((l - 192) / 256) + 192) as u8;
                let two = ((l - 192) % 256) as u8;

                debug_assert!(
                    (192..=254).contains(&one),
                    "Inconsistent SubpacketLength::Two"
                );

                writer.write_u8(one)?;
                writer.write_u8(two)?;
            }
            Self::Five(l) => {
                writer.write_u8(0xFF)?;
                writer.write_u32::<BigEndian>(*l)?
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Two(_) => 2,
            Self::Five(_) => 5,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Subpacket {
    pub is_critical: bool,
    pub data: SubpacketData,
    pub len: SubpacketLength,
}

impl Subpacket {
    pub fn regular(data: SubpacketData) -> Result<Self> {
        let raw_len = (data.write_len() + 1).try_into()?;
        let len = SubpacketLength::encode(raw_len);
        Ok(Subpacket {
            is_critical: false,
            data,
            len,
        })
    }

    pub fn critical(data: SubpacketData) -> Result<Self> {
        let raw_len = (data.write_len() + 1).try_into()?;
        let len = SubpacketLength::encode(raw_len);
        Ok(Subpacket {
            is_critical: true,
            data,
            len,
        })
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum SubpacketData {
    SignatureCreationTime(Timestamp),
    SignatureExpirationTime(Duration),
    KeyExpirationTime(Duration),
    IssuerKeyId(KeyId),
    PreferredSymmetricAlgorithms(SmallVec<[SymmetricKeyAlgorithm; 8]>),
    PreferredHashAlgorithms(SmallVec<[HashAlgorithm; 8]>),
    PreferredCompressionAlgorithms(SmallVec<[CompressionAlgorithm; 8]>),
    KeyServerPreferences(#[debug("{}", hex::encode(_0))] SmallVec<[u8; 4]>),
    KeyFlags(KeyFlags),
    Features(Features),
    RevocationReason(RevocationCode, Bytes),
    IsPrimary(bool),
    Revocable(bool),
    EmbeddedSignature(Box<Signature>),
    PreferredKeyServer(String),
    Notation(Notation),
    RevocationKey(RevocationKey),
    SignersUserID(Bytes),
    PolicyURI(String),
    TrustSignature(u8, u8),
    RegularExpression(Bytes),
    ExportableCertification(bool),
    IssuerFingerprint(Fingerprint),
    PreferredEncryptionModes(SmallVec<[AeadAlgorithm; 2]>),
    IntendedRecipientFingerprint(Fingerprint),
    PreferredAeadAlgorithms(SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>),
    Experimental(u8, #[debug("{}", hex::encode(_1))] Bytes),
    Other(u8, #[debug("{}", hex::encode(_1))] Bytes),
    SignatureTarget(
        PublicKeyAlgorithm,
        HashAlgorithm,
        #[debug("{}", hex::encode(_2))] Bytes,
    ),
}
