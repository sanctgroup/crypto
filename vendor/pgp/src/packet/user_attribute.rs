use std::io::{self, BufRead};

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;
use num_enum::{FromPrimitive, IntoPrimitive};
use rand::{CryptoRng, Rng};

use crate::{
    errors::{ensure, ensure_eq, Result},
    packet::{
        PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData, SubpacketLength, CERTIFICATION_SIGNATURE_TYPES,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{KeyDetails, KeyVersion, Password, SignedUserAttribute, SigningKey, Tag, Timestamp},
};

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive, derive_more::Display)]
#[repr(u8)]
pub enum UserAttributeType {
    #[display("Image")]
    Image = 0x01,
    #[num_enum(catch_all)]
    #[display("Unknown({:x})", 0)]
    Unknown(u8),
}

const JPEG_HEADER_PREFIX: &[u8; 4] = &[0x10, 0x00, 0x01, 0x01];

#[derive(Clone, PartialEq, Eq, derive_more::Debug, derive_more::Display)]
pub enum UserAttribute {
    #[display("User Attribute: Image (len: {})", data.len())]
    Image {
        packet_header: PacketHeader,
        subpacket_len: SubpacketLength,
        header: ImageHeader,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
    #[display("User Attribute: {} (len: {})", typ, data.len())]
    Unknown {
        packet_header: PacketHeader,
        subpacket_len: SubpacketLength,
        typ: UserAttributeType,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum ImageHeader {
    V1(ImageHeaderV1),
    Unknown {
        version: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum ImageHeaderV1 {
    Jpeg {
        data: [u8; 12],
    },
    Unknown {
        format: u8,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl ImageHeader {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let length: usize = i.read_le_u16()?.into();
        ensure!(length >= 4, "invalid image header length");

        let header_version = i.read_u8()?;

        match header_version {
            0x01 => {
                let format = i.read_u8()?;
                let mut data = i.read_take(length - 4);
                let header = match format {
                    0x01 => {
                        let data = data.read_arr::<12>()?;
                        ImageHeaderV1::Jpeg { data }
                    }
                    _ => ImageHeaderV1::Unknown {
                        format,
                        data: data.rest()?.freeze(),
                    },
                };
                Ok(Self::V1(header))
            }
            _ => {
                let data = i.take_bytes(length - 3)?;
                Ok(Self::Unknown {
                    version: header_version,
                    data: data.freeze(),
                })
            }
        }
    }
}

impl Serialize for ImageHeader {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::V1(header) => match header {
                ImageHeaderV1::Jpeg { data } => {
                    writer.write_all(JPEG_HEADER_PREFIX)?;
                    writer.write_all(data)?;
                }
                ImageHeaderV1::Unknown { format, data } => {
                    let len = (4 + data.len()).try_into()?;
                    writer.write_u16::<LittleEndian>(len)?;

                    writer.write_u8(0x01)?;
                    writer.write_u8(*format)?;
                    writer.write_all(data)?;
                }
            },
            Self::Unknown { version, data } => {
                let len = (1 + data.len()).try_into()?;
                writer.write_u16::<LittleEndian>(len)?;

                writer.write_u8(*version)?;
                writer.write_all(data)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        match self {
            Self::V1(header) => match header {
                ImageHeaderV1::Jpeg { .. } => 16,
                ImageHeaderV1::Unknown { data, .. } => 4 + data.len(),
            },
            Self::Unknown { data, .. } => 1 + data.len(),
        }
    }
}

impl UserAttribute {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut i: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::UserAttribute, "invalid tag");
        let packet_len = SubpacketLength::try_from_reader(&mut i)?;
        let mut rest = i.read_take(packet_len.len());
        let typ = rest.read_u8().map(UserAttributeType::from)?;

        match typ {
            UserAttributeType::Image => {
                let header = ImageHeader::try_from_reader(&mut rest)?;
                let data = rest.rest()?;

                Ok(UserAttribute::Image {
                    packet_header,
                    subpacket_len: packet_len,
                    header,
                    data: data.freeze(),
                })
            }
            UserAttributeType::Unknown(_) => Ok(UserAttribute::Unknown {
                packet_header,
                subpacket_len: packet_len,
                typ,
                data: rest.rest()?.freeze(),
            }),
        }
    }

    pub fn new_image(image: Bytes) -> Result<Self> {
        let header = ImageHeader::V1(ImageHeaderV1::Jpeg { data: [0u8; 12] });

        let packet_len = 1 + header.write_len() + image.len();
        let subpacket_len = SubpacketLength::encode(packet_len.try_into()?);

        let len = packet_len + subpacket_len.write_len();
        let packet_header = PacketHeader::new_fixed(Tag::UserAttribute, len.try_into()?);

        Ok(Self::Image {
            packet_header,
            subpacket_len,
            header,
            data: image,
        })
    }

    pub fn typ(&self) -> UserAttributeType {
        match self {
            UserAttribute::Image { .. } => UserAttributeType::Image,
            UserAttribute::Unknown { typ, .. } => *typ,
        }
    }

    pub fn sign<R, P, K>(
        &self,
        rng: R,
        signer_sec_key: &P,
        signer_pub_key: &K,
        key_pw: &Password,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        P: SigningKey,
        K: KeyDetails + Serialize,
    {
        self.sign_third_party(
            rng,
            signer_sec_key,
            key_pw,
            signer_pub_key,
            SignatureType::CertPositive,
        )
    }

    pub fn sign_third_party<R, P, K>(
        &self,
        mut rng: R,
        signer: &P,
        signer_pw: &Password,
        signee: &K,
        typ: SignatureType,
    ) -> Result<SignedUserAttribute>
    where
        R: CryptoRng + Rng,
        P: SigningKey,
        K: KeyDetails + Serialize,
    {
        ensure!(
            CERTIFICATION_SIGNATURE_TYPES.contains(&typ),
            "typ must be a certifying signature type"
        );

        let hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
        ];

        let mut config = SignatureConfig::from_key(&mut rng, signer, typ)?;

        config.hashed_subpackets = hashed_subpackets;
        if signer.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                signer.legacy_key_id(),
            ))?];
        }

        let sig =
            config.sign_certification_third_party(signer, signer_pw, signee, self.tag(), &self)?;

        Ok(SignedUserAttribute::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUserAttribute {
        SignedUserAttribute::new(self, vec![sig])
    }

    fn packet_len(&self) -> usize {
        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ..
            } => 1 + header.write_len() + data.len(),
            UserAttribute::Unknown { ref data, .. } => 1 + data.len(),
        }
    }

    fn subpacket_len(&self) -> &SubpacketLength {
        match self {
            UserAttribute::Image {
                ref subpacket_len, ..
            } => subpacket_len,
            UserAttribute::Unknown {
                ref subpacket_len, ..
            } => subpacket_len,
        }
    }
}

impl Serialize for UserAttribute {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            UserAttribute::Image {
                ref data,
                ref header,
                ref subpacket_len,
                ..
            } => {
                subpacket_len.to_writer(writer)?;

                writer.write_u8(0x01)?;
                header.to_writer(writer)?;

                writer.write_all(data)?;
            }
            UserAttribute::Unknown {
                ref data,
                typ,
                ref subpacket_len,
                ..
            } => {
                subpacket_len.to_writer(writer)?;

                writer.write_u8((*typ).into())?;
                writer.write_all(data)?;
            }
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        let packet_len = self.packet_len();
        let mut sum = self.subpacket_len().write_len();
        sum += packet_len;
        sum
    }
}

impl PacketTrait for UserAttribute {
    fn packet_header(&self) -> &PacketHeader {
        match self {
            UserAttribute::Image { packet_header, .. } => packet_header,
            UserAttribute::Unknown { packet_header, .. } => packet_header,
        }
    }
}
