use std::{
    io::{self, BufRead},
    str,
};

use bytes::Bytes;
use rand::{CryptoRng, Rng};

use crate::{
    errors::{ensure, Result},
    packet::{
        PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData, CERTIFICATION_SIGNATURE_TYPES,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        KeyDetails, KeyVersion, PacketHeaderVersion, PacketLength, Password, SignedUser,
        SigningKey, Tag, Timestamp,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("User ID: \"{:?}\"", id)]
pub struct UserId {
    packet_header: PacketHeader,

    id: Bytes,
}

impl UserId {
    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, mut input: B) -> Result<Self> {
        let id = input.rest()?;
        Ok(UserId {
            packet_header,
            id: id.freeze(),
        })
    }

    pub fn from_str(packet_version: PacketHeaderVersion, input: impl AsRef<str>) -> Result<Self> {
        let id: Bytes = input.as_ref().as_bytes().to_vec().into();

        let len = PacketLength::Fixed(id.len().try_into()?);
        let packet_header = PacketHeader::from_parts(packet_version, Tag::UserId, len)?;

        Ok(UserId { packet_header, id })
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.id
    }

    #[inline]
    pub fn try_into_string(self) -> Result<String, Bytes> {
        let Self { id, .. } = self;
        match std::string::String::from_utf8(Vec::from(id)) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into_bytes().into()),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.id).ok()
    }

    pub fn sign<R, S, K>(
        &self,
        rng: R,
        signer_sec_key: &S,
        signer_pub_key: &K,
        key_pw: &Password,
    ) -> Result<SignedUser>
    where
        R: CryptoRng + Rng,
        S: SigningKey,
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

    pub fn sign_third_party<R, S, K>(
        &self,
        mut rng: R,
        signer: &S,
        signer_pw: &Password,
        signee: &K,
        typ: SignatureType,
    ) -> Result<SignedUser>
    where
        R: CryptoRng + Rng,
        S: SigningKey,
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

        Ok(SignedUser::new(self.clone(), vec![sig]))
    }

    pub fn into_signed(self, sig: Signature) -> SignedUser {
        SignedUser::new(self, vec![sig])
    }
}

impl Serialize for UserId {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.id)?;

        Ok(())
    }

    fn write_len(&self) -> usize {
        self.id.len()
    }
}

impl PacketTrait for UserId {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}
