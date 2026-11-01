use std::{io::Read, iter::Peekable};

use aead::rand_core::CryptoRng;
use rand::Rng;

use crate::{
    armor,
    composed::{ArmorOptions, Deserializable, SubpacketConfig},
    crypto::hash::HashAlgorithm,
    errors::{bail, format_err, Result},
    packet::{Packet, PacketTrait, Signature, SignatureConfig, SignatureType},
    ser::Serialize,
    types::{KeyVersion, Password, SigningKey, Tag, VerifyingKey},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedSignature {
    pub signature: Signature,
}

impl DetachedSignature {
    pub fn new(signature: Signature) -> Self {
        DetachedSignature { signature }
    }

    pub fn sign_binary_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Binary,
            key,
            key_pw,
            hash_algorithm,
            data,
            SubpacketConfig::Default,
        )
    }

    pub fn sign_binary_data_with_subpackets<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Binary,
            key,
            key_pw,
            hash_algorithm,
            data,
            subpackets,
        )
    }

    pub fn sign_text_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Text,
            key,
            key_pw,
            hash_algorithm,
            data,
            SubpacketConfig::Default,
        )
    }

    pub fn sign_text_data_with_subpackets<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        Self::sign_data(
            rng,
            SignatureType::Text,
            key,
            key_pw,
            hash_algorithm,
            data,
            subpackets,
        )
    }

    fn sign_data<RNG: Rng + CryptoRng, R: Read>(
        rng: RNG,
        typ: SignatureType,
        key: &impl SigningKey,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
        data: R,
        subpackets: SubpacketConfig,
    ) -> Result<DetachedSignature> {
        let mut config = match key.version() {
            KeyVersion::V4 => SignatureConfig::v4(typ, key.algorithm(), hash_algorithm),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, key.algorithm(), hash_algorithm)?,
            v => bail!("unsupported key version: {:?}", v),
        };

        let (hashed, unhashed) = subpackets.to_subpackets(key)?;
        config.hashed_subpackets = hashed;
        config.unhashed_subpackets = unhashed;

        let sig = config.sign(key, key_pw, data)?;

        Ok(DetachedSignature::new(sig))
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl std::io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::Signature,
            writer,
            opts.headers,
            opts.include_checksum,
        )
    }

    pub fn to_armored_bytes(&self, opts: ArmorOptions<'_>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, opts)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, opts: ArmorOptions<'_>) -> Result<String> {
        let res = String::from_utf8(self.to_armored_bytes(opts)?).map_err(|e| e.utf8_error())?;
        Ok(res)
    }

    pub fn verify(&self, key: &impl VerifyingKey, content: &[u8]) -> Result<()> {
        self.signature.verify(key, content)
    }
}

impl Serialize for DetachedSignature {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.signature.to_writer_with_header(writer)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.signature.write_len_with_header()
    }
}

impl Deserializable for DetachedSignature {
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignatureParser { source: packets })
    }

    fn matches_block_type(typ: armor::BlockType) -> bool {
        matches!(typ, armor::BlockType::Signature)
    }
}

pub struct SignatureParser<I: Sized + Iterator<Item = Result<Packet>>> {
    source: Peekable<I>,
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for SignatureParser<I> {
    type Item = Result<DetachedSignature>;

    fn next(&mut self) -> Option<Self::Item> {
        next(self.source.by_ref())
    }
}

fn next<I: Iterator<Item = Result<Packet>>>(
    packets: &mut Peekable<I>,
) -> Option<Result<DetachedSignature>> {
    match packets.by_ref().next() {
        Some(Ok(packet)) => match packet.tag() {
            Tag::Signature => Some(packet.try_into().map(DetachedSignature::new)),
            _ => Some(Err(format_err!("unexpected packet {:?}", packet.tag()))),
        },
        Some(Err(e)) => Some(Err(e)),
        None => None,
    }
}
