use std::{io, ops::Deref};

use generic_array::GenericArray;
use log::warn;

use crate::{
    armor,
    composed::{
        signed_key::{SignedKeyDetails, SignedPublicSubKey},
        ArmorOptions, SignedPublicKey,
    },
    crypto::hash::KnownDigest,
    errors::{ensure, Result},
    packet::{self, Packet, PacketTrait, SignatureType},
    ser::Serialize,
    types::{Imprint, Tag, VerifyingKey},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretKey {
    pub primary_key: packet::SecretKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
    pub secret_subkeys: Vec<SignedSecretSubKey>,
}

pub struct SignedSecretKeyParser<
    I: Sized + Iterator<Item = crate::errors::Result<crate::packet::Packet>>,
> {
    inner: std::iter::Peekable<I>,
}

impl<I: Sized + Iterator<Item = crate::errors::Result<crate::packet::Packet>>>
    SignedSecretKeyParser<I>
{
    pub fn into_inner(self) -> std::iter::Peekable<I> {
        self.inner
    }

    pub fn from_packets(packets: std::iter::Peekable<I>) -> Self {
        SignedSecretKeyParser { inner: packets }
    }
}

impl<I: Sized + Iterator<Item = Result<Packet>>> Iterator for SignedSecretKeyParser<I> {
    type Item = Result<SignedSecretKey>;

    fn next(&mut self) -> Option<Self::Item> {
        match super::key_parser::next::<_, packet::SecretKey>(&mut self.inner, Tag::SecretKey, true)
        {
            Some(Err(err)) => Some(Err(err)),
            None => None,
            Some(Ok((primary_key, details, public_subkeys, secret_subkeys))) => Some(Ok(
                SignedSecretKey::new(primary_key, details, public_subkeys, secret_subkeys),
            )),
        }
    }
}

impl crate::composed::Deserializable for SignedSecretKey {
    fn from_packets<'a, I: Iterator<Item = Result<Packet>> + 'a>(
        packets: std::iter::Peekable<I>,
    ) -> Box<dyn Iterator<Item = Result<Self>> + 'a> {
        Box::new(SignedSecretKeyParser::from_packets(packets))
    }

    fn matches_block_type(typ: armor::BlockType) -> bool {
        matches!(typ, armor::BlockType::PrivateKey | armor::BlockType::File)
    }
}

impl SignedSecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: SignedKeyDetails,
        mut public_subkeys: Vec<SignedPublicSubKey>,
        mut secret_subkeys: Vec<SignedSecretSubKey>,
    ) -> Self {
        public_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        secret_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    pub fn verify_bindings(&self) -> Result<()> {
        self.details
            .verify_bindings(self.primary_key.public_key())?;
        for subkey in &self.public_subkeys {
            subkey.verify_bindings(self.primary_key.public_key())?;
        }

        for subkey in &self.secret_subkeys {
            subkey.verify_bindings(self.primary_key.public_key())?;
        }

        Ok(())
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        opts: ArmorOptions<'_>,
    ) -> Result<()> {
        armor::write(
            self,
            armor::BlockType::PrivateKey,
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

    pub fn to_public_key(&self) -> SignedPublicKey {
        let mut public_subkeys: Vec<SignedPublicSubKey> = self.public_subkeys.to_vec();
        let sec_subkeys: Vec<SignedPublicSubKey> = self
            .secret_subkeys
            .iter()
            .map(SignedSecretSubKey::signed_public_key)
            .collect();
        public_subkeys.extend(sec_subkeys);

        SignedPublicKey::new(
            self.primary_key.public_key().clone(),
            self.details.clone(),
            public_subkeys,
        )
    }
}

impl Serialize for SignedSecretKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.primary_key.to_writer_with_header(writer)?;
        self.details.to_writer(writer)?;
        for ps in &self.public_subkeys {
            ps.to_writer(writer)?;
        }

        for ps in &self.secret_subkeys {
            ps.to_writer(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.primary_key.write_len_with_header();
        sum += self.details.write_len();
        sum += self.public_subkeys.write_len();
        sum += self.secret_subkeys.write_len();
        sum
    }
}

impl Deref for SignedSecretKey {
    type Target = packet::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.primary_key
    }
}

impl Imprint for SignedSecretKey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.primary_key.imprint::<D>()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretSubKey {
    pub key: packet::SecretSubkey,
    pub signatures: Vec<packet::Signature>,
}

impl SignedSecretSubKey {
    pub fn new(key: packet::SecretSubkey, mut signatures: Vec<packet::Signature>) -> Self {
        signatures.retain(|sig| {
            if sig.typ() != Some(SignatureType::SubkeyBinding)
                && sig.typ() != Some(SignatureType::SubkeyRevocation)
            {
                warn!(
                    "ignoring unexpected signature {:?} after Subkey packet",
                    sig.typ()
                );
                false
            } else {
                true
            }
        });

        SignedSecretSubKey { key, signatures }
    }

    pub fn verify_bindings<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");

        for sig in &self.signatures {
            sig.verify_subkey_binding(key, self.key.public_key())?;
        }

        Ok(())
    }

    pub fn signed_public_key(&self) -> SignedPublicSubKey {
        SignedPublicSubKey::new(self.key.public_key().clone(), self.signatures.clone())
    }
}

impl Deref for SignedSecretSubKey {
    type Target = packet::SecretSubkey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Serialize for SignedSecretSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        self.key.to_writer_with_header(writer)?;
        for sig in &self.signatures {
            sig.to_writer_with_header(writer)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = self.key.write_len_with_header();
        for sig in &self.signatures {
            sum += sig.write_len_with_header()
        }
        sum
    }
}

impl Imprint for SignedSecretSubKey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.key.imprint::<D>()
    }
}

impl From<SignedSecretKey> for SignedPublicKey {
    fn from(value: SignedSecretKey) -> Self {
        let primary = value.primary_key.public_key();
        let details = value.details;

        let mut subkeys = value.public_subkeys;

        value
            .secret_subkeys
            .into_iter()
            .for_each(|key| subkeys.push(key.into()));

        SignedPublicKey::new(primary.clone(), details, subkeys)
    }
}

impl From<SignedSecretSubKey> for SignedPublicSubKey {
    fn from(value: SignedSecretSubKey) -> Self {
        SignedPublicSubKey::new(value.key.public_key().clone(), value.signatures)
    }
}
