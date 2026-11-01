use std::io::{self, BufRead, Read};

use log::{debug, warn};

use super::reader::{
    CompressedDataReader, LiteralDataReader, PacketBodyReader, SignatureManyReader,
    SymEncryptedDataReader, SymEncryptedProtectedDataReader,
};
use crate::{
    armor,
    composed::{message::decrypt::*, signed_key::SignedSecretKey, FullSignaturePacket},
    crypto::sym::SymmetricKeyAlgorithm,
    errors::{bail, ensure, ensure_eq, format_err, Error, Result},
    packet::{
        InnerSignature, LiteralDataHeader, Packet, PacketHeader, PacketTrait, ProtectedDataConfig,
        PublicKeyEncryptedSessionKey, Signature, SymKeyEncryptedSessionKey,
    },
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        DecryptionKey, EskType, KeyDetails, Password, PkeskBytes, PkeskVersion, Seipdv1ReadMode,
        SkeskVersion, Tag, VerifyingKey,
    },
    util::impl_try_from_into,
};

pub trait DebugBufRead: BufRead + std::fmt::Debug + Send {}

impl<T: BufRead + std::fmt::Debug + Send> DebugBufRead for T {}

#[derive(Debug)]
pub enum MessageReader<'a> {
    Compressed(Box<CompressedDataReader<MessageReader<'a>>>),
    Edata(Box<Edata<'a>>),
    Reader(Box<dyn DebugBufRead + 'a>),
}

impl MessageReader<'_> {
    pub fn get_mut(&mut self) -> &mut Self {
        match self {
            Self::Compressed(r) => r.get_mut().get_mut(),
            Self::Edata(r) => r.get_mut().get_mut().get_mut(),
            Self::Reader(_r) => self,
        }
    }

    fn check_trailing_data(&mut self) -> io::Result<()> {
        fn check_next_packet<R: DebugBufRead>(
            mut parser: crate::packet::PacketParser<R>,
        ) -> io::Result<()> {
            loop {
                match parser.next_ref() {
                    Some(Ok(mut packet)) => {
                        let tag = packet.packet_header().tag();
                        match tag {
                            Tag::Padding
                            | Tag::Marker
                            | Tag::UnassignedNonCritical(_)
                            | Tag::Experimental(_) => {
                                debug!("ignoring trailing packet: {tag:?}");

                                let mut out = Vec::new();
                                packet.read_to_end(&mut out)?;
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "unexpected trailing packet found: {:?}",
                                        packet.packet_header()
                                    ),
                                ));
                            }
                        }
                    }
                    Some(Err(err)) => {
                        warn!("failed to parse trailing data: {err:?}");
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "unexpected trailing bytes found",
                        ));
                    }
                    None => {
                        return Ok(());
                    }
                }
            }
        }

        match self {
            MessageReader::Compressed(r) => {
                let compressed_body_reader = r.get_mut();

                let excess = compressed_body_reader.drain()?;
                if excess > 0 {
                    debug!("discarded excess data in compressed packet: {excess}");
                }

                let message_reader = compressed_body_reader.get_mut();
                message_reader.check_trailing_data()?;
            }
            MessageReader::Edata(e) => {
                let mut inner_reader = e;
                let parser = crate::packet::PacketParser::new(&mut inner_reader);
                check_next_packet(parser)?;

                let message_reader = inner_reader.get_mut().get_mut();
                message_reader.check_trailing_data()?;
            }
            MessageReader::Reader(r) => {
                let parser = crate::packet::PacketParser::new(r);
                check_next_packet(parser)?;
            }
        }

        Ok(())
    }
}

impl Read for MessageReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Compressed(r) => r.read(buf),
            Self::Edata(r) => r.read(buf),
            Self::Reader(r) => r.read(buf),
        }
    }
}

impl BufRead for MessageReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Compressed(r) => r.fill_buf(),
            Self::Edata(r) => r.fill_buf(),
            Self::Reader(r) => r.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Compressed(r) => r.consume(amt),
            Self::Edata(r) => r.consume(amt),
            Self::Reader(r) => r.consume(amt),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Message<'a> {
    Literal {
        reader: LiteralDataReader<MessageReader<'a>>,
        is_nested: bool,
    },
    Compressed {
        reader: CompressedDataReader<MessageReader<'a>>,
        is_nested: bool,
    },
    Signed {
        reader: SignatureManyReader<'a>,
        is_nested: bool,
    },
    Encrypted {
        esk: Vec<Esk>,
        edata: Edata<'a>,
        is_nested: bool,
    },
}

pub(crate) enum MessageParts {
    Literal {
        packet_header: PacketHeader,
        header: LiteralDataHeader,
        is_nested: bool,
    },
    Compressed {
        packet_header: PacketHeader,
        is_nested: bool,
    },
    SignedOnePass {
        hashes: Vec<Option<Box<[u8]>>>,
        signatures: Vec<FullSignaturePacket>,
        parts: Box<MessageParts>,
        is_nested: bool,
    },
    Encrypted {
        packet_header: PacketHeader,
        esk: Vec<Esk>,
        config: Option<ProtectedDataConfig>,
        is_nested: bool,
    },
}

impl<'a> Message<'a> {
    pub(crate) fn into_parts(self) -> (MessageReader<'a>, MessageParts) {
        match self {
            Message::Literal { reader, is_nested } => {
                debug_assert!(reader.is_done());
                let packet_header = reader.packet_header();
                let header = reader.data_header().clone();
                (
                    reader.into_inner().into_inner(),
                    MessageParts::Literal {
                        packet_header,
                        header,
                        is_nested,
                    },
                )
            }
            Message::Compressed { reader, is_nested } => {
                assert!(reader.is_done());
                let packet_header = reader.packet_header();
                (
                    reader.into_inner().into_inner(),
                    MessageParts::Compressed {
                        packet_header,
                        is_nested,
                    },
                )
            }
            Message::Signed { reader, is_nested } => {
                let SignatureManyReader::Done {
                    hashes,
                    source,
                    signatures,
                } = reader
                else {
                    panic!("invalid state");
                };

                let (reader, parts) = source.into_parts();
                (
                    reader,
                    MessageParts::SignedOnePass {
                        hashes,
                        signatures,
                        parts: Box::new(parts),
                        is_nested,
                    },
                )
            }
            Message::Encrypted {
                esk,
                edata,
                is_nested,
            } => match edata {
                Edata::SymEncryptedData { reader } => {
                    let packet_header = reader.packet_header();
                    (
                        reader.into_inner().into_inner(),
                        MessageParts::Encrypted {
                            packet_header,
                            esk,
                            config: None,
                            is_nested,
                        },
                    )
                }
                Edata::SymEncryptedProtectedData { reader } => {
                    assert!(reader.is_done());
                    let packet_header = reader.packet_header();
                    let config = Some(reader.config().clone());
                    (
                        reader.into_inner().into_inner(),
                        MessageParts::Encrypted {
                            packet_header,
                            esk,
                            config,
                            is_nested,
                        },
                    )
                }
                Edata::GnupgAeadData { reader } => {
                    assert!(reader.is_done());
                    let packet_header = reader.packet_header();
                    let config = Some(reader.config().clone());
                    (
                        reader.into_inner().into_inner(),
                        MessageParts::Encrypted {
                            packet_header,
                            esk,
                            config,
                            is_nested,
                        },
                    )
                }
            },
        }
    }
}

impl MessageParts {
    pub(crate) fn into_message(self, reader: MessageReader<'_>) -> Message<'_> {
        match self {
            MessageParts::Literal {
                packet_header,
                header,
                is_nested,
            } => Message::Literal {
                reader: LiteralDataReader::new_done(
                    PacketBodyReader::new_done(packet_header, reader),
                    header,
                ),
                is_nested,
            },
            MessageParts::Compressed {
                packet_header,
                is_nested,
            } => Message::Compressed {
                reader: CompressedDataReader::new_done(PacketBodyReader::new_done(
                    packet_header,
                    reader,
                )),
                is_nested,
            },
            MessageParts::SignedOnePass {
                hashes,
                signatures,
                parts,
                is_nested,
            } => {
                let source = parts.into_message(reader);
                Message::Signed {
                    reader: SignatureManyReader::Done {
                        hashes,
                        source: Box::new(source),
                        signatures,
                    },
                    is_nested,
                }
            }
            MessageParts::Encrypted {
                packet_header,
                esk,
                config,
                is_nested,
            } => {
                let reader = PacketBodyReader::new_done(packet_header, reader);
                let edata = if let Some(config) = config {
                    let reader = SymEncryptedProtectedDataReader::new_done(config, reader);
                    Edata::SymEncryptedProtectedData { reader }
                } else {
                    let reader = SymEncryptedDataReader::new(reader).expect("used before");
                    Edata::SymEncryptedData { reader }
                };
                Message::Encrypted {
                    esk,
                    edata,
                    is_nested,
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Esk {
    PublicKeyEncryptedSessionKey(PublicKeyEncryptedSessionKey),
    SymKeyEncryptedSessionKey(SymKeyEncryptedSessionKey),
}

impl Esk {
    pub fn try_from_reader(packet: &mut PacketBodyReader<MessageReader<'_>>) -> Result<Self> {
        let packet_header = packet.packet_header();
        match packet_header.tag() {
            Tag::PublicKeyEncryptedSessionKey => {
                let esk = PublicKeyEncryptedSessionKey::try_from_reader(packet_header, packet)?;
                Ok(Self::PublicKeyEncryptedSessionKey(esk))
            }
            Tag::SymKeyEncryptedSessionKey => {
                let esk = SymKeyEncryptedSessionKey::try_from_reader(packet_header, packet)?;
                Ok(Self::SymKeyEncryptedSessionKey(esk))
            }
            _ => unreachable!("must not called with other tags"),
        }
    }
}

impl_try_from_into!(
    Esk,
    PublicKeyEncryptedSessionKey => PublicKeyEncryptedSessionKey,
    SymKeyEncryptedSessionKey => SymKeyEncryptedSessionKey
);

impl Esk {
    pub fn tag(&self) -> Tag {
        match self {
            Esk::PublicKeyEncryptedSessionKey(_) => Tag::PublicKeyEncryptedSessionKey,
            Esk::SymKeyEncryptedSessionKey(_) => Tag::SymKeyEncryptedSessionKey,
        }
    }
}

impl TryFrom<Packet> for Esk {
    type Error = Error;

    fn try_from(other: Packet) -> Result<Esk> {
        match other {
            Packet::PublicKeyEncryptedSessionKey(k) => Ok(Esk::PublicKeyEncryptedSessionKey(k)),
            Packet::SymKeyEncryptedSessionKey(k) => Ok(Esk::SymKeyEncryptedSessionKey(k)),
            _ => Err(format_err!("not a valid edata packet: {:?}", other)),
        }
    }
}

impl From<Esk> for Packet {
    fn from(other: Esk) -> Packet {
        match other {
            Esk::PublicKeyEncryptedSessionKey(k) => Packet::PublicKeyEncryptedSessionKey(k),
            Esk::SymKeyEncryptedSessionKey(k) => Packet::SymKeyEncryptedSessionKey(k),
        }
    }
}

impl Serialize for Esk {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.to_writer_with_header(writer),
            Esk::SymKeyEncryptedSessionKey(k) => k.to_writer_with_header(writer),
        }
    }

    fn write_len(&self) -> usize {
        match self {
            Esk::PublicKeyEncryptedSessionKey(k) => k.write_len_with_header(),
            Esk::SymKeyEncryptedSessionKey(k) => k.write_len_with_header(),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Edata<'a> {
    SymEncryptedData {
        reader: SymEncryptedDataReader<MessageReader<'a>>,
    },
    SymEncryptedProtectedData {
        reader: SymEncryptedProtectedDataReader<MessageReader<'a>>,
    },
    GnupgAeadData {
        reader: SymEncryptedProtectedDataReader<MessageReader<'a>>,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionOptions {
    legacy: bool,
    gnupg_aead: bool,

    seipdv1_read_mode: Seipdv1ReadMode,

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    draft_forwarding: bool,
}

impl DecryptionOptions {
    pub fn new() -> Self {
        Default::default()
    }

    #[must_use]
    pub fn enable_legacy(mut self) -> Self {
        self.legacy = true;
        self
    }

    #[must_use]
    pub fn enable_gnupg_aead(mut self) -> Self {
        self.gnupg_aead = true;
        self
    }

    #[must_use]
    pub fn set_seipdv1_read_mode(mut self, mode: Seipdv1ReadMode) -> Self {
        self.seipdv1_read_mode = mode;
        self
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    #[must_use]
    pub fn enable_draft_forwarding(mut self) -> Self {
        self.draft_forwarding = true;
        self
    }
}

impl<'a> Edata<'a> {
    pub fn try_from_reader(reader: PacketBodyReader<MessageReader<'a>>) -> Result<Self> {
        match reader.packet_header().tag() {
            Tag::SymEncryptedData => {
                let reader = SymEncryptedDataReader::new(reader)?;
                Ok(Self::SymEncryptedData { reader })
            }
            Tag::GnupgAeadData => {
                let reader = SymEncryptedProtectedDataReader::new_gnupg_aead(reader)?;
                Ok(Self::GnupgAeadData { reader })
            }
            Tag::SymEncryptedProtectedData => {
                let reader = SymEncryptedProtectedDataReader::new(reader)?;
                Ok(Self::SymEncryptedProtectedData { reader })
            }
            _ => unreachable!("must not be called with a different tag"),
        }
    }
}

impl BufRead for Edata<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::SymEncryptedData { reader } => reader.fill_buf(),
            Self::SymEncryptedProtectedData { reader } => reader.fill_buf(),
            Self::GnupgAeadData { reader } => reader.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::SymEncryptedData { reader } => reader.consume(amt),
            Self::SymEncryptedProtectedData { reader } => reader.consume(amt),
            Self::GnupgAeadData { reader } => reader.consume(amt),
        }
    }
}

impl Read for Edata<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::SymEncryptedData { reader } => reader.read(buf),
            Self::SymEncryptedProtectedData { reader } => reader.read(buf),
            Self::GnupgAeadData { reader } => reader.read(buf),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::SymEncryptedData { reader } => reader.read_to_end(buf),
            Self::SymEncryptedProtectedData { reader } => reader.read_to_end(buf),
            Self::GnupgAeadData { reader } => reader.read_to_end(buf),
        }
    }
}

impl<'a> Edata<'a> {
    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::SymEncryptedData { reader } => reader.packet_header(),
            Self::SymEncryptedProtectedData { reader } => reader.packet_header(),
            Self::GnupgAeadData { reader } => reader.packet_header(),
        }
    }

    pub fn tag(&self) -> Tag {
        self.packet_header().tag()
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::SymEncryptedData { reader } => reader.get_mut(),
            Self::SymEncryptedProtectedData { reader } => reader.get_mut(),
            Self::GnupgAeadData { reader } => reader.get_mut(),
        }
    }

    pub fn decrypt(&mut self, key: &PlainSessionKey) -> Result<()> {
        debug!("Edata::decrypt");
        self.decrypt_with_options(key, DecryptionOptions::default())
    }

    pub fn decrypt_with_options(
        &mut self,
        key: &PlainSessionKey,
        options: DecryptionOptions,
    ) -> Result<()> {
        let protected = self.tag() == Tag::SymEncryptedProtectedData;
        debug!("decrypt_permissive {options:?}: protected = {protected:?}");

        match self {
            Self::SymEncryptedProtectedData { reader } => {
                reader.decrypt(key, options.seipdv1_read_mode)?;
            }
            Self::SymEncryptedData { reader } => {
                if options.legacy {
                    reader.decrypt(key)?;
                } else {
                    bail!(
                        "Decryption of SymEncryptedData is discouraged, 'DecryptionOptions' allows opting into it"
                    )
                }
            }
            Self::GnupgAeadData { reader } => {
                if options.gnupg_aead {
                    reader.decrypt(key, Seipdv1ReadMode::default())?;
                } else {
                    bail!(
                        "GnuPG's AEAD packet (type 20) is non-standard, 'DecryptionOptions' allows opting into it"
                    )
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    Valid(Signature),
    Invalid,
}

impl<'a> Message<'a> {
    pub fn decompress(self) -> Result<Self> {
        match self {
            Message::Compressed { reader, is_nested } => {
                let reader = reader.decompress()?;
                Message::from_compressed(reader, is_nested)
            }
            Message::Signed { reader, is_nested } => Ok(Message::Signed {
                reader: reader.decompress()?,
                is_nested,
            }),
            Message::Encrypted { .. } => Ok(self),
            Message::Literal { .. } => Ok(self),
        }
    }

    pub fn verify_nested(&self, keys: &[&dyn VerifyingKey]) -> Result<Vec<VerificationResult>> {
        let mut out = vec![VerificationResult::Invalid; keys.len()];

        match self {
            Message::Signed { reader, .. } => {
                for i in 0..reader.num_signatures() {
                    for (key, res) in keys.iter().zip(out.iter_mut()) {
                        match self.verify_nested_explicit(i, *key) {
                            Ok(sig) => {
                                *res = VerificationResult::Valid(sig.clone());
                            }
                            Err(_err) => {}
                        }
                    }
                }
            }
            Message::Literal { .. } => {}
            Message::Compressed { .. } => {
                bail!("message must be decompressed before verifying");
            }
            Message::Encrypted { .. } => {
                bail!("message must be decrypted before verifying");
            }
        }

        Ok(out)
    }

    pub fn verify_read(&mut self, key: &dyn VerifyingKey) -> Result<&Signature> {
        self.drain()?;
        let sig = self.verify(key)?;
        Ok(sig)
    }

    pub fn verify(&self, key: &dyn VerifyingKey) -> Result<&Signature> {
        self.verify_nested_explicit(0, key)
    }

    pub fn verify_nested_explicit(
        &self,
        index: usize,
        key: &dyn VerifyingKey,
    ) -> Result<&Signature> {
        match self {
            Message::Signed { reader, .. } => {
                let Some(calculated_hash) = reader.hash(index) else {
                    bail!("cannot verify message before reading it to the end");
                };
                let Some(signature) = reader.signature(index) else {
                    bail!("cannot verify message before reading the final signature packet");
                };
                let InnerSignature::Known {
                    ref config,
                    ref signed_hash_value,
                    signature: ref signature_bytes,
                } = signature.inner
                else {
                    bail!("cannot verify unknown hash");
                };

                ensure_eq!(
                    signed_hash_value,
                    &calculated_hash[0..2],
                    "signature: invalid signed hash value"
                );
                key.verify(config.hash_alg, calculated_hash, signature_bytes)?;
                Ok(signature)
            }
            Message::Compressed { .. } => {
                bail!("message must be decompressed before verifying");
            }
            Message::Encrypted { .. } => {
                bail!("message must be decrypted before verifying");
            }
            Message::Literal { .. } => {
                bail!("message was not signed");
            }
        }
    }

    pub fn decrypt(self, key_pw: &Password, key: &SignedSecretKey) -> Result<Message<'a>> {
        self.decrypt_with_keys(vec![key_pw], vec![key])
    }

    pub fn decrypt_with_keys(
        self,
        key_passwords: Vec<&Password>,
        secret_keys: Vec<&SignedSecretKey>,
    ) -> Result<Message<'a>> {
        let ring = TheRing {
            secret_keys,
            key_passwords,
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    pub fn decrypt_legacy(self, key_pw: &Password, key: &SignedSecretKey) -> Result<Message<'a>> {
        let ring = TheRing {
            decrypt_options: DecryptionOptions::new().enable_legacy(),
            secret_keys: vec![key],
            key_passwords: vec![key_pw],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    pub fn decrypt_with_password(self, msg_pw: &Password) -> Result<Message<'a>> {
        let ring = TheRing {
            message_password: vec![msg_pw],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    pub fn decrypt_with_session_key(self, session_key: PlainSessionKey) -> Result<Message<'a>> {
        let ring = TheRing {
            session_keys: vec![session_key],
            ..Default::default()
        };
        let (msg, _) = self.decrypt_the_ring(ring, true)?;
        Ok(msg)
    }

    pub fn decrypt_the_ring(
        self,
        ring: TheRing<'_>,
        abort_early: bool,
    ) -> Result<(Message<'a>, RingResult)> {
        match self {
            Message::Compressed { .. } | Message::Literal { .. } => {
                bail!("even the ring can not decrypt plaintext");
            }
            Message::Signed { reader, is_nested } => {
                let (reader, res) = reader.decrypt_the_ring(ring, abort_early)?;
                Ok((Message::Signed { reader, is_nested }, res))
            }
            Message::Encrypted {
                esk,
                mut edata,
                is_nested,
            } => {
                let decrypt_options = ring.decrypt_options;
                let (session_key, result) = ring.find_session_key(&esk, abort_early)?;
                let Some(session_key) = session_key else {
                    return Err(Error::MissingKey);
                };

                edata.decrypt_with_options(&session_key, decrypt_options)?;

                let message = Message::from_edata(edata, is_nested)?;
                Ok((message, result))
            }
        }
    }

    pub fn is_one_pass_signed(&self) -> bool {
        let Message::Signed { reader, .. } = self else {
            return false;
        };
        reader.num_one_pass_signatures() > 0
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Message::Encrypted { .. })
    }

    pub fn is_signed(&self) -> bool {
        matches!(self, Message::Signed { .. })
    }

    pub fn is_compressed(&self) -> bool {
        matches!(self, Message::Compressed { .. })
    }

    pub fn is_literal(&self) -> bool {
        matches!(self, Message::Literal { .. })
    }

    pub fn literal_data_header(&self) -> Option<&LiteralDataHeader> {
        match self {
            Self::Literal { reader, .. } => Some(reader.data_header()),
            Self::Compressed { .. } => None,
            Self::Signed { reader, .. } => reader.get_ref().literal_data_header(),
            Self::Encrypted { .. } => None,
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        match self {
            Self::Literal { reader, .. } => reader.packet_header(),
            Self::Compressed { reader, .. } => reader.packet_header(),
            Self::Signed { reader, .. } => reader.get_ref().packet_header(),
            Self::Encrypted { edata, .. } => edata.packet_header(),
        }
    }

    pub fn as_data_vec(&mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_to_end(&mut out)?;
        Ok(out)
    }

    pub fn as_data_string(&mut self) -> io::Result<String> {
        let mut out = String::new();
        self.read_to_string(&mut out)?;
        Ok(out)
    }

    pub fn into_inner(self) -> PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::Literal { reader, .. } => reader.into_inner(),
            Self::Compressed { reader, .. } => reader.into_inner(),
            Self::Signed { reader, .. } => reader.into_inner(),
            Self::Encrypted { edata, .. } => match edata {
                Edata::SymEncryptedData { reader } => reader.into_inner(),
                Edata::SymEncryptedProtectedData { reader } => reader.into_inner(),
                Edata::GnupgAeadData { reader } => reader.into_inner(),
            },
        }
    }

    pub fn get_mut(&mut self) -> &mut PacketBodyReader<MessageReader<'a>> {
        match self {
            Self::Literal { reader, .. } => reader.get_mut(),
            Self::Compressed { reader, .. } => reader.get_mut(),
            Self::Signed { reader, .. } => reader.get_mut().get_mut(),
            Self::Encrypted { edata, .. } => match edata {
                Edata::SymEncryptedData { reader } => reader.get_mut(),
                Edata::SymEncryptedProtectedData { reader } => reader.get_mut(),
                Edata::GnupgAeadData { reader } => reader.get_mut(),
            },
        }
    }

    fn has_buffer_available(&mut self) -> io::Result<bool> {
        let buf = self.fill_inner()?;
        Ok(!buf.is_empty())
    }

    fn is_nested(&self) -> bool {
        match self {
            Self::Literal { is_nested, .. } => *is_nested,
            Self::Compressed { is_nested, .. } => *is_nested,
            Self::Encrypted { is_nested, .. } => *is_nested,
            Self::Signed { is_nested, .. } => *is_nested,
        }
    }

    fn check_trailing_data(&mut self) -> io::Result<()> {
        if self.is_nested() {
            return Ok(());
        }
        debug!("checking trailing data");

        let inner = self.get_mut().get_mut();
        inner.check_trailing_data()
    }

    fn fill_inner(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Literal { reader, .. } => reader.fill_buf(),
            Self::Compressed { reader, .. } => reader.fill_buf(),
            Self::Signed { reader, .. } => reader.fill_buf(),
            Self::Encrypted { edata, .. } => edata.fill_buf(),
        }
    }
}

impl Read for Message<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match self {
            Self::Literal { reader, .. } => reader.read(buf),
            Self::Compressed { reader, .. } => reader.read(buf),
            Self::Signed { reader, .. } => reader.read(buf),
            Self::Encrypted { edata, .. } => edata.read(buf),
        }?;

        if read == 0 {
            self.check_trailing_data()?;
        }

        Ok(read)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let read = match self {
            Self::Literal { reader, .. } => reader.read_to_end(buf),
            Self::Compressed { reader, .. } => reader.read_to_end(buf),
            Self::Signed { reader, .. } => reader.read_to_end(buf),
            Self::Encrypted { edata, .. } => edata.read_to_end(buf),
        }?;

        self.check_trailing_data()?;

        Ok(read)
    }
}

impl BufRead for Message<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if !self.has_buffer_available()? {
            self.check_trailing_data()?;
            return Ok(&[][..]);
        }

        self.fill_inner()
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Literal { reader, .. } => reader.consume(amt),
            Self::Compressed { reader, .. } => reader.consume(amt),
            Self::Signed { reader, .. } => reader.consume(amt),
            Self::Encrypted { edata, .. } => edata.consume(amt),
        }
    }
}

#[derive(Debug, Default)]
pub struct TheRing<'a> {
    pub secret_keys: Vec<&'a SignedSecretKey>,
    pub key_passwords: Vec<&'a Password>,
    pub message_password: Vec<&'a Password>,
    pub session_keys: Vec<PlainSessionKey>,

    pub decrypt_options: DecryptionOptions,
}

impl TheRing<'_> {
    fn find_session_key(
        mut self,
        esk: &[Esk],
        abort_early: bool,
    ) -> Result<(Option<PlainSessionKey>, RingResult)> {
        let mut result = RingResult {
            secret_keys: vec![InnerRingResult::Unchecked; self.secret_keys.len()],
            message_password: vec![InnerRingResult::Unchecked; self.message_password.len()],
            session_keys: vec![InnerRingResult::Unchecked; self.session_keys.len()],
        };

        if abort_early {
            if !self.session_keys.is_empty() {
                let session_key = self.session_keys.remove(0);
                result.session_keys[0] = InnerRingResult::Ok;
                return Ok((Some(session_key), result));
            }
        }

        let mut pkesks = Vec::new();
        let mut skesks = Vec::new();
        for esk in esk {
            match esk {
                Esk::PublicKeyEncryptedSessionKey(k) => pkesks.push(k),
                Esk::SymKeyEncryptedSessionKey(k) => {
                    if let Some(sym_alg) = k.sym_algorithm() {
                        ensure!(
                            sym_alg != SymmetricKeyAlgorithm::Plaintext,
                            "SKESK must not use plaintext"
                        );
                        skesks.push(k)
                    } else {
                        warn!("skipping unsupported SKESK {:?}", k.version());
                    }
                }
            }
        }

        let mut pkesk_session_keys = Vec::new();

        for esk in &pkesks {
            debug!("checking esk: {:?}/{:?}", esk.id(), esk.fingerprint());
            for (i, key) in self.secret_keys.iter().enumerate() {
                result.secret_keys[i] = InnerRingResult::NoMatch;

                let typ = match esk.version() {
                    PkeskVersion::V3 => EskType::V3_4,
                    PkeskVersion::V6 => EskType::V6,
                    PkeskVersion::Other(v) => {
                        warn!("unexpected PKESK version {v}");
                        continue;
                    }
                };

                let values = esk.values()?;

                debug!(
                    "checking primary key: {:?}",
                    key.primary_key.legacy_key_id()
                );
                if esk.match_identity(key.primary_key.public_key()) {
                    let (res, session_key) = self.try_decrypt(
                        values,
                        typ,
                        &key.primary_key,
                        key.primary_key.secret_params().is_encrypted(),
                    );

                    result.secret_keys[i] = res;

                    if let Some(session_key) = session_key {
                        pkesk_session_keys.push((i, session_key));
                    }
                }

                for subkey in &key.secret_subkeys {
                    if result.secret_keys[i] == InnerRingResult::Ok {
                        break;
                    }

                    debug!("checking subkey: {:?}", subkey.legacy_key_id());
                    if esk.match_identity(subkey.public_key()) {
                        #[cfg(feature = "draft-wussler-openpgp-forwarding")]
                        if !self.decrypt_options.draft_forwarding
                            && subkey.key.public_key().is_forwardee_key()
                        {
                            debug!("draft_forwarding unset in DecryptionOptions, not trying forwardee key: {:?}",  subkey.key.public_key().fingerprint());

                            result.secret_keys[i] = InnerRingResult::Invalid;
                            continue;
                        }

                        let (res, session_key) = self.try_decrypt(
                            values,
                            typ,
                            &subkey.key,
                            subkey.secret_params().is_encrypted(),
                        );

                        result.secret_keys[i] = res;

                        if let Some(session_key) = session_key {
                            pkesk_session_keys.push((i, session_key));
                        }
                    }
                }
            }
        }

        let mut skesk_session_keys: Vec<(usize, PlainSessionKey)> = Vec::new();

        for esk in skesks {
            for (i, pw) in self.message_password.iter().enumerate() {
                if !self.decrypt_options.gnupg_aead && esk.version() == SkeskVersion::V5 {
                    debug!("skipping v5 SKESK because allow_gnupg_aead is not enabled: {esk:?}");
                    continue;
                }

                match decrypt_session_key_with_password(esk, pw) {
                    Ok(session_key) => {
                        skesk_session_keys.push((i, session_key));
                        result.message_password[i] = InnerRingResult::Ok;
                        break;
                    }
                    Err(_err) => {
                        result.message_password[i] = InnerRingResult::Invalid;
                    }
                }
            }
        }

        let (is_pkesk_consistent, pkesk_session_key) = if pkesk_session_keys.is_empty() {
            (true, None)
        } else {
            let sk = pkesk_session_keys.remove(0);

            let mut is_consistent = true;

            for (_i, key) in pkesk_session_keys {
                if key != sk.1 {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        let (is_skesk_consistent, skesk_session_key) = if skesk_session_keys.is_empty() {
            (true, None)
        } else {
            let sk = skesk_session_keys.remove(0);

            let mut is_consistent = true;

            for (_i, key) in skesk_session_keys {
                if key != sk.1 {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        let (is_sks_consistent, sks_session_key) = if self.session_keys.is_empty() {
            (true, None)
        } else {
            let sk = self.session_keys.remove(0);

            let mut is_consistent = true;

            for key in self.session_keys.iter() {
                if key != &sk {
                    is_consistent = false;
                    break;
                }
            }

            (is_consistent, Some(sk))
        };

        let is_consistent = is_sks_consistent && is_skesk_consistent && is_pkesk_consistent;

        if !is_consistent {
            bail!("inconsistent session keys detected");
        }

        if let Some((_, session_key)) = pkesk_session_key {
            return Ok((Some(session_key), result));
        }

        if let Some((_, session_key)) = skesk_session_key {
            return Ok((Some(session_key), result));
        }

        if let Some(session_key) = sks_session_key {
            return Ok((Some(session_key), result));
        }

        Ok((None, result))
    }

    fn try_decrypt(
        &self,
        values: &PkeskBytes,
        typ: EskType,
        dec: &dyn DecryptionKey,
        is_locked: bool,
    ) -> (InnerRingResult, Option<PlainSessionKey>) {
        debug!(
            "found matching key {:?}, trying to decrypt",
            dec.fingerprint()
        );
        if is_locked {
            let mut res = InnerRingResult::Unchecked;

            for pw in &self.key_passwords {
                match dec.decrypt(pw, values, typ) {
                    Ok(Ok(session_key)) => {
                        debug!("decrypted session key");

                        return (InnerRingResult::Ok, Some(session_key));
                    }
                    Ok(Err(err)) => {
                        debug!("failed to decrypt session key: {:?}", err);

                        return (InnerRingResult::Invalid, None);
                    }
                    Err(err) => {
                        debug!("failed to unlock key: {:?}", err);
                        res = InnerRingResult::InvalidPassword;
                    }
                }
            }

            (res, None)
        } else {
            debug!("key is already unlocked");
            match dec.decrypt(&Password::empty(), values, typ) {
                Ok(Ok(session_key)) => {
                    debug!("decrypted session key");

                    (InnerRingResult::Ok, Some(session_key))
                }
                Ok(Err(err)) | Err(err) => {
                    debug!("failed to decrypt session key: {:?}", err);
                    (InnerRingResult::Invalid, None)
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct RingResult {
    pub secret_keys: Vec<InnerRingResult>,
    pub message_password: Vec<InnerRingResult>,
    pub session_keys: Vec<InnerRingResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerRingResult {
    Unchecked,
    NoMatch,
    InvalidPassword,
    InconsistentSessionKey,
    Invalid,
    Ok,
}

#[derive(Debug, Clone)]
pub struct ArmorOptions<'a> {
    pub headers: Option<&'a armor::Headers>,
    pub include_checksum: bool,
}

impl Default for ArmorOptions<'_> {
    fn default() -> Self {
        Self {
            headers: None,
            include_checksum: true,
        }
    }
}

impl<'a> From<Option<&'a armor::Headers>> for ArmorOptions<'a> {
    fn from(headers: Option<&'a armor::Headers>) -> Self {
        Self {
            headers,
            include_checksum: true,
        }
    }
}
