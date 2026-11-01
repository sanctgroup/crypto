use std::{
    collections::VecDeque,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use crc24::Crc24Hasher;
use generic_array::typenum::U64;
use log::debug;
use rand::{CryptoRng, Rng};

use super::{ArmorOptions, RawSessionKey};
use crate::{
    armor,
    composed::Esk,
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, Result},
    line_writer::{LineBreak, LineWriter},
    packet::{
        CompressedDataGenerator, DataMode, LiteralDataGenerator, LiteralDataHeader,
        OnePassSignature, PacketHeader, PacketTrait, PublicKeyEncryptedSessionKey, SignatureHasher,
        SignatureType, SignatureVersionSpecific, Subpacket, SubpacketData,
        SymEncryptedProtectedData, SymEncryptedProtectedDataConfig, SymKeyEncryptedSessionKey,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, EncryptionKey, Fingerprint, KeyId, KeyVersion, PacketHeaderVersion,
        PacketLength, Password, SigningKey, StringToKey, Tag, Timestamp,
    },
    util::{fill_buffer, TeeWriter},
};

pub type DummyReader = std::io::Cursor<Vec<u8>>;

pub struct Builder<'a, R = DummyReader, E = NoEncryption> {
    source: Source<R>,
    compression: Option<CompressionAlgorithm>,
    signing: Vec<SigningConfig<'a>>,
    encryption: E,
    partial_chunk_size: u32,

    data_mode: DataMode,
    sign_typ: SignatureType,
}

#[derive(Clone)]
enum Source<R = DummyReader> {
    Bytes { name: Bytes, bytes: Bytes },
    File(PathBuf),
    Reader { file_name: Bytes, reader: R },
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct NoEncryption;

#[derive(Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV1 {
    session_key: RawSessionKey,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
}

#[derive(derive_more::Debug, PartialEq, Clone)]
pub struct EncryptionSeipdV2 {
    session_key: RawSessionKey,
    sym_esks: Vec<SymKeyEncryptedSessionKey>,
    pub_esks: Vec<PublicKeyEncryptedSessionKey>,
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    #[debug("{}", hex::encode(salt))]
    salt: [u8; 32],
}

pub trait Encryption: PartialEq {
    fn encrypt<R, READ, W>(
        self,
        rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write;

    fn is_plaintext(&self) -> bool;
}

#[derive(Debug, Default)]
pub enum SubpacketConfig {
    #[default]
    Default,

    UserDefined {
        hashed: Vec<Subpacket>,
        unhashed: Vec<Subpacket>,
    },
}

impl SubpacketConfig {
    pub(crate) fn to_subpackets(
        &self,
        signer: &dyn SigningKey,
    ) -> Result<(Vec<Subpacket>, Vec<Subpacket>)> {
        match self {
            SubpacketConfig::Default => {
                let hashed = vec![
                    Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
                    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
                ];

                let mut unhashed = vec![];
                if signer.version() <= KeyVersion::V4 {
                    unhashed.push(Subpacket::regular(SubpacketData::IssuerKeyId(
                        signer.legacy_key_id(),
                    ))?);
                }

                Ok((hashed, unhashed))
            }
            SubpacketConfig::UserDefined { hashed, unhashed } => {
                Ok((hashed.clone(), unhashed.clone()))
            }
        }
    }
}

#[derive(Debug)]
struct SigningConfig<'a> {
    key: &'a dyn SigningKey,
    key_pw: Password,
    hash_algorithm: HashAlgorithm,

    subpackets: SubpacketConfig,
}

impl<'a> SigningConfig<'a> {
    fn new(key: &'a dyn SigningKey, key_pw: Password, hash: HashAlgorithm) -> Self {
        Self::with_subpackets(key, key_pw, hash, SubpacketConfig::Default)
    }

    fn with_subpackets(
        key: &'a dyn SigningKey,
        key_pw: Password,
        hash: HashAlgorithm,
        subpackets: SubpacketConfig,
    ) -> Self {
        Self {
            key,
            key_pw,
            hash_algorithm: hash,
            subpackets,
        }
    }
}

pub const DEFAULT_PARTIAL_CHUNK_SIZE: u32 = 1024 * 512;

impl Builder<'_, DummyReader> {
    pub fn from_file(path: impl AsRef<Path>) -> Self {
        Self {
            source: Source::File(path.as_ref().into()),
            compression: None,
            encryption: NoEncryption,
            signing: Vec::new(),
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            sign_typ: SignatureType::Binary,
        }
    }

    pub fn from_bytes(name: impl Into<Bytes>, bytes: impl Into<Bytes>) -> Self {
        Self {
            source: Source::Bytes {
                name: name.into(),
                bytes: bytes.into(),
            },
            compression: None,
            encryption: NoEncryption,
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            sign_typ: SignatureType::Binary,
            signing: Vec::new(),
        }
    }
}

fn prepare<R>(
    mut rng: R,
    typ: SignatureType,
    keys: &[SigningConfig<'_>],
) -> Result<Vec<(crate::packet::SignatureConfig, OnePassSignature)>>
where
    R: Rng + CryptoRng,
{
    let mut out = Vec::new();

    let keys_len = keys.len();
    for (i, config) in keys.iter().enumerate() {
        let is_last = i == keys_len - 1;

        let algorithm = config.key.algorithm();
        let hash_alg = config.hash_algorithm;

        let mut sig_config = match config.key.version() {
            KeyVersion::V4 => crate::packet::SignatureConfig::v4(typ, algorithm, hash_alg),
            KeyVersion::V6 => {
                crate::packet::SignatureConfig::v6(&mut rng, typ, algorithm, hash_alg)?
            }
            v => bail!("unsupported key version {:?}", v),
        };

        (sig_config.hashed_subpackets, sig_config.unhashed_subpackets) =
            config.subpackets.to_subpackets(config.key)?;

        let mut ops = match config.key.version() {
            KeyVersion::V4 => {
                OnePassSignature::v3(typ, hash_alg, algorithm, config.key.legacy_key_id())
            }
            KeyVersion::V6 => {
                let SignatureVersionSpecific::V6 { ref salt } = sig_config.version_specific else {
                    bail!("Inconsistent Signature and OnePassSignature version")
                };

                let Fingerprint::V6(fp) = config.key.fingerprint() else {
                    bail!("Inconsistent Signature and Fingerprint version")
                };

                OnePassSignature::v6(typ, hash_alg, algorithm, salt.clone(), fp)
            }
            v => bail!("Unsupported key version {:?}", v),
        };

        if !is_last {
            ops.set_is_nested();
        }

        out.push((sig_config, ops));
    }

    Ok(out)
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    pub fn seipd_v1<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
    ) -> Builder<'a, R, EncryptionSeipdV1>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);
        Builder {
            source: self.source,
            compression: self.compression,
            partial_chunk_size: self.partial_chunk_size,
            data_mode: self.data_mode,
            sign_typ: self.sign_typ,
            encryption: EncryptionSeipdV1 {
                sym_alg,
                session_key,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: self.signing,
        }
    }
}

impl<'a, R: Read> Builder<'a, R, NoEncryption> {
    pub fn seipd_v2<RAND>(
        self,
        mut rng: RAND,
        sym_alg: SymmetricKeyAlgorithm,
        aead: AeadAlgorithm,
        chunk_size: ChunkSize,
    ) -> Builder<'a, R, EncryptionSeipdV2>
    where
        RAND: CryptoRng + Rng,
    {
        let session_key = sym_alg.new_session_key(&mut rng);

        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);

        Builder {
            source: self.source,
            compression: self.compression,
            partial_chunk_size: self.partial_chunk_size,
            data_mode: self.data_mode,
            sign_typ: self.sign_typ,
            encryption: EncryptionSeipdV2 {
                sym_alg,
                session_key,
                chunk_size,
                aead,
                salt,
                sym_esks: Vec::new(),
                pub_esks: Vec::new(),
            },
            signing: self.signing,
        }
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV1> {
    pub fn set_session_key(&mut self, sk: RawSessionKey) -> Result<&mut Self> {
        ensure!(
            self.encryption.pub_esks.is_empty(),
            "Session key may not be set, already have PKESK"
        );
        ensure!(
            self.encryption.sym_esks.is_empty(),
            "Session key may not be set, already have SKESK"
        );

        ensure_eq!(
            sk.len(),
            self.encryption.sym_alg.key_size(),
            "Session key has inappropriate length for the symmetric algorithm"
        );

        self.encryption.session_key = sk;

        Ok(self)
    }

    pub fn encrypt_to_key<RAND, E>(&mut self, mut rng: RAND, enc: &E) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        E: EncryptionKey,
    {
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &self.encryption.session_key,
            self.encryption.sym_alg,
            enc,
        )?;
        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    pub fn encrypt_to_key_anonymous<RAND, E>(&mut self, mut rng: RAND, enc: &E) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        E: EncryptionKey,
    {
        let mut pkes = PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &self.encryption.session_key,
            self.encryption.sym_alg,
            enc,
        )?;

        if let PublicKeyEncryptedSessionKey::V3 { id, .. } = &mut pkes {
            *id = KeyId::WILDCARD;
        }

        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    pub fn encrypt_with_password(
        &mut self,
        s2k: StringToKey,
        msg_pw: &Password,
    ) -> Result<&mut Self> {
        let esk = SymKeyEncryptedSessionKey::encrypt_v4(
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
        )?;
        self.encryption.sym_esks.push(esk);
        Ok(self)
    }

    pub fn session_key(&self) -> &RawSessionKey {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, EncryptionSeipdV2> {
    pub fn set_session_key(&mut self, sk: RawSessionKey) -> Result<&mut Self> {
        ensure!(
            self.encryption.pub_esks.is_empty(),
            "Session key may not be set, already have PKESK"
        );
        ensure!(
            self.encryption.sym_esks.is_empty(),
            "Session key may not be set, already have SKESK"
        );

        ensure_eq!(
            sk.len(),
            self.encryption.sym_alg.key_size(),
            "Session key has inappropriate length for the symmetric algorithm"
        );

        self.encryption.session_key = sk;

        Ok(self)
    }

    pub fn encrypt_to_key<RAND, E>(&mut self, mut rng: RAND, enc: &E) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        E: EncryptionKey,
    {
        let pkes = PublicKeyEncryptedSessionKey::from_session_key_v6(
            &mut rng,
            &self.encryption.session_key,
            enc,
        )?;
        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    pub fn encrypt_to_key_anonymous<RAND, E>(&mut self, mut rng: RAND, enc: &E) -> Result<&mut Self>
    where
        RAND: CryptoRng + Rng,
        E: EncryptionKey,
    {
        let mut pkes = PublicKeyEncryptedSessionKey::from_session_key_v6(
            &mut rng,
            &self.encryption.session_key,
            enc,
        )?;

        if let PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } = &mut pkes {
            *fingerprint = None;
        }

        self.encryption.pub_esks.push(pkes);
        Ok(self)
    }

    pub fn encrypt_with_password<RAND>(
        &mut self,
        mut rng: RAND,
        s2k: StringToKey,
        msg_pw: &Password,
    ) -> Result<&mut Self>
    where
        RAND: Rng + CryptoRng,
    {
        let esk = SymKeyEncryptedSessionKey::encrypt_v6(
            &mut rng,
            msg_pw,
            &self.encryption.session_key,
            s2k,
            self.encryption.sym_alg,
            self.encryption.aead,
        )?;
        self.encryption.sym_esks.push(esk);
        Ok(self)
    }

    pub fn session_key(&self) -> &RawSessionKey {
        &self.encryption.session_key
    }
}

impl<R: Read> Builder<'_, R, NoEncryption> {
    pub fn from_reader(file_name: impl Into<Bytes>, reader: R) -> Self {
        Self {
            source: Source::Reader {
                file_name: file_name.into(),
                reader,
            },
            compression: None,
            encryption: NoEncryption,
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: DataMode::Binary,
            sign_typ: SignatureType::Binary,
            signing: Vec::new(),
        }
    }
}

impl<'a, R: Read, E: Encryption> Builder<'a, R, E> {
    pub fn data_mode(&mut self, mode: DataMode) -> Result<&mut Self> {
        ensure!(
            [DataMode::Binary, DataMode::Utf8].contains(&mode),
            "Unsupported data mode {:?}",
            mode
        );

        self.data_mode = mode;
        Ok(self)
    }

    pub fn sign_binary(&mut self) -> &mut Self {
        self.sign_typ = SignatureType::Binary;
        self
    }

    pub fn sign_text(&mut self) -> &mut Self {
        self.sign_typ = SignatureType::Text;
        self
    }

    pub fn partial_chunk_size(&mut self, size: u32) -> Result<&mut Self> {
        ensure!(size >= 512, "partial chunk size must be at least 512");
        ensure!(
            size.is_power_of_two(),
            "partial chunk size must be a power of two"
        );
        self.partial_chunk_size = size;
        Ok(self)
    }

    pub fn compression(&mut self, compression: CompressionAlgorithm) -> &mut Self {
        self.compression.replace(compression);
        self
    }

    pub fn sign(
        &mut self,
        key: &'a dyn SigningKey,
        key_pw: Password,
        hash_algorithm: HashAlgorithm,
    ) -> &mut Self {
        self.signing
            .push(SigningConfig::new(key, key_pw, hash_algorithm));
        self
    }

    pub fn sign_with_subpackets(
        &mut self,
        key: &'a dyn SigningKey,
        key_pw: Password,
        hash_algorithm: HashAlgorithm,
        subpackets: SubpacketConfig,
    ) -> &mut Self {
        self.signing.push(SigningConfig::with_subpackets(
            key,
            key_pw,
            hash_algorithm,
            subpackets,
        ));
        self
    }

    pub fn to_writer<RAND, W>(self, rng: RAND, out: W) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        let sign_typ = self.sign_typ;

        match self.source {
            Source::Bytes { name, bytes } => {
                debug!("sourcing bytes {:?}: {} bytes", name, bytes.len());

                let len = bytes.len().try_into().ok();
                let source = bytes.reader();
                to_writer_inner(
                    rng,
                    name,
                    source,
                    len,
                    sign_typ,
                    self.signing,
                    self.data_mode,
                    self.partial_chunk_size,
                    self.compression,
                    self.encryption,
                    out,
                )?;
            }
            Source::File(ref path) => {
                let in_file = std::fs::File::open(path)?;
                let in_meta = in_file.metadata()?;

                let Some(in_file_name) = path.file_name() else {
                    bail!("{}: is not a valid input file", path.display());
                };
                let file_name: Bytes = in_file_name.as_encoded_bytes().to_vec().into();

                debug!("sourcing file {:?}: {} bytes", file_name, in_meta.len());

                let in_file = BufReader::new(in_file);

                let in_file_size = in_meta.len().try_into().ok();

                to_writer_inner(
                    rng,
                    file_name,
                    in_file,
                    in_file_size,
                    sign_typ,
                    self.signing,
                    self.data_mode,
                    self.partial_chunk_size,
                    self.compression,
                    self.encryption,
                    out,
                )?;
            }
            Source::Reader { file_name, reader } => {
                to_writer_inner(
                    rng,
                    file_name,
                    reader,
                    None,
                    sign_typ,
                    self.signing,
                    self.data_mode,
                    self.partial_chunk_size,
                    self.compression,
                    self.encryption,
                    out,
                )?;
            }
        }
        Ok(())
    }

    pub fn to_armored_writer<RAND, W>(
        self,
        rng: RAND,
        opts: ArmorOptions<'_>,
        mut out: W,
    ) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        W: std::io::Write,
    {
        let typ = armor::BlockType::Message;

        armor::write_header(&mut out, typ, opts.headers)?;

        let mut crc_hasher = opts.include_checksum.then(Crc24Hasher::new);
        {
            let crc_hasher = crc_hasher.as_mut();
            let mut line_wrapper = LineWriter::<_, U64>::new(out.by_ref(), LineBreak::Lf);
            let mut enc = armor::Base64Encoder::new(&mut line_wrapper);

            if let Some(crc_hasher) = crc_hasher {
                let mut tee = TeeWriter::new(crc_hasher, &mut enc);
                self.to_writer(rng, &mut tee)?;
            } else {
                self.to_writer(rng, &mut enc)?;
            }
        }

        armor::write_footer(&mut out, typ, crc_hasher)?;
        out.flush()?;

        Ok(())
    }

    pub fn to_file<RAND, P>(self, rng: RAND, out_path: P) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        P: AsRef<Path>,
    {
        let out_path: &Path = out_path.as_ref();
        debug!("writing to file: {}", out_path.display());
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let out_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)?;
        let mut out_file = BufWriter::new(out_file);

        self.to_writer(rng, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }

    pub fn to_armored_file<RAND, P>(
        self,
        rng: RAND,
        out_path: P,
        opts: ArmorOptions<'_>,
    ) -> Result<()>
    where
        RAND: Rng + CryptoRng,
        P: AsRef<Path>,
    {
        let out_path: &Path = out_path.as_ref();
        debug!("writing to file: {}", out_path.display());
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let out_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(out_path)?;
        let mut out_file = BufWriter::new(out_file);

        self.to_armored_writer(rng, opts, &mut out_file)?;

        out_file.flush()?;

        Ok(())
    }

    pub fn to_vec<RAND>(self, rng: RAND) -> Result<Vec<u8>>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_writer(rng, &mut out)?;
        Ok(out)
    }

    pub fn to_armored_string<RAND>(self, rng: RAND, opts: ArmorOptions<'_>) -> Result<String>
    where
        RAND: Rng + CryptoRng,
    {
        let mut out = Vec::new();
        self.to_armored_writer(rng, opts, &mut out)?;
        let out = std::string::String::from_utf8(out).expect("ascii armor is utf8");
        Ok(out)
    }
}

#[allow(clippy::too_many_arguments)]
fn to_writer_inner<RAND, R, W, E>(
    mut rng: RAND,
    _name: Bytes,
    source: R,
    source_len: Option<u32>,
    sign_typ: SignatureType,
    signers: Vec<SigningConfig<'_>>,
    data_mode: DataMode,
    partial_chunk_size: u32,
    compression: Option<CompressionAlgorithm>,
    encryption: E,
    out: W,
) -> Result<()>
where
    RAND: Rng + CryptoRng,
    R: std::io::Read,
    W: std::io::Write,
    E: Encryption,
{
    let literal_data_header = LiteralDataHeader::new(data_mode);

    let sign_generator = SignGenerator::new(
        &mut rng,
        sign_typ,
        literal_data_header,
        partial_chunk_size,
        source,
        signers,
        source_len,
    )?;

    match compression {
        Some(compression) => {
            let len = sign_generator.len();
            let generator =
                CompressedDataGenerator::new(compression, sign_generator, len, partial_chunk_size)?;

            encryption.encrypt(&mut rng, generator, partial_chunk_size, None, out)?;
        }
        None => {
            let len = sign_generator.len();
            encryption.encrypt(&mut rng, sign_generator, partial_chunk_size, len, out)?;
        }
    }
    Ok(())
}

impl Encryption for NoEncryption {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        mut generator: READ,
        _partial_chunk_size: u32,
        _len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        std::io::copy(&mut generator, &mut out)?;
        Ok(())
    }

    fn is_plaintext(&self) -> bool {
        true
    }
}

impl Encryption for EncryptionSeipdV1 {
    fn encrypt<R, READ, W>(
        self,
        rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        let EncryptionSeipdV1 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
        } = self;

        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }

        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }

        let config = SymEncryptedProtectedDataConfig::V1;
        let encrypted = sym_alg.stream_encryptor(rng, session_key.as_ref(), generator)?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            partial_chunk_size,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

impl Encryption for EncryptionSeipdV2 {
    fn encrypt<R, READ, W>(
        self,
        _rng: R,
        generator: READ,
        partial_chunk_size: u32,
        len: Option<u32>,
        mut out: W,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        READ: std::io::Read,
        W: std::io::Write,
    {
        let EncryptionSeipdV2 {
            session_key,
            sym_esks,
            pub_esks,
            sym_alg,
            aead,
            chunk_size,
            salt,
        } = self;
        ensure_eq!(
            session_key.len(),
            sym_alg.key_size(),
            "Unexpected session key length for {:?}",
            sym_alg
        );

        for sym_esk in sym_esks {
            let esk = Esk::SymKeyEncryptedSessionKey(sym_esk);
            esk.to_writer(&mut out)?;
        }

        for pub_esk in pub_esks {
            let esk = Esk::PublicKeyEncryptedSessionKey(pub_esk);
            esk.to_writer(&mut out)?;
        }
        let config = SymEncryptedProtectedDataConfig::V2 {
            sym_alg,
            aead,
            chunk_size,
            salt,
        };

        let encrypted = SymEncryptedProtectedData::encrypt_seipdv2_stream(
            sym_alg,
            aead,
            chunk_size,
            session_key.as_ref(),
            salt,
            generator,
        )?;

        encrypt_write(
            Tag::SymEncryptedProtectedData,
            partial_chunk_size,
            sym_alg,
            config,
            len,
            encrypted,
            out,
        )
    }

    fn is_plaintext(&self) -> bool {
        false
    }
}

fn encrypt_write<R: std::io::Read, W: std::io::Write>(
    tag: Tag,
    partial_chunk_size: u32,
    sym_alg: SymmetricKeyAlgorithm,
    config: SymEncryptedProtectedDataConfig,
    len: Option<u32>,
    mut encrypted: R,
    mut out: W,
) -> Result<()> {
    debug!("encrypt {tag:?}: at {partial_chunk_size} chunks, total len: {len:?}");
    match len {
        None => {
            let config_len = config.write_len();
            let partial_chunk_size = partial_chunk_size as usize;

            let first_chunk_size = partial_chunk_size - config_len;

            let mut buffer = vec![0u8; partial_chunk_size];

            let mut is_first = true;

            loop {
                let (length, mut buf) = if is_first {
                    let read = fill_buffer(&mut encrypted, &mut buffer, Some(first_chunk_size))?;
                    if read < first_chunk_size {
                        let size = (read + config_len).try_into()?;
                        debug!("single chunk of size {size}");
                        (PacketLength::Fixed(size), &buffer[..read])
                    } else {
                        (
                            PacketLength::Partial(partial_chunk_size.try_into()?),
                            &buffer[..read],
                        )
                    }
                } else {
                    let read = fill_buffer(&mut encrypted, &mut buffer, Some(partial_chunk_size))?;
                    if read < partial_chunk_size {
                        (PacketLength::Fixed(read.try_into()?), &buffer[..read])
                    } else {
                        (
                            PacketLength::Partial(partial_chunk_size.try_into()?),
                            &buffer[..read],
                        )
                    }
                };

                if is_first {
                    let packet_header =
                        PacketHeader::from_parts(PacketHeaderVersion::New, tag, length)?;
                    debug!("first packet {packet_header:?}");

                    packet_header.to_writer(&mut out)?;
                    config.to_writer(&mut out)?;
                    is_first = false;
                } else {
                    debug!("partial packet {length:?}");
                    length.to_writer_new(&mut out)?;
                }

                std::io::copy(&mut buf, &mut out)?;

                if matches!(length, PacketLength::Fixed(_)) {
                    break;
                }
            }
        }
        Some(in_size) => {
            let enc_file_size = sym_alg.encrypted_protected_len(in_size.try_into()?);
            let packet_len = config.write_len() + enc_file_size;

            let packet_header = PacketHeader::from_parts(
                PacketHeaderVersion::New,
                tag,
                PacketLength::Fixed(packet_len.try_into()?),
            )?;
            packet_header.to_writer(&mut out)?;
            config.to_writer(&mut out)?;

            std::io::copy(&mut encrypted, &mut out)?;
        }
    }

    Ok(())
}

struct SignGenerator<'a, R: std::io::Read> {
    total_len: Option<u32>,
    state: State<'a, R>,
}

enum State<'a, R: std::io::Read> {
    Ops {
        ops: VecDeque<OnePassSignature>,
        buffer: BytesMut,
        configs: VecDeque<SigningConfig<'a>>,
        source: LiteralDataGenerator<SignatureHashers<R>>,
    },
    Body {
        configs: VecDeque<SigningConfig<'a>>,
        source: LiteralDataGenerator<SignatureHashers<R>>,
    },
    Signatures {
        buffer: BytesMut,
        configs: VecDeque<SigningConfig<'a>>,
        hashers: VecDeque<SignatureHasher>,
    },
    Error,
    Done,
}

struct SignatureHashers<R> {
    hashers: VecDeque<SignatureHasher>,
    source: R,
}

impl<R> SignatureHashers<R> {
    fn update_hashers(&mut self, buf: &[u8]) {
        for hasher in &mut self.hashers {
            hasher.update(buf);
        }
    }
}

impl<R: std::io::Read> std::io::Read for SignatureHashers<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.source.read(buf)?;

        self.update_hashers(&buf[..read]);

        Ok(read)
    }
}

impl<'a, R: std::io::Read> SignGenerator<'a, R> {
    fn new<RAND>(
        mut rng: RAND,
        typ: SignatureType,
        literal_data_header: LiteralDataHeader,
        chunk_size: u32,
        source: R,
        signers: Vec<SigningConfig<'a>>,
        source_len: Option<u32>,
    ) -> Result<Self>
    where
        RAND: CryptoRng + Rng,
    {
        let prep = prepare(&mut rng, typ, &signers)?;
        let mut configs = VecDeque::with_capacity(prep.len());
        let mut sign_hashers = VecDeque::with_capacity(prep.len());
        let mut ops = VecDeque::with_capacity(prep.len());
        for ((config, op), signer) in prep.into_iter().zip(signers) {
            ops.push_back(op);
            sign_hashers.push_back(config.into_hasher()?);
            configs.push_back(signer);
        }

        let hashed_source = SignatureHashers {
            hashers: sign_hashers,
            source,
        };

        let source =
            LiteralDataGenerator::new(literal_data_header, hashed_source, source_len, chunk_size)?;
        let _len = source.len();

        let total_len = None;

        let state = if ops.is_empty() {
            State::Body { configs, source }
        } else {
            State::Ops {
                ops,
                buffer: BytesMut::new(),
                configs,
                source,
            }
        };

        Ok(Self { total_len, state })
    }

    fn len(&self) -> Option<u32> {
        self.total_len
    }
}

impl<R: std::io::Read> std::io::Read for SignGenerator<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match std::mem::replace(&mut self.state, State::Error) {
                State::Done => {
                    self.state = State::Done;
                    return Ok(0);
                }
                State::Error => {
                    panic!("inconsistent state, panicked before");
                }
                State::Ops {
                    mut ops,
                    mut buffer,
                    configs,
                    source,
                } => {
                    if !buffer.has_remaining() {
                        if let Some(op) = ops.pop_front() {
                            let mut writer = buffer.writer();
                            op.to_writer_with_header(&mut writer).map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            buffer = writer.into_inner();
                        } else {
                            self.state = State::Body { configs, source };
                            continue;
                        }
                    }

                    let to_write = buf.len().min(buffer.remaining());
                    buffer.copy_to_slice(&mut buf[..to_write]);

                    self.state = State::Ops {
                        ops,
                        buffer,
                        configs,
                        source,
                    };

                    return Ok(to_write);
                }
                State::Body {
                    configs,
                    mut source,
                } => {
                    let read = source.read(buf)?;

                    if read == 0 {
                        let sig_hasher = source.into_inner();
                        let hashers = sig_hasher.hashers;

                        self.state = State::Signatures {
                            buffer: BytesMut::new(),
                            configs,
                            hashers,
                        };
                        continue;
                    }

                    self.state = State::Body { configs, source };
                    return Ok(read);
                }
                State::Signatures {
                    mut configs,
                    mut buffer,
                    mut hashers,
                } => {
                    if !buffer.has_remaining() {
                        if let (Some(signer), Some(hasher)) =
                            (configs.pop_back(), hashers.pop_back())
                        {
                            let mut writer = buffer.writer();

                            hasher
                                .sign(signer.key, &signer.key_pw)
                                .and_then(|sig| sig.to_writer_with_header(&mut writer))
                                .map_err(|e| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        e.to_string(),
                                    )
                                })?;

                            buffer = writer.into_inner();
                        } else {
                            self.state = State::Done;
                            return Ok(0);
                        }
                    }

                    let to_write = buf.len().min(buffer.remaining());
                    buffer.copy_to_slice(&mut buf[..to_write]);

                    self.state = State::Signatures {
                        buffer,
                        configs,
                        hashers,
                    };
                    return Ok(to_write);
                }
            }
        }
    }
}
