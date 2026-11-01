use std::io::{self, BufRead, Read};

use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use bytes::{Buf, BytesMut};
use camellia::{Camellia128, Camellia192, Camellia256};
use cast5::Cast5;
use cfb_mode::{cipher::KeyIvInit, BufDecryptor};
use cipher::{BlockCipher, BlockDecrypt, BlockEncryptMut, BlockSizeUser};
use des::TdesEde3;
use idea::Idea;
use log::debug;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use twofish::Twofish;
use zeroize::Zeroizing;

use crate::{
    crypto::sym::SymmetricKeyAlgorithm,
    errors::{bail, Error, Result},
    parsing_reader::BufReadParsing,
    types::Seipdv1ReadMode,
    util::{fill_buffer, fill_buffer_bytes},
};

const MDC_LEN: usize = 22;
const BUFFER_SIZE: usize = 1024 * 8;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum StreamDecryptor<R>
where
    R: BufRead,
{
    Idea(StreamDecryptorInner<Idea, R>),
    TripleDes(StreamDecryptorInner<TdesEde3, R>),
    Cast5(StreamDecryptorInner<Cast5, R>),
    Blowfish(StreamDecryptorInner<Blowfish, R>),
    Aes128(StreamDecryptorInner<Aes128, R>),
    Aes192(StreamDecryptorInner<Aes192, R>),
    Aes256(StreamDecryptorInner<Aes256, R>),
    Twofish(StreamDecryptorInner<Twofish, R>),
    Camellia128(StreamDecryptorInner<Camellia128, R>),
    Camellia192(StreamDecryptorInner<Camellia192, R>),
    Camellia256(StreamDecryptorInner<Camellia256, R>),
}

impl<R> BufRead for StreamDecryptor<R>
where
    R: BufRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        match self {
            Self::Idea(i) => i.fill_buf(),
            Self::TripleDes(i) => i.fill_buf(),
            Self::Cast5(i) => i.fill_buf(),
            Self::Blowfish(i) => i.fill_buf(),
            Self::Aes128(i) => i.fill_buf(),
            Self::Aes192(i) => i.fill_buf(),
            Self::Aes256(i) => i.fill_buf(),
            Self::Twofish(i) => i.fill_buf(),
            Self::Camellia128(i) => i.fill_buf(),
            Self::Camellia192(i) => i.fill_buf(),
            Self::Camellia256(i) => i.fill_buf(),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Idea(i) => i.consume(amt),
            Self::TripleDes(i) => i.consume(amt),
            Self::Cast5(i) => i.consume(amt),
            Self::Blowfish(i) => i.consume(amt),
            Self::Aes128(i) => i.consume(amt),
            Self::Aes192(i) => i.consume(amt),
            Self::Aes256(i) => i.consume(amt),
            Self::Twofish(i) => i.consume(amt),
            Self::Camellia128(i) => i.consume(amt),
            Self::Camellia192(i) => i.consume(amt),
            Self::Camellia256(i) => i.consume(amt),
        }
    }
}

impl<R> Read for StreamDecryptor<R>
where
    R: BufRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Idea(i) => i.read(buf),
            Self::TripleDes(i) => i.read(buf),
            Self::Cast5(i) => i.read(buf),
            Self::Blowfish(i) => i.read(buf),
            Self::Aes128(i) => i.read(buf),
            Self::Aes192(i) => i.read(buf),
            Self::Aes256(i) => i.read(buf),
            Self::Twofish(i) => i.read(buf),
            Self::Camellia128(i) => i.read(buf),
            Self::Camellia192(i) => i.read(buf),
            Self::Camellia256(i) => i.read(buf),
        }
    }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            Self::Idea(i) => i.read_to_end(buf),
            Self::TripleDes(i) => i.read_to_end(buf),
            Self::Cast5(i) => i.read_to_end(buf),
            Self::Blowfish(i) => i.read_to_end(buf),
            Self::Aes128(i) => i.read_to_end(buf),
            Self::Aes192(i) => i.read_to_end(buf),
            Self::Aes256(i) => i.read_to_end(buf),
            Self::Twofish(i) => i.read_to_end(buf),
            Self::Camellia128(i) => i.read_to_end(buf),
            Self::Camellia192(i) => i.read_to_end(buf),
            Self::Camellia256(i) => i.read_to_end(buf),
        }
    }
}

impl<R> StreamDecryptor<R>
where
    R: BufRead,
{
    pub fn new(
        alg: SymmetricKeyAlgorithm,
        protected: bool,
        seipdv1_read_mode: Seipdv1ReadMode,
        key: &[u8],
        ciphertext: R,
    ) -> Result<Self> {
        match alg {
            SymmetricKeyAlgorithm::Plaintext => {
                bail!("'Plaintext' is not a legal cipher for encrypted data")
            }
            SymmetricKeyAlgorithm::IDEA => Ok(StreamDecryptor::Idea(StreamDecryptorInner::new(
                protected,
                seipdv1_read_mode,
                ciphertext,
                key,
            )?)),
            SymmetricKeyAlgorithm::TripleDES => Ok(StreamDecryptor::TripleDes(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::CAST5 => Ok(StreamDecryptor::Cast5(StreamDecryptorInner::new(
                protected,
                seipdv1_read_mode,
                ciphertext,
                key,
            )?)),
            SymmetricKeyAlgorithm::Blowfish => Ok(StreamDecryptor::Blowfish(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES128 => Ok(StreamDecryptor::Aes128(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES192 => Ok(StreamDecryptor::Aes192(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::AES256 => Ok(StreamDecryptor::Aes256(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Twofish => Ok(StreamDecryptor::Twofish(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia128 => Ok(StreamDecryptor::Camellia128(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia192 => Ok(StreamDecryptor::Camellia192(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Camellia256 => Ok(StreamDecryptor::Camellia256(
                StreamDecryptorInner::new(protected, seipdv1_read_mode, ciphertext, key)?,
            )),
            SymmetricKeyAlgorithm::Private10 | SymmetricKeyAlgorithm::Other(_) => {
                bail!("SymmetricKeyAlgorithm {} is unsupported", u8::from(alg))
            }
        }
    }

    pub fn into_inner(self) -> R {
        match self {
            Self::Idea(i) => i.into_inner(),
            Self::TripleDes(i) => i.into_inner(),
            Self::Cast5(i) => i.into_inner(),
            Self::Blowfish(i) => i.into_inner(),
            Self::Aes128(i) => i.into_inner(),
            Self::Aes192(i) => i.into_inner(),
            Self::Aes256(i) => i.into_inner(),
            Self::Twofish(i) => i.into_inner(),
            Self::Camellia128(i) => i.into_inner(),
            Self::Camellia192(i) => i.into_inner(),
            Self::Camellia256(i) => i.into_inner(),
        }
    }

    pub fn get_ref(&self) -> &R {
        match self {
            Self::Idea(i) => i.get_ref(),
            Self::TripleDes(i) => i.get_ref(),
            Self::Cast5(i) => i.get_ref(),
            Self::Blowfish(i) => i.get_ref(),
            Self::Aes128(i) => i.get_ref(),
            Self::Aes192(i) => i.get_ref(),
            Self::Aes256(i) => i.get_ref(),
            Self::Twofish(i) => i.get_ref(),
            Self::Camellia128(i) => i.get_ref(),
            Self::Camellia192(i) => i.get_ref(),
            Self::Camellia256(i) => i.get_ref(),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Idea(i) => i.get_mut(),
            Self::TripleDes(i) => i.get_mut(),
            Self::Cast5(i) => i.get_mut(),
            Self::Blowfish(i) => i.get_mut(),
            Self::Aes128(i) => i.get_mut(),
            Self::Aes192(i) => i.get_mut(),
            Self::Aes256(i) => i.get_mut(),
            Self::Twofish(i) => i.get_mut(),
            Self::Camellia128(i) => i.get_mut(),
            Self::Camellia192(i) => i.get_mut(),
            Self::Camellia256(i) => i.get_mut(),
        }
    }
}

#[derive(derive_more::Debug)]
pub enum MaybeProtected {
    ProtectedCheckFirst {
        hasher: Sha1,

        max_message_size: usize,
    },

    ProtectedStreaming {
        hasher: Sha1,
    },

    Unprotected {
        key: Zeroizing<Vec<u8>>,
    },
}

#[derive(derive_more::Debug)]
pub enum StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    Prefix {
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        prefix: BytesMut,
        source: R,
        protected: MaybeProtected,
    },
    Data {
        data_available: usize,
        #[debug("BufDecryptor")]
        decryptor: BufDecryptor<M>,
        buffer: BytesMut,
        source: R,
        protected: MaybeProtected,
    },
    Done {
        buffer: BytesMut,
        source: R,
    },
    Error,
}

impl<M, R> StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn new(
        protected: bool,
        seipdv1_read_mode: Seipdv1ReadMode,
        source: R,
        key: &[u8],
    ) -> Result<Self> {
        debug!("protected decrypt stream");

        let bs = <M as BlockSizeUser>::block_size();

        let iv_vec = vec![0u8; bs];

        let decryptor = BufDecryptor::<M>::new_from_slices(key, &iv_vec)?;
        let prefix_len = bs + 2;

        let protected = if protected {
            let hasher = Sha1::default();

            match seipdv1_read_mode {
                Seipdv1ReadMode::CheckFirst { max_message_size } => {
                    MaybeProtected::ProtectedCheckFirst {
                        hasher,
                        max_message_size,
                    }
                }
                Seipdv1ReadMode::Streaming => MaybeProtected::ProtectedStreaming { hasher },
            }
        } else {
            MaybeProtected::Unprotected {
                key: key.to_vec().into(),
            }
        };

        Ok(Self::Prefix {
            decryptor,
            prefix: BytesMut::zeroed(prefix_len),
            source,
            protected,
        })
    }

    fn into_inner(self) -> R {
        match self {
            Self::Prefix { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    fn get_ref(&self) -> &R {
        match self {
            Self::Prefix { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    fn get_mut(&mut self) -> &mut R {
        match self {
            Self::Prefix { source, .. } => source,
            Self::Data { source, .. } => source,
            Self::Done { source, .. } => source,
            Self::Error => panic!("error state"),
        }
    }

    fn fill_inner(&mut self) -> io::Result<()> {
        if matches!(self, Self::Prefix { .. }) {
            self.advance_prefix()?;
        }
        match self {
            Self::Prefix { .. } => unreachable!("advance_prefix must transition away from Prefix"),
            Self::Data { .. } => match self.fill_data() {
                Ok(is_last_read) => {
                    if is_last_read {
                        self.finalize_data()?;
                    }
                }
                Err(e) => {
                    *self = Self::Error;
                    return Err(e);
                }
            },
            Self::Done { .. } => {}
            Self::Error => return Err(io::Error::other("decryptor is in error state")),
        }
        Ok(())
    }

    fn advance_prefix(&mut self) -> io::Result<()> {
        match std::mem::replace(self, Self::Error) {
            Self::Prefix {
                mut decryptor,
                mut prefix,
                mut source,
                mut protected,
            } => {
                let bs = <M as BlockSizeUser>::block_size();

                let read = fill_buffer(&mut source, &mut prefix, Some(bs + 2))?;
                if read < bs + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "missing quick check",
                    ));
                }

                match protected {
                    MaybeProtected::Unprotected { ref key } => {
                        let encrypted_prefix = prefix[2..].to_vec();
                        decryptor.decrypt(&mut prefix);
                        decryptor = BufDecryptor::<M>::new_from_slices(key, &encrypted_prefix)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                    }
                    MaybeProtected::ProtectedStreaming { ref mut hasher, .. }
                    | MaybeProtected::ProtectedCheckFirst { ref mut hasher, .. } => {
                        decryptor.decrypt(&mut prefix);
                        hasher.update(&prefix);
                    }
                }

                *self = Self::Data {
                    data_available: 0,
                    decryptor,
                    buffer: BytesMut::with_capacity(BUFFER_SIZE),
                    source,
                    protected,
                };
                Ok(())
            }
            _ => unreachable!("advance_prefix called in non-prefix state"),
        }
    }

    fn fill_data(&mut self) -> io::Result<bool> {
        let Self::Data {
            data_available,
            decryptor,
            buffer,
            source,
            protected,
        } = self
        else {
            unreachable!("fill_data called in non-data state")
        };

        match protected {
            MaybeProtected::ProtectedStreaming { .. } => {
                if buffer.remaining() > MDC_LEN {
                    return Ok(false);
                }
            }
            MaybeProtected::Unprotected { .. } => {
                if buffer.has_remaining() {
                    return Ok(false);
                }
            }
            MaybeProtected::ProtectedCheckFirst { .. } => {}
        }

        let current_len = buffer.remaining();

        let is_last_read = match protected {
            MaybeProtected::ProtectedCheckFirst {
                max_message_size, ..
            } => {
                let read = fill_buffer_bytes(&mut *source, buffer, *max_message_size)?;

                if read == *max_message_size {
                    if source.read_u8().is_ok() {
                        return Err(io::Error::other(
                            "Input stream too long for ProtectedCheckFirst mode",
                        ));
                    }
                }

                true
            }

            _ => {
                let buf_size = BUFFER_SIZE;
                let to_read = buf_size - current_len;
                let read = fill_buffer_bytes(source, buffer, buf_size)?;

                read < to_read
            }
        };

        decryptor.decrypt(&mut buffer[current_len..]);

        match protected {
            MaybeProtected::ProtectedCheckFirst { ref mut hasher, .. }
            | MaybeProtected::ProtectedStreaming { ref mut hasher, .. } => {
                if buffer.remaining() < MDC_LEN {
                    return Err(io::Error::other(Error::MdcError));
                }

                let start = *data_available;
                debug_assert!(buffer.len() >= MDC_LEN);
                let end = buffer.len() - MDC_LEN;
                if start < end {
                    hasher.update(&buffer[start..end]);

                    if !is_last_read {
                        *data_available += end - start;
                    }
                }
            }
            MaybeProtected::Unprotected { .. } => {
                if !is_last_read {
                    let start = *data_available;
                    let end = buffer.len();
                    if start < end {
                        *data_available += end - start;
                    }
                }
            }
        }

        Ok(is_last_read)
    }

    fn finalize_data(&mut self) -> io::Result<()> {
        match std::mem::replace(self, Self::Error) {
            Self::Data {
                mut buffer,
                source,
                protected,
                ..
            } => {
                match protected {
                    MaybeProtected::ProtectedCheckFirst { mut hasher, .. }
                    | MaybeProtected::ProtectedStreaming { mut hasher, .. } => {
                        let msg_mdc = buffer.split_off(buffer.len() - MDC_LEN);

                        hasher.update(&msg_mdc[..2]);
                        let hash: [u8; 20] = hasher.finalize().into();

                        let mdc_ok = msg_mdc[0].ct_eq(&0xD3)
                            & msg_mdc[1].ct_eq(&0x14)
                            & msg_mdc[2..].ct_eq(hash.as_slice());
                        if bool::from(!mdc_ok) {
                            return Err(io::Error::other(Error::MdcError));
                        }
                    }

                    MaybeProtected::Unprotected { .. } => {}
                }

                *self = Self::Done { buffer, source };
                Ok(())
            }
            _ => unreachable!("finalize_data called in non-Data state"),
        }
    }
}

impl<M, R> BufRead for StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_inner()?;
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => Ok(&buffer[..*data_available]),
            Self::Done { buffer, .. } => Ok(&buffer[..]),
            Self::Error => unreachable!("error state "),
        }
    }

    fn consume(&mut self, amt: usize) {
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => {
                buffer.advance(amt);
                *data_available -= amt;
            }
            Self::Done { buffer, .. } => {
                buffer.advance(amt);
            }
            Self::Error => unreachable!("error state "),
        }
    }
}

impl<M, R> Read for StreamDecryptorInner<M, R>
where
    M: BlockDecrypt + BlockEncryptMut + BlockCipher,
    BufDecryptor<M>: KeyIvInit,
    R: BufRead,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fill_inner()?;
        match self {
            Self::Prefix { .. } => panic!("invalid state"),
            Self::Data {
                buffer,
                data_available,
                ..
            } => {
                let to_write = (*data_available).min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                *data_available -= to_write;
                Ok(to_write)
            }
            Self::Done { buffer, .. } => {
                let to_write = buffer.remaining().min(buf.len());
                buffer.copy_to_slice(&mut buf[..to_write]);
                Ok(to_write)
            }
            Self::Error => unreachable!("error state"),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut read = 0;

        loop {
            self.fill_inner()?;
            match self {
                Self::Prefix { .. } => panic!("invalid state"),
                Self::Data {
                    buffer,
                    data_available,
                    ..
                } => {
                    let to_write = *data_available;
                    buf.extend_from_slice(&buffer[..to_write]);
                    buffer.advance(to_write);
                    *data_available -= to_write;
                    read += to_write;
                }
                Self::Done { buffer, .. } => {
                    let to_write = buffer.remaining();
                    buf.extend_from_slice(buffer);
                    buffer.clear();
                    read += to_write;
                    break;
                }
                Self::Error => unreachable!("error state "),
            }
        }
        Ok(read)
    }
}
