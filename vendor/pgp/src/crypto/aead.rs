use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, AesGcm, Key as GcmKey, Nonce as GcmNonce,
};
use bytes::BytesMut;
use eax::{Eax, Key as EaxKey, Nonce as EaxNonce};
use generic_array::{
    typenum::{U15, U16},
    GenericArray,
};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use ocb3::{Nonce as Ocb3Nonce, Ocb3};
use sha2::Sha256;
use snafu::Snafu;
use zeroize::Zeroizing;

use super::sym::SymmetricKeyAlgorithm;
use crate::types::Tag;

type Aes128Ocb3 = Ocb3<Aes128, U15, U16>;
type Aes192Ocb3 = Ocb3<Aes192, U15, U16>;
type Aes256Ocb3 = Ocb3<Aes256, U15, U16>;

pub type Aes192Gcm = AesGcm<Aes192, U12>;

mod decryptor;
mod encryptor;

pub use self::{decryptor::StreamDecryptor, encryptor::StreamEncryptor};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("unsupported algorithm {:?}", alg))]
    UnsupporedAlgorithm { alg: AeadAlgorithm },
    #[snafu(display("invalid session key: length does not match {} != {}", alg.key_size(), session_key_size))]
    InvalidSessionKey {
        alg: SymmetricKeyAlgorithm,
        session_key_size: usize,
    },
    #[snafu(display("decryption failed: {:?}", alg))]
    Decrypt { alg: AeadAlgorithm },
    #[snafu(display("encryption failed: {:?}", alg))]
    Encrypt { alg: AeadAlgorithm },
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    None = 0,
    Eax = 1,
    Ocb = 2,
    Gcm = 3,

    Private100 = 100,
    Private101 = 101,
    Private102 = 102,
    Private103 = 103,
    Private104 = 104,
    Private105 = 105,
    Private106 = 106,
    Private107 = 107,
    Private108 = 108,
    Private109 = 109,
    Private110 = 110,

    #[num_enum(catch_all)]
    Other(u8),
}

impl AeadAlgorithm {
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Eax => 16,
            Self::Ocb => 15,
            Self::Gcm => 12,
            _ => 0,
        }
    }

    pub fn iv_size(&self) -> usize {
        match self {
            Self::Eax => 16,
            Self::Ocb => 15,
            Self::Gcm => 12,
            _ => 0,
        }
    }

    pub fn tag_size(&self) -> Option<usize> {
        match self {
            Self::Eax => Some(16),
            Self::Ocb => Some(16),
            Self::Gcm => Some(16),
            _ => None,
        }
    }

    pub fn decrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut BytesMut,
    ) -> Result<(), Error> {
        let res = match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                cipher.decrypt_in_place(nonce, associated_data, buffer)
            }
            _ => {
                return Err(UnsupporedAlgorithmSnafu { alg: *self }.build());
            }
        };
        res.map_err(|_| DecryptSnafu { alg: *self }.build())
    }

    pub fn encrypt_in_place(
        &self,
        sym_algorithm: &SymmetricKeyAlgorithm,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut BytesMut,
    ) -> Result<(), Error> {
        let res = match (sym_algorithm, self) {
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes128Gcm>::from_slice(&key[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes192Gcm>::from_slice(&key[..24]);
                let cipher = Aes192Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm) => {
                let key = GcmKey::<Aes256Gcm>::from_slice(&key[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = GcmNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes128>::from_slice(&key[..16]);
                let cipher = Eax::<Aes128>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes192>::from_slice(&key[..24]);
                let cipher = Eax::<Aes192>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax) => {
                let key = EaxKey::<Aes256>::from_slice(&key[..32]);
                let cipher = Eax::<Aes256>::new(key);
                let nonce = EaxNonce::from_slice(nonce);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..16]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes128Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..24]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes192Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb) => {
                let key = GenericArray::from_slice(&key[..32]);
                let nonce = Ocb3Nonce::from_slice(nonce);
                let cipher = Aes256Ocb3::new(key);
                cipher.encrypt_in_place(nonce, associated_data, buffer)
            }
            _ => {
                return Err(UnsupporedAlgorithmSnafu { alg: *self }.build());
            }
        };

        res.map_err(|_| EncryptSnafu { alg: *self }.build())
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn aead_setup_rfc9580(
    sym_alg: SymmetricKeyAlgorithm,
    aead: AeadAlgorithm,
    chunk_size: ChunkSize,
    salt: &[u8],
    ikm: &[u8],
) -> ([u8; 5], Zeroizing<Vec<u8>>, Vec<u8>) {
    let info = [
        Tag::SymEncryptedProtectedData.encode(),
        0x02,
        sym_alg.into(),
        aead.into(),
        chunk_size.into(),
    ];

    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 42]);
    hk.expand(&info, okm.as_mut_slice()).expect("42");

    let mut message_key = Zeroizing::new(vec![0; sym_alg.key_size()]);
    message_key.copy_from_slice(&okm.as_slice()[..sym_alg.key_size()]);

    let raw_iv_len = aead.nonce_size() - 8;
    let iv = &okm[sym_alg.key_size()..sym_alg.key_size() + raw_iv_len];
    let mut nonce = vec![0u8; aead.nonce_size()];
    nonce[..raw_iv_len].copy_from_slice(iv);

    (info, message_key, nonce)
}

#[derive(
    Default, IntoPrimitive, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, TryFromPrimitive,
)]
#[repr(u8)]

pub enum ChunkSize {
    C64B = 0,
    C128B = 1,
    C256B = 2,
    C512B = 3,
    C1KiB = 4,
    C2KiB = 5,
    #[default]
    C4KiB = 6,
    C8KiB = 7,
    C16KiB = 8,
    C32KiB = 9,
    C64KiB = 10,
    C128KiB = 11,
    C256KiB = 12,
    C512KiB = 13,
    C1MiB = 14,
    C2MiB = 15,
    C4MiB = 16,
}

impl ChunkSize {
    pub const fn as_byte_size(self) -> u32 {
        1u32 << ((self as u32) + 6)
    }
}
