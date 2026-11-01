use std::io::{self, BufRead};

use byteorder::WriteBytesExt;
use bytes::Bytes;
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::{
    composed::RawSessionKey,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, ensure, unimplemented_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::KeyVersion,
};

const EXPBIAS: u32 = 6;
const DEFAULT_ITER_SALTED_COUNT: u8 = 224;

const ARGON2_MEMORY_LIMIT_KIB: u32 = 2 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum S2kUsage {
    Unprotected,
    LegacyCfb(SymmetricKeyAlgorithm),
    Aead,
    Cfb,
    MalleableCfb,
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]
pub enum S2kParams {
    Unprotected,
    LegacyCfb {
        sym_alg: SymmetricKeyAlgorithm,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
    Aead {
        sym_alg: SymmetricKeyAlgorithm,
        aead_mode: AeadAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(nonce))]
        nonce: Bytes,
    },
    Cfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
    MalleableCfb {
        sym_alg: SymmetricKeyAlgorithm,
        s2k: StringToKey,
        #[debug("{}", hex::encode(iv))]
        iv: Bytes,
    },
}

impl From<&S2kParams> for u8 {
    fn from(value: &S2kParams) -> Self {
        match value {
            S2kParams::Unprotected => 0,
            S2kParams::LegacyCfb { sym_alg, .. } => (*sym_alg).into(),
            S2kParams::Aead { .. } => 253,
            S2kParams::Cfb { .. } => 254,
            S2kParams::MalleableCfb { .. } => 255,
        }
    }
}

impl S2kParams {
    pub fn new_default<R: Rng + CryptoRng>(mut rng: R, key_version: KeyVersion) -> Self {
        match key_version {
            KeyVersion::V6 => {
                let sym_alg = SymmetricKeyAlgorithm::AES256;
                let aead_mode = AeadAlgorithm::Ocb;

                let mut nonce = vec![0u8; aead_mode.nonce_size()];
                rng.fill(&mut nonce[..]);

                let mut salt = [0u8; 16];
                rng.fill(&mut salt[..]);

                S2kParams::Aead {
                    sym_alg,
                    aead_mode,

                    s2k: StringToKey::Argon2 {
                        salt,
                        t: 3,
                        p: 4,
                        m_enc: 16,
                    },
                    nonce: nonce.into(),
                }
            }
            _ => {
                let sym_alg = SymmetricKeyAlgorithm::AES256;

                let mut iv = vec![0u8; sym_alg.block_size()];
                rng.fill(&mut iv[..]);

                Self::Cfb {
                    sym_alg,
                    s2k: StringToKey::new_default(rng),
                    iv: iv.into(),
                }
            }
        }
    }
}

impl From<u8> for S2kUsage {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Unprotected,
            v @ 1..=252 => Self::LegacyCfb(SymmetricKeyAlgorithm::from(v)),
            253 => Self::Aead,
            254 => Self::Cfb,
            255 => Self::MalleableCfb,
        }
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone)]

pub enum StringToKey {
    Simple {
        hash_alg: HashAlgorithm,
    },
    Salted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
    },

    Reserved {
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },
    IteratedAndSalted {
        hash_alg: HashAlgorithm,
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 8],
        count: u8,
    },
    Argon2 {
        #[debug("{}", hex::encode(salt))]
        salt: [u8; 16],
        t: u8,
        p: u8,
        m_enc: u8,
    },

    Private {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },

    Other {
        typ: u8,
        #[debug("{}", hex::encode(unknown))]
        unknown: Bytes,
    },
}

impl StringToKey {
    pub fn new_default<R: CryptoRng + Rng>(rng: R) -> Self {
        StringToKey::new_iterated(rng, HashAlgorithm::default(), DEFAULT_ITER_SALTED_COUNT)
    }

    pub fn new_iterated<R: CryptoRng + Rng>(
        mut rng: R,
        hash_alg: HashAlgorithm,
        count: u8,
    ) -> Self {
        let mut salt = [0u8; 8];
        rng.fill(&mut salt[..]);

        StringToKey::IteratedAndSalted {
            hash_alg,
            salt,
            count,
        }
    }

    pub fn new_argon2<R: CryptoRng + Rng>(mut rng: R, t: u8, p: u8, m_enc: u8) -> Self {
        let mut salt = [0u8; 16];
        rng.fill(&mut salt[..]);

        StringToKey::Argon2 { salt, t, p, m_enc }
    }

    pub fn id(&self) -> u8 {
        match self {
            Self::Simple { .. } => 0,
            Self::Salted { .. } => 1,
            Self::Reserved { .. } => 2,
            Self::IteratedAndSalted { .. } => 3,
            Self::Argon2 { .. } => 4,

            Self::Private { typ, .. } => *typ,
            Self::Other { typ, .. } => *typ,
        }
    }

    pub fn uses_salt(&self) -> bool {
        matches![
            self,
            StringToKey::Salted { .. }
                | StringToKey::IteratedAndSalted { .. }
                | StringToKey::Argon2 { .. }
        ]
    }

    pub(crate) fn known_weak_hash_algo(&self) -> bool {
        match self {
            Self::Simple { hash_alg }
            | Self::Salted { hash_alg, .. }
            | Self::IteratedAndSalted { hash_alg, .. } => {
                hash_alg == &HashAlgorithm::Md5
                    || hash_alg == &HashAlgorithm::Sha1
                    || hash_alg == &HashAlgorithm::Ripemd160
            }
            _ => false,
        }
    }

    pub fn derive_key(&self, passphrase: &[u8], key_size: usize) -> Result<RawSessionKey> {
        let key = match self {
            Self::Simple { hash_alg, .. }
            | Self::Salted { hash_alg, .. }
            | Self::IteratedAndSalted { hash_alg, .. } => {
                let Some(digest_size) = hash_alg.digest_size() else {
                    bail!("invalid hash algorithm: {}", hash_alg);
                };
                let rounds = (key_size as f32 / digest_size as f32).ceil() as usize;

                let mut key = Zeroizing::new(vec![0u8; key_size]);
                let zeros = vec![0u8; rounds];

                for round in 0..rounds {
                    let mut hasher = hash_alg.new_hasher()?;

                    hasher.update(&zeros[..round]);

                    match self {
                        StringToKey::Simple { .. } => {
                            hasher.update(passphrase);
                        }
                        StringToKey::Salted { salt, .. } => {
                            hasher.update(salt);
                            hasher.update(passphrase);
                        }
                        StringToKey::IteratedAndSalted { salt, count, .. } => {
                            fn decode_count(coded_count: u8) -> usize {
                                ((16u32 + u32::from(coded_count & 15))
                                    << (u32::from(coded_count >> 4) + EXPBIAS))
                                    as usize
                            }

                            let data_size = salt.len() + passphrase.len();

                            let mut count = decode_count(*count);

                            if count < data_size {
                                count = data_size;
                            }

                            while count > data_size {
                                hasher.update(salt);
                                hasher.update(passphrase);
                                count -= data_size;
                            }

                            if count < salt.len() {
                                hasher.update(&salt[..count]);
                            } else {
                                hasher.update(salt);
                                count -= salt.len();
                                hasher.update(&passphrase[..count]);
                            }
                        }
                        _ => unimplemented_err!("S2K {:?} is not available", self),
                    }

                    let start = round * digest_size;
                    let end = if round == rounds - 1 {
                        key_size
                    } else {
                        (round + 1) * digest_size
                    };

                    let hash = hasher.finalize();
                    key[start..end].copy_from_slice(&hash[..end - start]);
                }

                key
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                ensure!(
                    *t <= 32 && *p <= 32,
                    "unsupported settings t={}, p={} in argon s2k",
                    t,
                    p,
                );

                let min_m = (*p as f32).log2().ceil() as u8;
                ensure!(
                    *m_enc >= min_m && *m_enc <= 31,
                    "unsupported value {} for m in argon s2k",
                    m_enc
                );

                let m = 2u32.pow(*m_enc as u32);

                ensure!(
                    m <= ARGON2_MEMORY_LIMIT_KIB,
                    "unsupported memory usage setting ({} KiB) for m in argon s2k",
                    m
                );

                use argon2::{Algorithm, Argon2, Params, Version};

                let a2 = Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(m, *t as u32, *p as u32, Some(key_size))?,
                );

                let mut output_key_material = Zeroizing::new(vec![0; key_size]);

                a2.hash_password_into(passphrase, salt, &mut output_key_material)?;

                output_key_material
            }

            _ => unimplemented_err!("S2K {:?} is not available", self),
        };

        Ok(key.into())
    }

    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> Result<u8> {
        let len = match self {
            Self::Simple { .. } => 2,
            Self::Salted { .. } => 10,
            Self::IteratedAndSalted { .. } => 11,
            Self::Argon2 { .. } => 20,
            _ => bail!("not implemented for StringToKey: {:?}", self),
        };

        Ok(len)
    }

    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let typ = i.read_u8()?;

        match typ {
            0 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;

                Ok(StringToKey::Simple { hash_alg })
            }
            1 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
                let salt = i.read_arr::<8>()?;

                Ok(StringToKey::Salted { hash_alg, salt })
            }
            2 => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Reserved { unknown })
            }
            3 => {
                let hash_alg = i.read_u8().map(HashAlgorithm::from)?;
                let salt = i.read_arr::<8>()?;
                let count = i.read_u8()?;

                Ok(StringToKey::IteratedAndSalted {
                    hash_alg,
                    salt,
                    count,
                })
            }
            4 => {
                let salt = i.read_arr::<16>()?;
                let t = i.read_u8()?;
                let p = i.read_u8()?;
                let m_enc = i.read_u8()?;

                Ok(StringToKey::Argon2 { salt, t, p, m_enc })
            }
            100..=110 => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Private { typ, unknown })
            }
            _ => {
                let unknown = i.rest()?.freeze();
                Ok(StringToKey::Other { typ, unknown })
            }
        }
    }
}

impl Serialize for StringToKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Simple { hash_alg } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
            }
            Self::Salted { hash_alg, salt } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
                writer.write_all(salt)?;
            }
            Self::IteratedAndSalted {
                hash_alg,
                salt,
                count,
            } => {
                writer.write_u8(self.id())?;
                writer.write_u8((*hash_alg).into())?;
                writer.write_all(salt)?;
                writer.write_u8(*count)?;
            }
            Self::Argon2 { salt, t, p, m_enc } => {
                writer.write_u8(self.id())?;
                writer.write_all(salt)?;
                writer.write_all(&[*t, *p, *m_enc])?;
            }

            Self::Reserved { unknown, .. }
            | Self::Private { unknown, .. }
            | Self::Other { unknown, .. } => {
                writer.write_u8(self.id())?;
                writer.write_all(unknown)?;
            }
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        let mut sum = 0;
        match self {
            Self::Simple { .. } => {
                sum += 1 + 1;
            }
            Self::Salted { salt, .. } => {
                sum += 1 + 1;
                sum += salt.len();
            }
            Self::IteratedAndSalted { salt, .. } => {
                sum += 1 + 1;
                sum += salt.len();
                sum += 1;
            }
            Self::Argon2 { salt, .. } => {
                sum += 1;
                sum += salt.len();
                sum += 3;
            }

            Self::Reserved { unknown, .. }
            | Self::Private { unknown, .. }
            | Self::Other { unknown, .. } => {
                sum += 1;
                sum += unknown.len();
            }
        }

        sum
    }
}
