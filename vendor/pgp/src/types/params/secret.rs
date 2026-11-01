use std::io::{self, BufRead};

use zeroize::ZeroizeOnDrop;

use crate::{
    crypto::{aead::AeadAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    errors::{bail, InvalidInputSnafu, Result},
    parsing_reader::BufReadParsing,
    types::*,
};

#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
#[allow(clippy::large_enum_variant)]
pub enum SecretParams {
    Plain(PlainSecretParams),
    Encrypted(EncryptedSecretParams),
}

impl SecretParams {
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    pub fn from_slice(
        data: &[u8],
        key_ver: KeyVersion,
        alg: PublicKeyAlgorithm,
        params: &PublicParams,
    ) -> Result<Self> {
        let params = parse_secret_fields(key_ver, alg, params, data)?;

        if key_ver == KeyVersion::V6 && ![0, 253, 254].contains(&params.string_to_key_id()) {
            bail!(
                "Illegal S2K Usage setting {} for a V6 key",
                params.string_to_key_id()
            )
        }

        Ok(params)
    }

    pub fn has_sha1_checksum(&self) -> bool {
        self.string_to_key_id() == 254
    }

    pub fn string_to_key_id(&self) -> u8 {
        match self {
            SecretParams::Plain(k) => k.string_to_key_id(),
            SecretParams::Encrypted(k) => k.string_to_key_id(),
        }
    }

    pub fn checksum(&self) -> Vec<u8> {
        match self {
            SecretParams::Plain(k) => k.checksum_simple(),
            SecretParams::Encrypted(k) => k.checksum(),
        }
    }

    pub fn to_writer<W: io::Write>(&self, writer: &mut W, version: KeyVersion) -> Result<()> {
        match self {
            SecretParams::Plain(k) => {
                writer.write_all(&[k.string_to_key_id()])?;
                k.to_writer(writer, version)
            }
            SecretParams::Encrypted(k) => k.to_writer(writer, version),
        }
    }

    pub fn write_len(&self, version: KeyVersion) -> usize {
        match self {
            SecretParams::Plain(k) => {
                let mut sum = 1;
                sum += k.write_len(version);
                sum
            }
            SecretParams::Encrypted(k) => k.write_len(version),
        }
    }
}

fn parse_secret_fields<B: BufRead>(
    key_ver: KeyVersion,
    alg: PublicKeyAlgorithm,
    public_params: &PublicParams,
    mut i: B,
) -> Result<SecretParams> {
    let s2k_usage = i.read_u8().map(S2kUsage::from)?;

    let _s2k_len = if key_ver == KeyVersion::V6 && s2k_usage != S2kUsage::Unprotected {
        let len = i.read_u8()?;
        if len == 0 {
            return Err(InvalidInputSnafu.build());
        }
        Some(len)
    } else {
        None
    };

    let enc_params = match s2k_usage {
        S2kUsage::Unprotected => S2kParams::Unprotected,

        S2kUsage::LegacyCfb(sym_alg) => {
            let iv = i.take_bytes(sym_alg.block_size())?.freeze();
            S2kParams::LegacyCfb { sym_alg, iv }
        }
        S2kUsage::Aead => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
            let aead_mode = i.read_u8().map(AeadAlgorithm::from)?;

            let len = if key_ver == KeyVersion::V6 {
                i.read_u8().map(Some)?
            } else {
                None
            };

            let s2k = StringToKey::try_from_reader(&mut i)?;

            if let Some(len) = len {
                if s2k.len()? != len {
                    bail!(
                        "String2Key length {} doesn't match for s2k type {:?}",
                        len,
                        s2k
                    );
                }
            }

            let nonce = i.take_bytes(aead_mode.nonce_size())?.freeze();

            S2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k,
                nonce,
            }
        }

        S2kUsage::Cfb => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;

            let len = if key_ver == KeyVersion::V6 {
                i.read_u8().map(Some)?
            } else {
                None
            };

            let s2k = StringToKey::try_from_reader(&mut i)?;

            if let Some(len) = len {
                if s2k.len()? != len {
                    bail!(
                        "String2Key length {} doesn't match for s2k type {:?}",
                        len,
                        s2k
                    );
                }
            }

            let iv = i.take_bytes(sym_alg.block_size())?.freeze();
            S2kParams::Cfb { sym_alg, s2k, iv }
        }
        S2kUsage::MalleableCfb => {
            let sym_alg = i.read_u8().map(SymmetricKeyAlgorithm::from)?;
            let s2k = StringToKey::try_from_reader(&mut i)?;
            let iv = i.take_bytes(sym_alg.block_size())?.freeze();

            S2kParams::Cfb { sym_alg, s2k, iv }
        }
    };

    match s2k_usage {
        S2kUsage::Unprotected => {
            let params = PlainSecretParams::try_from_reader(i, key_ver, alg, public_params)?;
            Ok(SecretParams::Plain(params))
        }
        _ => {
            let params = EncryptedSecretParams::new(i.rest()?.freeze(), enc_params);
            Ok(SecretParams::Encrypted(params))
        }
    }
}
