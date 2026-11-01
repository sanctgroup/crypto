use std::{
    cmp::Ordering,
    io::{BufRead, Read},
};

use bitfields::bitfield;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bytes::Bytes;
use digest::DynDigest;
use log::debug;
use num_enum::{FromPrimitive, IntoPrimitive};

use crate::{
    crypto::{
        aead::AeadAlgorithm,
        hash::{HashAlgorithm, WriteHasher},
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, unimplemented_err, unsupported_err, Result},
    line_writer::LineBreak,
    normalize_lines::NormalizedReader,
    packet::{
        signature::SignatureConfig, PacketHeader, PacketTrait, SignatureVersionSpecific, Subpacket,
        SubpacketData,
    },
    parsing::BufParsing,
    parsing_reader::BufReadParsing,
    ser::Serialize,
    types::{
        self, CompressionAlgorithm, Duration, Fingerprint, KeyDetails, KeyId, KeyVersion,
        PacketLength, SignatureBytes, Tag, Timestamp, VerifyingKey,
    },
};

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub struct Signature {
    packet_header: PacketHeader,
    pub(crate) inner: InnerSignature,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub(crate) enum InnerSignature {
    Known {
        config: SignatureConfig,
        #[debug("{}", hex::encode(signed_hash_value))]
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    },
    Unknown {
        version: SignatureVersion,
        #[debug("{}", hex::encode(data))]
        data: Bytes,
    },
}

impl Signature {
    #[allow(clippy::too_many_arguments)]
    pub fn v2(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: Timestamp,
        issuer_key_id: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets: vec![],
                    unhashed_subpackets: vec![],
                    version_specific: SignatureVersionSpecific::V2 {
                        created,
                        issuer_key_id,
                    },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn v3(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: Timestamp,
        issuer_key_id: KeyId,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets: vec![],
                    unhashed_subpackets: vec![],
                    version_specific: SignatureVersionSpecific::V3 {
                        created,
                        issuer_key_id,
                    },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn v4(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets,
                    unhashed_subpackets,
                    version_specific: SignatureVersionSpecific::V4,
                },
                signed_hash_value,
                signature,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn v6(
        packet_header: PacketHeader,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
        hashed_subpackets: Vec<Subpacket>,
        unhashed_subpackets: Vec<Subpacket>,
        salt: Vec<u8>,
    ) -> Self {
        Signature {
            packet_header,
            inner: InnerSignature::Known {
                config: SignatureConfig {
                    typ,
                    pub_alg,
                    hash_alg,
                    hashed_subpackets,
                    unhashed_subpackets,
                    version_specific: SignatureVersionSpecific::V6 { salt },
                },
                signed_hash_value,
                signature,
            },
        }
    }

    pub fn unknown(packet_header: PacketHeader, version: SignatureVersion, data: Bytes) -> Self {
        Self {
            packet_header,
            inner: InnerSignature::Unknown { version, data },
        }
    }

    pub fn from_config(
        config: SignatureConfig,
        signed_hash_value: [u8; 2],
        signature: SignatureBytes,
    ) -> Result<Self> {
        let len = match config.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let mut sum = 1;
                sum += config.write_len_v3();
                sum += 2;
                sum += signature.write_len();
                sum
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut sum = 1;
                sum += config.write_len_v4_v6();
                sum += 2;
                if let SignatureVersionSpecific::V6 { ref salt } = config.version_specific {
                    sum += 1;
                    sum += salt.len();
                }
                sum += signature.write_len();
                sum
            }
            SignatureVersion::V5 => {
                unsupported_err!("crate V5 signature")
            }
            SignatureVersion::Other(version) => unsupported_err!("signature version {}", version),
        };
        let packet_header = PacketHeader::new_fixed(Tag::Signature, len.try_into()?);

        Ok(Signature {
            packet_header,
            inner: InnerSignature::Known {
                config,
                signed_hash_value,
                signature,
            },
        })
    }

    pub fn config(&self) -> Option<&SignatureConfig> {
        match self.inner {
            InnerSignature::Known { ref config, .. } => Some(config),
            InnerSignature::Unknown { .. } => None,
        }
    }

    pub fn unhashed_subpacket_push(&mut self, subpacket: Subpacket) -> Result<()> {
        if let InnerSignature::Known { ref config, .. } = self.inner {
            self.unhashed_subpacket_insert(config.unhashed_subpackets.len(), subpacket)
        } else {
            bail!("Unknown Signature type, can't add Subpacket");
        }
    }

    pub fn unhashed_subpacket_insert(&mut self, index: usize, subpacket: Subpacket) -> Result<()> {
        if let InnerSignature::Known { ref mut config, .. } = self.inner {
            if let PacketLength::Fixed(packetlen) = self.packet_header.packet_length_mut() {
                ensure!(
                    index <= config.unhashed_subpackets.len(),
                    "Index {} is larger than the unhashed subpacket area",
                    index
                );

                let len = u32::try_from(subpacket.write_len())?;

                config.unhashed_subpackets.insert(index, subpacket);
                *packetlen += len;
            } else {
                bail!(
                    "Unexpected PacketLength encoding {:?}, can't modify the unhashed area",
                    self.packet_header.packet_length()
                );
            }

            Ok(())
        } else {
            bail!("Unknown Signature type, can't add Subpacket");
        }
    }

    pub fn unhashed_subpacket_remove(&mut self, index: usize) -> Result<Subpacket> {
        if let InnerSignature::Known { ref mut config, .. } = self.inner {
            ensure!(
                index < config.unhashed_subpackets.len(),
                "Index {} is not contained in the unhashed subpacket area",
                index
            );

            if let PacketLength::Fixed(packetlen) = self.packet_header.packet_length_mut() {
                let sp = config.unhashed_subpackets.remove(index);
                *packetlen -= u32::try_from(sp.write_len())?;
                Ok(sp)
            } else {
                bail!(
                    "Unexpected PacketLength encoding {:?}, can't modify the unhashed area",
                    self.packet_header.packet_length()
                );
            }
        } else {
            bail!("Unknown Signature type, can't remove Subpacket");
        }
    }

    pub fn unhashed_subpackets_sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&Subpacket, &Subpacket) -> Ordering,
    {
        if let InnerSignature::Known { ref mut config, .. } = self.inner {
            config.unhashed_subpackets.sort_by(compare);
        }
    }

    pub fn version(&self) -> SignatureVersion {
        match self.inner {
            InnerSignature::Known { ref config, .. } => config.version(),
            InnerSignature::Unknown { version, .. } => version,
        }
    }

    pub fn typ(&self) -> Option<SignatureType> {
        self.config().map(|c| c.typ())
    }

    pub fn hash_alg(&self) -> Option<HashAlgorithm> {
        self.config().map(|c| c.hash_alg)
    }

    pub fn signature(&self) -> Option<&SignatureBytes> {
        match self.inner {
            InnerSignature::Known { ref signature, .. } => Some(signature),
            InnerSignature::Unknown { .. } => None,
        }
    }

    pub fn signed_hash_value(&self) -> Option<[u8; 2]> {
        match self.inner {
            InnerSignature::Known {
                signed_hash_value, ..
            } => Some(signed_hash_value),
            InnerSignature::Unknown { .. } => None,
        }
    }

    fn match_identity(sig: &Signature, key: &impl KeyDetails) -> bool {
        let issuer_key_ids = sig.issuer_key_id();
        let issuer_fps = sig.issuer_fingerprint();

        if issuer_key_ids.is_empty() && issuer_fps.is_empty() {
            return true;
        }

        issuer_key_ids
            .iter()
            .any(|&key_id| key_id == &key.legacy_key_id())
            || issuer_fps.iter().any(|&fp| fp == &key.fingerprint())
    }

    fn check_signature_key_version_alignment(
        key: &impl KeyDetails,
        config: &SignatureConfig,
    ) -> Result<()> {
        if key.version() == KeyVersion::V6 {
            ensure_eq!(
                config.version(),
                SignatureVersion::V6,
                "Non v6 signature by a v6 key is not allowed"
            );
        }

        if config.version() == SignatureVersion::V6 {
            ensure_eq!(
                key.version(),
                KeyVersion::V6,
                "v6 signature by a non-v6 key is not allowed"
            );
        }

        Ok(())
    }

    pub(crate) fn check_signature_hash_strength(config: &SignatureConfig) -> Result<()> {
        if config.pub_alg.is_pqc() {
            let Some(digest_size) = config.hash_alg.digest_size() else {
                bail!("Illegal hash_alg setting {}", config.hash_alg);
            };

            ensure!(
                digest_size * 8 >= 256,
                "PQC signatures must use hash algorithms with digest size >= 256 bits, {} is insufficient",
                config.hash_alg
            );
        }

        Ok(())
    }

    pub fn verify<R>(&self, key: &impl VerifyingKey, data: R) -> Result<()>
    where
        R: Read,
    {
        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        Self::check_signature_key_version_alignment(&key, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, key),
            "verify: No matching issuer_key_id or issuer_fingerprint for Key ID: {:?}",
            &key.legacy_key_id(),
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            ensure_eq!(
                config.hash_alg.salt_len(),
                Some(salt.len()),
                "Illegal salt length {} for a V6 Signature using {:?}",
                salt.len(),
                config.hash_alg
            );

            hasher.update(salt.as_ref())
        }

        if matches!(self.typ(), Some(SignatureType::Text)) {
            let normalized = NormalizedReader::new(data, LineBreak::Crlf);

            config.hash_data_to_sign(&mut hasher, normalized)?;
        } else {
            config.hash_data_to_sign(&mut hasher, data)?;
        }
        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];

        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "signature: invalid signed hash value"
        );

        key.verify(config.hash_alg, hash, signature)
    }

    pub fn verify_certification<V>(&self, key: &V, tag: Tag, id: &impl Serialize) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        self.verify_third_party_certification(&key, &key, tag, id)
    }

    pub fn verify_third_party_certification<V, K>(
        &self,
        signee: &K,
        signer: &V,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<()>
    where
        V: VerifyingKey + Serialize,
        K: KeyDetails + Serialize,
    {
        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };
        let key_id = signee.legacy_key_id();
        debug!("verifying certification {key_id:?} {self:#?}");

        ensure!(
            matches!(
                config.typ,
                SignatureType::CertGeneric
                    | SignatureType::CertPersona
                    | SignatureType::CertCasual
                    | SignatureType::CertPositive
                    | SignatureType::CertRevocation
            ),
            "Expected certification signature or certificate revocation signature"
        );

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, signer),
            "verify_certification: No matching issuer_key_id or issuer_fingerprint for Key ID: {:?}",
            key_id,
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        {
            serialize_for_hashing(signee, &mut hasher)?;
        }

        {
            let packet_len = id.write_len();

            match config.version() {
                SignatureVersion::V2 | SignatureVersion::V3 => {}
                SignatureVersion::V4 | SignatureVersion::V6 => {
                    let prefix = match tag {
                        Tag::UserId => 0xB4,
                        Tag::UserAttribute => 0xD1,
                        _ => bail!("invalid tag for certification validation: {:?}", tag),
                    };

                    let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                    BigEndian::write_u32(&mut prefix_buf[1..], packet_len.try_into()?);

                    hasher.update(&prefix_buf);
                }
                SignatureVersion::V5 => {
                    bail!("v5 signature unsupported tpc")
                }
                SignatureVersion::Other(version) => {
                    bail!("unsupported signature version: {:?}", version)
                }
            }

            id.to_writer(&mut WriteHasher(&mut hasher))?;
        }

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "certification: invalid signed hash value"
        );

        signer.verify(config.hash_alg, hash, signature)
    }

    pub fn verify_subkey_binding<V, K>(&self, signer: &V, signee: &K) -> Result<()>
    where
        V: VerifyingKey + Serialize,
        K: KeyDetails + Serialize,
    {
        debug!("verifying subkey binding: {self:#?} - {signer:#?} - {signee:#?}",);

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        ensure!(
            matches!(
                config.typ,
                SignatureType::SubkeyBinding | SignatureType::SubkeyRevocation
            ),
            "Expected subkey binding or revocation signature"
        );

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signer, &mut hasher)?;
        serialize_for_hashing(signee, &mut hasher)?;

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "subkey binding: invalid signed hash value"
        );

        signer.verify(config.hash_alg, hash, signature)
    }

    pub fn verify_primary_key_binding<V, K>(&self, signer: &V, signee: &K) -> Result<()>
    where
        V: VerifyingKey + Serialize,
        K: KeyDetails + Serialize,
    {
        debug!("verifying primary key binding: {self:#?} - {signer:#?} - {signee:#?}");

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };

        ensure_eq!(
            config.typ,
            SignatureType::KeyBinding,
            "Expected primary key binding signature"
        );

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?;
        serialize_for_hashing(signer, &mut hasher)?;

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "key binding: invalid signed hash value"
        );

        signer.verify(config.hash_alg, hash, signature)
    }

    pub fn verify_key<V>(&self, key: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
    {
        self.verify_key_third_party(key, key)
    }

    pub fn verify_key_third_party<V, K>(&self, signee: &K, signer: &V) -> Result<()>
    where
        V: VerifyingKey + Serialize,
        K: KeyDetails + Serialize,
    {
        debug!("verifying direct signature: {self:#?} - signer {signer:#?}, signee {signee:#?}");

        let InnerSignature::Known {
            ref config,
            ref signed_hash_value,
            ref signature,
        } = self.inner
        else {
            unsupported_err!("signature version {:?}", self.version());
        };
        ensure!(
            matches!(
                config.typ,
                SignatureType::Key | SignatureType::KeyRevocation
            ),
            "Expected direct key signature or key revocation signature"
        );

        Self::check_signature_key_version_alignment(&signer, config)?;
        Self::check_signature_hash_strength(config)?;

        ensure!(
            Self::match_identity(self, signer),
            "verify_key: No matching issuer_key_id or issuer_fingerprint for Key ID: {:?}",
            &signer.legacy_key_id(),
        );

        let mut hasher = config.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?;

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        let hash = &hasher.finalize()[..];
        ensure_eq!(
            signed_hash_value,
            &hash[0..2],
            "key: invalid signed hash value"
        );

        signer.verify(config.hash_alg, hash, signature)
    }

    pub fn is_certification(&self) -> bool {
        self.config()
            .map(|c| c.is_certification())
            .unwrap_or_default()
    }

    pub fn key_expiration_time(&self) -> Option<Duration> {
        self.config().and_then(|h| {
            h.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::KeyExpirationTime(d) => Some(*d),
                _ => None,
            })
        })
    }

    pub fn signature_expiration_time(&self) -> Option<Duration> {
        self.config().and_then(|h| {
            h.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::SignatureExpirationTime(d) => Some(*d),
                _ => None,
            })
        })
    }

    pub fn created(&self) -> Option<Timestamp> {
        self.config().and_then(|c| c.created())
    }

    pub fn issuer_key_id(&self) -> Vec<&KeyId> {
        self.config().map(|c| c.issuer_key_id()).unwrap_or_default()
    }

    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.config()
            .map(|c| c.issuer_fingerprint())
            .unwrap_or_default()
    }

    pub fn preferred_symmetric_algs(&self) -> &[SymmetricKeyAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredSymmetricAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_aead_algs(&self) -> &[(SymmetricKeyAlgorithm, AeadAlgorithm)] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredAeadAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_hash_algs(&self) -> &[HashAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredHashAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn preferred_compression_algs(&self) -> &[CompressionAlgorithm] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::PreferredCompressionAlgorithms(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_server_prefs(&self) -> &[u8] {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::KeyServerPreferences(d) => Some(&d[..]),
                    _ => None,
                })
            })
            .unwrap_or_else(|| &[][..])
    }

    pub fn key_flags(&self) -> KeyFlags {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::KeyFlags(flags) => Some(flags.clone()),
                    _ => None,
                })
            })
            .unwrap_or_default()
    }

    pub fn features(&self) -> Option<&Features> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::Features(feat) => Some(feat),
                _ => None,
            })
        })
    }

    pub fn revocation_reason_code(&self) -> Option<&RevocationCode> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationReason(code, _) => Some(code),
                _ => None,
            })
        })
    }

    pub fn revocation_reason_string(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationReason(_, reason) => Some(reason),
                _ => None,
            })
        })
    }

    pub fn is_primary(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::IsPrimary(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(false)
    }

    pub fn is_revocable(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::Revocable(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(true)
    }

    pub fn embedded_signature(&self) -> Option<&Signature> {
        if let Some(sub) = self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::EmbeddedSignature(d) => Some(&**d),
                _ => None,
            })
        }) {
            return Some(sub);
        }
        if let Some(sub) = self.config().and_then(|c| {
            c.unhashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::EmbeddedSignature(d) => Some(&**d),
                _ => None,
            })
        }) {
            return Some(sub);
        }

        None
    }

    pub fn preferred_key_server(&self) -> Option<&str> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::PreferredKeyServer(d) => Some(d.as_str()),
                _ => None,
            })
        })
    }

    pub fn notations(&self) -> Vec<&Notation> {
        self.config()
            .map(|c| {
                c.hashed_subpackets()
                    .filter_map(|p| match &p.data {
                        SubpacketData::Notation(d) => Some(d),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn revocation_key(&self) -> Option<&types::RevocationKey> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RevocationKey(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn signers_userid(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::SignersUserID(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn policy_uri(&self) -> Option<&str> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::PolicyURI(d) => Some(d.as_ref()),
                _ => None,
            })
        })
    }

    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::TrustSignature(depth, value) => Some((*depth, *value)),
                _ => None,
            })
        })
    }

    pub fn regular_expression(&self) -> Option<&Bytes> {
        self.config().and_then(|c| {
            c.hashed_subpackets().find_map(|p| match &p.data {
                SubpacketData::RegularExpression(d) => Some(d),
                _ => None,
            })
        })
    }

    pub fn exportable_certification(&self) -> bool {
        self.config()
            .and_then(|c| {
                c.hashed_subpackets().find_map(|p| match &p.data {
                    SubpacketData::ExportableCertification(d) => Some(*d),
                    _ => None,
                })
            })
            .unwrap_or(true)
    }
}

#[derive(derive_more::Debug, PartialEq, Eq, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SignatureVersion {
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
    V6 = 6,

    #[num_enum(catch_all)]
    Other(#[debug("0x{:x}", _0)] u8),
}

#[allow(clippy::derivable_impls)]
impl Default for SignatureVersion {
    fn default() -> Self {
        Self::V4
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SignatureType {
    Binary = 0x00,
    Text = 0x01,
    Standalone = 0x02,
    CertGeneric = 0x10,
    CertPersona = 0x11,
    CertCasual = 0x12,
    CertPositive = 0x13,
    SubkeyBinding = 0x18,
    KeyBinding = 0x19,
    Key = 0x1F,
    KeyRevocation = 0x20,
    SubkeyRevocation = 0x28,
    CertRevocation = 0x30,
    Timestamp = 0x40,
    ThirdParty = 0x50,

    #[num_enum(catch_all)]
    Other(u8),
}

pub const CERTIFICATION_SIGNATURE_TYPES: &[SignatureType] = &[
    SignatureType::CertPositive,
    SignatureType::CertGeneric,
    SignatureType::CertCasual,
    SignatureType::CertPersona,
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyFlags {
    known: KnownKeyFlags,
    rest: Option<Bytes>,
    original_len: usize,
}

impl Default for KeyFlags {
    fn default() -> Self {
        Self {
            known: KnownKeyFlags::default(),
            rest: None,
            original_len: 1,
        }
    }
}

impl KeyFlags {
    pub fn try_from_reader<B: BufRead>(mut reader: B) -> Result<Self> {
        let mut buf = reader.rest()?.freeze();
        let remaining = buf.len();

        if remaining == 0 {
            return Ok(Self {
                known: KnownKeyFlags::default(),
                rest: None,
                original_len: remaining,
            });
        }
        if remaining == 1 {
            let known = KnownKeyFlags::from_bits(buf.read_u8()? as u16);
            return Ok(Self {
                known,
                rest: None,
                original_len: remaining,
            });
        }
        if remaining == 2 {
            let known = KnownKeyFlags::from_bits(buf.read_le_u16()?);
            return Ok(Self {
                known,
                rest: None,
                original_len: remaining,
            });
        }
        let known = KnownKeyFlags::from_bits(buf.read_le_u16()?);
        let rest = Some(buf.rest());
        Ok(Self {
            known,
            rest,
            original_len: remaining,
        })
    }

    pub fn set_certify(&mut self, val: bool) {
        self.known.set_certify(val);
    }
    pub fn set_encrypt_comms(&mut self, val: bool) {
        self.known.set_encrypt_comms(val);
    }
    pub fn set_encrypt_storage(&mut self, val: bool) {
        self.known.set_encrypt_storage(val);
    }
    pub fn set_sign(&mut self, val: bool) {
        self.known.set_sign(val);
    }
    pub fn set_shared(&mut self, val: bool) {
        self.known.set_shared(val);
    }
    pub fn set_authentication(&mut self, val: bool) {
        self.known.set_authentication(val);
    }
    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    pub fn set_draft_decrypt_forwarded(&mut self, val: bool) {
        self.known.set_draft_decrypt_forwarded(val);
    }
    pub fn set_group(&mut self, val: bool) {
        self.known.set_group(val);
    }

    pub fn set_adsk(&mut self, val: bool) {
        self.known.set_adsk(val);
    }

    pub fn set_timestamping(&mut self, val: bool) {
        self.known.set_timestamping(val);
    }

    pub fn certify(&self) -> bool {
        self.known.certify()
    }

    pub fn encrypt_comms(&self) -> bool {
        self.known.encrypt_comms()
    }

    pub fn encrypt_storage(&self) -> bool {
        self.known.encrypt_storage()
    }

    pub fn sign(&self) -> bool {
        self.known.sign()
    }

    pub fn shared(&self) -> bool {
        self.known.shared()
    }

    pub fn authentication(&self) -> bool {
        self.known.authentication()
    }

    pub fn draft_decrypt_forwarded(&self) -> bool {
        self.known.draft_decrypt_forwarded()
    }

    pub fn group(&self) -> bool {
        self.known.group()
    }

    pub fn adsk(&self) -> bool {
        self.known.adsk()
    }

    pub fn timestamping(&self) -> bool {
        self.known.timestamping()
    }
}

impl Serialize for KeyFlags {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        if self.original_len == 0 {
            return Ok(());
        }

        let [a, b] = self.known.into_bits().to_le_bytes();
        writer.write_u8(a)?;

        if self.original_len > 1 || b != 0 {
            writer.write_u8(b)?;
        }

        if let Some(ref rest) = self.rest {
            writer.write_all(rest)?;
        }
        Ok(())
    }

    fn write_len(&self) -> usize {
        if self.original_len == 0 {
            return 0;
        }
        let mut sum = 0;
        let [_, b] = self.known.into_bits().to_le_bytes();
        if self.original_len > 1 || b > 0 {
            sum += 2;
        } else {
            sum += 1;
        }

        if let Some(ref rest) = self.rest {
            sum += rest.len();
        }
        sum
    }
}

#[bitfield(u16, order = lsb)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct KnownKeyFlags {
    #[bits(1)]
    certify: bool,
    #[bits(1)]
    sign: bool,
    #[bits(1)]
    encrypt_comms: bool,
    #[bits(1)]
    encrypt_storage: bool,
    #[bits(1)]
    shared: bool,
    #[bits(1)]
    authentication: bool,
    #[bits(1)]
    draft_decrypt_forwarded: bool,
    #[bits(1)]
    group: bool,
    #[bits(2)]
    _padding1: u8,

    #[bits(1)]
    adsk: bool,
    #[bits(1)]
    timestamping: bool,
    #[bits(4)]
    _padding2: u8,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Features {
    first: Option<KnownFeatures>,

    rest: Vec<u8>,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            first: Some(KnownFeatures::default()),
            rest: vec![],
        }
    }
}

impl From<&[u8]> for Features {
    fn from(value: &[u8]) -> Self {
        match value.len() {
            0 => Self {
                first: None,
                rest: vec![],
            },
            _ => Self {
                first: Some(KnownFeatures(value[0])),
                rest: value[1..].to_vec(),
            },
        }
    }
}

impl From<&Features> for Vec<u8> {
    fn from(value: &Features) -> Self {
        let mut v = vec![];
        value.to_writer(&mut v).expect("vec");
        v
    }
}

impl From<KnownFeatures> for Features {
    fn from(value: KnownFeatures) -> Self {
        Self {
            first: Some(value),
            rest: vec![],
        }
    }
}

impl Features {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seipd_v1(&self) -> bool {
        match self.first {
            Some(k) => k.seipd_v1(),
            None => false,
        }
    }

    pub fn set_seipd_v1(&mut self, val: bool) {
        if self.first.is_none() {
            self.first = Some(KnownFeatures::default());
        }

        if let Some(k) = self.first.as_mut() {
            k.set_seipd_v1(val);
        }
    }

    pub fn seipd_v2(&self) -> bool {
        match self.first {
            Some(k) => k.seipd_v2(),
            None => false,
        }
    }

    pub fn set_seipd_v2(&mut self, val: bool) {
        if self.first.is_none() {
            self.first = Some(KnownFeatures::default());
        }

        if let Some(k) = self.first.as_mut() {
            k.set_seipd_v2(val);
        }
    }
}

impl Serialize for Features {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        if let Some(k) = self.first {
            writer.write_u8(k.0)?;
            writer.write_all(&self.rest)?;
        }

        Ok(())
    }

    fn write_len(&self) -> usize {
        if self.first.is_none() {
            0
        } else {
            1 + self.rest.len()
        }
    }
}

#[bitfield(u8)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct KnownFeatures {
    #[bits(1)]
    seipd_v1: bool,

    #[bits(1)]
    _libre_ocb: u8,

    #[bits(1)]
    _libre_v5_keys: u8,

    #[bits(1)]
    seipd_v2: bool,

    #[bits(4)]
    _padding: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Notation {
    pub readable: bool,
    pub name: Bytes,
    pub value: Bytes,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum RevocationCode {
    NoReason = 0,
    KeySuperseded = 1,
    KeyCompromised = 2,
    KeyRetired = 3,
    CertUserIdInvalid = 32,

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

impl PacketTrait for Signature {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

pub(super) fn serialize_for_hashing<K: KeyDetails + Serialize>(
    key: &K,
    hasher: &mut Box<dyn DynDigest + Send>,
) -> Result<()> {
    let key_len = key.write_len();

    let mut writer = WriteHasher(hasher);

    match key.version() {
        KeyVersion::V2 | KeyVersion::V3 | KeyVersion::V4 => {
            writer.write_u8(0x99)?;
            writer.write_u16::<BigEndian>(key_len.try_into()?)?;
        }

        KeyVersion::V6 => {
            writer.write_u8(0x9b)?;
            writer.write_u32::<BigEndian>(key_len.try_into()?)?;
        }

        v => unimplemented_err!("key version {:?}", v),
    }

    key.to_writer(&mut writer)?;

    Ok(())
}
