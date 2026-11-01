use std::io::Read;

use byteorder::{BigEndian, ByteOrder};
use digest::DynDigest;
use log::debug;
use rand::{CryptoRng, Rng};

use crate::{
    crypto::{
        hash::{HashAlgorithm, WriteHasher},
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure, unimplemented_err, unsupported_err, Result},
    packet::{
        types::serialize_for_hashing, Signature, SignatureType, SignatureVersion, Subpacket,
        SubpacketData, SubpacketType,
    },
    ser::Serialize,
    types::{Fingerprint, KeyDetails, KeyId, KeyVersion, Password, SigningKey, Tag, Timestamp},
    util::NormalizingHasher,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignatureConfig {
    pub typ: SignatureType,
    pub pub_alg: PublicKeyAlgorithm,
    pub hash_alg: HashAlgorithm,

    pub unhashed_subpackets: Vec<Subpacket>,
    pub hashed_subpackets: Vec<Subpacket>,

    pub version_specific: SignatureVersionSpecific,
}

#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
pub enum SignatureVersionSpecific {
    V2 {
        created: Timestamp,
        issuer_key_id: KeyId,
    },
    V3 {
        created: Timestamp,
        issuer_key_id: KeyId,
    },
    V4,
    V6 {
        #[debug("{}", hex::encode(salt))]
        salt: Vec<u8>,
    },
}

impl From<&SignatureVersionSpecific> for SignatureVersion {
    fn from(value: &SignatureVersionSpecific) -> Self {
        match value {
            SignatureVersionSpecific::V2 { .. } => SignatureVersion::V2,
            SignatureVersionSpecific::V3 { .. } => SignatureVersion::V3,
            SignatureVersionSpecific::V4 => SignatureVersion::V4,
            SignatureVersionSpecific::V6 { .. } => SignatureVersion::V6,
        }
    }
}

impl SignatureConfig {
    pub fn from_key<R: CryptoRng + Rng, S: SigningKey>(
        mut rng: R,
        key: &S,
        typ: SignatureType,
    ) -> Result<Self> {
        match key.version() {
            KeyVersion::V4 => Ok(SignatureConfig::v4(typ, key.algorithm(), key.hash_alg())),
            KeyVersion::V6 => SignatureConfig::v6(&mut rng, typ, key.algorithm(), key.hash_alg()),
            v => unsupported_err!("unsupported key version: {:?}", v),
        }
    }

    pub fn v2(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: Timestamp,
        issuer_key_id: KeyId,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V2 {
                created,
                issuer_key_id,
            },
        }
    }

    pub fn v3(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        created: Timestamp,
        issuer_key_id: KeyId,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            hashed_subpackets: Vec::new(),
            unhashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V3 {
                created,
                issuer_key_id,
            },
        }
    }

    pub fn v4(typ: SignatureType, pub_alg: PublicKeyAlgorithm, hash_alg: HashAlgorithm) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![],
            version_specific: SignatureVersionSpecific::V4,
        }
    }

    fn v6_salt_for<R: CryptoRng + Rng>(mut rng: R, hash_alg: HashAlgorithm) -> Result<Vec<u8>> {
        let Some(salt_len) = hash_alg.salt_len() else {
            bail!("Unknown v6 signature salt length for hash algorithm {hash_alg:?}");
        };

        let mut salt = vec![0; salt_len];
        rng.fill_bytes(&mut salt);

        Ok(salt)
    }

    pub fn v6<R: CryptoRng + Rng>(
        rng: R,
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
    ) -> Result<Self> {
        Ok(Self::v6_with_salt(
            typ,
            pub_alg,
            hash_alg,
            Self::v6_salt_for(rng, hash_alg)?,
        ))
    }

    pub fn v6_with_salt(
        typ: SignatureType,
        pub_alg: PublicKeyAlgorithm,
        hash_alg: HashAlgorithm,
        salt: Vec<u8>,
    ) -> Self {
        Self {
            typ,
            pub_alg,
            hash_alg,
            unhashed_subpackets: Vec::new(),
            hashed_subpackets: Vec::new(),
            version_specific: SignatureVersionSpecific::V6 { salt },
        }
    }

    pub fn version(&self) -> SignatureVersion {
        (&self.version_specific).into()
    }

    pub fn sign<R>(self, key: &impl SigningKey, key_pw: &Password, mut data: R) -> Result<Signature>
    where
        R: Read,
    {
        let mut hasher = self.into_hasher()?;
        std::io::copy(&mut data, &mut hasher)?;

        hasher.sign(key, key_pw)
    }

    pub fn into_hasher(self) -> Result<SignatureHasher> {
        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        let text_mode = self.typ == SignatureType::Text;
        let norm_hasher = NormalizingHasher::new(hasher, text_mode);

        Ok(SignatureHasher {
            norm_hasher,
            config: self,
        })
    }

    pub fn sign_certification<S, K>(
        self,
        key: &S,
        pub_key: &K,
        key_pw: &Password,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        S: SigningKey,
        K: KeyDetails + Serialize,
    {
        self.sign_certification_third_party(key, key_pw, pub_key, tag, id)
    }

    pub fn sign_certification_third_party<K>(
        self,
        signer: &impl SigningKey,
        signer_pw: &Password,
        signee: &K,
        tag: Tag,
        id: &impl Serialize,
    ) -> Result<Signature>
    where
        K: KeyDetails + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        ensure!(
            self.is_certification(),
            "can not sign non certification as certification"
        );

        debug!("signing certification {:#?}", self.typ);

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?;

        let mut packet_buf = Vec::new();
        id.to_writer(&mut packet_buf)?;

        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {}
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let prefix = match tag {
                    Tag::UserId => 0xB4,
                    Tag::UserAttribute => 0xD1,
                    _ => bail!("invalid tag for certification signature: {:?}", tag),
                };

                let mut prefix_buf = [prefix, 0u8, 0u8, 0u8, 0u8];
                BigEndian::write_u32(&mut prefix_buf[1..], packet_buf.len().try_into()?);

                hasher.update(&prefix_buf);
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported sign tps")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }

        hasher.update(&packet_buf);

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.sign(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    pub fn sign_subkey_binding<S, K1, K2>(
        self,
        signer: &S,
        signer_pub: &K1,
        signer_pw: &Password,
        signee: &K2,
    ) -> Result<Signature>
    where
        S: SigningKey,
        K1: KeyDetails + Serialize,
        K2: KeyDetails + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        debug!("signing subkey binding: {self:#?} - {signer:#?} - {signee:#?}");

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signer_pub, &mut hasher)?;
        serialize_for_hashing(signee, &mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.sign(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    pub fn sign_primary_key_binding<S, K1, K2>(
        self,
        signer: &S,
        signer_pub: &K1,
        signer_pw: &Password,
        signee: &K2,
    ) -> Result<Signature>
    where
        S: SigningKey,
        K1: KeyDetails + Serialize,
        K2: KeyDetails + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signer.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6 && signer.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signer.version()
        );
        debug!("signing primary key binding: {self:#?} - {signer:#?} - {signee:#?}");

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(signee, &mut hasher)?;
        serialize_for_hashing(signer_pub, &mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signer.sign(signer_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    pub fn sign_key<S, K>(self, signing_key: &S, key_pw: &Password, key: &K) -> Result<Signature>
    where
        S: SigningKey,
        K: KeyDetails + Serialize,
    {
        ensure!(
            (self.version() == SignatureVersion::V4 && signing_key.version() == KeyVersion::V4)
                || (self.version() == SignatureVersion::V6
                    && signing_key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            self.version(),
            signing_key.version()
        );
        debug!("signing key ({:?}): {self:#?} - {key:#?}", self.typ);

        ensure!(
            [SignatureType::Key, SignatureType::KeyRevocation].contains(&self.typ),
            "signature type must be suitable for direct signatures"
        );

        let mut hasher = self.hash_alg.new_hasher()?;

        if let SignatureVersionSpecific::V6 { salt } = &self.version_specific {
            hasher.update(salt.as_ref())
        }

        serialize_for_hashing(key, &mut hasher)?;

        let len = self.hash_signature_data(&mut hasher)?;
        hasher.update(&self.trailer(len)?);

        let hash = &hasher.finalize()[..];
        let signed_hash_value = [hash[0], hash[1]];
        let signature = signing_key.sign(key_pw, self.hash_alg, hash)?;

        Signature::from_config(self, signed_hash_value, signature)
    }

    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    pub fn hash_signature_data(&self, hasher: &mut Box<dyn DynDigest + Send>) -> Result<usize> {
        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                let created = {
                    if let SignatureVersionSpecific::V2 { created, .. }
                    | SignatureVersionSpecific::V3 { created, .. } = self.version_specific
                    {
                        created
                    } else {
                        bail!("must exist for a v2/3 signature")
                    }
                };

                let mut buf = [0u8; 5];
                buf[0] = self.typ.into();
                BigEndian::write_u32(&mut buf[1..], created.as_secs());

                hasher.update(&buf);

                Ok(0)
            }
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut res = vec![
                    self.version().into(),
                    self.typ.into(),
                    self.pub_alg.into(),
                    self.hash_alg.into(),
                ];

                let mut hashed_subpackets = Vec::new();
                for packet in &self.hashed_subpackets {
                    debug!("hashing {packet:#?}");

                    if packet.is_critical && matches!(packet.typ(), SubpacketType::Other(_)) {
                        bail!("Unknown critical subpacket {:?}", packet);
                    }

                    if let SubpacketData::IssuerFingerprint(fp) = &packet.data {
                        match (self.version(), fp.version()) {
                            (SignatureVersion::V6, Some(KeyVersion::V6)) => {}
                            (SignatureVersion::V4, Some(KeyVersion::V4)) => {}
                            _ => bail!(
                                "IntendedRecipientFingerprint {:?} doesn't match signature version {:?}",
                                fp,
                                self.version()
                            ),
                        }
                    }

                    packet.to_writer(&mut hashed_subpackets)?;
                }

                if self.version() == SignatureVersion::V4 {
                    res.extend(u16::try_from(hashed_subpackets.len())?.to_be_bytes());
                } else if self.version() == SignatureVersion::V6 {
                    res.extend(u32::try_from(hashed_subpackets.len())?.to_be_bytes());
                }

                res.extend(hashed_subpackets);

                hasher.update(&res);

                Ok(res.len())
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported hash data")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    pub fn hash_data_to_sign<R>(
        &self,
        hasher: &mut Box<dyn DynDigest + Send>,
        mut data: R,
    ) -> Result<usize>
    where
        R: Read,
    {
        match self.typ {
            SignatureType::Text | SignatureType::Binary => {
                let written = std::io::copy(&mut data, &mut WriteHasher(hasher))?;
                Ok(written.try_into()?)
            }
            SignatureType::Timestamp | SignatureType::Standalone => {
                let mut val = [0u8; 1];
                data.read_exact(&mut val[..])?;
                hasher.update(&val[..]);
                Ok(1)
            }
            SignatureType::CertGeneric
            | SignatureType::CertPersona
            | SignatureType::CertCasual
            | SignatureType::CertPositive
            | SignatureType::CertRevocation => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::SubkeyBinding
            | SignatureType::SubkeyRevocation
            | SignatureType::KeyBinding
            | SignatureType::Key => {
                unimplemented_err!("{:?}", self.typ);
            }
            SignatureType::KeyRevocation => unimplemented_err!("KeyRevocation"),
            SignatureType::ThirdParty => unimplemented_err!("signing ThirdParty"),

            SignatureType::Other(id) => unimplemented_err!("Other ({})", id),
        }
    }

    pub fn trailer(&self, len: usize) -> Result<Vec<u8>> {
        match self.version() {
            SignatureVersion::V2 | SignatureVersion::V3 => Ok(Vec::new()),
            SignatureVersion::V4 | SignatureVersion::V6 => {
                let mut trailer = vec![self.version().into(), 0xFF, 0, 0, 0, 0];
                BigEndian::write_u32(&mut trailer[2..], len.try_into()?);
                Ok(trailer)
            }
            SignatureVersion::V5 => {
                bail!("v5 signature unsupported")
            }
            SignatureVersion::Other(version) => {
                bail!("unsupported signature version {}", version)
            }
        }
    }

    #[deprecated(
        note = "Usually only hashed_subpackets should be used. unhashed_subpackets are only safe and useful to access in rare circumstances. When they are needed, unhashed_subpackets should be explicitly called."
    )]
    pub fn subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets().chain(self.unhashed_subpackets())
    }

    pub fn hashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.hashed_subpackets.iter()
    }

    pub fn unhashed_subpackets(&self) -> impl Iterator<Item = &Subpacket> {
        self.unhashed_subpackets.iter()
    }

    pub fn is_certification(&self) -> bool {
        matches!(
            self.typ,
            SignatureType::CertGeneric
                | SignatureType::CertPersona
                | SignatureType::CertCasual
                | SignatureType::CertPositive
                | SignatureType::CertRevocation
        )
    }

    pub fn created(&self) -> Option<Timestamp> {
        if let SignatureVersionSpecific::V2 { created, .. }
        | SignatureVersionSpecific::V3 { created, .. } = &self.version_specific
        {
            return Some(*created);
        }

        self.hashed_subpackets().find_map(|p| match p.data {
            SubpacketData::SignatureCreationTime(d) => Some(d),
            _ => None,
        })
    }

    pub fn issuer_key_id(&self) -> Vec<&KeyId> {
        if let SignatureVersionSpecific::V2 { issuer_key_id, .. }
        | SignatureVersionSpecific::V3 { issuer_key_id, .. } = &self.version_specific
        {
            return vec![issuer_key_id];
        }

        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match sp.data {
                SubpacketData::IssuerKeyId(ref id) => Some(id),
                _ => None,
            })
            .collect()
    }

    pub fn issuer_fingerprint(&self) -> Vec<&Fingerprint> {
        self.hashed_subpackets()
            .chain(self.unhashed_subpackets())
            .filter_map(|sp| match &sp.data {
                SubpacketData::IssuerFingerprint(fp) => Some(fp),
                _ => None,
            })
            .collect()
    }
}

pub struct SignatureHasher {
    norm_hasher: NormalizingHasher,
    config: SignatureConfig,
}

impl SignatureHasher {
    pub fn sign<S>(self, key: &S, key_pw: &Password) -> Result<Signature>
    where
        S: SigningKey + ?Sized,
    {
        let Self {
            config,
            norm_hasher,
        } = self;

        let mut hasher = norm_hasher.done();

        ensure!(
            (config.version() == SignatureVersion::V4 && key.version() == KeyVersion::V4)
                || (config.version() == SignatureVersion::V6 && key.version() == KeyVersion::V6),
            "signature version {:?} not allowed for signer key version {:?}",
            config.version(),
            key.version()
        );
        ensure!(
            matches!(config.typ, SignatureType::Binary | SignatureType::Text),
            "incompatible signature type {:?}",
            config.typ
        );

        Signature::check_signature_hash_strength(&config)?;

        let len = config.hash_signature_data(&mut hasher)?;
        let trailer = config.trailer(len)?;
        hasher.update(&trailer);

        let hash = &hasher.finalize()[..];

        let signed_hash_value = [hash[0], hash[1]];
        let signature = key.sign(key_pw, config.hash_alg, hash)?;

        Signature::from_config(config, signed_hash_value, signature)
    }

    pub(crate) fn update(&mut self, buf: &[u8]) {
        self.norm_hasher.hash_buf(buf);
    }
}

impl std::io::Write for SignatureHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.norm_hasher.hash_buf(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
