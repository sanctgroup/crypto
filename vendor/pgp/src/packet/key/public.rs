use std::io::BufRead;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use digest::generic_array::GenericArray;
use md5::Md5;
use rand::{CryptoRng, Rng};

use sha1_checked::Sha1;
use sha2::Sha256;

use crate::{
    crypto::{
        self,
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure, ensure_eq, unimplemented_err, unsupported_err, Result},
    packet::{
        KeyFlags, PacketHeader, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    },
    ser::Serialize,
    types::{
        EcdhPublicParams, EddsaLegacyPublicParams, EncryptionKey, EskType, Fingerprint, Imprint,
        KeyDetails, KeyId, KeyVersion, Mpi, Password, PkeskBytes, PublicParams, SignatureBytes,
        SigningKey, Tag, Timestamp, VerifyingKey,
    },
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKey {
    packet_header: PacketHeader,
    inner: PubKeyInner,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicSubkey {
    packet_header: PacketHeader,
    inner: PubKeyInner,
}

impl PublicKey {
    pub fn from_inner(inner: PubKeyInner) -> Result<Self> {
        let len = inner.write_len();
        let packet_header = PacketHeader::new_fixed(Tag::PublicKey, len.try_into()?);
        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub(super) fn from_inner_with_header(packet_header: PacketHeader, inner: PubKeyInner) -> Self {
        Self {
            packet_header,
            inner,
        }
    }

    pub fn new_with_header(
        packet_header: PacketHeader,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: Timestamp,
        legacy_v3_expiration_days: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(
            version,
            algorithm,
            created_at,
            legacy_v3_expiration_days,
            public_params,
        )?;

        if let Some(len) = packet_header.packet_length().maybe_len() {
            ensure_eq!(
                inner.write_len(),
                len as usize,
                "PublicKey: inconsisteng packet length"
            );
        }
        ensure_eq!(packet_header.tag(), Tag::PublicKey, "invalid tag");

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::PublicKey, "invalid tag");

        let inner = PubKeyInner::try_from_reader(input)?;

        Ok(Self {
            packet_header,
            inner,
        })
    }
}

impl EncryptionKey for PublicKey {
    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.inner, rng, plain, typ)
    }
}

impl PublicSubkey {
    pub fn from_inner(inner: PubKeyInner) -> Result<Self> {
        let len = inner.write_len();
        let packet_header = PacketHeader::new_fixed(Tag::PublicSubkey, len.try_into()?);

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn from_inner_with_header(packet_header: PacketHeader, inner: PubKeyInner) -> Result<Self> {
        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn new_with_header(
        packet_header: PacketHeader,
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: Timestamp,
        legacy_v3_expiration_days: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        let inner = PubKeyInner::new(
            version,
            algorithm,
            created_at,
            legacy_v3_expiration_days,
            public_params,
        )?;

        if let Some(len) = packet_header.packet_length().maybe_len() {
            ensure_eq!(
                inner.write_len(),
                len as usize,
                "PublicSubkey: inconsistent packet length"
            );
        }
        ensure_eq!(packet_header.tag(), Tag::PublicSubkey, "invalid tag");
        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(packet_header.tag(), Tag::PublicSubkey, "invalid tag");
        let inner = PubKeyInner::try_from_reader(input)?;

        Ok(Self {
            packet_header,
            inner,
        })
    }

    pub fn sign<R: CryptoRng + Rng, S, K>(
        &self,
        rng: R,
        primary_sec_key: &S,
        primary_pub_key: &K,
        key_pw: &Password,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
    ) -> Result<Signature>
    where
        S: SigningKey,
        K: KeyDetails + Serialize,
    {
        let mut config =
            SignatureConfig::from_key(rng, primary_sec_key, SignatureType::SubkeyBinding)?;

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                primary_sec_key.fingerprint(),
            ))?,
        ];

        if let Some(embedded) = embedded {
            config
                .hashed_subpackets
                .push(Subpacket::regular(SubpacketData::EmbeddedSignature(
                    Box::new(embedded),
                ))?)
        }

        if primary_sec_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                primary_sec_key.legacy_key_id(),
            ))?];
        }

        config.sign_subkey_binding(primary_sec_key, primary_pub_key, key_pw, &self)
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    pub fn is_forwardee_key(&self) -> bool {
        self.inner.is_forwardee_key()
    }
}

impl EncryptionKey for PublicSubkey {
    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        encrypt(&self.inner, rng, plain, typ)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[doc(hidden)]
pub struct PubKeyInner {
    version: KeyVersion,
    algorithm: PublicKeyAlgorithm,
    created_at: Timestamp,
    legacy_v3_expiration_days: Option<u16>,
    public_params: PublicParams,
}

impl PubKeyInner {
    fn try_from_reader<B: BufRead>(input: B) -> Result<Self> {
        let details = crate::packet::public_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params) = details;

        Self::new(version, algorithm, created_at, expiration, public_params)
    }

    pub fn new(
        version: KeyVersion,
        algorithm: PublicKeyAlgorithm,
        created_at: Timestamp,
        legacy_v3_expiration_days: Option<u16>,
        public_params: PublicParams,
    ) -> Result<Self> {
        if (version == KeyVersion::V2 || version == KeyVersion::V3)
            && !(algorithm == PublicKeyAlgorithm::RSA
                || algorithm == PublicKeyAlgorithm::RSAEncrypt
                || algorithm == PublicKeyAlgorithm::RSASign)
        {
            unsupported_err!(
                "Invalid algorithm {:?} for key version: {:?}",
                algorithm,
                version,
            );
        }

        if version != KeyVersion::V4 {
            if matches!(
                public_params,
                PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { .. })
            ) {
                bail!(
                    "ECDH over Curve25519 is illegal for key version {}",
                    u8::from(version)
                );
            }

            if matches!(public_params, PublicParams::EdDSALegacy { .. }) {
                bail!(
                    "EdDSALegacy is illegal for key version {}",
                    u8::from(version)
                );
            }
        }

        Ok(Self {
            version,
            algorithm,
            created_at,
            legacy_v3_expiration_days,
            public_params,
        })
    }

    fn to_writer_v2_v3<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        self.created_at.to_writer(writer)?;
        writer.write_u16::<BigEndian>(
            self.legacy_v3_expiration_days
                .expect("old key versions have an expiration"),
        )?;
        writer.write_u8(self.algorithm.into())?;
        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn writer_len_v2_v3(&self) -> usize {
        let mut sum = 4 + 2 + 1;
        sum += self.public_params.write_len();
        sum
    }

    fn to_writer_v4_v6<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        use crate::ser::Serialize;

        self.created_at.to_writer(writer)?;
        writer.write_u8(self.algorithm.into())?;

        if self.version == KeyVersion::V6 {
            writer.write_u32::<BigEndian>(self.public_params.write_len().try_into()?)?;
        }

        self.public_params.to_writer(writer)?;

        Ok(())
    }

    fn writer_len_v4_v6(&self) -> usize {
        let mut sum = 4 + 1;

        if self.version == KeyVersion::V6 {
            sum += 4;
        }
        sum += self.public_params.write_len();

        sum
    }

    #[allow(dead_code)]

    fn sign<R: CryptoRng + Rng, S>(
        &self,
        mut rng: R,
        key: &S,
        key_pw: &Password,
        sig_type: SignatureType,
    ) -> Result<Signature>
    where
        S: SigningKey + Serialize,
    {
        let mut config = SignatureConfig::from_key(&mut rng, key, sig_type)?;
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
        ];
        if key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                key.legacy_key_id(),
            ))?];
        }

        config.sign_key(key, key_pw, &self)
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    fn is_forwardee_key(&self) -> bool {
        match self.public_params {
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { ecdh_kdf_type, .. }) => {
                matches!(ecdh_kdf_type, crate::types::EcdhKdfType::Replaced { .. })
            }
            _ => false,
        }
    }
}

pub(crate) fn encrypt<R: rand::CryptoRng + rand::Rng, K: KeyDetails>(
    key: &K,
    mut rng: R,
    plain: &[u8],
    typ: EskType,
) -> Result<PkeskBytes> {
    match key.public_params() {
        PublicParams::EdDSALegacy { .. } => bail!("EdDSALegacy is only used for signing"),
        PublicParams::Ed25519 { .. } => bail!("Ed25519 is only used for signing"),

        PublicParams::ECDH(ref params) => match params {
            EcdhPublicParams::Unsupported { ref curve, .. } => {
                unsupported_err!("ECDH over curve {:?} is unsupported", curve)
            }
            _ => {
                if key.version() == KeyVersion::V6 {
                    let curve = params.curve();
                    match params {
                        EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. } => {
                            if curve.hash_algo()? != *hash || curve.sym_algo()? != *alg_sym {
                                bail!(
                                    "Unsupported KDF/KEK parameters for {:?} and KeyVersion::V6: {:?}, {:?}",
                                    curve,
                                    hash,
                                    alg_sym
                                );
                            }
                        }
                        _ => unsupported_err!("{:?} for ECDH", params),
                    }
                }

                crypto::ecdh::encrypt(rng, params, key.fingerprint().as_bytes(), plain)
            }
        },
        PublicParams::X25519(ref params) => {
            let (sym_alg, plain) = match typ {
                EskType::V6 => (None, plain),
                EskType::V3_4 => {
                    ensure!(!plain.is_empty(), "plain may not be empty");

                    (Some(plain[0].into()), &plain[1..])
                }
            };

            let (ephemeral, session_key) = crypto::x25519::encrypt(&mut rng, &params.key, plain)?;

            Ok(PkeskBytes::X25519 {
                ephemeral,
                session_key: session_key.into(),
                sym_alg,
            })
        }

        PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
        PublicParams::DSA { .. } => bail!("DSA is only used for signing"),

        PublicParams::Unknown { .. } => bail!("Unknown algorithm"),
    }
}

impl crate::ser::Serialize for PublicKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.inner.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        self.inner.write_len()
    }
}

impl crate::ser::Serialize for PublicSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        self.inner.to_writer(writer)
    }

    fn write_len(&self) -> usize {
        self.inner.write_len()
    }
}

impl crate::ser::Serialize for PubKeyInner {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.version.into())?;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => self.to_writer_v2_v3(writer),
            KeyVersion::V4 | KeyVersion::V6 => self.to_writer_v4_v6(writer),
            KeyVersion::V5 => unimplemented_err!("V5 keys"),
            KeyVersion::Other(v) => {
                unimplemented_err!("Unsupported key version {}", v)
            }
        }
    }

    fn write_len(&self) -> usize {
        let mut sum = 1;
        sum += match self.version {
            KeyVersion::V2 | KeyVersion::V3 => self.writer_len_v2_v3(),
            KeyVersion::V4 | KeyVersion::V6 => self.writer_len_v4_v6(),
            KeyVersion::V5 => panic!("V5 keys"),
            KeyVersion::Other(v) => {
                panic!("Unsupported key version {v}")
            }
        };
        sum
    }
}

impl crate::packet::PacketTrait for PublicKey {
    fn packet_header(&self) -> &crate::packet::PacketHeader {
        &self.packet_header
    }
}

impl crate::packet::PacketTrait for PublicSubkey {
    fn packet_header(&self) -> &crate::packet::PacketHeader {
        &self.packet_header
    }
}

impl PubKeyInner {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        let mut hasher = D::new();

        use crate::ser::Serialize;

        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => {
                let mut v: Vec<u8> = Vec::new();
                self.public_params.to_writer(&mut v)?;

                hasher.update(&v);

                Ok(hasher.finalize())
            }
            KeyVersion::V4 => {
                hasher.update([0x99]);

                let mut packet = vec![4, 0, 0, 0, 0];

                BigEndian::write_u32(&mut packet[1..5], self.created_at.as_secs());

                packet.push(self.algorithm.into());

                self.public_params.to_writer(&mut packet)?;

                hasher.update((packet.len() as u16).to_be_bytes());
                hasher.update(&packet);

                Ok(hasher.finalize())
            }
            KeyVersion::V5 => unsupported_err!("Imprint for V5 keys"),
            KeyVersion::V6 => {
                hasher.update([0x9B]);

                let len = self.public_params.write_len() as u32;

                let total_len: u32 = 1 + 4 + 1 + 4 + len;
                hasher.update(total_len.to_be_bytes());

                hasher.update([0x06]);

                hasher.update(self.created_at.as_secs().to_be_bytes());

                hasher.update([self.algorithm.into()]);

                hasher.update(len.to_be_bytes());

                let mut pp: Vec<u8> = vec![];
                self.public_params.to_writer(&mut pp)?;
                hasher.update(&pp);

                Ok(hasher.finalize())
            }
            KeyVersion::Other(v) => unsupported_err!("Imprint for {} keys", v),
        }
    }
}

impl KeyDetails for PubKeyInner {
    fn version(&self) -> KeyVersion {
        self.version
    }

    fn fingerprint(&self) -> Fingerprint {
        match self.version {
            KeyVersion::V2 => Fingerprint::V2(
                self.imprint::<Md5>()
                    .expect("failure is not an option")
                    .into(),
            ),
            KeyVersion::V3 => Fingerprint::V3(
                self.imprint::<Md5>()
                    .expect("failure is not an option")
                    .into(),
            ),
            KeyVersion::V4 => Fingerprint::V4(
                self.imprint::<Sha1>()
                    .expect("failure is not an option")
                    .into(),
            ),
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::V6 => Fingerprint::V6(
                self.imprint::<Sha256>()
                    .expect("failure is not an option")
                    .into(),
            ),
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self.version {
            KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
                _ => panic!("invalid key constructed: {:?}", self.public_params),
            },
            KeyVersion::V4 => {
                let f = self.fingerprint();
                let offset = f.len() - 8;
                let raw: [u8; 8] = f.as_bytes()[offset..].try_into().expect("fixed size");
                raw.into()
            }
            KeyVersion::V5 => unimplemented!("V5 keys"),
            KeyVersion::V6 => {
                let f = self.fingerprint();
                let raw: [u8; 8] = f.as_bytes()[0..8].try_into().expect("fixed size");
                raw.into()
            }
            KeyVersion::Other(v) => unimplemented!("Unsupported key version {}", v),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.legacy_v3_expiration_days
    }

    fn created_at(&self) -> Timestamp {
        self.created_at
    }

    fn public_params(&self) -> &PublicParams {
        &self.public_params
    }
}

impl VerifyingKey for PubKeyInner {
    fn verify(&self, hash: HashAlgorithm, hashed: &[u8], sig: &SignatureBytes) -> Result<()> {
        match self.public_params {
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { .. }) => {
                bail!("ECDH cannot verify signatures");
            }
            PublicParams::EdDSALegacy(ref params) => match params {
                EddsaLegacyPublicParams::Ed25519 { ref key } => {
                    let sig: &[Mpi] = sig.try_into()?;

                    ensure_eq!(sig.len(), 2);

                    let r = sig[0].as_ref();
                    let s = sig[1].as_ref();

                    ensure!(r.len() < 33, "invalid R (len)");
                    ensure!(s.len() < 33, "invalid S (len)");

                    let mut sig_bytes = vec![0u8; 64];

                    sig_bytes[(32 - r.len())..32].copy_from_slice(r);
                    sig_bytes[32 + (32 - s.len())..].copy_from_slice(s);

                    crypto::ed25519::verify(key, hash, hashed, &sig_bytes)
                }
                EddsaLegacyPublicParams::Unsupported { curve, .. } => {
                    unsupported_err!("curve {:?} for EdDSA", curve.to_string());
                }
            },
            PublicParams::Ed25519(ref params) => {
                crypto::ed25519::verify(&params.key, hash, hashed, sig.try_into()?)
            }

            PublicParams::X25519 { .. } => {
                bail!("X25519 can not be used for verify operations");
            }

            PublicParams::ECDH(
                EcdhPublicParams::Brainpool256 { .. }
                | EcdhPublicParams::Brainpool384 { .. }
                | EcdhPublicParams::Brainpool512 { .. },
            ) => {
                bail!("ECDH (unsupported: brainpool) can not be used for verify operations");
            }
            PublicParams::ECDH(EcdhPublicParams::Unsupported { ref curve, .. }) => {
                bail!(
                    "ECDH (unsupported: {:?}) can not be used for verify operations",
                    curve,
                );
            }
            PublicParams::Elgamal { .. } => {
                unimplemented_err!("verify Elgamal");
            }
            PublicParams::DSA(ref params) => {
                let sig: &[Mpi] = sig.try_into()?;
                ensure_eq!(sig.len(), 2, "invalid signature");

                crypto::dsa::verify(params, hashed, sig[0].clone().into(), sig[1].clone().into())
            }
            PublicParams::Unknown { .. } => {
                unimplemented_err!("PublicParams::Unknown can not be used for verify operations");
            }
        }
    }
}

impl KeyDetails for PublicKey {
    fn version(&self) -> KeyVersion {
        self.inner.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.inner.legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.inner.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.inner.created_at
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.inner.legacy_v3_expiration_days
    }

    fn public_params(&self) -> &PublicParams {
        self.inner.public_params()
    }
}

impl Imprint for PublicKey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.inner.imprint::<D>()
    }
}

impl VerifyingKey for PublicKey {
    fn verify(&self, hash: HashAlgorithm, hashed: &[u8], sig: &SignatureBytes) -> Result<()> {
        self.inner.verify(hash, hashed, sig)
    }
}

impl KeyDetails for PublicSubkey {
    fn version(&self) -> KeyVersion {
        self.inner.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.inner.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.inner.legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.inner.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.inner.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.inner.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.inner.public_params()
    }
}

impl Imprint for PublicSubkey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.inner.imprint::<D>()
    }
}

impl VerifyingKey for PublicSubkey {
    fn verify(&self, hash: HashAlgorithm, hashed: &[u8], sig: &SignatureBytes) -> Result<()> {
        VerifyingKey::verify(&self.inner, hash, hashed, sig)
    }
}
