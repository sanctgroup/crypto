use std::io::BufRead;

use generic_array::GenericArray;
use log::debug;
use rand::{CryptoRng, Rng};

use super::public::PubKeyInner;
use crate::{
    composed::PlainSessionKey,
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::{bail, ensure_eq, unsupported_err, Result},
    packet::{
        KeyFlags, PacketHeader, PacketTrait, Signature, SignatureConfig, SignatureType, Subpacket,
        SubpacketData,
    },
    ser::Serialize,
    types::{
        DecryptionKey, EddsaLegacyPublicParams, EskType, Fingerprint, Imprint, KeyDetails, KeyId,
        KeyVersion, Password, PkeskBytes, PlainSecretParams, PublicParams, SecretParams,
        SignatureBytes, SigningKey, Tag, Timestamp,
    },
};

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: super::PublicKey,
    secret_params: SecretParams,
}

#[derive(Debug, PartialEq, Eq, Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretSubkey {
    #[zeroize(skip)]
    packet_header: PacketHeader,
    #[zeroize(skip)]
    details: super::PublicSubkey,
    secret_params: SecretParams,
}

impl SecretKey {
    pub fn new(details: super::PublicKey, secret_params: SecretParams) -> Result<Self> {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretKey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretKey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;

        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;
        let len = inner.write_len();

        let pub_packet_header = PacketHeader::from_parts(
            packet_header.version(),
            Tag::PublicKey,
            crate::types::PacketLength::Fixed(len.try_into()?),
        )?;

        let details = super::PublicKey::from_inner_with_header(pub_packet_header, inner);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    pub fn has_sha1_checksum(&self) -> bool {
        self.secret_params.has_sha1_checksum()
    }

    pub fn unlock<G, T>(&self, pw: &Password, work: G) -> Result<Result<T>>
    where
        G: FnOnce(&PublicParams, &PlainSecretParams) -> Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => Ok(work(pub_params, k)),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                Ok(work(pub_params, &plain))
            }
        }
    }

    pub fn public_key(&self) -> &super::PublicKey {
        &self.details
    }
}

impl SecretSubkey {
    pub fn new(details: super::PublicSubkey, secret_params: SecretParams) -> Result<Self> {
        let len =
            crate::ser::Serialize::write_len(&details) + secret_params.write_len(details.version());
        let packet_header = PacketHeader::new_fixed(Tag::SecretSubkey, len.try_into()?);

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn try_from_reader<B: BufRead>(packet_header: PacketHeader, input: B) -> Result<Self> {
        ensure_eq!(Tag::SecretSubkey, packet_header.tag(), "invalid tag");

        let details = crate::packet::secret_key_parser::parse(input)?;
        let (version, algorithm, created_at, expiration, public_params, secret_params) = details;
        let inner = PubKeyInner::new(version, algorithm, created_at, expiration, public_params)?;
        let len = inner.write_len();

        let pub_packet_header = PacketHeader::from_parts(
            packet_header.version(),
            Tag::PublicSubkey,
            crate::types::PacketLength::Fixed(len.try_into()?),
        )?;

        let details = super::PublicSubkey::from_inner_with_header(pub_packet_header, inner)?;

        Ok(Self {
            packet_header,
            details,
            secret_params,
        })
    }

    pub fn secret_params(&self) -> &SecretParams {
        &self.secret_params
    }

    pub fn has_sha1_checksum(&self) -> bool {
        self.secret_params.has_sha1_checksum()
    }

    pub fn sign_primary_key_binding<R: CryptoRng + Rng, K>(
        &self,
        rng: R,
        pub_key: &K,
        key_pw: &Password,
    ) -> Result<Signature>
    where
        K: KeyDetails + Serialize,
    {
        let mut config = SignatureConfig::from_key(rng, self, SignatureType::KeyBinding)?;

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(self.fingerprint()))?,
        ];

        if self.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                self.legacy_key_id(),
            ))?];
        }

        config.sign_primary_key_binding(self, &self.public_key(), key_pw, &pub_key)
    }

    pub fn unlock<G, T>(&self, pw: &Password, work: G) -> Result<Result<T>>
    where
        G: FnOnce(&PublicParams, &PlainSecretParams) -> Result<T>,
    {
        let pub_params = self.details.public_params();
        match self.secret_params {
            SecretParams::Plain(ref k) => Ok(work(pub_params, k)),
            SecretParams::Encrypted(ref k) => {
                let plain = k.unlock(pw, &self.details, Some(self.packet_header.tag()))?;
                Ok(work(pub_params, &plain))
            }
        }
    }

    pub fn public_key(&self) -> &super::PublicSubkey {
        &self.details
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    pub fn generate_proxy_parameter(
        &self,
        forwardee: &SecretSubkey,
        password_recipient: &Password,
        password_forwardee: &Password,
    ) -> Result<crate::types::ForwardingProxyParameter> {
        self.unlock(
            password_recipient,
            |_, unlocked_recipient| match unlocked_recipient {
                PlainSecretParams::ECDH(crate::crypto::ecdh::SecretKey::Curve25519Legacy(r)) => {
                    forwardee.unlock(password_forwardee, |_, unlocked_forwardee| {
                        match unlocked_forwardee {
                            PlainSecretParams::ECDH(
                                crate::crypto::ecdh::SecretKey::Curve25519Legacy(f),
                            ) => Self::compute_proxy_parameter(
                                zeroize::Zeroizing::new(r.to_bytes_rev()),
                                zeroize::Zeroizing::new(f.to_bytes_rev()),
                            ),
                            _ => bail!("Only ECDH/Curve 25519 forwardee keys are supported"),
                        }
                    })?
                }
                _ => bail!("Only ECDH/Curve 25519 recipient keys are supported"),
            },
        )?
    }

    #[cfg(feature = "draft-wussler-openpgp-forwarding")]
    fn compute_proxy_parameter(
        mut db: zeroize::Zeroizing<[u8; 32]>,
        mut dc: zeroize::Zeroizing<[u8; 32]>,
    ) -> Result<crate::types::ForwardingProxyParameter> {
        use zeroize::Zeroizing;

        db.reverse();
        dc.reverse();

        let recipient = Zeroizing::new(curve25519_dalek::Scalar::from_bytes_mod_order(
            *Zeroizing::new(curve25519_dalek::scalar::clamp_integer(*db)),
        ));
        let forwardee = Zeroizing::new(curve25519_dalek::Scalar::from_bytes_mod_order(
            *Zeroizing::new(curve25519_dalek::scalar::clamp_integer(*dc)),
        ));

        if forwardee.ct_eq(&curve25519_dalek::Scalar::ZERO).into() {
            bail!("Forwardee private key is zero");
        }

        let forwardee_inverted = Zeroizing::new(forwardee.invert());

        let k = Zeroizing::new((*recipient) * (*forwardee_inverted));

        Ok(k.to_bytes().into())
    }
}

impl SigningKey for SecretKey {
    fn sign(&self, key_pw: &Password, hash: HashAlgorithm, data: &[u8]) -> Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            let sig = create_signature(pub_params, priv_key, hash, data)?;
            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl KeyDetails for SecretKey {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.details.legacy_key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.details.legacy_v3_expiration_days()
    }

    fn created_at(&self) -> Timestamp {
        self.details.created_at()
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

impl Imprint for SecretKey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.details.imprint::<D>()
    }
}

impl KeyDetails for SecretSubkey {
    fn version(&self) -> KeyVersion {
        self.details.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.details.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.details.legacy_key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.details.algorithm()
    }
    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.details.legacy_v3_expiration_days()
    }

    fn created_at(&self) -> Timestamp {
        self.details.created_at()
    }

    fn public_params(&self) -> &PublicParams {
        self.details.public_params()
    }
}

impl Imprint for SecretSubkey {
    fn imprint<D: KnownDigest>(&self) -> Result<GenericArray<u8, D::OutputSize>> {
        self.details.imprint::<D>()
    }
}

impl SigningKey for SecretSubkey {
    fn sign(&self, key_pw: &Password, hash: HashAlgorithm, data: &[u8]) -> Result<SignatureBytes> {
        let mut signature: Option<SignatureBytes> = None;
        self.unlock(key_pw, |pub_params, priv_key| {
            let sig = create_signature(pub_params, priv_key, hash, data)?;
            signature.replace(sig);
            Ok(())
        })??;

        signature.ok_or_else(|| unreachable!())
    }
    fn hash_alg(&self) -> HashAlgorithm {
        self.details.public_params().hash_alg()
    }
}

impl crate::ser::Serialize for SecretKey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer, self.version())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let details_len = crate::ser::Serialize::write_len(&self.details);
        let secret_params_len = self.secret_params.write_len(self.version());

        details_len + secret_params_len
    }
}

impl crate::ser::Serialize for SecretSubkey {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<()> {
        crate::ser::Serialize::to_writer(&self.details, writer)?;
        self.secret_params.to_writer(writer, self.version())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        let details_len = crate::ser::Serialize::write_len(&self.details);
        let secret_params_len = self.secret_params.write_len(self.version());

        details_len + secret_params_len
    }
}

impl PacketTrait for SecretKey {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

impl PacketTrait for SecretSubkey {
    fn packet_header(&self) -> &PacketHeader {
        &self.packet_header
    }
}

impl SecretKey {
    pub fn remove_password(&mut self, password: &Password) -> Result<()> {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    pub fn set_password<R>(&mut self, rng: R, password: &Password) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let s2k = crate::types::S2kParams::new_default(rng, self.version());
        Self::set_password_with_s2k(self, password, s2k)
    }

    pub fn set_password_with_s2k(
        &mut self,
        password: &Password,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()> {
        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password.read(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
    }
}

impl SecretSubkey {
    pub fn remove_password(&mut self, password: &Password) -> Result<()> {
        if let SecretParams::Encrypted(enc) = &self.secret_params {
            let unlocked = enc.unlock(password, &self.details, Some(self.packet_header.tag()))?;
            self.secret_params = SecretParams::Plain(unlocked);
        }

        Ok(())
    }

    pub fn set_password<R>(&mut self, rng: R, password: &Password) -> Result<()>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let s2k = crate::types::S2kParams::new_default(rng, self.version());
        Self::set_password_with_s2k(self, password, s2k)
    }

    pub fn set_password_with_s2k(
        &mut self,
        password: &Password,
        s2k_params: crate::types::S2kParams,
    ) -> Result<()> {
        let plain = match &self.secret_params {
            SecretParams::Plain(plain) => plain,
            SecretParams::Encrypted(_) => {
                bail!("Secret Key packet must be unlocked")
            }
        };

        self.secret_params = SecretParams::Encrypted(plain.clone().encrypt(
            &password.read(),
            s2k_params,
            &self.details,
            Some(self.packet_header.tag()),
        )?);

        Ok(())
    }

    pub fn sign<R: CryptoRng + Rng, S, K>(
        &self,
        mut rng: R,
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
        self.details.sign(
            &mut rng,
            primary_sec_key,
            primary_pub_key,
            key_pw,
            keyflags,
            embedded,
        )
    }
}

impl DecryptionKey for SecretKey {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        self.unlock(key_pw, |pub_params, priv_key| {
            priv_key.decrypt(pub_params, values, typ, self.public_key())
        })
    }
}

impl DecryptionKey for SecretSubkey {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        self.unlock(key_pw, |pub_params, priv_key| {
            priv_key.decrypt(pub_params, values, typ, self.public_key())
        })
    }
}

fn create_signature(
    pub_params: &PublicParams,
    priv_key: &PlainSecretParams,
    hash: HashAlgorithm,
    data: &[u8],
) -> Result<SignatureBytes> {
    use crate::crypto::Signer;

    debug!("unlocked key");
    match *priv_key {
        PlainSecretParams::DSA(ref priv_key) => {
            let PublicParams::DSA(_) = pub_params else {
                bail!("inconsistent key");
            };
            priv_key.sign(hash, data)
        }
        PlainSecretParams::ECDH(_) => {
            bail!("ECDH can not be used for signing operations")
        }
        PlainSecretParams::X25519(_) => {
            bail!("X25519 can not be used for signing operations")
        }

        PlainSecretParams::Ed25519(ref priv_key) => {
            let PublicParams::Ed25519(_) = pub_params else {
                bail!("invalid inconsistent key");
            };
            priv_key.sign(hash, data)
        }

        PlainSecretParams::EdDSALegacy(ref priv_key) => match (priv_key, pub_params) {
            (
                crate::crypto::eddsa_legacy::SecretKey::Ed25519(ed25519),
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }),
            ) => ed25519.sign(hash, data),
            (
                crate::crypto::eddsa_legacy::SecretKey::Unsupported { .. },
                PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Unsupported { curve, .. }),
            ) => {
                unsupported_err!("curve {} for EdDSA", curve);
            }
            _ => {
                bail!("invalid inconsistent key");
            }
        },
        PlainSecretParams::Elgamal(_) => {
            unsupported_err!("Elgamal signing");
        }

        PlainSecretParams::Unknown { alg, .. } => {
            unsupported_err!("{:?} signing", alg);
        }
    }
}

#[allow(dead_code)]

fn sign<R: CryptoRng + Rng, S, K>(
    mut rng: R,
    key: &S,
    key_pw: &Password,
    sig_typ: SignatureType,
    pub_key: &K,
) -> Result<Signature>
where
    S: SigningKey,
    K: KeyDetails + Serialize,
{
    let mut config = SignatureConfig::from_key(&mut rng, key, sig_typ)?;
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))?,
    ];
    if key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            key.legacy_key_id(),
        ))?];
    }

    config.sign_key(key, key_pw, pub_key)
}
