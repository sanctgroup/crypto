use std::cmp::PartialEq;

use derive_builder::Builder;
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

use crate::{
    composed::{KeyDetails, SignedSecretKey},
    crypto::{
        aead::AeadAlgorithm, dsa, ecc_curve::ECCCurve, ecdh, ed25519, eddsa_legacy,
        hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm, x25519,
    },
    errors::Result,
    packet::{self, KeyFlags, PubKeyInner, UserAttribute, UserId},
    types::{
        self, CompressionAlgorithm, Password, PlainSecretParams, PublicParams, S2kParams, Timestamp,
    },
};

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptionCaps {
    #[default]
    None,
    Communication,
    Storage,
    All,
}

impl EncryptionCaps {
    fn is_communication(&self) -> bool {
        matches!(self, Self::Communication | Self::All)
    }

    fn is_storage(&self) -> bool {
        matches!(self, Self::Storage | Self::All)
    }
}

#[derive(Debug, PartialEq, Eq, Builder)]
#[builder(build_fn(validate = "Self::validate"))]
pub struct SecretKeyParams {
    #[builder(default)]
    version: types::KeyVersion,

    key_type: KeyType,

    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_certify: bool,
    #[builder(default)]
    can_encrypt: EncryptionCaps,
    #[builder(default)]
    can_authenticate: bool,

    #[builder(default = "Timestamp::now()")]
    created_at: Timestamp,
    #[builder(default = "true")]
    feature_seipd_v1: bool,
    #[builder(default)]
    feature_seipd_v2: bool,

    #[builder(default)]
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    #[builder(default)]
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    #[builder(default)]
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    #[builder(default)]
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,

    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,

    #[builder(default)]
    packet_version: types::PacketHeaderVersion,

    #[builder(default, setter(custom))]
    primary_user_id: Option<String>,
    #[builder(default)]
    user_ids: Vec<String>,
    #[builder(default)]
    user_attributes: Vec<UserAttribute>,
    #[builder(default)]
    subkeys: Vec<SubkeyParams>,
}

#[derive(Debug, Clone, PartialEq, Eq, Builder)]
pub struct SubkeyParams {
    #[builder(default)]
    version: types::KeyVersion,

    key_type: KeyType,

    #[builder(default)]
    can_sign: bool,
    #[builder(default)]
    can_encrypt: EncryptionCaps,
    #[builder(default)]
    can_authenticate: bool,

    #[builder(default = "Timestamp::now()")]
    created_at: Timestamp,

    #[builder(default)]
    passphrase: Option<String>,
    #[builder(default)]
    s2k: Option<S2kParams>,

    #[builder(default)]
    packet_version: types::PacketHeaderVersion,
}

impl SecretKeyParamsBuilder {
    fn validate_keytype(
        key_type: Option<&KeyType>,
        can_sign: Option<bool>,
        can_encrypt: EncryptionCaps,
        can_authenticate: Option<bool>,
    ) -> std::result::Result<(), String> {
        if let Some(key_type) = &key_type {
            if can_sign == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for signing keys"
                ));
            }
            if (can_encrypt == EncryptionCaps::All
                || can_encrypt == EncryptionCaps::Storage
                || can_encrypt == EncryptionCaps::Communication)
                && !key_type.can_encrypt()
            {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for encryption keys"
                ));
            }
            if can_authenticate == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for authentication keys"
                ));
            }

            match key_type {
                KeyType::Rsa(size) => {
                    if *size < 2048 {
                        return Err("Keys with less than 2048bits are considered insecure".into());
                    }
                }
                KeyType::ECDSA(curve) => match curve {
                    ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 | ECCCurve::Secp256k1 => {}
                    _ => return Err(format!("Curve {} is not supported for ECDSA", curve.name())),
                },
                _ => {}
            }
        }

        Ok(())
    }

    fn validate(&self) -> std::result::Result<(), String> {
        match self.version {
            Some(types::KeyVersion::V6) => {
                for sub in self.subkeys.iter().flatten() {
                    if sub.version != types::KeyVersion::V6 {
                        return Err(format!(
                            "V6 primary key may not be combined with {:?} subkey",
                            sub.version
                        ));
                    }
                }
            }

            _ => {
                for sub in self.subkeys.iter().flatten() {
                    if sub.version == types::KeyVersion::V6 {
                        return Err(format!(
                            "{:?} primary key may not be combined with V6 subkey",
                            self.version
                        ));
                    }
                }
            }
        };

        Self::validate_keytype(
            self.key_type.as_ref(),
            self.can_sign,
            self.can_encrypt.unwrap_or_default(),
            self.can_authenticate,
        )?;

        if let Some(subkeys) = &self.subkeys {
            for subkey in subkeys {
                Self::validate_keytype(
                    Some(&subkey.key_type),
                    Some(subkey.can_sign),
                    subkey.can_encrypt,
                    Some(subkey.can_authenticate),
                )?;
            }
        }

        if self.version == Some(types::KeyVersion::V4) && self.primary_user_id.is_none() {
            return Err("V4 keys must have a primary User ID".into());
        }

        Ok(())
    }

    pub fn user_id<VALUE: Into<String>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut user_ids) = self.user_ids {
            user_ids.push(value.into());
        } else {
            self.user_ids = Some(vec![value.into()]);
        }
        self
    }

    pub fn subkey<VALUE: Into<SubkeyParams>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut subkeys) = self.subkeys {
            subkeys.push(value.into());
        } else {
            self.subkeys = Some(vec![value.into()]);
        }
        self
    }

    pub fn primary_user_id(&mut self, value: String) -> &mut Self {
        self.primary_user_id = Some(Some(value));
        self
    }
}

impl SecretKeyParams {
    pub fn generate<R: Rng + CryptoRng>(self, mut rng: R) -> Result<SignedSecretKey> {
        let passphrase = self.passphrase;
        let s2k = self
            .s2k
            .unwrap_or_else(|| S2kParams::new_default(&mut rng, self.version));
        let (public_params, secret_params) = self.key_type.generate(&mut rng)?;
        let pub_key = PubKeyInner::new(
            self.version,
            self.key_type.to_alg(),
            self.created_at,
            None,
            public_params,
        )?;
        let primary_pub_key = crate::packet::PublicKey::from_inner(pub_key)?;
        let mut primary_key = packet::SecretKey::new(primary_pub_key.clone(), secret_params)?;

        let have_pw = passphrase.is_some();
        let key_pw = passphrase.map(Into::into).unwrap_or_else(Password::empty);

        if have_pw {
            primary_key.set_password_with_s2k(&key_pw, s2k)?;
        }

        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(self.can_certify);
        keyflags.set_encrypt_comms(self.can_encrypt.is_communication());
        keyflags.set_encrypt_storage(self.can_encrypt.is_storage());
        keyflags.set_sign(self.can_sign);
        keyflags.set_authentication(self.can_authenticate);

        let primary_user_id = match self.primary_user_id {
            None => None,
            Some(id) => Some(UserId::from_str(Default::default(), id)?),
        };

        let mut features = packet::Features::default();
        if self.feature_seipd_v1 {
            features.set_seipd_v1(true);
        }
        if self.feature_seipd_v2 {
            features.set_seipd_v2(true);
        };

        let key = super::secret::RawSecretKey::new(
            primary_key,
            KeyDetails::new(
                primary_user_id,
                self.user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect::<Result<Vec<_>, _>>()?,
                self.user_attributes,
                keyflags,
                features,
                self.preferred_symmetric_algorithms,
                self.preferred_hash_algorithms,
                self.preferred_compression_algorithms,
                self.preferred_aead_algorithms,
            ),
            Default::default(),
            self.subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let s2k = subkey
                        .s2k
                        .unwrap_or_else(|| S2kParams::new_default(&mut rng, subkey.version));
                    let (public_params, secret_params) = subkey.key_type.generate(&mut rng)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_encrypt_comms(subkey.can_encrypt.is_communication());
                    keyflags.set_encrypt_storage(subkey.can_encrypt.is_storage());
                    keyflags.set_sign(subkey.can_sign);
                    keyflags.set_authentication(subkey.can_authenticate);

                    let pub_key = PubKeyInner::new(
                        subkey.version,
                        subkey.key_type.to_alg(),
                        subkey.created_at,
                        None,
                        public_params,
                    )?;
                    let pub_key = packet::PublicSubkey::from_inner(pub_key)?;
                    let mut sub = packet::SecretSubkey::new(pub_key, secret_params)?;

                    let embedded = if subkey.can_sign {
                        let backsig =
                            sub.sign_primary_key_binding(&mut rng, &primary_pub_key, &"".into())?;

                        Some(backsig)
                    } else {
                        None
                    };

                    if let Some(passphrase) = passphrase {
                        sub.set_password_with_s2k(&passphrase.as_str().into(), s2k)?;
                    }

                    Ok((sub, keyflags, embedded))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let signed = key.sign(rng, &key_pw)?;
        Ok(signed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    Rsa(u32),
    ECDH(ECCCurve),
    Ed25519Legacy,
    ECDSA(ECCCurve),
    Dsa(DsaKeySize),
    Ed25519,
    Ed448,
    X25519,
    X448,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsaKeySize {
    B1024 = 1024,
    B2048 = 2048,
    B3072 = 3072,
}

impl From<DsaKeySize> for dsa::KeySize {
    fn from(value: DsaKeySize) -> Self {
        match value {
            #[allow(deprecated)]
            DsaKeySize::B1024 => dsa::KeySize::DSA_1024_160,
            DsaKeySize::B2048 => dsa::KeySize::DSA_2048_256,
            DsaKeySize::B3072 => dsa::KeySize::DSA_3072_256,
        }
    }
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH(_) => PublicKeyAlgorithm::ECDH,
            KeyType::Ed25519Legacy => PublicKeyAlgorithm::EdDSALegacy,
            KeyType::ECDSA(_) => PublicKeyAlgorithm::ECDSA,
            KeyType::Dsa(_) => PublicKeyAlgorithm::DSA,
            KeyType::Ed25519 => PublicKeyAlgorithm::Ed25519,
            KeyType::Ed448 => PublicKeyAlgorithm::Ed448,
            KeyType::X25519 => PublicKeyAlgorithm::X25519,
            KeyType::X448 => PublicKeyAlgorithm::X448,
        }
    }

    pub fn can_sign(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => true,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => false,
        }
    }

    pub fn can_encrypt(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => false,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => true,
        }
    }

    pub fn generate<R: Rng + CryptoRng>(
        &self,
        rng: R,
    ) -> Result<(PublicParams, types::SecretParams)> {
        let (pub_params, plain) = match self {
            KeyType::Rsa(_) => return Err(crate::errors::Error::DisabledAlgorithm),
            KeyType::ECDH(curve) => {
                let secret = ecdh::SecretKey::generate(rng, curve)?;
                let public_params = PublicParams::ECDH((&secret).try_into()?);
                let secret_params = PlainSecretParams::ECDH(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519Legacy => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::EdDSALegacy);
                let public_params = PublicParams::EdDSALegacy((&secret).into());
                let secret_params =
                    PlainSecretParams::EdDSALegacy(eddsa_legacy::SecretKey::Ed25519(secret));
                (public_params, secret_params)
            }
            KeyType::ECDSA(_) => return Err(crate::errors::Error::DisabledAlgorithm),
            KeyType::Dsa(key_size) => {
                let secret = dsa::SecretKey::generate(rng, (*key_size).into());
                let public_params = PublicParams::DSA((&secret).into());
                let secret_params = PlainSecretParams::DSA(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519 => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::Ed25519);
                let public_params = PublicParams::Ed25519((&secret).into());
                let secret_params = PlainSecretParams::Ed25519(secret);
                (public_params, secret_params)
            }
            KeyType::Ed448 => return Err(crate::errors::Error::DisabledAlgorithm),
            KeyType::X25519 => {
                let secret = x25519::SecretKey::generate(rng);
                let public_params = PublicParams::X25519((&secret).into());
                let secret_params = PlainSecretParams::X25519(secret);
                (public_params, secret_params)
            }
            KeyType::X448 => return Err(crate::errors::Error::DisabledAlgorithm),
        };

        Ok((pub_params, types::SecretParams::Plain(plain)))
    }
}
