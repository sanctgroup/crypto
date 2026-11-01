use rand::{CryptoRng, Rng};

use crate::{
    composed::PlainSessionKey,
    crypto::{
        hash::{HashAlgorithm, KnownDigest},
        public_key::PublicKeyAlgorithm,
    },
    errors::Result,
    types::{
        EskType, Fingerprint, KeyId, KeyVersion, Password, PkeskBytes, PublicParams,
        SignatureBytes, Timestamp,
    },
};

pub trait KeyDetails: std::fmt::Debug {
    fn version(&self) -> KeyVersion;

    fn legacy_key_id(&self) -> KeyId;

    fn fingerprint(&self) -> Fingerprint;

    fn algorithm(&self) -> PublicKeyAlgorithm;
    fn created_at(&self) -> Timestamp;

    fn legacy_v3_expiration_days(&self) -> Option<u16>;

    fn public_params(&self) -> &PublicParams;
}

pub trait Imprint {
    fn imprint<D: KnownDigest>(&self) -> Result<generic_array::GenericArray<u8, D::OutputSize>>;
}

pub trait VerifyingKey: KeyDetails {
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &SignatureBytes) -> Result<()>;
}

impl<T: KeyDetails> KeyDetails for &T {
    fn version(&self) -> KeyVersion {
        (*self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (*self).fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        (*self).legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (*self).algorithm()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        (*self).legacy_v3_expiration_days()
    }

    fn created_at(&self) -> Timestamp {
        (*self).created_at()
    }

    fn public_params(&self) -> &PublicParams {
        (*self).public_params()
    }
}

impl<T: VerifyingKey> VerifyingKey for &T {
    fn verify(&self, hash: HashAlgorithm, data: &[u8], sig: &SignatureBytes) -> Result<()> {
        (*self).verify(hash, data, sig)
    }
}

impl KeyDetails for Box<&dyn SigningKey> {
    fn version(&self) -> KeyVersion {
        (**self).version()
    }

    fn fingerprint(&self) -> Fingerprint {
        (**self).fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        (**self).legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        (**self).algorithm()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        (**self).legacy_v3_expiration_days()
    }

    fn created_at(&self) -> Timestamp {
        (**self).created_at()
    }

    fn public_params(&self) -> &PublicParams {
        (**self).public_params()
    }
}

pub trait SigningKey: KeyDetails {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes>;

    fn hash_alg(&self) -> HashAlgorithm;
}

impl SigningKey for Box<&dyn SigningKey> {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> Result<crate::types::SignatureBytes> {
        (**self).sign(key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        (**self).hash_alg()
    }
}

pub trait EncryptionKey: KeyDetails {
    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> crate::errors::Result<PkeskBytes>;
}

impl<T: EncryptionKey> EncryptionKey for &T {
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> Result<PkeskBytes> {
        (*self).encrypt(rng, plain, typ)
    }
}

pub trait DecryptionKey: KeyDetails {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>>;
}

impl<T: DecryptionKey> DecryptionKey for &T {
    fn decrypt(
        &self,
        key_pw: &Password,
        values: &PkeskBytes,
        typ: EskType,
    ) -> Result<Result<PlainSessionKey>> {
        (*self).decrypt(key_pw, values, typ)
    }
}
