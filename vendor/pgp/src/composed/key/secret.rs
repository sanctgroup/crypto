use aes_gcm::aead::rand_core::CryptoRng;
use rand::Rng;

use crate::{
    composed::{KeyDetails, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey},
    errors::Result,
    packet::{self, KeyFlags, Signature},
    types::Password,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct RawSecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<(packet::PublicSubkey, KeyFlags, Option<Signature>)>,
    secret_subkeys: Vec<(packet::SecretSubkey, KeyFlags, Option<Signature>)>,
}

impl RawSecretKey {
    pub(super) fn new(
        primary_key: packet::SecretKey,
        details: KeyDetails,
        public_subkeys: Vec<(packet::PublicSubkey, KeyFlags, Option<Signature>)>,
        secret_subkeys: Vec<(packet::SecretSubkey, KeyFlags, Option<Signature>)>,
    ) -> Self {
        RawSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    pub(super) fn sign<R>(self, mut rng: R, key_pw: &Password) -> Result<SignedSecretKey>
    where
        R: CryptoRng + Rng,
    {
        let primary_key = self.primary_key;
        let details =
            self.details
                .sign(&mut rng, &primary_key, primary_key.public_key(), key_pw)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|(sub_key, keyflags, embedded)| {
                let signature = sub_key.sign(
                    &mut rng,
                    &primary_key,
                    primary_key.public_key(),
                    key_pw,
                    keyflags,
                    embedded,
                )?;
                Ok(SignedPublicSubKey {
                    key: sub_key,
                    signatures: vec![signature],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|(sub_key, keyflags, embedded)| {
                let signature = sub_key.sign(
                    &mut rng,
                    &primary_key,
                    primary_key.public_key(),
                    key_pw,
                    keyflags,
                    embedded,
                )?;
                Ok(SignedSecretSubKey {
                    key: sub_key,
                    signatures: vec![signature],
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}
