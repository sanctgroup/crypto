use ed25519_dalek::Signer as _;
use ml_dsa::signature::Keypair;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::PrivateKeys;
use crate::CryptoError;

pub const ED25519_PUBLIC_LEN: usize = 32;
pub const MLDSA65_PUBLIC_LEN: usize = 1952;
const ED25519_SIGNATURE_LEN: usize = 64;
const MLDSA65_SIGNATURE_LEN: usize = 3309;
const VERSION_LEN: usize = 4;
pub const SIGNATURE_BLOCK_LEN: usize = VERSION_LEN + ED25519_SIGNATURE_LEN + MLDSA65_SIGNATURE_LEN;
const MLDSA_CONTEXT: &[u8] = b"sanct-mail-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningPublicKeys {
    pub ed25519: Vec<u8>,
    pub mldsa65: Vec<u8>,
}

pub struct MailTranscript<'a> {
    pub sender_address: &'a str,
    pub recipient_key_hash: &'a [u8],
    pub binding_id: &'a [u8],
    pub body: &'a [u8],
    pub metadata: &'a [u8],
}

impl MailTranscript<'_> {
    fn digest(&self) -> [u8; 32] {
        let sender = self.sender_address.trim().to_ascii_lowercase();
        let mut hasher = Sha256::new();
        for field in [
            b"sanct-mail-transcript-v1".as_slice(),
            sender.as_bytes(),
            self.recipient_key_hash,
            self.binding_id,
            Sha256::digest(self.body).as_slice(),
            Sha256::digest(self.metadata).as_slice(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }
}

fn seed_array(seed: &[u8]) -> Result<[u8; 32], CryptoError> {
    seed.try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(seed.len()))
}

pub fn public_keys(
    ed25519_seed: &[u8],
    mldsa65_seed: &[u8],
) -> Result<SigningPublicKeys, CryptoError> {
    let ed_seed = Zeroizing::new(seed_array(ed25519_seed)?);
    let ml_seed = Zeroizing::new(seed_array(mldsa65_seed)?);
    let ed = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
    let ml = SigningKey::<MlDsa65>::from_seed(&Seed::from(*ml_seed));
    Ok(SigningPublicKeys {
        ed25519: ed.verifying_key().to_bytes().to_vec(),
        mldsa65: ml.verifying_key().encode().to_vec(),
    })
}

pub fn sign_mail(
    keys: &PrivateKeys,
    transcript: &MailTranscript<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let digest = transcript.digest();
    let ed_seed = Zeroizing::new(seed_array(&keys.ed25519_seed)?);
    let ml_seed = Zeroizing::new(seed_array(&keys.mldsa65_seed)?);
    let ed = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
    let ml = SigningKey::<MlDsa65>::from_seed(&Seed::from(*ml_seed));

    let ed_signature = ed.sign(&digest);
    let ml_signature = ml
        .expanded_key()
        .sign_deterministic(&digest, MLDSA_CONTEXT)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut block = Vec::with_capacity(SIGNATURE_BLOCK_LEN);
    block.extend_from_slice(&keys.key_version.to_be_bytes());
    block.extend_from_slice(&ed_signature.to_bytes());
    block.extend_from_slice(ml_signature.encode().as_slice());
    Ok(block)
}

pub fn signature_key_version(block: &[u8]) -> Result<u32, CryptoError> {
    if block.len() != SIGNATURE_BLOCK_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut version = [0u8; VERSION_LEN];
    version.copy_from_slice(&block[..VERSION_LEN]);
    Ok(u32::from_be_bytes(version))
}

pub fn verify_mail(
    block: &[u8],
    ed25519_public: &[u8],
    mldsa65_public: &[u8],
    transcript: &MailTranscript<'_>,
) -> bool {
    if block.len() != SIGNATURE_BLOCK_LEN {
        return false;
    }
    let digest = transcript.digest();
    let (ed_bytes, ml_bytes) = block[VERSION_LEN..].split_at(ED25519_SIGNATURE_LEN);

    let Ok(ed_public) = <[u8; ED25519_PUBLIC_LEN]>::try_from(ed25519_public) else {
        return false;
    };
    let Ok(ed_key) = ed25519_dalek::VerifyingKey::from_bytes(&ed_public) else {
        return false;
    };
    let Ok(ed_signature) = <[u8; ED25519_SIGNATURE_LEN]>::try_from(ed_bytes) else {
        return false;
    };
    let ed_signature = ed25519_dalek::Signature::from_bytes(&ed_signature);
    if ed_key.verify_strict(&digest, &ed_signature).is_err() {
        return false;
    }

    let Ok(ml_public) = <&EncodedVerifyingKey<MlDsa65>>::try_from(mldsa65_public) else {
        return false;
    };
    let ml_key = VerifyingKey::<MlDsa65>::decode(ml_public);
    let Ok(ml_encoded) = <&EncodedSignature<MlDsa65>>::try_from(ml_bytes) else {
        return false;
    };
    let Some(ml_signature) = Signature::<MlDsa65>::decode(ml_encoded) else {
        return false;
    };
    ml_key.verify_with_context(&digest, MLDSA_CONTEXT, &ml_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{decrypt_private_bundle, generate_identity_keys, parse_private_keys};

    fn identity() -> (crate::keys::IdentityKeyBundle, PrivateKeys) {
        let account_key = [0x33u8; 32];
        let identity = generate_identity_keys(&account_key).unwrap();
        let keys = parse_private_keys(
            &decrypt_private_bundle(&account_key, &identity.encrypted_private_bundle).unwrap(),
        )
        .unwrap();
        (identity, keys)
    }

    fn transcript() -> MailTranscript<'static> {
        MailTranscript {
            sender_address: "Alice@Sanct.test",
            recipient_key_hash: &[7u8; 32],
            binding_id: &[9u8; 16],
            body: b"body",
            metadata: b"metadata",
        }
    }

    #[test]
    fn signature_verifies_and_carries_version() {
        let (identity, keys) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();
        assert_eq!(block.len(), SIGNATURE_BLOCK_LEN);
        assert_eq!(signature_key_version(&block).unwrap(), 1);
        assert!(verify_mail(
            &block,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            &transcript()
        ));
    }

    #[test]
    fn sender_case_and_whitespace_do_not_matter() {
        let (identity, keys) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();
        let mut other = transcript();
        other.sender_address = " alice@sanct.test ";
        assert!(verify_mail(
            &block,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            &other
        ));
    }

    #[test]
    fn every_transcript_field_is_bound() {
        let (identity, keys) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();
        let mutations: [fn(&mut MailTranscript<'static>); 5] = [
            |t| t.sender_address = "mallory@sanct.test",
            |t| t.recipient_key_hash = &[8u8; 32],
            |t| t.binding_id = &[1u8; 16],
            |t| t.body = b"other body",
            |t| t.metadata = b"other metadata",
        ];
        for mutate in mutations {
            let mut changed = transcript();
            mutate(&mut changed);
            assert!(!verify_mail(
                &block,
                &identity.ed25519_public,
                &identity.mldsa65_public,
                &changed
            ));
        }
    }

    #[test]
    fn both_algorithms_must_verify() {
        let (identity, keys) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();

        let mut bad_ed = block.clone();
        bad_ed[VERSION_LEN] ^= 1;
        assert!(!verify_mail(
            &bad_ed,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            &transcript()
        ));

        let mut bad_ml = block.clone();
        let last = bad_ml.len() - 40;
        bad_ml[last] ^= 1;
        assert!(!verify_mail(
            &bad_ml,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            &transcript()
        ));
    }

    #[test]
    fn another_identity_cannot_verify() {
        let (_, keys) = identity();
        let (other, _) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();
        assert!(!verify_mail(
            &block,
            &other.ed25519_public,
            &other.mldsa65_public,
            &transcript()
        ));
    }

    #[test]
    fn malformed_block_and_keys_are_rejected() {
        let (identity, keys) = identity();
        let block = sign_mail(&keys, &transcript()).unwrap();
        assert!(!verify_mail(
            &block[..10],
            &identity.ed25519_public,
            &identity.mldsa65_public,
            &transcript()
        ));
        assert!(!verify_mail(
            &block,
            &[0u8; 3],
            &identity.mldsa65_public,
            &transcript()
        ));
        assert!(!verify_mail(
            &block,
            &identity.ed25519_public,
            &[0u8; 3],
            &transcript()
        ));
        assert!(signature_key_version(&block[..10]).is_err());
    }
}
