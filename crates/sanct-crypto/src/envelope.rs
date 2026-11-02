use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::hybrid;
use crate::keys::PrivateKeys;
use crate::signing::{self, MailTranscript};
use crate::symmetric;
use crate::CryptoError;

const SEALED_VERSION: u8 = 3;
const SELF_VERSION: u8 = 4;
const X25519_PUB_LEN: usize = 32;
pub const BINDING_ID_LEN: usize = 16;
const PREFIX_LEN: usize = 2 + BINDING_ID_LEN;
const SEALED_HEADER_LEN: usize = PREFIX_LEN + X25519_PUB_LEN + hybrid::MLKEM_CIPHERTEXT_LEN;
const AEAD_OVERHEAD: usize = 24 + 16;
const SIGNATURE_LEN_PREFIX: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    MailBody = 1,
    MailMetadata = 2,
    Contact = 3,
    Signature = 4,
    CalendarEvent = 5,
}

impl RecordKind {
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        match value {
            "mail-body" => Ok(Self::MailBody),
            "mail-metadata" => Ok(Self::MailMetadata),
            "contact" => Ok(Self::Contact),
            "signature" => Ok(Self::Signature),
            "calendar-event" => Ok(Self::CalendarEvent),
            _ => Err(CryptoError::InvalidCiphertext),
        }
    }

    fn is_mail(self) -> bool {
        matches!(self, Self::MailBody | Self::MailMetadata)
    }
}

pub struct SealedMail {
    pub body: Vec<u8>,
    pub metadata: Vec<u8>,
    pub binding_id: [u8; BINDING_ID_LEN],
}

pub struct OpenedMail {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub binding_id: [u8; BINDING_ID_LEN],
    pub self_sealed: bool,
    pub recipient_key_hash: Option<[u8; 32]>,
    pub signature: Option<Vec<u8>>,
}

pub struct Signer<'a> {
    pub keys: &'a PrivateKeys,
    pub sender_address: &'a str,
}

fn new_binding_id() -> Result<[u8; BINDING_ID_LEN], CryptoError> {
    let mut binding = [0u8; BINDING_ID_LEN];
    getrandom::fill(&mut binding).map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(binding)
}

fn sealed_aad(
    kind: u8,
    binding_id: &[u8],
    recipient_key_hash: &[u8; 32],
    ephemeral: &[u8],
    mlkem_ciphertext: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sanct-envelope-v3");
    hasher.update([kind]);
    hasher.update(binding_id);
    hasher.update(recipient_key_hash);
    hasher.update(ephemeral);
    hasher.update(mlkem_ciphertext);
    hasher.finalize().into()
}

fn self_aad(kind: u8, binding_id: &[u8]) -> Vec<u8> {
    [b"sanct-self-record-v4".as_slice(), &[kind], binding_id].concat()
}

fn seal_public(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    kind: RecordKind,
    binding_id: &[u8; BINDING_ID_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let encap = hybrid::encapsulate(recipient_x25519_public, recipient_mlkem_public)?;
    let recipient_hash =
        hybrid::recipient_key_hash(recipient_x25519_public, recipient_mlkem_public);
    let aad = sealed_aad(
        kind as u8,
        binding_id,
        &recipient_hash,
        &encap.x25519_ephemeral_public,
        &encap.mlkem_ciphertext,
    );
    let mut output = Vec::with_capacity(SEALED_HEADER_LEN + AEAD_OVERHEAD + plaintext.len());
    output.push(SEALED_VERSION);
    output.push(kind as u8);
    output.extend_from_slice(binding_id);
    output.extend_from_slice(&encap.x25519_ephemeral_public);
    output.extend_from_slice(&encap.mlkem_ciphertext);
    symmetric::encrypt_into(&encap.shared_secret, &aad, plaintext, output)
}

fn frame_signed_body(
    signature: Option<&[u8]>,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let signature = signature.unwrap_or_default();
    let length = u32::try_from(signature.len()).map_err(|_| CryptoError::EncryptionFailed)?;
    let mut framed = Zeroizing::new(Vec::with_capacity(
        SIGNATURE_LEN_PREFIX + signature.len() + body.len(),
    ));
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(signature);
    framed.extend_from_slice(body);
    Ok(framed)
}

pub fn seal_mail(
    recipient_x25519_public: &[u8],
    recipient_mlkem_public: &[u8],
    body: &[u8],
    metadata: &[u8],
    signer: Option<Signer<'_>>,
) -> Result<SealedMail, CryptoError> {
    let binding_id = new_binding_id()?;
    let signature = match signer {
        Some(signer) => {
            let recipient_key_hash =
                hybrid::recipient_key_hash(recipient_x25519_public, recipient_mlkem_public);
            Some(signing::sign_mail(
                signer.keys,
                &MailTranscript {
                    sender_address: signer.sender_address,
                    recipient_key_hash: &recipient_key_hash,
                    binding_id: &binding_id,
                    body,
                    metadata,
                },
            )?)
        }
        None => None,
    };
    let framed = frame_signed_body(signature.as_deref(), body)?;
    Ok(SealedMail {
        body: seal_public(
            recipient_x25519_public,
            recipient_mlkem_public,
            RecordKind::MailBody,
            &binding_id,
            &framed,
        )?,
        metadata: seal_public(
            recipient_x25519_public,
            recipient_mlkem_public,
            RecordKind::MailMetadata,
            &binding_id,
            metadata,
        )?,
        binding_id,
    })
}

pub fn seal_mail_for_self(
    keys: &PrivateKeys,
    body: &[u8],
    metadata: &[u8],
) -> Result<SealedMail, CryptoError> {
    let binding_id = new_binding_id()?;
    Ok(SealedMail {
        body: seal_self(keys, RecordKind::MailBody, &binding_id, body)?,
        metadata: seal_self(keys, RecordKind::MailMetadata, &binding_id, metadata)?,
        binding_id,
    })
}

fn seal_self(
    keys: &PrivateKeys,
    kind: RecordKind,
    binding_id: &[u8; BINDING_ID_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let aad = self_aad(kind as u8, binding_id);
    let mut output = Vec::with_capacity(PREFIX_LEN + AEAD_OVERHEAD + plaintext.len());
    output.push(SELF_VERSION);
    output.push(kind as u8);
    output.extend_from_slice(binding_id);
    symmetric::encrypt_into(&keys.data_key, &aad, plaintext, output)
}

pub fn seal_record(
    keys: &PrivateKeys,
    kind: RecordKind,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if kind.is_mail() {
        return Err(CryptoError::InvalidCiphertext);
    }
    seal_self(keys, kind, &new_binding_id()?, plaintext)
}

pub fn open_record(
    keys: &PrivateKeys,
    kind: RecordKind,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if kind.is_mail() {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (version, data_kind, binding_id) = parse_prefix(data)?;
    if version != SELF_VERSION {
        return Err(CryptoError::UnsupportedVersion(version));
    }
    if data_kind != kind as u8 {
        return Err(CryptoError::DecryptionFailed);
    }
    open_self(keys, data_kind, binding_id, data)
}

fn parse_prefix(data: &[u8]) -> Result<(u8, u8, &[u8]), CryptoError> {
    if data.len() < PREFIX_LEN + AEAD_OVERHEAD {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok((data[0], data[1], &data[2..PREFIX_LEN]))
}

fn open_self(
    keys: &PrivateKeys,
    kind: u8,
    binding_id: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let aad = self_aad(kind, binding_id);
    Ok(Zeroizing::new(symmetric::decrypt(
        &keys.data_key,
        &aad,
        &data[PREFIX_LEN..],
    )?))
}

pub fn open_mail(
    keys: &PrivateKeys,
    kind: RecordKind,
    data: &[u8],
) -> Result<OpenedMail, CryptoError> {
    if !kind.is_mail() {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (version, data_kind, binding_bytes) = parse_prefix(data)?;
    if data_kind != kind as u8 {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut binding_id = [0u8; BINDING_ID_LEN];
    binding_id.copy_from_slice(binding_bytes);

    match version {
        SELF_VERSION => Ok(OpenedMail {
            plaintext: open_self(keys, data_kind, binding_bytes, data)?,
            binding_id,
            self_sealed: true,
            recipient_key_hash: None,
            signature: None,
        }),
        SEALED_VERSION => open_sealed_mail(keys, kind, binding_id, data),
        other => Err(CryptoError::UnsupportedVersion(other)),
    }
}

fn open_sealed_mail(
    keys: &PrivateKeys,
    kind: RecordKind,
    binding_id: [u8; BINDING_ID_LEN],
    data: &[u8],
) -> Result<OpenedMail, CryptoError> {
    if data.len() < SEALED_HEADER_LEN + AEAD_OVERHEAD {
        return Err(CryptoError::InvalidCiphertext);
    }
    let candidates = std::iter::once((&keys.x25519_secret, &keys.mlkem768_secret)).chain(
        keys.previous
            .iter()
            .map(|entry| (&entry.x25519_secret, &entry.mlkem768_secret)),
    );

    for (x25519_secret, mlkem_secret) in candidates {
        if let Ok((plaintext, recipient_key_hash)) =
            try_open_sealed(x25519_secret, mlkem_secret, kind, &binding_id, data)
        {
            let (plaintext, signature) = match kind {
                RecordKind::MailBody => split_signed_body(plaintext)?,
                _ => (plaintext, None),
            };
            return Ok(OpenedMail {
                plaintext,
                binding_id,
                self_sealed: false,
                recipient_key_hash: Some(recipient_key_hash),
                signature,
            });
        }
    }
    Err(CryptoError::DecryptionFailed)
}

fn try_open_sealed(
    x25519_secret: &[u8],
    mlkem_secret: &[u8],
    kind: RecordKind,
    binding_id: &[u8; BINDING_ID_LEN],
    data: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), CryptoError> {
    let ephemeral: &[u8; X25519_PUB_LEN] = data[PREFIX_LEN..PREFIX_LEN + X25519_PUB_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidCiphertext)?;
    let mlkem_ciphertext = &data[PREFIX_LEN + X25519_PUB_LEN..SEALED_HEADER_LEN];
    let shared = Zeroizing::new(hybrid::decapsulate(
        x25519_secret,
        mlkem_secret,
        ephemeral,
        mlkem_ciphertext,
    )?);
    let recipient_hash = hybrid::recipient_key_hash_from_secrets(x25519_secret, mlkem_secret)?;
    let aad = sealed_aad(
        kind as u8,
        binding_id,
        &recipient_hash,
        ephemeral,
        mlkem_ciphertext,
    );
    let plaintext = Zeroizing::new(symmetric::decrypt(
        shared.as_ref(),
        &aad,
        &data[SEALED_HEADER_LEN..],
    )?);
    Ok((plaintext, recipient_hash))
}

type SignedBody = (Zeroizing<Vec<u8>>, Option<Vec<u8>>);

fn split_signed_body(framed: Zeroizing<Vec<u8>>) -> Result<SignedBody, CryptoError> {
    if framed.len() < SIGNATURE_LEN_PREFIX {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut length = [0u8; SIGNATURE_LEN_PREFIX];
    length.copy_from_slice(&framed[..SIGNATURE_LEN_PREFIX]);
    let length = u32::from_be_bytes(length) as usize;
    let body_start = SIGNATURE_LEN_PREFIX
        .checked_add(length)
        .filter(|end| *end <= framed.len())
        .ok_or(CryptoError::InvalidCiphertext)?;
    let signature = (length > 0).then(|| framed[SIGNATURE_LEN_PREFIX..body_start].to_vec());
    Ok((Zeroizing::new(framed[body_start..].to_vec()), signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{
        decrypt_private_bundle, generate_identity_keys, parse_private_keys, rotate_identity_keys,
        IdentityKeyBundle,
    };

    const ACCOUNT_KEY: [u8; 32] = [0x42; 32];

    fn identity() -> (IdentityKeyBundle, PrivateKeys) {
        let identity = generate_identity_keys(&ACCOUNT_KEY).unwrap();
        let keys = parse_private_keys(
            &decrypt_private_bundle(&ACCOUNT_KEY, &identity.encrypted_private_bundle).unwrap(),
        )
        .unwrap();
        (identity, keys)
    }

    #[test]
    fn signed_mail_roundtrip_and_verify() {
        let (sender_id, sender) = identity();
        let (recipient_id, recipient) = identity();
        let sealed = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"body",
            b"metadata",
            Some(Signer {
                keys: &sender,
                sender_address: "alice@sanct.test",
            }),
        )
        .unwrap();

        let body = open_mail(&recipient, RecordKind::MailBody, &sealed.body).unwrap();
        let metadata = open_mail(&recipient, RecordKind::MailMetadata, &sealed.metadata).unwrap();
        assert_eq!(&body.plaintext[..], b"body");
        assert_eq!(&metadata.plaintext[..], b"metadata");
        assert_eq!(body.binding_id, metadata.binding_id);
        assert!(!body.self_sealed);

        let signature = body.signature.as_ref().unwrap();
        let recipient_hash = body.recipient_key_hash.unwrap();
        let transcript = MailTranscript {
            sender_address: "alice@sanct.test",
            recipient_key_hash: &recipient_hash,
            binding_id: &body.binding_id,
            body: &body.plaintext,
            metadata: &metadata.plaintext,
        };
        assert!(signing::verify_mail(
            signature,
            &sender_id.ed25519_public,
            &sender_id.mldsa65_public,
            &transcript
        ));
    }

    #[test]
    fn server_sealed_mail_has_no_signature() {
        let (recipient_id, recipient) = identity();
        let sealed = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"body",
            b"metadata",
            None,
        )
        .unwrap();
        let body = open_mail(&recipient, RecordKind::MailBody, &sealed.body).unwrap();
        assert!(body.signature.is_none());
        assert_eq!(&body.plaintext[..], b"body");
    }

    #[test]
    fn body_and_metadata_cannot_be_swapped() {
        let (recipient_id, recipient) = identity();
        let sealed = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"body",
            b"metadata",
            None,
        )
        .unwrap();
        assert!(open_mail(&recipient, RecordKind::MailBody, &sealed.metadata).is_err());
        assert!(open_mail(&recipient, RecordKind::MailMetadata, &sealed.body).is_err());
    }

    #[test]
    fn header_fields_are_authenticated() {
        let (recipient_id, recipient) = identity();
        let sealed = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"body",
            b"metadata",
            None,
        )
        .unwrap();

        let mut wrong_binding = sealed.body.clone();
        wrong_binding[2] ^= 1;
        assert!(open_mail(&recipient, RecordKind::MailBody, &wrong_binding).is_err());

        let mut wrong_kind = sealed.body.clone();
        wrong_kind[1] = RecordKind::MailMetadata as u8;
        assert!(open_mail(&recipient, RecordKind::MailMetadata, &wrong_kind).is_err());

        for index in [PREFIX_LEN, PREFIX_LEN + 40, sealed.body.len() - 1] {
            let mut tampered = sealed.body.clone();
            tampered[index] ^= 1;
            assert!(open_mail(&recipient, RecordKind::MailBody, &tampered).is_err());
        }
    }

    #[test]
    fn distinct_messages_have_distinct_bindings() {
        let (recipient_id, recipient) = identity();
        let one = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"one",
            b"m1",
            None,
        )
        .unwrap();
        let two = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"two",
            b"m2",
            None,
        )
        .unwrap();
        let body = open_mail(&recipient, RecordKind::MailBody, &one.body).unwrap();
        let foreign = open_mail(&recipient, RecordKind::MailMetadata, &two.metadata).unwrap();
        assert_ne!(body.binding_id, foreign.binding_id);
    }

    #[test]
    fn wrong_recipient_fails() {
        let (recipient_id, _) = identity();
        let (_, other) = identity();
        let sealed = seal_mail(
            &recipient_id.x25519_public,
            &recipient_id.mlkem768_public,
            b"body",
            b"metadata",
            None,
        )
        .unwrap();
        assert!(open_mail(&other, RecordKind::MailBody, &sealed.body).is_err());
    }

    #[test]
    fn self_sealed_mail_roundtrip_and_key_isolation() {
        let (_, keys) = identity();
        let (_, other) = identity();
        let sealed = seal_mail_for_self(&keys, b"draft", b"draft metadata").unwrap();
        let body = open_mail(&keys, RecordKind::MailBody, &sealed.body).unwrap();
        assert!(body.self_sealed);
        assert_eq!(&body.plaintext[..], b"draft");
        assert!(open_mail(&other, RecordKind::MailBody, &sealed.body).is_err());
    }

    #[test]
    fn records_only_open_under_data_key_and_matching_kind() {
        let (identity_keys, keys) = identity();
        let sealed = seal_record(&keys, RecordKind::Contact, b"contact").unwrap();
        assert_eq!(
            &open_record(&keys, RecordKind::Contact, &sealed).unwrap()[..],
            b"contact"
        );
        assert!(open_record(&keys, RecordKind::Signature, &sealed).is_err());

        let mut relabelled = sealed.clone();
        relabelled[1] = RecordKind::Signature as u8;
        assert!(open_record(&keys, RecordKind::Signature, &relabelled).is_err());

        let forged = seal_public(
            &identity_keys.x25519_public,
            &identity_keys.mlkem768_public,
            RecordKind::Contact,
            &[0u8; BINDING_ID_LEN],
            b"server forged",
        )
        .unwrap();
        assert!(open_record(&keys, RecordKind::Contact, &forged).is_err());
        assert!(seal_record(&keys, RecordKind::MailBody, b"x").is_err());
    }

    #[test]
    fn rotated_keys_still_open_old_mail() {
        let (first_id, first) = identity();
        let old = seal_mail(
            &first_id.x25519_public,
            &first_id.mlkem768_public,
            b"old body",
            b"old metadata",
            None,
        )
        .unwrap();
        let old_self = seal_record(&first, RecordKind::Contact, b"old contact").unwrap();

        let second_id = rotate_identity_keys(&ACCOUNT_KEY, &first).unwrap();
        let second = parse_private_keys(
            &decrypt_private_bundle(&ACCOUNT_KEY, &second_id.encrypted_private_bundle).unwrap(),
        )
        .unwrap();

        let opened = open_mail(&second, RecordKind::MailBody, &old.body).unwrap();
        assert_eq!(&opened.plaintext[..], b"old body");
        assert_eq!(
            &open_record(&second, RecordKind::Contact, &old_self).unwrap()[..],
            b"old contact"
        );

        let new = seal_mail(
            &second_id.x25519_public,
            &second_id.mlkem768_public,
            b"new body",
            b"new metadata",
            None,
        )
        .unwrap();
        assert_eq!(
            &open_mail(&second, RecordKind::MailBody, &new.body)
                .unwrap()
                .plaintext[..],
            b"new body"
        );
    }

    #[test]
    fn signature_length_cannot_overrun_body() {
        let framed = Zeroizing::new([u32::MAX.to_be_bytes().as_slice(), b"short"].concat());
        assert!(split_signed_body(framed).is_err());
        assert!(split_signed_body(Zeroizing::new(vec![0u8; 2])).is_err());
    }

    #[test]
    fn unknown_versions_rejected() {
        let (recipient_id, recipient) = identity();
        for version in [0u8, 1, 2, 9] {
            let sealed = seal_mail(
                &recipient_id.x25519_public,
                &recipient_id.mlkem768_public,
                b"body",
                b"metadata",
                None,
            )
            .unwrap();
            let mut data = sealed.body;
            data[0] = version;
            assert!(matches!(
                open_mail(&recipient, RecordKind::MailBody, &data),
                Err(CryptoError::UnsupportedVersion(_))
            ));
        }
    }

    #[test]
    fn truncated_data_rejected() {
        let (_, keys) = identity();
        for length in [0, 1, 17, 40, 57] {
            assert!(open_mail(&keys, RecordKind::MailBody, &vec![3u8; length]).is_err());
        }
    }
}
