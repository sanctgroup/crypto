use std::io::{Cursor, Read};

use chrono::Utc;
use pgp::composed::{
    ArmorOptions, DecryptionOptions, Deserializable, EncryptionCaps, KeyType, Message,
    MessageBuilder, SecretKeyParamsBuilder, SignatureManyReader, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder, TheRing,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{
    CompressionAlgorithm, KeyDetails, Password, PublicParams, S2kParams, SecretParams,
    Seipdv1ReadMode, StringToKey, Tag,
};
use rand::rngs::OsRng;
use smallvec::smallvec;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_PGP_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
const MAX_PGP_CIPHERTEXT_BYTES: usize = 96 * 1024 * 1024;
const MAX_PGP_KEY_BYTES: usize = 1024 * 1024;
const MAX_PGP_KEYS: usize = 128;
const MAX_PGP_LAYERS: usize = 8;
const MAX_PGP_DECOMPRESSION_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PgpError {
    #[error("invalid armored or binary key data: {0}")]
    Parse(String),
    #[error("the imported key is a smartcard/stub key with no usable secret material")]
    SmartcardStub,
    #[error("the input contains only a public key; a secret key is required")]
    PublicOnly,
    #[error("incorrect passphrase")]
    BadPassphrase,
    #[error("key generation failed: {0}")]
    Generation(String),
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("export failed: {0}")]
    Export(String),
    #[error("private-key algorithm disabled because of unresolved upstream timing advisories")]
    UnsafePrivateKey,
    #[error("signature verification failed: {0}")]
    Verification(String),
    #[error("OpenPGP resource limit exceeded")]
    ResourceLimit,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedKey {
    pub armored_public: String,
    pub armored_secret: String,
    pub fingerprint: String,
    pub primary_uid: String,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ImportedKey {
    pub armored_secret_unprotected: String,
    pub armored_public: String,
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub can_encrypt: bool,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub fingerprint_used: String,
    pub signer_fingerprint: Option<String>,
}

pub fn generate_key(name: &str, email: &str) -> Result<GeneratedKey, PgpError> {
    let primary_uid = format_uid(name, email);

    let subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_encrypt(EncryptionCaps::All)
        .passphrase(None)
        .build()
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(primary_uid.clone())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256, HashAlgorithm::Sha512,])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(subkey)
        .build()
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let signed_secret = params
        .generate(OsRng)
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let signed_public = SignedPublicKey::from(signed_secret.clone());

    let fingerprint = fingerprint_hex(&signed_secret);
    let armored_public = signed_public
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Generation(e.to_string()))?;
    let armored_secret = signed_secret
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    Ok(GeneratedKey {
        armored_public,
        armored_secret,
        fingerprint,
        primary_uid,
    })
}

pub fn import_key(input: &[u8], passphrase: Option<&str>) -> Result<ImportedKey, PgpError> {
    if passphrase.is_some_and(|password| password.len() > 4096) {
        return Err(PgpError::ResourceLimit);
    }
    if looks_like_public_only(input) {
        return Err(PgpError::PublicOnly);
    }

    let mut signed = parse_secret(input)?;

    if is_smartcard_stub(&signed) {
        return Err(PgpError::SmartcardStub);
    }

    let needs_unlock = signed.primary_key.secret_params().is_encrypted()
        || signed
            .secret_subkeys
            .iter()
            .any(|sub| sub.key.secret_params().is_encrypted());

    if needs_unlock {
        let pw = Password::from(passphrase.unwrap_or(""));
        if signed.primary_key.secret_params().is_encrypted() {
            signed
                .primary_key
                .remove_password(&pw)
                .map_err(|_| PgpError::BadPassphrase)?;
        }
        for subkey in &mut signed.secret_subkeys {
            if subkey.key.secret_params().is_encrypted() {
                subkey
                    .key
                    .remove_password(&pw)
                    .map_err(|_| PgpError::BadPassphrase)?;
            }
        }
    }

    let armored_secret_unprotected = signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Parse(e.to_string()))?;
    let signed_public = SignedPublicKey::from(signed.clone());
    let armored_public_signed = signed_public
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Parse(e.to_string()))?;

    let info = collect_info(&signed)?;
    Ok(ImportedKey {
        armored_secret_unprotected,
        armored_public: armored_public_signed,
        fingerprint: info.fingerprint,
        uids: info.uids,
        created_at_unix: info.created_at_unix,
        expires_at_unix: info.expires_at_unix,
        is_expired: info.is_expired,
        is_revoked: info.is_revoked,
    })
}

pub fn export_key(unprotected_armored: &[u8], passphrase: &str) -> Result<String, PgpError> {
    if passphrase.len() > 4096 {
        return Err(PgpError::ResourceLimit);
    }
    if passphrase.is_empty() {
        return Err(PgpError::Export(
            "export passphrase must not be empty".into(),
        ));
    }
    let mut signed = parse_secret(unprotected_armored)?;
    let rng = OsRng;

    let key_version = signed.primary_key.version();
    let s2k = S2kParams::new_default(rng, key_version);
    let pw_primary = Password::from(passphrase);
    signed
        .primary_key
        .set_password_with_s2k(&pw_primary, s2k)
        .map_err(|e| PgpError::Export(e.to_string()))?;

    for subkey in signed.secret_subkeys.iter_mut() {
        let sub_s2k = S2kParams::new_default(rng, key_version);
        let pw_sub = Password::from(passphrase);
        subkey
            .key
            .set_password_with_s2k(&pw_sub, sub_s2k)
            .map_err(|e| PgpError::Export(e.to_string()))?;
    }

    signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Export(e.to_string()))
}

pub fn parse_public_info(input: &[u8]) -> Result<PublicKeyInfo, PgpError> {
    let signed = parse_public(input)?;
    let now = Utc::now().timestamp();
    let expires_at_unix = primary_expiration(&signed);
    let is_expired = expires_at_unix.is_some_and(|e| e <= now);
    let is_revoked = !signed.details.revocation_signatures.is_empty();
    Ok(PublicKeyInfo {
        fingerprint: fingerprint_hex_pub(&signed),
        uids: signed
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect(),
        created_at_unix: signed.primary_key.created_at().as_secs() as i64,
        expires_at_unix,
        is_expired,
        is_revoked,
        can_encrypt: primary_is_active(&signed, now)
            && signed
                .public_subkeys
                .iter()
                .any(|sk| subkey_is_active(sk, now, false)),
    })
}

pub fn encrypt_to_recipients(
    armored_publics: &[Vec<u8>],
    plaintext: &[u8],
) -> Result<String, PgpError> {
    if plaintext.len() > MAX_PGP_PLAINTEXT_BYTES || armored_publics.len() > MAX_PGP_KEYS {
        return Err(PgpError::ResourceLimit);
    }
    if armored_publics.is_empty() {
        return Err(PgpError::Encryption("no recipients".into()));
    }
    let keys = armored_publics
        .iter()
        .map(|k| parse_public(k))
        .collect::<Result<Vec<_>, _>>()?;
    let now = Utc::now().timestamp();
    let mut msg = MessageBuilder::from_bytes(b"".as_slice(), plaintext.to_vec())
        .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
    for key in &keys {
        if !primary_is_active(key, now) {
            return Err(PgpError::Encryption(
                "recipient key is expired, revoked or not yet valid".into(),
            ));
        }
        let subkey = key
            .public_subkeys
            .iter()
            .find(|sk| subkey_is_active(sk, now, false))
            .ok_or_else(|| {
                PgpError::Encryption("recipient has no active encryption subkey".into())
            })?;
        msg.encrypt_to_key(OsRng, subkey)
            .map_err(|e| PgpError::Encryption(e.to_string()))?;
    }
    msg.to_armored_string(OsRng, ArmorOptions::default())
        .map_err(|e| PgpError::Encryption(e.to_string()))
}

pub fn decrypt_message(
    armored_secrets: &[Vec<u8>],
    armored_ciphertext: &[u8],
) -> Result<DecryptResult, PgpError> {
    decrypt_message_inner(armored_secrets, armored_ciphertext, &[], false)
}

pub fn decrypt_message_verified(
    armored_secrets: &[Vec<u8>],
    armored_ciphertext: &[u8],
    trusted_signers: &[Vec<u8>],
) -> Result<DecryptResult, PgpError> {
    if trusted_signers.is_empty() {
        return Err(PgpError::Verification(
            "a trusted signer key is required".into(),
        ));
    }
    decrypt_message_inner(armored_secrets, armored_ciphertext, trusted_signers, true)
}

fn decrypt_message_inner(
    armored_secrets: &[Vec<u8>],
    armored_ciphertext: &[u8],
    trusted_signers: &[Vec<u8>],
    require_signature: bool,
) -> Result<DecryptResult, PgpError> {
    if armored_secrets.len() > MAX_PGP_KEYS
        || trusted_signers.len() > MAX_PGP_KEYS
        || armored_ciphertext.len() > MAX_PGP_CIPHERTEXT_BYTES
    {
        return Err(PgpError::ResourceLimit);
    }
    if armored_secrets.is_empty() {
        return Err(PgpError::Decryption("no secret keys provided".into()));
    }
    let signers = trusted_signers
        .iter()
        .map(|k| parse_public(k))
        .collect::<Result<Vec<_>, _>>()?;
    let mut last_err = None;
    for armored in armored_secrets {
        let secret = parse_secret(armored)?;
        let msg = Message::from_armor(Cursor::new(armored_ciphertext))
            .map_err(|e| PgpError::Decryption(format!("parse message: {e}")))?
            .0;
        if !msg.is_encrypted() {
            return Err(PgpError::Decryption(
                "an encrypted OpenPGP message is required".into(),
            ));
        }
        let pw = Password::empty();
        let ring = TheRing {
            secret_keys: vec![&secret],
            key_passwords: vec![&pw],
            decrypt_options: DecryptionOptions::new().set_seipdv1_read_mode(
                Seipdv1ReadMode::CheckFirst {
                    max_message_size: MAX_PGP_PLAINTEXT_BYTES + MAX_PGP_KEY_BYTES,
                },
            ),
            ..Default::default()
        };
        let decrypted = match msg.decrypt_the_ring(ring, true) {
            Ok((message, _)) => message,
            Err(e) => {
                last_err = Some(e.to_string());
                continue;
            }
        };
        let mut budget = MAX_PGP_DECOMPRESSION_BYTES;
        let mut message = normalize_message(decrypted, 0, &mut budget)?;
        let mut plaintext = read_bounded(&mut message, MAX_PGP_PLAINTEXT_BYTES)?;
        let signer_fingerprint = verify_message(&message, &signers, require_signature)?;
        return Ok(DecryptResult {
            plaintext: std::mem::take(&mut *plaintext),
            fingerprint_used: fingerprint_hex(&secret),
            signer_fingerprint,
        });
    }
    Err(PgpError::Decryption(
        last_err.unwrap_or_else(|| "no key matched".into()),
    ))
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, PgpError> {
    let mut output = Zeroizing::new(Vec::new());
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|e| PgpError::Decryption(e.to_string()))?;
    if output.len() > limit {
        return Err(PgpError::ResourceLimit);
    }
    Ok(output)
}

fn normalize_message<'a>(
    message: Message<'a>,
    depth: usize,
    budget: &mut usize,
) -> Result<Message<'a>, PgpError> {
    if depth >= MAX_PGP_LAYERS {
        return Err(PgpError::ResourceLimit);
    }
    match message {
        Message::Compressed { reader, .. } => {
            let decompressed = reader
                .decompress()
                .map_err(|e| PgpError::Decryption(e.to_string()))?;
            let bytes = read_bounded(
                decompressed,
                (*budget).min(MAX_PGP_PLAINTEXT_BYTES + MAX_PGP_KEY_BYTES),
            )?;
            *budget -= bytes.len();
            let inner = Message::from_bytes(Cursor::new(bytes))
                .map_err(|e| PgpError::Decryption(e.to_string()))?;
            normalize_message(inner, depth + 1, budget)
        }
        Message::Signed {
            reader:
                SignatureManyReader::Init {
                    packets,
                    hashers,
                    source,
                },
            is_nested,
        } => {
            if packets.len() > MAX_PGP_KEYS {
                return Err(PgpError::ResourceLimit);
            }
            let source = Box::new(normalize_message(*source, depth + 1, budget)?);
            Ok(Message::Signed {
                reader: SignatureManyReader::Init {
                    packets,
                    hashers,
                    source,
                },
                is_nested,
            })
        }
        Message::Literal { .. } => Ok(message),
        _ => Err(PgpError::Decryption(
            "unsupported nested OpenPGP message".into(),
        )),
    }
}

fn verify_message(
    message: &Message<'_>,
    signers: &[SignedPublicKey],
    required: bool,
) -> Result<Option<String>, PgpError> {
    match message {
        Message::Literal { .. } if !required => Ok(None),
        Message::Literal { .. } => Err(PgpError::Verification("message is unsigned".into())),
        Message::Signed { reader, .. } => {
            if signers.is_empty() {
                return Err(PgpError::Verification(
                    "signed messages require a trusted signer key".into(),
                ));
            }
            let now = Utc::now().timestamp();
            let mut fingerprint = None;
            for index in 0..reader.num_signatures() {
                let mut found = None;
                for signer in signers {
                    if !primary_is_active(signer, now) {
                        continue;
                    }
                    let primary = primary_signature(signer)
                        .filter(|certification| certification.key_flags().sign())
                        .and_then(|_| {
                            message
                                .verify_nested_explicit(index, &signer.primary_key)
                                .ok()
                        });
                    let signature = primary.or_else(|| {
                        signer
                            .public_subkeys
                            .iter()
                            .filter(|sk| subkey_is_active(sk, now, true))
                            .find_map(|sk| message.verify_nested_explicit(index, &sk.key).ok())
                    });
                    if let Some(signature) = signature {
                        if matches!(
                            signature.typ(),
                            Some(SignatureType::Binary | SignatureType::Text)
                        ) && signature_is_current(signature, now)
                        {
                            found = Some(fingerprint_hex_pub(signer));
                            break;
                        }
                    }
                }
                fingerprint = Some(found.ok_or_else(|| {
                    PgpError::Verification("invalid, expired or untrusted signature".into())
                })?);
            }
            if fingerprint.is_none() {
                return Err(PgpError::Verification("missing signature".into()));
            }
            verify_message(reader.get_ref(), signers, false)?;
            Ok(fingerprint)
        }
        _ => Err(PgpError::Verification(
            "message was not fully decoded".into(),
        )),
    }
}

fn format_uid(name: &str, email: &str) -> String {
    let name = name.trim();
    let email = email.trim();
    if name.is_empty() {
        format!("<{email}>")
    } else {
        format!("{name} <{email}>")
    }
}

fn parse_secret(input: &[u8]) -> Result<SignedSecretKey, PgpError> {
    if input.len() > MAX_PGP_KEY_BYTES {
        return Err(PgpError::ResourceLimit);
    }
    let key = if looks_armored(input) {
        let s = std::str::from_utf8(input).map_err(|e| PgpError::Parse(e.to_string()))?;
        SignedSecretKey::from_string(s)
            .map(|(k, _)| k)
            .map_err(|e| PgpError::Parse(e.to_string()))
    } else {
        SignedSecretKey::from_bytes(Cursor::new(input)).map_err(|e| PgpError::Parse(e.to_string()))
    }?;
    if !private_algorithm_allowed(&key.primary_key)
        || key
            .secret_subkeys
            .iter()
            .any(|s| !private_algorithm_allowed(&s.key))
    {
        return Err(PgpError::UnsafePrivateKey);
    }
    if key.secret_subkeys.len() > 32 {
        return Err(PgpError::ResourceLimit);
    }
    let mut kdf_budget = 1024 * 1024;
    check_secret_kdf(key.primary_key.secret_params(), &mut kdf_budget)?;
    for subkey in &key.secret_subkeys {
        check_secret_kdf(subkey.key.secret_params(), &mut kdf_budget)?;
    }
    validated_public(SignedPublicKey::from(key.clone()))?;
    Ok(key)
}

fn parse_public(input: &[u8]) -> Result<SignedPublicKey, PgpError> {
    if input.len() > MAX_PGP_KEY_BYTES {
        return Err(PgpError::ResourceLimit);
    }
    let key = if looks_armored(input) {
        let s = std::str::from_utf8(input).map_err(|e| PgpError::Parse(e.to_string()))?;
        SignedPublicKey::from_string(s)
            .map(|(k, _)| k)
            .map_err(|e| PgpError::Parse(e.to_string()))
    } else {
        SignedPublicKey::from_bytes(Cursor::new(input)).map_err(|e| PgpError::Parse(e.to_string()))
    }?;
    validated_public(key)
}

fn validated_public(mut key: SignedPublicKey) -> Result<SignedPublicKey, PgpError> {
    let primary = &key.primary_key;
    for user in &mut key.details.users {
        user.signatures.retain(|s| {
            s.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        });
    }
    key.details.users.retain(|u| !u.signatures.is_empty());
    for attribute in &mut key.details.user_attributes {
        attribute.signatures.retain(|s| {
            s.verify_certification(primary, Tag::UserAttribute, &attribute.attr)
                .is_ok()
        });
    }
    key.details
        .user_attributes
        .retain(|a| !a.signatures.is_empty());
    key.details
        .direct_signatures
        .retain(|s| s.verify_key(primary).is_ok());
    key.details
        .revocation_signatures
        .retain(|s| s.verify_key(primary).is_ok());
    if primary_signature(&key).is_none() {
        return Err(PgpError::Parse(
            "key has no valid self-certification".into(),
        ));
    }
    key.verify_bindings()
        .map_err(|e| PgpError::Parse(format!("invalid key signatures: {e}")))?;
    Ok(key)
}

fn looks_armored(input: &[u8]) -> bool {
    let prefix = &input[..input.len().min(32)];
    std::str::from_utf8(prefix)
        .map(|s| s.trim_start().starts_with("-----BEGIN"))
        .unwrap_or(false)
}

fn looks_like_public_only(input: &[u8]) -> bool {
    let prefix = &input[..input.len().min(64)];
    if let Ok(s) = std::str::from_utf8(prefix) {
        s.contains("BEGIN PGP PUBLIC KEY BLOCK")
    } else {
        false
    }
}

fn is_smartcard_stub(signed: &SignedSecretKey) -> bool {
    let params = signed.primary_key.secret_params();
    if !params.is_encrypted() {
        return false;
    }
    let dbg = format!("{params:?}");
    dbg.contains("GnuDummy") || dbg.contains("Mode: 1001")
}

fn fingerprint_hex(signed: &SignedSecretKey) -> String {
    hex_lower(signed.primary_key.fingerprint().as_bytes())
}

fn fingerprint_hex_pub(signed: &SignedPublicKey) -> String {
    hex_lower(signed.primary_key.fingerprint().as_bytes())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0x0f));
    }
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

struct InfoSnapshot {
    fingerprint: String,
    uids: Vec<String>,
    created_at_unix: i64,
    expires_at_unix: Option<i64>,
    is_expired: bool,
    is_revoked: bool,
}

fn collect_info(signed: &SignedSecretKey) -> Result<InfoSnapshot, PgpError> {
    let public = validated_public(SignedPublicKey::from(signed.clone()))?;
    let fingerprint = fingerprint_hex(signed);
    let uids = public
        .details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect();
    let created_at_unix = signed.primary_key.created_at().as_secs() as i64;
    let expires_at_unix = primary_expiration(&public);
    let now = Utc::now().timestamp();
    let is_expired = expires_at_unix.is_some_and(|e| e <= now);
    let is_revoked = !public.details.revocation_signatures.is_empty();
    Ok(InfoSnapshot {
        fingerprint,
        uids,
        created_at_unix,
        expires_at_unix,
        is_expired,
        is_revoked,
    })
}

fn signature_allows_encrypt(sig: &Signature) -> bool {
    let key_flags = sig.key_flags();
    key_flags.encrypt_comms() || key_flags.encrypt_storage()
}

fn primary_signature(key: &SignedPublicKey) -> Option<&Signature> {
    key.details
        .direct_signatures
        .iter()
        .chain(key.details.users.iter().flat_map(|u| &u.signatures))
        .filter(|sig| sig.created().is_some())
        .max_by_key(|sig| {
            (
                sig.created().map(|t| t.as_secs()),
                std::cmp::Reverse(
                    sig.key_expiration_time()
                        .filter(|d| d.as_secs() != 0)
                        .map_or(u32::MAX, |d| d.as_secs()),
                ),
            )
        })
}

fn primary_expiration(key: &SignedPublicKey) -> Option<i64> {
    primary_signature(key)
        .and_then(|sig| sig.key_expiration_time())
        .filter(|d| d.as_secs() != 0)
        .map(|d| i64::from(key.primary_key.created_at().as_secs()) + i64::from(d.as_secs()))
}

fn signature_is_current(signature: &Signature, now: i64) -> bool {
    let Some(created) = signature.created().map(|t| i64::from(t.as_secs())) else {
        return false;
    };
    created <= now
        && signature
            .signature_expiration_time()
            .filter(|d| d.as_secs() != 0)
            .is_none_or(|duration| created + i64::from(duration.as_secs()) > now)
        && signature.config().is_some_and(|c| {
            matches!(
                c.hash_alg,
                HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
            )
        })
}

fn primary_is_active(key: &SignedPublicKey, now: i64) -> bool {
    key.details.revocation_signatures.is_empty()
        && i64::from(key.primary_key.created_at().as_secs()) <= now
        && primary_expiration(key).is_none_or(|e| e > now)
        && primary_signature(key).is_some_and(|s| signature_is_current(s, now))
}

fn subkey_is_active(key: &pgp::composed::SignedPublicSubKey, now: i64, signing: bool) -> bool {
    if key
        .signatures
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
    {
        return false;
    }
    let Some(binding) = key
        .signatures
        .iter()
        .filter(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|s| s.created().map(|t| t.as_secs()))
    else {
        return false;
    };
    let created = i64::from(key.key.created_at().as_secs());
    created <= now
        && signature_is_current(binding, now)
        && binding
            .key_expiration_time()
            .filter(|d| d.as_secs() != 0)
            .is_none_or(|d| created + i64::from(d.as_secs()) > now)
        && if signing {
            binding.key_flags().sign()
        } else {
            private_algorithm_allowed(&key.key) && signature_allows_encrypt(binding)
        }
}

fn check_secret_kdf(params: &SecretParams, budget: &mut u32) -> Result<(), PgpError> {
    let SecretParams::Encrypted(encrypted) = params else {
        return Ok(());
    };
    let s2k = match encrypted.string_to_key_params() {
        S2kParams::Aead { s2k, .. }
        | S2kParams::Cfb { s2k, .. }
        | S2kParams::MalleableCfb { s2k, .. } => s2k,
        _ => return Err(PgpError::Parse("unsupported legacy key protection".into())),
    };
    let cost = match s2k {
        StringToKey::Argon2 { t, p, m_enc, .. } => {
            if *t == 0 || *t > 6 || *p == 0 || *p > 8 || *m_enc > 16 {
                return Err(PgpError::ResourceLimit);
            }
            (1u32 << *m_enc) * u32::from(*t)
        }
        StringToKey::IteratedAndSalted { count, .. } => {
            ((16 + u32::from(count & 15)) << (u32::from(count >> 4) + 6)) / 1024
        }
        StringToKey::Simple { .. } | StringToKey::Salted { .. } => 1,
        _ => return Err(PgpError::SmartcardStub),
    };
    *budget = budget.checked_sub(cost).ok_or(PgpError::ResourceLimit)?;
    Ok(())
}

fn private_algorithm_allowed(key: &impl KeyDetails) -> bool {
    match key.public_params() {
        PublicParams::Ed25519(_) | PublicParams::X25519(_) => true,
        PublicParams::EdDSALegacy(params) => params.curve() == ECCCurve::Ed25519Legacy,
        PublicParams::ECDH(params) => params.curve() == ECCCurve::Curve25519Legacy,
        _ => false,
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use pgp::packet::{SignatureConfig, Subpacket, SubpacketData};
    use pgp::types::{Duration, Timestamp};

    fn signed_ciphertext(sender: &GeneratedKey, recipient: &GeneratedKey) -> Vec<u8> {
        let secret = parse_secret(sender.armored_secret.as_bytes()).unwrap();
        let public = parse_public(recipient.armored_public.as_bytes()).unwrap();
        let mut builder =
            MessageBuilder::from_bytes(b"".as_slice(), b"authenticated body".to_vec())
                .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
        builder.sign(
            &secret.primary_key,
            Password::empty(),
            HashAlgorithm::Sha256,
        );
        builder.compression(CompressionAlgorithm::ZLIB);
        builder
            .encrypt_to_key(OsRng, &public.public_subkeys[0])
            .unwrap();
        builder
            .to_armored_string(OsRng, ArmorOptions::default())
            .unwrap()
            .into_bytes()
    }

    #[test]
    fn signed_messages_require_a_trusted_signer() {
        let sender = generate_key("Sender", "sender@example.invalid").unwrap();
        let recipient = generate_key("Recipient", "recipient@example.invalid").unwrap();
        let other = generate_key("Other", "other@example.invalid").unwrap();
        let ciphertext = signed_ciphertext(&sender, &recipient);
        let secrets = vec![recipient.armored_secret.as_bytes().to_vec()];
        assert!(matches!(
            decrypt_message(&secrets, &ciphertext),
            Err(PgpError::Verification(_))
        ));
        assert!(decrypt_message_verified(
            &secrets,
            &ciphertext,
            &[other.armored_public.as_bytes().to_vec()]
        )
        .is_err());
        let decrypted = decrypt_message_verified(
            &secrets,
            &ciphertext,
            &[sender.armored_public.as_bytes().to_vec()],
        )
        .unwrap();
        assert_eq!(decrypted.plaintext, b"authenticated body");
        assert_eq!(
            decrypted.signer_fingerprint.as_deref(),
            Some(sender.fingerprint.as_str())
        );
    }

    #[test]
    fn unsigned_messages_cannot_satisfy_verified_decryption() {
        let key = generate_key("Unsigned", "unsigned@example.invalid").unwrap();
        let public = vec![key.armored_public.as_bytes().to_vec()];
        let secrets = vec![key.armored_secret.as_bytes().to_vec()];
        let ciphertext = encrypt_to_recipients(&public, b"unsigned").unwrap();
        assert!(decrypt_message_verified(&secrets, ciphertext.as_bytes(), &public).is_err());
        assert!(decrypt_message(&secrets, ciphertext.as_bytes())
            .unwrap()
            .signer_fingerprint
            .is_none());
    }

    #[test]
    fn third_party_certifications_do_not_replace_self_certifications() {
        let alice = generate_key("Alice", "alice@example.invalid").unwrap();
        let mallory = generate_key("Mallory", "mallory@example.invalid").unwrap();
        let mut secret = parse_secret(alice.armored_secret.as_bytes()).unwrap();
        let signer = parse_secret(mallory.armored_secret.as_bytes()).unwrap();
        let public_primary = SignedPublicKey::from(secret.clone()).primary_key;
        let config = secret.details.users[0].signatures[0]
            .config()
            .unwrap()
            .clone();
        let third_party = config
            .sign_certification_third_party(
                &signer.primary_key,
                &Password::empty(),
                &public_primary,
                Tag::UserId,
                &secret.details.users[0].id,
            )
            .unwrap();
        secret.details.users[0].signatures.push(third_party);
        let public = SignedPublicKey::from(secret.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        let validated = parse_public(public.as_bytes()).unwrap();
        assert_eq!(validated.details.users[0].signatures.len(), 1);
        assert_eq!(fingerprint_hex_pub(&validated), alice.fingerprint);
        let imported = import_key(
            secret
                .to_armored_string(ArmorOptions::default())
                .unwrap()
                .as_bytes(),
            None,
        )
        .unwrap();
        assert_eq!(imported.fingerprint, alice.fingerprint);
        encrypt_to_recipients(&[public.into_bytes()], b"still Alice").unwrap();
    }

    #[test]
    fn expired_and_revoked_recipients_are_rejected() {
        let generated = generate_key("Old", "old@example.invalid").unwrap();
        let secret = parse_secret(generated.armored_secret.as_bytes()).unwrap();
        let mut public = SignedPublicKey::from(secret.clone());
        let mut config = public.details.users[0].signatures[0]
            .config()
            .unwrap()
            .clone();
        config.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(1))).unwrap(),
        );
        let certification = config
            .sign_certification(
                &secret.primary_key,
                &public.primary_key,
                &Password::empty(),
                Tag::UserId,
                &public.details.users[0].id,
            )
            .unwrap();
        public.details.users[0].signatures = vec![certification];
        let future = i64::from(public.primary_key.created_at().as_secs()) + 2;
        assert!(!primary_is_active(
            &validated_public(public).unwrap(),
            future
        ));
        let mut config = SignatureConfig::v4(
            SignatureType::KeyRevocation,
            secret.primary_key.algorithm(),
            HashAlgorithm::Sha256,
        );
        config.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        );
        let revocation = config
            .sign_key(
                &secret.primary_key,
                &Password::empty(),
                &SignedPublicKey::from(secret.clone()).primary_key,
            )
            .unwrap();
        let mut public = SignedPublicKey::from(secret.clone());
        public.details.revocation_signatures.push(revocation);
        let wire = public.to_armored_string(ArmorOptions::default()).unwrap();
        assert!(parse_public_info(wire.as_bytes()).unwrap().is_revoked);
        assert!(encrypt_to_recipients(&[wire.into_bytes()], b"must reject").is_err());
    }

    #[test]
    fn unsafe_private_key_algorithms_are_rejected() {
        for kind in [KeyType::Rsa(2048), KeyType::ECDSA(ECCCurve::P256)] {
            let secret = SecretKeyParamsBuilder::default()
                .key_type(kind)
                .can_sign(true)
                .can_certify(true)
                .primary_user_id("Fixture <fixture@example.invalid>".into())
                .build()
                .unwrap()
                .generate(OsRng)
                .unwrap();
            let wire = secret.to_armored_string(ArmorOptions::default()).unwrap();
            assert!(matches!(
                import_key(wire.as_bytes(), None),
                Err(PgpError::UnsafePrivateKey)
            ));
            assert!(matches!(
                decrypt_message(&[wire.into_bytes()], b"invalid"),
                Err(PgpError::UnsafePrivateKey)
            ));
        }
    }

    #[test]
    fn encryption_does_not_generate_unsafe_ephemeral_curve_keys() {
        let subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::P256))
            .can_encrypt(EncryptionCaps::All)
            .build()
            .unwrap();
        let secret = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Fixture <fixture@example.invalid>".into())
            .subkey(subkey)
            .build()
            .unwrap()
            .generate(OsRng)
            .unwrap();
        let public = SignedPublicKey::from(secret)
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        assert!(!parse_public_info(public.as_bytes()).unwrap().can_encrypt);
        assert!(
            encrypt_to_recipients(&[public.into_bytes()], b"must not use an unsafe curve").is_err()
        );
    }

    #[test]
    fn excessive_imported_argon2_parameters_are_rejected_before_derivation() {
        use pgp::crypto::aead::AeadAlgorithm;
        use pgp::types::{EncryptedSecretParams, KeyVersion};
        let mut secret = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_sign(true)
            .can_certify(true)
            .build()
            .unwrap()
            .generate(OsRng)
            .unwrap();
        let public = SignedPublicKey::from(secret.clone()).primary_key;
        let params = S2kParams::Aead {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            aead_mode: AeadAlgorithm::Ocb,
            s2k: StringToKey::Argon2 {
                salt: [0; 16],
                t: 3,
                p: 4,
                m_enc: 31,
            },
            nonce: vec![0; 15].into(),
        };
        let encrypted = EncryptedSecretParams::new(vec![0; 64].into(), params);
        secret.primary_key =
            pgp::packet::SecretKey::new(public, SecretParams::Encrypted(encrypted)).unwrap();
        let wire = secret.to_armored_string(ArmorOptions::default()).unwrap();
        assert!(matches!(
            import_key(wire.as_bytes(), Some("fixture")),
            Err(PgpError::ResourceLimit)
        ));
    }

    #[test]
    fn compressed_messages_obey_an_aggregate_byte_budget() {
        let mut builder = MessageBuilder::from_bytes(b"".as_slice(), vec![0x41; 1024 * 1024]);
        builder.compression(CompressionAlgorithm::ZLIB);
        let wire = builder.to_vec(OsRng).unwrap();
        let message = Message::from_bytes(Cursor::new(wire)).unwrap();
        assert!(matches!(
            normalize_message(message, 0, &mut 1024),
            Err(PgpError::ResourceLimit)
        ));
    }

    #[test]
    fn deeply_nested_messages_are_rejected() {
        let mut wire = MessageBuilder::from_bytes(b"".as_slice(), b"nested".to_vec())
            .to_vec(OsRng)
            .unwrap();
        for _ in 0..MAX_PGP_LAYERS {
            let length = wire.len() + 1;
            assert!(length < 192);
            let mut wrapped = vec![0xc8, length as u8, 0];
            wrapped.extend(wire);
            wire = wrapped;
        }
        let message = Message::from_bytes(Cursor::new(wire)).unwrap();
        let mut budget = MAX_PGP_DECOMPRESSION_BYTES;
        assert!(matches!(
            normalize_message(message, 0, &mut budget),
            Err(PgpError::ResourceLimit)
        ));
    }

    #[test]
    fn reject_substituted_encryption_subkey() {
        let alice = generate_key("Alice", "alice@example.invalid").unwrap();
        let mallory = generate_key("Mallory", "mallory@example.invalid").unwrap();
        let mut substituted = parse_public(alice.armored_public.as_bytes()).unwrap();
        let attacker = parse_public(mallory.armored_public.as_bytes()).unwrap();
        substituted.public_subkeys = attacker.public_subkeys;
        assert!(substituted.verify_bindings().is_err());
        let wire = substituted
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        let result = encrypt_to_recipients(&[wire.into_bytes()], b"intended only for Alice");
        if let Ok(ciphertext) = &result {
            let leaked = decrypt_message(
                &[mallory.armored_secret.as_bytes().to_vec()],
                ciphertext.as_bytes(),
            )
            .unwrap();
            assert_eq!(leaked.plaintext, b"intended only for Alice");
        }
        assert!(
            result.is_err(),
            "substituted subkey must be rejected before encryption"
        );
    }

    #[test]
    fn generate_and_roundtrip_encryption() {
        let key = generate_key("Alice", "alice@sanct.local").expect("gen");
        assert!(key.armored_public.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(key.armored_secret.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert_eq!(key.fingerprint.len(), 40);
        assert_eq!(key.primary_uid, "Alice <alice@sanct.local>");

        let plaintext = b"sealed by pgp";
        let armored = encrypt_to_recipients(&[key.armored_public.as_bytes().to_vec()], plaintext)
            .expect("encrypt");

        let decrypted = decrypt_message(
            &[key.armored_secret.as_bytes().to_vec()],
            armored.as_bytes(),
        )
        .expect("decrypt");
        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(decrypted.fingerprint_used, key.fingerprint);
    }

    #[test]
    fn import_unprotected_secret_key() {
        let gen = generate_key("Bob", "bob@sanct.local").expect("gen");
        let imported = import_key(gen.armored_secret.as_bytes(), None).expect("import");
        assert_eq!(imported.fingerprint, gen.fingerprint);
        assert!(!imported.uids.is_empty());
        assert!(!imported.is_expired);
        assert!(!imported.is_revoked);
    }

    #[test]
    fn export_then_reimport_with_passphrase() {
        let gen = generate_key("Carol", "carol@sanct.local").expect("gen");
        let exported = export_key(gen.armored_secret.as_bytes(), "correct horse").expect("export");
        assert!(exported.contains("BEGIN PGP PRIVATE KEY BLOCK"));

        let bad = import_key(exported.as_bytes(), Some("wrong"));
        assert!(matches!(bad, Err(PgpError::BadPassphrase)));

        let imported = import_key(exported.as_bytes(), Some("correct horse")).expect("reimport");
        assert_eq!(imported.fingerprint, gen.fingerprint);
    }

    #[test]
    fn import_public_only_is_refused() {
        let gen = generate_key("Dan", "dan@sanct.local").expect("gen");
        let err = import_key(gen.armored_public.as_bytes(), None);
        assert!(matches!(err, Err(PgpError::PublicOnly)));
    }

    #[test]
    fn parse_public_info_reports_uids_and_capabilities() {
        let gen = generate_key("Erin", "erin@sanct.local").expect("gen");
        let info = parse_public_info(gen.armored_public.as_bytes()).expect("parse");
        assert_eq!(info.fingerprint, gen.fingerprint);
        assert!(info.uids.iter().any(|u| u.contains("erin@sanct.local")));
        assert!(info.can_encrypt);
        assert!(!info.is_expired);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let alice = generate_key("Alice", "alice@sanct.local").unwrap();
        let bob = generate_key("Bob", "bob@sanct.local").unwrap();
        let armored = encrypt_to_recipients(
            &[alice.armored_public.as_bytes().to_vec()],
            b"only-for-alice",
        )
        .unwrap();
        let res = decrypt_message(
            &[bob.armored_secret.as_bytes().to_vec()],
            armored.as_bytes(),
        );
        assert!(res.is_err());
    }
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKey").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ImportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedKey").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DecryptResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptResult").finish_non_exhaustive()
    }
}
