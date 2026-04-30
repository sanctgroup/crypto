use std::io::Cursor;

use chrono::Utc;
use pgp::composed::{
    ArmorOptions, Deserializable, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{CompressionAlgorithm, PublicKeyTrait, S2kParams, SecretKeyTrait};
use pgp::{Message, Signature};
use rand::rngs::OsRng;
use smallvec::smallvec;

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
}

#[derive(Debug, Clone)]
pub struct GeneratedKey {
    pub armored_public: String,
    pub armored_secret: String,
    pub fingerprint: String,
    pub primary_uid: String,
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub fingerprint_used: String,
}

pub fn generate_key(name: &str, email: &str) -> Result<GeneratedKey, PgpError> {
    let primary_uid = format_uid(name, email);

    let subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::ECDH(ECCCurve::Curve25519))
        .can_encrypt(true)
        .passphrase(None)
        .build()
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::EdDSALegacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(primary_uid.clone())
        .passphrase(None)
        .preferred_symmetric_algorithms(smallvec![
            SymmetricKeyAlgorithm::AES256,
            SymmetricKeyAlgorithm::AES192,
            SymmetricKeyAlgorithm::AES128,
        ])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256, HashAlgorithm::SHA2_512,])
        .preferred_compression_algorithms(smallvec![
            CompressionAlgorithm::ZLIB,
            CompressionAlgorithm::ZIP,
        ])
        .subkey(subkey)
        .build()
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let mut rng = OsRng;
    let secret = params
        .generate(rng)
        .map_err(|e| PgpError::Generation(e.to_string()))?;
    let signed_secret = secret
        .sign(&mut rng, String::new)
        .map_err(|e| PgpError::Generation(e.to_string()))?;

    let public_key = signed_secret.public_key();
    let signed_public = public_key
        .sign(&mut rng, &signed_secret, String::new)
        .map_err(|e| PgpError::Generation(e.to_string()))?;

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
        let pw = passphrase.unwrap_or("").to_string();
        let pw_for_check = pw.clone();
        signed
            .primary_key
            .unlock(|| pw_for_check.clone(), |_| Ok(()))
            .map_err(|_| PgpError::BadPassphrase)?;

        let pw_primary = pw.clone();
        signed
            .primary_key
            .remove_password(|| pw_primary.clone())
            .map_err(|_| PgpError::BadPassphrase)?;
        for subkey in signed.secret_subkeys.iter_mut() {
            if subkey.key.secret_params().is_encrypted() {
                let pw_sub = pw.clone();
                subkey
                    .key
                    .remove_password(|| pw_sub.clone())
                    .map_err(|_| PgpError::BadPassphrase)?;
            }
        }
    }

    let armored_secret_unprotected = signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Parse(e.to_string()))?;
    let mut rng = OsRng;
    let signed_public = signed
        .public_key()
        .sign(&mut rng, &signed, String::new)
        .map_err(|e| PgpError::Parse(format!("re-sign public: {e}")))?;
    let armored_public_signed = signed_public
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Parse(e.to_string()))?;

    let info = collect_info(&signed);
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
    if passphrase.is_empty() {
        return Err(PgpError::Export(
            "export passphrase must not be empty".into(),
        ));
    }
    let mut signed = parse_secret(unprotected_armored)?;
    let rng = OsRng;

    let key_version = signed.primary_key.version();
    let s2k = S2kParams::new_default(rng, key_version);
    let pw_primary = passphrase.to_string();
    signed
        .primary_key
        .set_password_with_s2k(|| pw_primary.clone(), s2k)
        .map_err(|e| PgpError::Export(e.to_string()))?;

    for subkey in signed.secret_subkeys.iter_mut() {
        let sub_s2k = S2kParams::new_default(rng, key_version);
        let pw_sub = passphrase.to_string();
        subkey
            .key
            .set_password_with_s2k(|| pw_sub.clone(), sub_s2k)
            .map_err(|e| PgpError::Export(e.to_string()))?;
    }

    signed
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Export(e.to_string()))
}

pub fn parse_public_info(input: &[u8]) -> Result<PublicKeyInfo, PgpError> {
    let signed = parse_public(input)?;
    let fingerprint = fingerprint_hex_pub(&signed);
    let uids = signed
        .details
        .users
        .iter()
        .map(|u| u.id.id().to_string())
        .collect::<Vec<_>>();
    let created_at_unix = signed.primary_key.created_at().timestamp();
    let expires_at_unix = signed
        .details
        .key_expiration_time()
        .map(|d| created_at_unix.saturating_add(d.num_seconds()));
    let now = Utc::now().timestamp();
    let is_expired = expires_at_unix.is_some_and(|e| e <= now);
    let is_revoked = !signed.details.revocation_signatures.is_empty();
    let can_encrypt = signed
        .public_subkeys
        .iter()
        .any(|sk| sk.signatures.iter().any(signature_allows_encrypt))
        || signed
            .details
            .users
            .iter()
            .any(|u| u.signatures.iter().any(signature_allows_encrypt));

    Ok(PublicKeyInfo {
        fingerprint,
        uids,
        created_at_unix,
        expires_at_unix,
        is_expired,
        is_revoked,
        can_encrypt,
    })
}

pub fn encrypt_to_recipients(
    armored_publics: &[Vec<u8>],
    plaintext: &[u8],
) -> Result<String, PgpError> {
    if armored_publics.is_empty() {
        return Err(PgpError::Encryption("no recipients".into()));
    }
    let mut keys = Vec::with_capacity(armored_publics.len());
    for k in armored_publics {
        keys.push(parse_public(k)?);
    }
    let mut encryption_subkeys = Vec::new();
    for k in keys.iter() {
        let subkey = k
            .public_subkeys
            .iter()
            .find(|sk| sk.signatures.iter().any(signature_allows_encrypt))
            .ok_or_else(|| PgpError::Encryption("recipient has no encryption subkey".into()))?;
        encryption_subkeys.push(subkey);
    }

    let msg = Message::new_literal_bytes(b"" as &[u8], plaintext);
    let encrypted = msg
        .encrypt_to_keys_seipdv1(
            &mut OsRng,
            SymmetricKeyAlgorithm::AES256,
            &encryption_subkeys,
        )
        .map_err(|e| PgpError::Encryption(e.to_string()))?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| PgpError::Encryption(e.to_string()))
}

pub fn decrypt_message(
    armored_secrets: &[Vec<u8>],
    armored_ciphertext: &[u8],
) -> Result<DecryptResult, PgpError> {
    if armored_secrets.is_empty() {
        return Err(PgpError::Decryption("no secret keys provided".into()));
    }
    let armored_str = std::str::from_utf8(armored_ciphertext)
        .map_err(|e| PgpError::Decryption(format!("ciphertext utf8: {e}")))?;
    let (msg, _headers) = Message::from_string(armored_str)
        .map_err(|e| PgpError::Decryption(format!("parse message: {e}")))?;

    let mut last_err: Option<String> = None;
    for armored in armored_secrets {
        let secret = match parse_secret(armored) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("parse secret: {e}"));
                continue;
            }
        };
        let fp = fingerprint_hex(&secret);
        let key_pw = || String::new();
        match msg.decrypt(key_pw, &[&secret]) {
            Ok((decrypted, _ids)) => {
                let literal = extract_literal(decrypted)
                    .map_err(|e: String| PgpError::Decryption(format!("extract literal: {e}")))?;
                return Ok(DecryptResult {
                    plaintext: literal,
                    fingerprint_used: fp,
                });
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
    }
    Err(PgpError::Decryption(
        last_err.unwrap_or_else(|| "no key matched".into()),
    ))
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
    if looks_armored(input) {
        let s = std::str::from_utf8(input).map_err(|e| PgpError::Parse(e.to_string()))?;
        SignedSecretKey::from_string(s)
            .map(|(k, _)| k)
            .map_err(|e| PgpError::Parse(e.to_string()))
    } else {
        SignedSecretKey::from_bytes(Cursor::new(input)).map_err(|e| PgpError::Parse(e.to_string()))
    }
}

fn parse_public(input: &[u8]) -> Result<SignedPublicKey, PgpError> {
    if looks_armored(input) {
        let s = std::str::from_utf8(input).map_err(|e| PgpError::Parse(e.to_string()))?;
        SignedPublicKey::from_string(s)
            .map(|(k, _)| k)
            .map_err(|e| PgpError::Parse(e.to_string()))
    } else {
        SignedPublicKey::from_bytes(Cursor::new(input)).map_err(|e| PgpError::Parse(e.to_string()))
    }
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

fn collect_info(signed: &SignedSecretKey) -> InfoSnapshot {
    let fingerprint = fingerprint_hex(signed);
    let uids = signed
        .details
        .users
        .iter()
        .map(|u| u.id.id().to_string())
        .collect();
    let created_at_unix = signed.primary_key.created_at().timestamp();
    let expires_at_unix = signed
        .details
        .key_expiration_time()
        .map(|d| created_at_unix.saturating_add(d.num_seconds()));
    let now = Utc::now().timestamp();
    let is_expired = expires_at_unix.is_some_and(|e| e <= now);
    let is_revoked = !signed.details.revocation_signatures.is_empty();
    InfoSnapshot {
        fingerprint,
        uids,
        created_at_unix,
        expires_at_unix,
        is_expired,
        is_revoked,
    }
}

fn signature_allows_encrypt(sig: &Signature) -> bool {
    let key_flags = sig.key_flags();
    key_flags.encrypt_comms() || key_flags.encrypt_storage()
}

fn extract_literal(msg: Message) -> Result<Vec<u8>, String> {
    match msg {
        Message::Literal(lit) => Ok(lit.data().to_vec()),
        Message::Compressed(c) => {
            let inner = Message::from_bytes(c.decompress().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            extract_literal(inner)
        }
        Message::Signed { message, .. } => match message {
            Some(inner) => extract_literal(*inner),
            None => Err("signed message had no body".into()),
        },
        Message::Encrypted { .. } => Err("nested encrypted message".into()),
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

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
