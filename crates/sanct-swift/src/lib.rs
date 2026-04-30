uniffi::setup_scaffolding!("sanct_swift");

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SanctCryptoError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("pgp/{code}: {message}")]
    Pgp { code: String, message: String },
}

impl From<sanct_crypto::CryptoError> for SanctCryptoError {
    fn from(e: sanct_crypto::CryptoError) -> Self {
        SanctCryptoError::Crypto(e.to_string())
    }
}

fn pgp_err(e: sanct_crypto::pgp::PgpError) -> SanctCryptoError {
    use sanct_crypto::pgp::PgpError;
    let code = match &e {
        PgpError::Parse(_) => "parse",
        PgpError::SmartcardStub => "smartcard_stub",
        PgpError::PublicOnly => "public_only",
        PgpError::BadPassphrase => "bad_passphrase",
        PgpError::Generation(_) => "generation",
        PgpError::Encryption(_) => "encryption",
        PgpError::Decryption(_) => "decryption",
        PgpError::Export(_) => "export",
    };
    SanctCryptoError::Pgp {
        code: code.to_string(),
        message: e.to_string(),
    }
}

#[derive(uniffi::Record)]
pub struct IdentityKeys {
    pub x25519_public: Vec<u8>,
    pub mlkem768_public: Vec<u8>,
    pub encrypted_private_bundle: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PrivateKeys {
    pub x25519_secret: Vec<u8>,
    pub mlkem768_secret: Vec<u8>,
    pub threading_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct RecoveryResult {
    pub phrase: String,
    pub recovery_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PgpGeneratedKey {
    pub armored_public: String,
    pub armored_secret: String,
    pub fingerprint: String,
    pub primary_uid: String,
}

#[derive(uniffi::Record)]
pub struct PgpImportedKey {
    pub armored_secret: String,
    pub armored_public: String,
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
}

#[derive(uniffi::Record)]
pub struct PgpPublicKeyInfo {
    pub fingerprint: String,
    pub uids: Vec<String>,
    pub created_at_unix: i64,
    pub expires_at_unix: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub can_encrypt: bool,
}

#[derive(uniffi::Record)]
pub struct PgpDecryptResult {
    pub plaintext: Vec<u8>,
    pub fingerprint_used: String,
}

#[uniffi::export]
pub fn generate_salt() -> Vec<u8> {
    sanct_crypto::password::generate_salt().to_vec()
}

#[uniffi::export]
pub fn derive_master_key(password: String, salt: Vec<u8>) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::password::derive_master_key(password.as_bytes(), &salt)?.to_vec())
}

#[uniffi::export]
pub fn generate_identity_keys(master_key: Vec<u8>) -> Result<IdentityKeys, SanctCryptoError> {
    let bundle = sanct_crypto::keys::generate_identity_keys(&master_key)?;
    Ok(IdentityKeys {
        x25519_public: bundle.x25519_public,
        mlkem768_public: bundle.mlkem768_public,
        encrypted_private_bundle: bundle.encrypted_private_bundle,
    })
}

#[uniffi::export]
pub fn decrypt_private_keys(
    master_key: Vec<u8>,
    encrypted_bundle: Vec<u8>,
) -> Result<PrivateKeys, SanctCryptoError> {
    let keys = sanct_crypto::keys::decrypt_private_bundle(&master_key, &encrypted_bundle)?;
    Ok(PrivateKeys {
        x25519_secret: keys.x25519_secret.clone(),
        mlkem768_secret: keys.mlkem768_secret.clone(),
        threading_key: keys.threading_key.clone(),
    })
}

#[uniffi::export]
pub fn encrypt_message(
    recipient_x25519_pub: Vec<u8>,
    recipient_mlkem_pub: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    let sealed = sanct_crypto::envelope::SealedEnvelope::seal(
        &recipient_x25519_pub,
        &recipient_mlkem_pub,
        &plaintext,
    )?;
    Ok(sealed.to_bytes())
}

#[uniffi::export]
pub fn decrypt_message(
    x25519_private: Vec<u8>,
    mlkem_private: Vec<u8>,
    sealed_bytes: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    let sealed = sanct_crypto::envelope::SealedEnvelope::from_bytes(&sealed_bytes)?;
    Ok(sealed.open(&x25519_private, &mlkem_private)?)
}

#[uniffi::export]
pub fn seal_for_recipient(
    recipient_x25519_pub: Vec<u8>,
    recipient_mlkem_pub: Vec<u8>,
    plaintext_body: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    encrypt_message(recipient_x25519_pub, recipient_mlkem_pub, plaintext_body)
}

#[uniffi::export]
pub fn seal_metadata_for_recipient(
    recipient_x25519_pub: Vec<u8>,
    recipient_mlkem_pub: Vec<u8>,
    metadata_json: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    encrypt_message(recipient_x25519_pub, recipient_mlkem_pub, metadata_json)
}

#[uniffi::export]
pub fn encrypt_draft(
    own_x25519_pub: Vec<u8>,
    own_mlkem_pub: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    encrypt_message(own_x25519_pub, own_mlkem_pub, plaintext)
}

#[uniffi::export]
pub fn encrypt_metadata(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::symmetric::encrypt(&key, &plaintext)?)
}

#[uniffi::export]
pub fn decrypt_metadata(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::symmetric::decrypt(&key, &ciphertext)?)
}

#[uniffi::export]
pub fn compute_subject_hash(threading_key: Vec<u8>, subject: String) -> Vec<u8> {
    sanct_crypto::keys::compute_subject_hash(&threading_key, &subject)
}

#[uniffi::export]
pub fn generate_recovery_phrase() -> RecoveryResult {
    let rp = sanct_crypto::recovery::generate_recovery_phrase();
    RecoveryResult {
        phrase: rp.phrase,
        recovery_key: rp.recovery_key.to_vec(),
    }
}

#[uniffi::export]
pub fn recovery_key_from_phrase(phrase: String) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::recovery::recovery_key_from_phrase(&phrase)?.to_vec())
}

#[uniffi::export]
pub fn hash_recovery_key(recovery_key: Vec<u8>) -> Vec<u8> {
    sanct_crypto::recovery::hash_recovery_key(&recovery_key)
}

#[uniffi::export]
pub fn encrypt_bundle_for_recovery(
    recovery_key: Vec<u8>,
    private_bundle_plaintext: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::recovery::encrypt_bundle_for_recovery(
        &recovery_key,
        &private_bundle_plaintext,
    )?)
}

#[uniffi::export]
pub fn decrypt_bundle_with_recovery(
    recovery_key: Vec<u8>,
    recovery_encrypted_bundle: Vec<u8>,
) -> Result<Vec<u8>, SanctCryptoError> {
    Ok(sanct_crypto::recovery::decrypt_bundle_with_recovery(
        &recovery_key,
        &recovery_encrypted_bundle,
    )?)
}

#[uniffi::export]
pub fn pgp_generate_key(name: String, email: String) -> Result<PgpGeneratedKey, SanctCryptoError> {
    let key = sanct_crypto::pgp::generate_key(&name, &email).map_err(pgp_err)?;
    Ok(PgpGeneratedKey {
        armored_public: key.armored_public,
        armored_secret: key.armored_secret,
        fingerprint: key.fingerprint,
        primary_uid: key.primary_uid,
    })
}

#[uniffi::export]
pub fn pgp_import_key(
    input: Vec<u8>,
    passphrase: Option<String>,
) -> Result<PgpImportedKey, SanctCryptoError> {
    let imported = sanct_crypto::pgp::import_key(&input, passphrase.as_deref()).map_err(pgp_err)?;
    Ok(PgpImportedKey {
        armored_secret: imported.armored_secret_unprotected,
        armored_public: imported.armored_public,
        fingerprint: imported.fingerprint,
        uids: imported.uids,
        created_at_unix: imported.created_at_unix,
        expires_at_unix: imported.expires_at_unix,
        is_expired: imported.is_expired,
        is_revoked: imported.is_revoked,
    })
}

#[uniffi::export]
pub fn pgp_export_key(
    unprotected_armored: Vec<u8>,
    passphrase: String,
) -> Result<String, SanctCryptoError> {
    sanct_crypto::pgp::export_key(&unprotected_armored, &passphrase).map_err(pgp_err)
}

#[uniffi::export]
pub fn pgp_key_info(armored_public: Vec<u8>) -> Result<PgpPublicKeyInfo, SanctCryptoError> {
    let info = sanct_crypto::pgp::parse_public_info(&armored_public).map_err(pgp_err)?;
    Ok(PgpPublicKeyInfo {
        fingerprint: info.fingerprint,
        uids: info.uids,
        created_at_unix: info.created_at_unix,
        expires_at_unix: info.expires_at_unix,
        is_expired: info.is_expired,
        is_revoked: info.is_revoked,
        can_encrypt: info.can_encrypt,
    })
}

#[uniffi::export]
pub fn pgp_encrypt_to_recipients(
    armored_publics: Vec<Vec<u8>>,
    plaintext: Vec<u8>,
) -> Result<String, SanctCryptoError> {
    sanct_crypto::pgp::encrypt_to_recipients(&armored_publics, &plaintext).map_err(pgp_err)
}

#[uniffi::export]
pub fn pgp_decrypt_message(
    armored_secrets: Vec<Vec<u8>>,
    armored_ciphertext: Vec<u8>,
) -> Result<PgpDecryptResult, SanctCryptoError> {
    let res = sanct_crypto::pgp::decrypt_message(&armored_secrets, &armored_ciphertext)
        .map_err(pgp_err)?;
    Ok(PgpDecryptResult {
        plaintext: res.plaintext,
        fingerprint_used: res.fingerprint_used,
    })
}
