use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct IdentityKeys {
    pub(crate) x25519_public: Vec<u8>,
    pub(crate) mlkem768_public: Vec<u8>,
    pub(crate) encrypted_private_bundle: Vec<u8>,
}

#[wasm_bindgen]
impl IdentityKeys {
    #[wasm_bindgen(getter, js_name = "x25519Public")]
    pub fn x25519_public(&self) -> Vec<u8> {
        self.x25519_public.clone()
    }

    #[wasm_bindgen(getter, js_name = "mlkem768Public")]
    pub fn mlkem768_public(&self) -> Vec<u8> {
        self.mlkem768_public.clone()
    }

    #[wasm_bindgen(getter, js_name = "encryptedPrivateBundle")]
    pub fn encrypted_private_bundle(&self) -> Vec<u8> {
        self.encrypted_private_bundle.clone()
    }
}

#[wasm_bindgen]
pub struct PrivateKeys {
    pub(crate) x25519_secret: Vec<u8>,
    pub(crate) mlkem768_secret: Vec<u8>,
    pub(crate) threading_key: Vec<u8>,
}

#[wasm_bindgen]
impl PrivateKeys {
    #[wasm_bindgen(getter, js_name = "x25519Secret")]
    pub fn x25519_secret(&self) -> Vec<u8> {
        self.x25519_secret.clone()
    }

    #[wasm_bindgen(getter, js_name = "mlkem768Secret")]
    pub fn mlkem768_secret(&self) -> Vec<u8> {
        self.mlkem768_secret.clone()
    }

    #[wasm_bindgen(getter, js_name = "threadingKey")]
    pub fn threading_key(&self) -> Vec<u8> {
        self.threading_key.clone()
    }
}

#[wasm_bindgen]
pub struct RecoveryResult {
    pub(crate) phrase: String,
    pub(crate) recovery_key: Vec<u8>,
}

#[wasm_bindgen]
impl RecoveryResult {
    #[wasm_bindgen(getter)]
    pub fn phrase(&self) -> String {
        self.phrase.clone()
    }

    #[wasm_bindgen(getter, js_name = "recoveryKey")]
    pub fn recovery_key(&self) -> Vec<u8> {
        self.recovery_key.clone()
    }
}

#[wasm_bindgen(js_name = "generateSalt")]
pub fn generate_salt() -> Vec<u8> {
    sanct_crypto::password::generate_salt().to_vec()
}

#[wasm_bindgen(js_name = "deriveMasterKey")]
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::password::derive_master_key(password.as_bytes(), salt)?.to_vec())
}

#[wasm_bindgen(js_name = "generateIdentityKeys")]
pub fn generate_identity_keys(master_key: &[u8]) -> Result<IdentityKeys, JsError> {
    let bundle = sanct_crypto::keys::generate_identity_keys(master_key)?;
    Ok(IdentityKeys {
        x25519_public: bundle.x25519_public,
        mlkem768_public: bundle.mlkem768_public,
        encrypted_private_bundle: bundle.encrypted_private_bundle,
    })
}

#[wasm_bindgen(js_name = "decryptPrivateKeys")]
pub fn decrypt_private_keys(
    master_key: &[u8],
    encrypted_bundle: &[u8],
) -> Result<PrivateKeys, JsError> {
    let keys = sanct_crypto::keys::decrypt_private_bundle(master_key, encrypted_bundle)?;
    Ok(PrivateKeys {
        x25519_secret: keys.x25519_secret.clone(),
        mlkem768_secret: keys.mlkem768_secret.clone(),
        threading_key: keys.threading_key.clone(),
    })
}

#[wasm_bindgen(js_name = "encryptMessage")]
pub fn encrypt_message(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_pub: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    let sealed = sanct_crypto::envelope::SealedEnvelope::seal(
        recipient_x25519_pub,
        recipient_mlkem_pub,
        plaintext,
    )?;
    Ok(sealed.to_bytes())
}

#[wasm_bindgen(js_name = "decryptMessage")]
pub fn decrypt_message(
    x25519_private: &[u8],
    mlkem_private: &[u8],
    sealed_bytes: &[u8],
) -> Result<Vec<u8>, JsError> {
    let sealed = sanct_crypto::envelope::SealedEnvelope::from_bytes(sealed_bytes)?;
    Ok(sealed.open(x25519_private, mlkem_private)?)
}

#[wasm_bindgen(js_name = "sealForRecipient")]
pub fn seal_for_recipient(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_pub: &[u8],
    plaintext_body: &[u8],
) -> Result<Vec<u8>, JsError> {
    encrypt_message(recipient_x25519_pub, recipient_mlkem_pub, plaintext_body)
}

#[wasm_bindgen(js_name = "sealMetadataForRecipient")]
pub fn seal_metadata_for_recipient(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_pub: &[u8],
    metadata_json: &[u8],
) -> Result<Vec<u8>, JsError> {
    encrypt_message(recipient_x25519_pub, recipient_mlkem_pub, metadata_json)
}

#[wasm_bindgen(js_name = "encryptDraft")]
pub fn encrypt_draft(
    own_x25519_pub: &[u8],
    own_mlkem_pub: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    encrypt_message(own_x25519_pub, own_mlkem_pub, plaintext)
}

#[wasm_bindgen(js_name = "encryptMetadata")]
pub fn encrypt_metadata(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::symmetric::encrypt(key, plaintext)?)
}

#[wasm_bindgen(js_name = "decryptMetadata")]
pub fn decrypt_metadata(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::symmetric::decrypt(key, ciphertext)?)
}

#[wasm_bindgen(js_name = "computeSubjectHash")]
pub fn compute_subject_hash(threading_key: &[u8], subject: &str) -> Vec<u8> {
    sanct_crypto::keys::compute_subject_hash(threading_key, subject)
}

#[wasm_bindgen(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> RecoveryResult {
    let rp = sanct_crypto::recovery::generate_recovery_phrase();
    RecoveryResult {
        phrase: rp.phrase,
        recovery_key: rp.recovery_key.to_vec(),
    }
}

#[wasm_bindgen(js_name = "recoveryKeyFromPhrase")]
pub fn recovery_key_from_phrase(phrase: &str) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::recovery::recovery_key_from_phrase(phrase)?.to_vec())
}

#[wasm_bindgen(js_name = "hashRecoveryKey")]
pub fn hash_recovery_key(recovery_key: &[u8]) -> Vec<u8> {
    sanct_crypto::recovery::hash_recovery_key(recovery_key)
}

#[wasm_bindgen(js_name = "encryptBundleForRecovery")]
pub fn encrypt_bundle_for_recovery(
    recovery_key: &[u8],
    private_bundle_plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::recovery::encrypt_bundle_for_recovery(
        recovery_key,
        private_bundle_plaintext,
    )?)
}

#[wasm_bindgen(js_name = "decryptBundleWithRecovery")]
pub fn decrypt_bundle_with_recovery(
    recovery_key: &[u8],
    recovery_encrypted_bundle: &[u8],
) -> Result<Vec<u8>, JsError> {
    Ok(sanct_crypto::recovery::decrypt_bundle_with_recovery(
        recovery_key,
        recovery_encrypted_bundle,
    )?)
}

#[wasm_bindgen]
pub struct PgpGeneratedKey {
    pub(crate) armored_public: String,
    pub(crate) armored_secret: String,
    pub(crate) fingerprint: String,
    pub(crate) primary_uid: String,
}

#[wasm_bindgen]
impl PgpGeneratedKey {
    #[wasm_bindgen(getter, js_name = "armoredPublic")]
    pub fn armored_public(&self) -> String {
        self.armored_public.clone()
    }
    #[wasm_bindgen(getter, js_name = "armoredSecret")]
    pub fn armored_secret(&self) -> String {
        self.armored_secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
    #[wasm_bindgen(getter, js_name = "primaryUid")]
    pub fn primary_uid(&self) -> String {
        self.primary_uid.clone()
    }
}

#[wasm_bindgen]
pub struct PgpImportedKey {
    pub(crate) armored_secret: String,
    pub(crate) armored_public: String,
    pub(crate) fingerprint: String,
    pub(crate) uids: Vec<String>,
    pub(crate) created_at_unix: i64,
    pub(crate) expires_at_unix: Option<i64>,
    pub(crate) is_expired: bool,
    pub(crate) is_revoked: bool,
}

#[wasm_bindgen]
impl PgpImportedKey {
    #[wasm_bindgen(getter, js_name = "armoredSecret")]
    pub fn armored_secret(&self) -> String {
        self.armored_secret.clone()
    }
    #[wasm_bindgen(getter, js_name = "armoredPublic")]
    pub fn armored_public(&self) -> String {
        self.armored_public.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn uids(&self) -> Vec<String> {
        self.uids.clone()
    }
    #[wasm_bindgen(getter, js_name = "createdAt")]
    pub fn created_at(&self) -> i64 {
        self.created_at_unix
    }
    #[wasm_bindgen(getter, js_name = "expiresAt")]
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at_unix
    }
    #[wasm_bindgen(getter, js_name = "isExpired")]
    pub fn is_expired(&self) -> bool {
        self.is_expired
    }
    #[wasm_bindgen(getter, js_name = "isRevoked")]
    pub fn is_revoked(&self) -> bool {
        self.is_revoked
    }
}

#[wasm_bindgen]
pub struct PgpPublicKeyInfo {
    pub(crate) fingerprint: String,
    pub(crate) uids: Vec<String>,
    pub(crate) created_at_unix: i64,
    pub(crate) expires_at_unix: Option<i64>,
    pub(crate) is_expired: bool,
    pub(crate) is_revoked: bool,
    pub(crate) can_encrypt: bool,
}

#[wasm_bindgen]
impl PgpPublicKeyInfo {
    #[wasm_bindgen(getter)]
    pub fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn uids(&self) -> Vec<String> {
        self.uids.clone()
    }
    #[wasm_bindgen(getter, js_name = "createdAt")]
    pub fn created_at(&self) -> i64 {
        self.created_at_unix
    }
    #[wasm_bindgen(getter, js_name = "expiresAt")]
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at_unix
    }
    #[wasm_bindgen(getter, js_name = "isExpired")]
    pub fn is_expired(&self) -> bool {
        self.is_expired
    }
    #[wasm_bindgen(getter, js_name = "isRevoked")]
    pub fn is_revoked(&self) -> bool {
        self.is_revoked
    }
    #[wasm_bindgen(getter, js_name = "canEncrypt")]
    pub fn can_encrypt(&self) -> bool {
        self.can_encrypt
    }
}

#[wasm_bindgen]
pub struct PgpDecryptResult {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) fingerprint_used: String,
}

#[wasm_bindgen]
impl PgpDecryptResult {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }
    #[wasm_bindgen(getter, js_name = "fingerprintUsed")]
    pub fn fingerprint_used(&self) -> String {
        self.fingerprint_used.clone()
    }
}

fn pgp_to_jserror(e: sanct_crypto::pgp::PgpError) -> JsError {
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
    JsError::new(&format!("{code}: {e}"))
}

#[wasm_bindgen(js_name = "pgpGenerateKey")]
pub fn pgp_generate_key(name: &str, email: &str) -> Result<PgpGeneratedKey, JsError> {
    let key = sanct_crypto::pgp::generate_key(name, email).map_err(pgp_to_jserror)?;
    Ok(PgpGeneratedKey {
        armored_public: key.armored_public,
        armored_secret: key.armored_secret,
        fingerprint: key.fingerprint,
        primary_uid: key.primary_uid,
    })
}

#[wasm_bindgen(js_name = "pgpImportKey")]
pub fn pgp_import_key(
    input: &[u8],
    passphrase: Option<String>,
) -> Result<PgpImportedKey, JsError> {
    let imported = sanct_crypto::pgp::import_key(input, passphrase.as_deref())
        .map_err(pgp_to_jserror)?;
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

#[wasm_bindgen(js_name = "pgpExportKey")]
pub fn pgp_export_key(unprotected_armored: &[u8], passphrase: &str) -> Result<String, JsError> {
    sanct_crypto::pgp::export_key(unprotected_armored, passphrase).map_err(pgp_to_jserror)
}

#[wasm_bindgen(js_name = "pgpKeyInfo")]
pub fn pgp_key_info(armored_public: &[u8]) -> Result<PgpPublicKeyInfo, JsError> {
    let info = sanct_crypto::pgp::parse_public_info(armored_public).map_err(pgp_to_jserror)?;
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

#[wasm_bindgen(js_name = "pgpEncryptToRecipients")]
pub fn pgp_encrypt_to_recipients(
    armored_publics: Vec<js_sys::Uint8Array>,
    plaintext: &[u8],
) -> Result<String, JsError> {
    let publics: Vec<Vec<u8>> = armored_publics.iter().map(|a| a.to_vec()).collect();
    sanct_crypto::pgp::encrypt_to_recipients(&publics, plaintext).map_err(pgp_to_jserror)
}

#[wasm_bindgen(js_name = "pgpDecryptMessage")]
pub fn pgp_decrypt_message(
    armored_secrets: Vec<js_sys::Uint8Array>,
    armored_ciphertext: &[u8],
) -> Result<PgpDecryptResult, JsError> {
    let secrets: Vec<Vec<u8>> = armored_secrets.iter().map(|a| a.to_vec()).collect();
    let res = sanct_crypto::pgp::decrypt_message(&secrets, armored_ciphertext)
        .map_err(pgp_to_jserror)?;
    Ok(PgpDecryptResult {
        plaintext: res.plaintext,
        fingerprint_used: res.fingerprint_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_and_identity_roundtrip() {
        let salt = generate_salt();
        let master_key = derive_master_key("correct horse battery staple", &salt).unwrap();

        let identity = generate_identity_keys(&master_key).unwrap();
        let private =
            decrypt_private_keys(&master_key, &identity.encrypted_private_bundle).unwrap();

        assert_eq!(identity.x25519_public.len(), 32);
        assert!(!identity.mlkem768_public.is_empty());
        assert_eq!(private.x25519_secret.len(), 32);
        assert!(!private.mlkem768_secret.is_empty());
        assert_eq!(private.threading_key.len(), 32);
    }

    #[test]
    fn envelope_roundtrip() {
        let master_key = [0x42; 32];
        let identity = generate_identity_keys(&master_key).unwrap();
        let private =
            decrypt_private_keys(&master_key, &identity.encrypted_private_bundle).unwrap();

        let plaintext = b"wasm envelope roundtrip";
        let sealed = encrypt_message(
            &identity.x25519_public,
            &identity.mlkem768_public,
            plaintext,
        )
        .unwrap();
        let decrypted =
            decrypt_message(&private.x25519_secret, &private.mlkem768_secret, &sealed).unwrap();
        assert_eq!(decrypted, plaintext);

        let draft = encrypt_draft(
            &identity.x25519_public,
            &identity.mlkem768_public,
            plaintext,
        )
        .unwrap();
        let decrypted_draft =
            decrypt_message(&private.x25519_secret, &private.mlkem768_secret, &draft).unwrap();
        assert_eq!(decrypted_draft, plaintext);
    }

    #[test]
    fn metadata_and_subject_hash_roundtrip() {
        let key = [7u8; 32];
        let plaintext = br#"{"subject":"Plans","from":"alice@sanct.local"}"#;

        let encrypted = encrypt_metadata(&key, plaintext).unwrap();
        let decrypted = decrypt_metadata(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        let hash = compute_subject_hash(&key, "Re: Plans");
        let expected = sanct_crypto::keys::compute_subject_hash(&key, "Plans");
        assert_eq!(hash, expected);
    }

    #[test]
    fn recipient_sealing_roundtrip() {
        let master_key = [0x24; 32];
        let identity = generate_identity_keys(&master_key).unwrap();
        let private =
            decrypt_private_keys(&master_key, &identity.encrypted_private_bundle).unwrap();

        let body = b"sealed body";
        let metadata = br#"{"subject":"sealed metadata"}"#;

        let sealed_body =
            seal_for_recipient(&identity.x25519_public, &identity.mlkem768_public, body).unwrap();
        let sealed_metadata = seal_metadata_for_recipient(
            &identity.x25519_public,
            &identity.mlkem768_public,
            metadata,
        )
        .unwrap();

        assert_eq!(
            decrypt_message(
                &private.x25519_secret,
                &private.mlkem768_secret,
                &sealed_body,
            )
            .unwrap(),
            body
        );
        assert_eq!(
            decrypt_message(
                &private.x25519_secret,
                &private.mlkem768_secret,
                &sealed_metadata,
            )
            .unwrap(),
            metadata
        );
    }

    #[test]
    fn recovery_roundtrip() {
        let result = generate_recovery_phrase();
        let derived = recovery_key_from_phrase(&result.phrase).unwrap();
        assert_eq!(derived, result.recovery_key);

        let payload = b"encrypted-private-bundle";
        let encrypted = encrypt_bundle_for_recovery(&derived, payload).unwrap();
        let decrypted = decrypt_bundle_with_recovery(&derived, &encrypted).unwrap();
        assert_eq!(decrypted, payload);

        assert_eq!(
            hash_recovery_key(&derived),
            sanct_crypto::recovery::hash_recovery_key(&result.recovery_key)
        );
    }
}
