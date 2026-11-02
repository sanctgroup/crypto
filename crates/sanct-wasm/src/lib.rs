use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct IdentityKeys {
    pub(crate) x25519_public: Vec<u8>,
    pub(crate) mlkem768_public: Vec<u8>,
    pub(crate) ed25519_public: Vec<u8>,
    pub(crate) mldsa65_public: Vec<u8>,
    pub(crate) key_version: u32,
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

    #[wasm_bindgen(getter, js_name = "ed25519Public")]
    pub fn ed25519_public(&self) -> Vec<u8> {
        self.ed25519_public.clone()
    }

    #[wasm_bindgen(getter, js_name = "mldsa65Public")]
    pub fn mldsa65_public(&self) -> Vec<u8> {
        self.mldsa65_public.clone()
    }

    #[wasm_bindgen(getter, js_name = "keyVersion")]
    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    #[wasm_bindgen(getter, js_name = "encryptedPrivateBundle")]
    pub fn encrypted_private_bundle(&self) -> Vec<u8> {
        self.encrypted_private_bundle.clone()
    }
}

impl From<sanct_crypto::keys::IdentityKeyBundle> for IdentityKeys {
    fn from(bundle: sanct_crypto::keys::IdentityKeyBundle) -> Self {
        Self {
            x25519_public: bundle.x25519_public,
            mlkem768_public: bundle.mlkem768_public,
            ed25519_public: bundle.ed25519_public,
            mldsa65_public: bundle.mldsa65_public,
            key_version: bundle.key_version,
            encrypted_private_bundle: bundle.encrypted_private_bundle,
        }
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SplitKeys {
    pub(crate) auth_key: Vec<u8>,
    pub(crate) wrap_key: Vec<u8>,
}

#[wasm_bindgen]
impl SplitKeys {
    #[wasm_bindgen(getter, js_name = "authKey")]
    pub fn auth_key(&self) -> Vec<u8> {
        self.auth_key.clone()
    }

    #[wasm_bindgen(getter, js_name = "wrapKey")]
    pub fn wrap_key(&self) -> Vec<u8> {
        self.wrap_key.clone()
    }
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryResult {
    pub(crate) phrase: String,
    pub(crate) auth_key: Vec<u8>,
    pub(crate) wrap_key: Vec<u8>,
}

#[wasm_bindgen]
impl RecoveryResult {
    #[wasm_bindgen(getter)]
    pub fn phrase(&self) -> String {
        self.phrase.clone()
    }

    #[wasm_bindgen(getter, js_name = "authKey")]
    pub fn auth_key(&self) -> Vec<u8> {
        self.auth_key.clone()
    }

    #[wasm_bindgen(getter, js_name = "wrapKey")]
    pub fn wrap_key(&self) -> Vec<u8> {
        self.wrap_key.clone()
    }
}

#[wasm_bindgen]
pub struct SealedMail {
    pub(crate) body: Vec<u8>,
    pub(crate) metadata: Vec<u8>,
}

#[wasm_bindgen]
impl SealedMail {
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn metadata(&self) -> Vec<u8> {
        self.metadata.clone()
    }
}

#[wasm_bindgen]
pub struct OpenedMail {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) binding_id: Vec<u8>,
    pub(crate) self_sealed: bool,
    pub(crate) recipient_key_hash: Option<Vec<u8>>,
    pub(crate) signature: Option<Vec<u8>>,
}

impl Drop for OpenedMail {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}

#[wasm_bindgen]
impl OpenedMail {
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }

    #[wasm_bindgen(getter, js_name = "bindingId")]
    pub fn binding_id(&self) -> Vec<u8> {
        self.binding_id.clone()
    }

    #[wasm_bindgen(getter, js_name = "selfSealed")]
    pub fn self_sealed(&self) -> bool {
        self.self_sealed
    }

    #[wasm_bindgen(getter, js_name = "recipientKeyHash")]
    pub fn recipient_key_hash(&self) -> Option<Vec<u8>> {
        self.recipient_key_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Option<Vec<u8>> {
        self.signature.clone()
    }
}

fn parse_bundle(bundle: Vec<u8>) -> Result<sanct_crypto::keys::PrivateKeys, JsError> {
    let bundle = Zeroizing::new(bundle);
    Ok(sanct_crypto::keys::parse_private_keys(bundle.as_slice())?)
}

#[wasm_bindgen(js_name = "generateSalt")]
pub fn generate_salt() -> Vec<u8> {
    sanct_crypto::password::generate_salt().to_vec()
}

#[wasm_bindgen(js_name = "derivePasswordKeys")]
pub fn derive_password_keys(password: String, salt: &[u8]) -> Result<SplitKeys, JsError> {
    let password = Zeroizing::new(password);
    let keys = sanct_crypto::password::derive_password_keys(password.as_bytes(), salt)?;
    Ok(SplitKeys {
        auth_key: keys.auth_key.to_vec(),
        wrap_key: keys.wrap_key.to_vec(),
    })
}

#[wasm_bindgen(js_name = "generateAccountKey")]
pub fn generate_account_key() -> Vec<u8> {
    sanct_crypto::keys::generate_account_key().to_vec()
}

#[wasm_bindgen(js_name = "wrapAccountKey")]
pub fn wrap_account_key(
    wrap_key: Vec<u8>,
    account_key: Vec<u8>,
    purpose: String,
) -> Result<Vec<u8>, JsError> {
    let wrap_key = Zeroizing::new(wrap_key);
    let account_key = Zeroizing::new(account_key);
    let purpose = sanct_crypto::keys::WrapPurpose::parse(&purpose)?;
    Ok(sanct_crypto::keys::wrap_account_key(
        wrap_key.as_slice(),
        account_key.as_slice(),
        purpose,
    )?)
}

#[wasm_bindgen(js_name = "unwrapAccountKey")]
pub fn unwrap_account_key(
    wrap_key: Vec<u8>,
    wrapped: &[u8],
    purpose: String,
) -> Result<Vec<u8>, JsError> {
    let wrap_key = Zeroizing::new(wrap_key);
    let purpose = sanct_crypto::keys::WrapPurpose::parse(&purpose)?;
    let account_key =
        sanct_crypto::keys::unwrap_account_key(wrap_key.as_slice(), wrapped, purpose)?;
    Ok(account_key.to_vec())
}

#[wasm_bindgen(js_name = "generateIdentityKeys")]
pub fn generate_identity_keys(account_key: Vec<u8>) -> Result<IdentityKeys, JsError> {
    let account_key = Zeroizing::new(account_key);
    Ok(sanct_crypto::keys::generate_identity_keys(account_key.as_slice())?.into())
}

#[wasm_bindgen(js_name = "rotateIdentityKeys")]
pub fn rotate_identity_keys(
    account_key: Vec<u8>,
    private_bundle: Vec<u8>,
) -> Result<IdentityKeys, JsError> {
    let account_key = Zeroizing::new(account_key);
    let keys = parse_bundle(private_bundle)?;
    Ok(sanct_crypto::keys::rotate_identity_keys(account_key.as_slice(), &keys)?.into())
}

#[wasm_bindgen(js_name = "decryptPrivateBundle")]
pub fn decrypt_private_bundle(
    account_key: Vec<u8>,
    encrypted_bundle: &[u8],
) -> Result<Vec<u8>, JsError> {
    let account_key = Zeroizing::new(account_key);
    Ok(
        sanct_crypto::keys::decrypt_private_bundle(account_key.as_slice(), encrypted_bundle)?
            .to_vec(),
    )
}

#[wasm_bindgen(js_name = "threadingKeyFromBundle")]
pub fn threading_key_from_bundle(private_bundle: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let keys = parse_bundle(private_bundle)?;
    Ok(keys.threading_key.clone())
}

#[wasm_bindgen(js_name = "sealMailForRecipient")]
pub fn seal_mail_for_recipient(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_pub: &[u8],
    private_bundle: Vec<u8>,
    signing_address: Option<String>,
    body: Vec<u8>,
    metadata: Vec<u8>,
) -> Result<SealedMail, JsError> {
    let keys = parse_bundle(private_bundle)?;
    let body = Zeroizing::new(body);
    let metadata = Zeroizing::new(metadata);
    let signer = signing_address
        .as_deref()
        .map(|sender_address| sanct_crypto::envelope::Signer {
            keys: &keys,
            sender_address,
        });
    let sealed = sanct_crypto::envelope::seal_mail(
        recipient_x25519_pub,
        recipient_mlkem_pub,
        body.as_slice(),
        metadata.as_slice(),
        signer,
    )?;
    Ok(SealedMail {
        body: sealed.body,
        metadata: sealed.metadata,
    })
}

#[wasm_bindgen(js_name = "sealMailForSelf")]
pub fn seal_mail_for_self(
    private_bundle: Vec<u8>,
    body: Vec<u8>,
    metadata: Vec<u8>,
) -> Result<SealedMail, JsError> {
    let keys = parse_bundle(private_bundle)?;
    let body = Zeroizing::new(body);
    let metadata = Zeroizing::new(metadata);
    let sealed =
        sanct_crypto::envelope::seal_mail_for_self(&keys, body.as_slice(), metadata.as_slice())?;
    Ok(SealedMail {
        body: sealed.body,
        metadata: sealed.metadata,
    })
}

#[wasm_bindgen(js_name = "openMail")]
pub fn open_mail(
    private_bundle: Vec<u8>,
    kind: String,
    sealed: &[u8],
) -> Result<OpenedMail, JsError> {
    let keys = parse_bundle(private_bundle)?;
    let kind = sanct_crypto::envelope::RecordKind::parse(&kind)?;
    let opened = sanct_crypto::envelope::open_mail(&keys, kind, sealed)?;
    Ok(OpenedMail {
        plaintext: opened.plaintext.to_vec(),
        binding_id: opened.binding_id.to_vec(),
        self_sealed: opened.self_sealed,
        recipient_key_hash: opened.recipient_key_hash.map(|hash| hash.to_vec()),
        signature: opened.signature.clone(),
    })
}

#[wasm_bindgen(js_name = "mailSignatureKeyVersion")]
pub fn mail_signature_key_version(signature: &[u8]) -> Result<u32, JsError> {
    Ok(sanct_crypto::signing::signature_key_version(signature)?)
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = "verifyMailSignature")]
pub fn verify_mail_signature(
    signature: &[u8],
    ed25519_public: &[u8],
    mldsa65_public: &[u8],
    sender_address: &str,
    recipient_key_hash: &[u8],
    binding_id: &[u8],
    body: Vec<u8>,
    metadata: Vec<u8>,
) -> bool {
    let body = Zeroizing::new(body);
    let metadata = Zeroizing::new(metadata);
    sanct_crypto::signing::verify_mail(
        signature,
        ed25519_public,
        mldsa65_public,
        &sanct_crypto::signing::MailTranscript {
            sender_address,
            recipient_key_hash,
            binding_id,
            body: body.as_slice(),
            metadata: metadata.as_slice(),
        },
    )
}

#[wasm_bindgen(js_name = "sealRecord")]
pub fn seal_record(
    private_bundle: Vec<u8>,
    kind: String,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    let keys = parse_bundle(private_bundle)?;
    let plaintext = Zeroizing::new(plaintext);
    let kind = sanct_crypto::envelope::RecordKind::parse(&kind)?;
    Ok(sanct_crypto::envelope::seal_record(
        &keys,
        kind,
        plaintext.as_slice(),
    )?)
}

#[wasm_bindgen(js_name = "openRecord")]
pub fn open_record(
    private_bundle: Vec<u8>,
    kind: String,
    sealed: &[u8],
) -> Result<Vec<u8>, JsError> {
    let keys = parse_bundle(private_bundle)?;
    let kind = sanct_crypto::envelope::RecordKind::parse(&kind)?;
    Ok(sanct_crypto::envelope::open_record(&keys, kind, sealed)?.to_vec())
}

#[wasm_bindgen(js_name = "computeSubjectHash")]
pub fn compute_subject_hash(threading_key: Vec<u8>, subject: String) -> Vec<u8> {
    let threading_key = Zeroizing::new(threading_key);
    let threading_key = threading_key.as_slice();
    let subject = Zeroizing::new(subject);
    let subject = subject.as_str();
    sanct_crypto::keys::compute_subject_hash(threading_key, subject)
}

#[wasm_bindgen(js_name = "generateRecoveryPhrase")]
pub fn generate_recovery_phrase() -> Result<RecoveryResult, JsError> {
    let mut generated = sanct_crypto::recovery::generate_recovery_phrase()?;
    Ok(RecoveryResult {
        phrase: std::mem::take(&mut generated.phrase),
        auth_key: generated.keys.auth_key.to_vec(),
        wrap_key: generated.keys.wrap_key.to_vec(),
    })
}

#[wasm_bindgen(js_name = "recoveryKeysFromPhrase")]
pub fn recovery_keys_from_phrase(phrase: String) -> Result<SplitKeys, JsError> {
    let phrase = Zeroizing::new(phrase);
    let keys = sanct_crypto::recovery::recovery_keys_from_phrase(phrase.as_str())?;
    Ok(SplitKeys {
        auth_key: keys.auth_key.to_vec(),
        wrap_key: keys.wrap_key.to_vec(),
    })
}

#[wasm_bindgen(js_name = "hashRecoveryAuthKey")]
pub fn hash_recovery_auth_key(auth_key: Vec<u8>) -> Vec<u8> {
    let auth_key = Zeroizing::new(auth_key);
    sanct_crypto::recovery::hash_recovery_auth_key(auth_key.as_slice())
}

#[wasm_bindgen]
#[derive(Zeroize, ZeroizeOnDrop)]
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
#[derive(Zeroize, ZeroizeOnDrop)]
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
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PgpDecryptResult {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) fingerprint_used: String,
    pub(crate) signer_fingerprint: Option<String>,
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
    #[wasm_bindgen(getter, js_name = "signatureVerified")]
    pub fn signature_verified(&self) -> bool {
        self.signer_fingerprint.is_some()
    }
    #[wasm_bindgen(getter, js_name = "signerFingerprint")]
    pub fn signer_fingerprint(&self) -> Option<String> {
        self.signer_fingerprint.clone()
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
        PgpError::UnsafePrivateKey => "unsafe_key",
        PgpError::Verification(_) => "verification",
        PgpError::ResourceLimit => "resource_limit",
    };
    JsError::new(&format!("{code}: {e}"))
}

#[wasm_bindgen(js_name = "pgpGenerateKey")]
pub fn pgp_generate_key(name: String, email: String) -> Result<PgpGeneratedKey, JsError> {
    let name = Zeroizing::new(name);
    let name = name.as_str();
    let email = Zeroizing::new(email);
    let email = email.as_str();
    let mut key = sanct_crypto::pgp::generate_key(name, email).map_err(pgp_to_jserror)?;
    Ok(PgpGeneratedKey {
        armored_public: std::mem::take(&mut key.armored_public),
        armored_secret: std::mem::take(&mut key.armored_secret),
        fingerprint: std::mem::take(&mut key.fingerprint),
        primary_uid: std::mem::take(&mut key.primary_uid),
    })
}

#[wasm_bindgen(js_name = "pgpImportKey")]
pub fn pgp_import_key(
    input: Vec<u8>,
    passphrase: Option<String>,
) -> Result<PgpImportedKey, JsError> {
    let input = Zeroizing::new(input);
    let input = input.as_slice();
    let passphrase = passphrase.map(Zeroizing::new);
    let mut imported =
        sanct_crypto::pgp::import_key(input, passphrase.as_ref().map(|p| p.as_str()))
            .map_err(pgp_to_jserror)?;
    Ok(PgpImportedKey {
        armored_secret: std::mem::take(&mut imported.armored_secret_unprotected),
        armored_public: std::mem::take(&mut imported.armored_public),
        fingerprint: std::mem::take(&mut imported.fingerprint),
        uids: std::mem::take(&mut imported.uids),
        created_at_unix: imported.created_at_unix,
        expires_at_unix: imported.expires_at_unix,
        is_expired: imported.is_expired,
        is_revoked: imported.is_revoked,
    })
}

#[wasm_bindgen(js_name = "pgpExportKey")]
pub fn pgp_export_key(unprotected_armored: Vec<u8>, passphrase: String) -> Result<String, JsError> {
    let unprotected_armored = Zeroizing::new(unprotected_armored);
    let unprotected_armored = unprotected_armored.as_slice();
    let passphrase = Zeroizing::new(passphrase);
    let passphrase = passphrase.as_str();
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
    let secrets = Zeroizing::new(
        armored_secrets
            .iter()
            .map(|a| a.to_vec())
            .collect::<Vec<Vec<u8>>>(),
    );
    let mut res =
        sanct_crypto::pgp::decrypt_message(&secrets, armored_ciphertext).map_err(pgp_to_jserror)?;
    Ok(PgpDecryptResult {
        plaintext: std::mem::take(&mut res.plaintext),
        fingerprint_used: std::mem::take(&mut res.fingerprint_used),
        signer_fingerprint: std::mem::take(&mut res.signer_fingerprint),
    })
}

#[wasm_bindgen(js_name = "pgpDecryptMessageVerified")]
pub fn pgp_decrypt_message_verified(
    armored_secrets: Vec<js_sys::Uint8Array>,
    armored_ciphertext: &[u8],
    trusted_signers: Vec<js_sys::Uint8Array>,
) -> Result<PgpDecryptResult, JsError> {
    let secrets = Zeroizing::new(
        armored_secrets
            .iter()
            .map(|a| a.to_vec())
            .collect::<Vec<Vec<u8>>>(),
    );
    let signers = trusted_signers
        .iter()
        .map(|a| a.to_vec())
        .collect::<Vec<_>>();
    let mut result =
        sanct_crypto::pgp::decrypt_message_verified(&secrets, armored_ciphertext, &signers)
            .map_err(pgp_to_jserror)?;
    Ok(PgpDecryptResult {
        plaintext: std::mem::take(&mut result.plaintext),
        fingerprint_used: std::mem::take(&mut result.fingerprint_used),
        signer_fingerprint: std::mem::take(&mut result.signer_fingerprint),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked(account_key: &[u8; 32], identity: &IdentityKeys) -> Vec<u8> {
        decrypt_private_bundle(account_key.to_vec(), &identity.encrypted_private_bundle).unwrap()
    }

    #[test]
    fn subject_hash_normalizes() {
        let key = [7u8; 32];
        let hash = compute_subject_hash(key.to_vec(), "Re: Plans".to_owned());
        let expected = sanct_crypto::keys::compute_subject_hash(&key, "Plans");
        assert_eq!(hash, expected);
    }

    #[test]
    fn signed_mail_roundtrip() {
        let account_key = [0x24; 32];
        let identity = generate_identity_keys(account_key.to_vec()).unwrap();
        let bundle = unlocked(&account_key, &identity);

        let body = b"sealed body";
        let metadata = br#"{"subject":"sealed metadata"}"#;
        let sealed = seal_mail_for_recipient(
            &identity.x25519_public,
            &identity.mlkem768_public,
            bundle.clone(),
            Some("alice@sanct.test".to_owned()),
            body.to_vec(),
            metadata.to_vec(),
        )
        .unwrap();

        let opened_body = open_mail(bundle.clone(), "mail-body".into(), &sealed.body).unwrap();
        let opened_metadata =
            open_mail(bundle.clone(), "mail-metadata".into(), &sealed.metadata).unwrap();
        assert_eq!(opened_body.plaintext, body);
        assert_eq!(opened_metadata.plaintext, metadata);
        assert_eq!(opened_body.binding_id, opened_metadata.binding_id);
        assert!(!opened_body.self_sealed);

        let signature = opened_body.signature.clone().unwrap();
        assert_eq!(mail_signature_key_version(&signature).unwrap(), 1);
        let hash = opened_body.recipient_key_hash.clone().unwrap();
        assert!(verify_mail_signature(
            &signature,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            "alice@sanct.test",
            &hash,
            &opened_body.binding_id,
            body.to_vec(),
            metadata.to_vec(),
        ));
        assert!(!verify_mail_signature(
            &signature,
            &identity.ed25519_public,
            &identity.mldsa65_public,
            "mallory@sanct.test",
            &hash,
            &opened_body.binding_id,
            body.to_vec(),
            metadata.to_vec(),
        ));
    }

    #[test]
    fn self_records_and_mail_roundtrip() {
        let account_key = [0x25; 32];
        let identity = generate_identity_keys(account_key.to_vec()).unwrap();
        let bundle = unlocked(&account_key, &identity);

        let sealed = seal_record(bundle.clone(), "contact".into(), b"contact".to_vec()).unwrap();
        assert_eq!(
            open_record(bundle.clone(), "contact".into(), &sealed).unwrap(),
            b"contact"
        );

        let mail = seal_mail_for_self(bundle.clone(), b"body".to_vec(), b"meta".to_vec()).unwrap();
        let opened = open_mail(bundle, "mail-body".into(), &mail.body).unwrap();
        assert!(opened.self_sealed);
        assert_eq!(opened.plaintext, b"body");
    }

    #[test]
    fn account_key_wrap_and_recovery_roundtrip() {
        let account_key = generate_account_key();
        let recovery = generate_recovery_phrase().unwrap();
        let derived = recovery_keys_from_phrase(recovery.phrase.clone()).unwrap();
        assert_eq!(derived.auth_key, recovery.auth_key);
        assert_eq!(derived.wrap_key, recovery.wrap_key);

        let wrapped = wrap_account_key(
            derived.wrap_key.clone(),
            account_key.clone(),
            "recovery".into(),
        )
        .unwrap();
        assert_eq!(
            unwrap_account_key(derived.wrap_key.clone(), &wrapped, "recovery".into()).unwrap(),
            account_key
        );
        assert_eq!(
            hash_recovery_auth_key(derived.auth_key.clone()),
            sanct_crypto::recovery::hash_recovery_auth_key(&recovery.auth_key)
        );
    }

    #[test]
    fn rotation_retains_old_mail() {
        let account_key = [0x26; 32];
        let first = generate_identity_keys(account_key.to_vec()).unwrap();
        let first_bundle = unlocked(&account_key, &first);
        let old = seal_mail_for_recipient(
            &first.x25519_public,
            &first.mlkem768_public,
            first_bundle.clone(),
            None,
            b"old".to_vec(),
            b"meta".to_vec(),
        )
        .unwrap();
        let second = rotate_identity_keys(account_key.to_vec(), first_bundle).unwrap();
        assert_eq!(second.key_version, 2);
        let second_bundle = unlocked(&account_key, &second);
        assert_eq!(
            open_mail(second_bundle, "mail-body".into(), &old.body)
                .unwrap()
                .plaintext,
            b"old"
        );
    }
}
