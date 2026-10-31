
export class IdentityKeys {
    static __wrap(ptr) {
        const obj = Object.create(IdentityKeys.prototype);
        obj.__wbg_ptr = ptr;
        IdentityKeysFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        IdentityKeysFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_identitykeys_free(ptr, 0);
    }
    get encryptedPrivateBundle() {
        const ret = wasm.identitykeys_encryptedPrivateBundle(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
    get mlkem768Public() {
        const ret = wasm.identitykeys_mlkem768Public(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
    get x25519Public() {
        const ret = wasm.identitykeys_x25519Public(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) IdentityKeys.prototype[Symbol.dispose] = IdentityKeys.prototype.free;

export class PgpDecryptResult {
    static __wrap(ptr) {
        const obj = Object.create(PgpDecryptResult.prototype);
        obj.__wbg_ptr = ptr;
        PgpDecryptResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PgpDecryptResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pgpdecryptresult_free(ptr, 0);
    }
    get fingerprintUsed() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpdecryptresult_fingerprintUsed(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get plaintext() {
        const ret = wasm.pgpdecryptresult_plaintext(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
    get signatureVerified() {
        const ret = wasm.pgpdecryptresult_signatureVerified(this.__wbg_ptr);
        return ret !== 0;
    }
    get signerFingerprint() {
        const ret = wasm.pgpdecryptresult_signerFingerprint(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]);
            zeroizeAndFree(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
}
if (Symbol.dispose) PgpDecryptResult.prototype[Symbol.dispose] = PgpDecryptResult.prototype.free;

export class PgpGeneratedKey {
    static __wrap(ptr) {
        const obj = Object.create(PgpGeneratedKey.prototype);
        obj.__wbg_ptr = ptr;
        PgpGeneratedKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PgpGeneratedKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pgpgeneratedkey_free(ptr, 0);
    }
    get armoredPublic() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpgeneratedkey_armoredPublic(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get armoredSecret() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpgeneratedkey_armoredSecret(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get fingerprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpgeneratedkey_fingerprint(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get primaryUid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpgeneratedkey_primaryUid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) PgpGeneratedKey.prototype[Symbol.dispose] = PgpGeneratedKey.prototype.free;

export class PgpImportedKey {
    static __wrap(ptr) {
        const obj = Object.create(PgpImportedKey.prototype);
        obj.__wbg_ptr = ptr;
        PgpImportedKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PgpImportedKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pgpimportedkey_free(ptr, 0);
    }
    get armoredPublic() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpimportedkey_armoredPublic(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get armoredSecret() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpimportedkey_armoredSecret(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get createdAt() {
        const ret = wasm.pgpimportedkey_createdAt(this.__wbg_ptr);
        return ret;
    }
    get expiresAt() {
        const ret = wasm.pgpimportedkey_expiresAt(this.__wbg_ptr);
        return ret[0] === 0 ? undefined : ret[1];
    }
    get fingerprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgpimportedkey_fingerprint(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get isExpired() {
        const ret = wasm.pgpimportedkey_isExpired(this.__wbg_ptr);
        return ret !== 0;
    }
    get isRevoked() {
        const ret = wasm.pgpimportedkey_isRevoked(this.__wbg_ptr);
        return ret !== 0;
    }
    get uids() {
        const ret = wasm.pgpimportedkey_uids(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]);
        zeroizeAndFree(ret[0], ret[1] * 4, 4);
        return v1;
    }
}
if (Symbol.dispose) PgpImportedKey.prototype[Symbol.dispose] = PgpImportedKey.prototype.free;

export class PgpPublicKeyInfo {
    static __wrap(ptr) {
        const obj = Object.create(PgpPublicKeyInfo.prototype);
        obj.__wbg_ptr = ptr;
        PgpPublicKeyInfoFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PgpPublicKeyInfoFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_pgppublickeyinfo_free(ptr, 0);
    }
    get canEncrypt() {
        const ret = wasm.pgppublickeyinfo_canEncrypt(this.__wbg_ptr);
        return ret !== 0;
    }
    get createdAt() {
        const ret = wasm.pgppublickeyinfo_createdAt(this.__wbg_ptr);
        return ret;
    }
    get expiresAt() {
        const ret = wasm.pgppublickeyinfo_expiresAt(this.__wbg_ptr);
        return ret[0] === 0 ? undefined : ret[1];
    }
    get fingerprint() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.pgppublickeyinfo_fingerprint(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get isExpired() {
        const ret = wasm.pgppublickeyinfo_isExpired(this.__wbg_ptr);
        return ret !== 0;
    }
    get isRevoked() {
        const ret = wasm.pgppublickeyinfo_isRevoked(this.__wbg_ptr);
        return ret !== 0;
    }
    get uids() {
        const ret = wasm.pgppublickeyinfo_uids(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]);
        zeroizeAndFree(ret[0], ret[1] * 4, 4);
        return v1;
    }
}
if (Symbol.dispose) PgpPublicKeyInfo.prototype[Symbol.dispose] = PgpPublicKeyInfo.prototype.free;

export class PrivateKeys {
    static __wrap(ptr) {
        const obj = Object.create(PrivateKeys.prototype);
        obj.__wbg_ptr = ptr;
        PrivateKeysFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        PrivateKeysFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_privatekeys_free(ptr, 0);
    }
    get mlkem768Secret() {
        const ret = wasm.privatekeys_mlkem768Secret(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
    get threadingKey() {
        const ret = wasm.privatekeys_threadingKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
    get x25519Secret() {
        const ret = wasm.privatekeys_x25519Secret(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) PrivateKeys.prototype[Symbol.dispose] = PrivateKeys.prototype.free;

export class RecoveryResult {
    static __wrap(ptr) {
        const obj = Object.create(RecoveryResult.prototype);
        obj.__wbg_ptr = ptr;
        RecoveryResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        RecoveryResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_recoveryresult_free(ptr, 0);
    }
    get phrase() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.recoveryresult_phrase(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            zeroizeAndFree(deferred1_0, deferred1_1, 1);
        }
    }
    get recoveryKey() {
        const ret = wasm.recoveryresult_recoveryKey(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        zeroizeAndFree(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) RecoveryResult.prototype[Symbol.dispose] = RecoveryResult.prototype.free;

export function computeSubjectHash(threading_key, subject) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(threading_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(subject, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.computeSubjectHash(ptr0, len0, ptr1, len1);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function decryptBundleWithRecovery(recovery_key, recovery_encrypted_bundle) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(recovery_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(recovery_encrypted_bundle, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decryptBundleWithRecovery(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function decryptMessage(x25519_private, mlkem_private, sealed_bytes) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(x25519_private, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(mlkem_private, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(sealed_bytes, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { zeroizeAndFree(ptr2, len2 * 1, 1); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decryptMessage(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v4;
}

export function decryptMetadata(key, ciphertext) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decryptMetadata(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function decryptPrivateKeys(master_key, encrypted_bundle) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(master_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(encrypted_bundle, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decryptPrivateKeys(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PrivateKeys.__wrap(ret[0]);
}

export function deriveMasterKey(password, salt) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.deriveMasterKey(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function encryptBundleForRecovery(recovery_key, private_bundle_plaintext) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(recovery_key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(private_bundle_plaintext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encryptBundleForRecovery(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function encryptDraft(own_x25519_pub, own_mlkem_pub, plaintext) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(own_x25519_pub, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(own_mlkem_pub, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { zeroizeAndFree(ptr2, len2 * 1, 1); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encryptDraft(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v4;
}

export function encryptMessage(recipient_x25519_pub, recipient_mlkem_pub, plaintext) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(recipient_x25519_pub, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(recipient_mlkem_pub, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { zeroizeAndFree(ptr2, len2 * 1, 1); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encryptMessage(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v4;
}

export function encryptMetadata(key, plaintext) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.encryptMetadata(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v3;
}

export function generateIdentityKeys(master_key) {
    const ptr0 = passArray8ToWasm0(master_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.generateIdentityKeys(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return IdentityKeys.__wrap(ret[0]);
}

export function generateRecoveryPhrase() {
    const ret = wasm.generateRecoveryPhrase();
    return RecoveryResult.__wrap(ret);
}

export function generateSalt() {
    const ret = wasm.generateSalt();
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v1;
}

export function hashRecoveryKey(recovery_key) {
    const ptr0 = passArray8ToWasm0(recovery_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hashRecoveryKey(ptr0, len0);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v2;
}

export function pgpDecryptMessage(armored_secrets, armored_ciphertext) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArrayJsValueToWasm0(armored_secrets, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(armored_ciphertext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__externref_drop_slice(ptr0, len0); zeroizeAndFree(ptr0, len0 * 4, 4); }
        throw e;
    }
    const ret = wasm.pgpDecryptMessage(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PgpDecryptResult.__wrap(ret[0]);
}

export function pgpDecryptMessageVerified(armored_secrets, armored_ciphertext, trusted_signers) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArrayJsValueToWasm0(armored_secrets, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(armored_ciphertext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArrayJsValueToWasm0(trusted_signers, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__externref_drop_slice(ptr2, len2); zeroizeAndFree(ptr2, len2 * 4, 4); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__externref_drop_slice(ptr0, len0); zeroizeAndFree(ptr0, len0 * 4, 4); }
        throw e;
    }
    const ret = wasm.pgpDecryptMessageVerified(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PgpDecryptResult.__wrap(ret[0]);
}

export function pgpEncryptToRecipients(armored_publics, plaintext) {
    let deferred4_0;
    let deferred4_1;
    try {
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passArrayJsValueToWasm0(armored_publics, wasm.__wbindgen_malloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__externref_drop_slice(ptr0, len0); zeroizeAndFree(ptr0, len0 * 4, 4); }
            throw e;
        }
        const ret = wasm.pgpEncryptToRecipients(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        zeroizeAndFree(deferred4_0, deferred4_1, 1);
    }
}

export function pgpExportKey(unprotected_armored, passphrase) {
    let deferred4_0;
    let deferred4_1;
    try {
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passArray8ToWasm0(unprotected_armored, wasm.__wbindgen_malloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
            if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.pgpExportKey(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        zeroizeAndFree(deferred4_0, deferred4_1, 1);
    }
}

export function pgpGenerateKey(name, email) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(email, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.pgpGenerateKey(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PgpGeneratedKey.__wrap(ret[0]);
}

export function pgpImportKey(input, passphrase) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(input, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = isLikeNone(passphrase) ? 0 : passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.pgpImportKey(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PgpImportedKey.__wrap(ret[0]);
}

export function pgpKeyInfo(armored_public) {
    const ptr0 = passArray8ToWasm0(armored_public, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.pgpKeyInfo(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return PgpPublicKeyInfo.__wrap(ret[0]);
}

export function recoveryKeyFromPhrase(phrase) {
    const ptr0 = passStringToWasm0(phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.recoveryKeyFromPhrase(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v2;
}

export function sealForRecipient(recipient_x25519_pub, recipient_mlkem_pub, plaintext_body) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(recipient_x25519_pub, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(recipient_mlkem_pub, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(plaintext_body, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { zeroizeAndFree(ptr2, len2 * 1, 1); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.sealForRecipient(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v4;
}

export function sealMetadataForRecipient(recipient_x25519_pub, recipient_mlkem_pub, metadata_json) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(recipient_x25519_pub, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(recipient_mlkem_pub, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(metadata_json, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { zeroizeAndFree(ptr2, len2 * 1, 1); }
        if (ptr1) { zeroizeAndFree(ptr1, len1 * 1, 1); }
        if (ptr0) { zeroizeAndFree(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.sealMetadataForRecipient(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    zeroizeAndFree(ret[0], ret[1] * 1, 1);
    return v4;
}

export function start() {
    wasm.start();
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_208446807d0d1e30: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_is_function_741ff2bb612836f5: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_8b968c3ab8e96595: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_fc456fee5d3317de: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_be5b34249ff1fc15: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_4c88d8bf264fd984: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_a410eb4b59ed5965: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_23f565a907d30078: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_error_757e9472f8410341: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                zeroizeAndFree(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_8b6f1f663e6f188d: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_d2908e0b99612b91: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_getTime_edc91481cbc4cd78: function(arg0) {
            const ret = arg0.getTime();
            return ret;
        },
        __wbg_length_186163212ffe79c3: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_d5f06fad6bf1409b: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_0_36d738a0c8cfac43: function() {
            const ret = new Date();
            return ret;
        },
        __wbg_new_bb74001155cb8ca8: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_with_length_01b143a7e5dd5a3e: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_86166ff8ce1f2002: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_463ac581d2fc7ea3: function() {
            const ret = Date.now();
            return ret;
        },
        __wbg_process_91f425a63f58e399: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_13162965d1fe7aa3: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_34b023059e3363de: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_9a7d8cc2e1d275c0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_stack_575c4e0918581b9c: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 1, len1, true);
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 0, ptr1, true);
        },
        __wbg_static_accessor_GLOBAL_THIS_003ee833af9699fc: function() {
            const ret = typeof globalThis === 'undefined' ? undefined : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_e4293fb22cbe77da: function() {
            const ret = typeof global === 'undefined' ? undefined : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_53bb20457401453d: function() {
            const ret = typeof self === 'undefined' ? undefined : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_b5e0810bfecb7feb: function() {
            const ret = typeof window === 'undefined' ? undefined : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_58f388a9247ac0bb: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_6e128a981b0df859: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_generic_0000000000000001: function(arg0, arg1) {
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_generic_0000000000000002: function(arg0, arg1) {
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            table.set(0, undefined);
            table.set(1024, undefined);
            table.set(1025, null);
            table.set(1026, true);
            table.set(1027, false);
        },
    };
    return {
        __proto__: null,
        "./sanct_wasm_bg.js": import0,
    };
}

const IdentityKeysFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_identitykeys_free(ptr, 1));
const PgpDecryptResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pgpdecryptresult_free(ptr, 1));
const PgpGeneratedKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pgpgeneratedkey_free(ptr, 1));
const PgpImportedKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pgpimportedkey_free(ptr, 1));
const PgpPublicKeyInfoFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_pgppublickeyinfo_free(ptr, 1));
const PrivateKeysFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_privatekeys_free(ptr, 1));
const RecoveryResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_recoveryresult_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(bytes) {
    numBytesDecoded += bytes.length;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
        cachedTextDecoder.decode();
        numBytesDecoded = bytes.length;
    }
    return cachedTextDecoder.decode(bytes);
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

let __wbg_init_promise;
async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;
    if (__wbg_init_promise === undefined) {
        __wbg_init_promise = __wbg_init_once(module_or_path);
        __wbg_init_promise.catch(() => { __wbg_init_promise = undefined; });
    }
    return __wbg_init_promise;
}

async function __wbg_init_once(module_or_path) {

    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('sanct_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };

function zeroizeAndFree(ptr, length, alignment) {
    getUint8ArrayMemory0().fill(0, ptr, ptr + length);
    wasm.__wbindgen_free(ptr, length, alignment);
}
