/* tslint:disable */
/* eslint-disable */

export class IdentityKeys {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly encryptedPrivateBundle: Uint8Array;
    readonly mlkem768Public: Uint8Array;
    readonly x25519Public: Uint8Array;
}

export class PgpDecryptResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly fingerprintUsed: string;
    readonly plaintext: Uint8Array;
}

export class PgpGeneratedKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly armoredPublic: string;
    readonly armoredSecret: string;
    readonly fingerprint: string;
    readonly primaryUid: string;
}

export class PgpImportedKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly armoredPublic: string;
    readonly armoredSecret: string;
    readonly createdAt: bigint;
    readonly expiresAt: bigint | undefined;
    readonly fingerprint: string;
    readonly isExpired: boolean;
    readonly isRevoked: boolean;
    readonly uids: string[];
}

export class PgpPublicKeyInfo {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly canEncrypt: boolean;
    readonly createdAt: bigint;
    readonly expiresAt: bigint | undefined;
    readonly fingerprint: string;
    readonly isExpired: boolean;
    readonly isRevoked: boolean;
    readonly uids: string[];
}

export class PrivateKeys {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly mlkem768Secret: Uint8Array;
    readonly threadingKey: Uint8Array;
    readonly x25519Secret: Uint8Array;
}

export class RecoveryResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly phrase: string;
    readonly recoveryKey: Uint8Array;
}

export function computeSubjectHash(threading_key: Uint8Array, subject: string): Uint8Array;

export function decryptBundleWithRecovery(recovery_key: Uint8Array, recovery_encrypted_bundle: Uint8Array): Uint8Array;

export function decryptMessage(x25519_private: Uint8Array, mlkem_private: Uint8Array, sealed_bytes: Uint8Array): Uint8Array;

export function decryptMetadata(key: Uint8Array, ciphertext: Uint8Array): Uint8Array;

export function decryptPrivateKeys(master_key: Uint8Array, encrypted_bundle: Uint8Array): PrivateKeys;

export function deriveMasterKey(password: string, salt: Uint8Array): Uint8Array;

export function encryptBundleForRecovery(recovery_key: Uint8Array, private_bundle_plaintext: Uint8Array): Uint8Array;

export function encryptDraft(own_x25519_pub: Uint8Array, own_mlkem_pub: Uint8Array, plaintext: Uint8Array): Uint8Array;

export function encryptMessage(recipient_x25519_pub: Uint8Array, recipient_mlkem_pub: Uint8Array, plaintext: Uint8Array): Uint8Array;

export function encryptMetadata(key: Uint8Array, plaintext: Uint8Array): Uint8Array;

export function generateIdentityKeys(master_key: Uint8Array): IdentityKeys;

export function generateRecoveryPhrase(): RecoveryResult;

export function generateSalt(): Uint8Array;

export function hashRecoveryKey(recovery_key: Uint8Array): Uint8Array;

export function pgpDecryptMessage(armored_secrets: Uint8Array[], armored_ciphertext: Uint8Array): PgpDecryptResult;

export function pgpEncryptToRecipients(armored_publics: Uint8Array[], plaintext: Uint8Array): string;

export function pgpExportKey(unprotected_armored: Uint8Array, passphrase: string): string;

export function pgpGenerateKey(name: string, email: string): PgpGeneratedKey;

export function pgpImportKey(input: Uint8Array, passphrase?: string | null): PgpImportedKey;

export function pgpKeyInfo(armored_public: Uint8Array): PgpPublicKeyInfo;

export function recoveryKeyFromPhrase(phrase: string): Uint8Array;

export function sealForRecipient(recipient_x25519_pub: Uint8Array, recipient_mlkem_pub: Uint8Array, plaintext_body: Uint8Array): Uint8Array;

export function sealMetadataForRecipient(recipient_x25519_pub: Uint8Array, recipient_mlkem_pub: Uint8Array, metadata_json: Uint8Array): Uint8Array;

export function start(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_identitykeys_free: (a: number, b: number) => void;
    readonly __wbg_pgpdecryptresult_free: (a: number, b: number) => void;
    readonly __wbg_pgpgeneratedkey_free: (a: number, b: number) => void;
    readonly __wbg_pgpimportedkey_free: (a: number, b: number) => void;
    readonly __wbg_pgppublickeyinfo_free: (a: number, b: number) => void;
    readonly __wbg_privatekeys_free: (a: number, b: number) => void;
    readonly __wbg_recoveryresult_free: (a: number, b: number) => void;
    readonly computeSubjectHash: (a: number, b: number, c: number, d: number) => [number, number];
    readonly decryptBundleWithRecovery: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decryptMessage: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly decryptMetadata: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decryptPrivateKeys: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly deriveMasterKey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encryptBundleForRecovery: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encryptDraft: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encryptMessage: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encryptMetadata: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly generateIdentityKeys: (a: number, b: number) => [number, number, number];
    readonly generateRecoveryPhrase: () => number;
    readonly generateSalt: () => [number, number];
    readonly hashRecoveryKey: (a: number, b: number) => [number, number];
    readonly identitykeys_encryptedPrivateBundle: (a: number) => [number, number];
    readonly identitykeys_mlkem768Public: (a: number) => [number, number];
    readonly identitykeys_x25519Public: (a: number) => [number, number];
    readonly pgpDecryptMessage: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpEncryptToRecipients: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pgpExportKey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pgpGenerateKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpImportKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpKeyInfo: (a: number, b: number) => [number, number, number];
    readonly pgpdecryptresult_fingerprintUsed: (a: number) => [number, number];
    readonly pgpdecryptresult_plaintext: (a: number) => [number, number];
    readonly pgpgeneratedkey_armoredPublic: (a: number) => [number, number];
    readonly pgpgeneratedkey_armoredSecret: (a: number) => [number, number];
    readonly pgpgeneratedkey_fingerprint: (a: number) => [number, number];
    readonly pgpgeneratedkey_primaryUid: (a: number) => [number, number];
    readonly pgpimportedkey_armoredPublic: (a: number) => [number, number];
    readonly pgpimportedkey_armoredSecret: (a: number) => [number, number];
    readonly pgpimportedkey_createdAt: (a: number) => bigint;
    readonly pgpimportedkey_expiresAt: (a: number) => [number, bigint];
    readonly pgpimportedkey_fingerprint: (a: number) => [number, number];
    readonly pgpimportedkey_isExpired: (a: number) => number;
    readonly pgpimportedkey_isRevoked: (a: number) => number;
    readonly pgpimportedkey_uids: (a: number) => [number, number];
    readonly pgppublickeyinfo_canEncrypt: (a: number) => number;
    readonly pgppublickeyinfo_fingerprint: (a: number) => [number, number];
    readonly pgppublickeyinfo_isExpired: (a: number) => number;
    readonly pgppublickeyinfo_isRevoked: (a: number) => number;
    readonly pgppublickeyinfo_uids: (a: number) => [number, number];
    readonly privatekeys_mlkem768Secret: (a: number) => [number, number];
    readonly privatekeys_threadingKey: (a: number) => [number, number];
    readonly privatekeys_x25519Secret: (a: number) => [number, number];
    readonly recoveryKeyFromPhrase: (a: number, b: number) => [number, number, number, number];
    readonly recoveryresult_phrase: (a: number) => [number, number];
    readonly recoveryresult_recoveryKey: (a: number) => [number, number];
    readonly sealForRecipient: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly sealMetadataForRecipient: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly start: () => void;
    readonly pgppublickeyinfo_createdAt: (a: number) => bigint;
    readonly pgppublickeyinfo_expiresAt: (a: number) => [number, bigint];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
