
export class IdentityKeys {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly ed25519Public: Uint8Array;
    readonly encryptedPrivateBundle: Uint8Array;
    readonly keyVersion: number;
    readonly mldsa65Public: Uint8Array;
    readonly mlkem768Public: Uint8Array;
    readonly x25519Public: Uint8Array;
}

export class OpenedMail {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly bindingId: Uint8Array;
    readonly plaintext: Uint8Array;
    readonly recipientKeyHash: Uint8Array | undefined;
    readonly selfSealed: boolean;
    readonly signature: Uint8Array | undefined;
}

export class PgpDecryptResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly fingerprintUsed: string;
    readonly plaintext: Uint8Array;
    readonly signatureVerified: boolean;
    readonly signerFingerprint: string | undefined;
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

export class RecoveryResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly authKey: Uint8Array;
    readonly phrase: string;
    readonly wrapKey: Uint8Array;
}

export class SealedMail {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly body: Uint8Array;
    readonly metadata: Uint8Array;
}

export class SplitKeys {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly authKey: Uint8Array;
    readonly wrapKey: Uint8Array;
}

export function computeSubjectHash(threading_key: Uint8Array | number[], subject: string): Uint8Array;

export function decryptPrivateBundle(account_key: Uint8Array | number[], encrypted_bundle: Uint8Array | number[]): Uint8Array;

export function derivePasswordKeys(password: string, salt: Uint8Array | number[]): SplitKeys;

export function generateAccountKey(): Uint8Array;

export function generateIdentityKeys(account_key: Uint8Array | number[]): IdentityKeys;

export function generateRecoveryPhrase(): RecoveryResult;

export function generateSalt(): Uint8Array;

export function hashRecoveryAuthKey(auth_key: Uint8Array | number[]): Uint8Array;

export function mailSignatureKeyVersion(signature: Uint8Array | number[]): number;

export function openMail(private_bundle: Uint8Array | number[], kind: string, sealed: Uint8Array | number[]): OpenedMail;

export function openRecord(private_bundle: Uint8Array | number[], kind: string, sealed: Uint8Array | number[]): Uint8Array;

export function pgpDecryptMessage(armored_secrets: Uint8Array[], armored_ciphertext: Uint8Array | number[]): PgpDecryptResult;

export function pgpDecryptMessageVerified(armored_secrets: Uint8Array[], armored_ciphertext: Uint8Array | number[], trusted_signers: Uint8Array[]): PgpDecryptResult;

export function pgpEncryptToRecipients(armored_publics: Uint8Array[], plaintext: Uint8Array | number[]): string;

export function pgpExportKey(unprotected_armored: Uint8Array | number[], passphrase: string): string;

export function pgpGenerateKey(name: string, email: string): PgpGeneratedKey;

export function pgpImportKey(input: Uint8Array | number[], passphrase?: string | null): PgpImportedKey;

export function pgpKeyInfo(armored_public: Uint8Array | number[]): PgpPublicKeyInfo;

export function recoveryKeysFromPhrase(phrase: string): SplitKeys;

export function rotateIdentityKeys(account_key: Uint8Array | number[], private_bundle: Uint8Array | number[]): IdentityKeys;

export function sealMailForRecipient(recipient_x25519_pub: Uint8Array | number[], recipient_mlkem_pub: Uint8Array | number[], private_bundle: Uint8Array | number[], signing_address: string | null | undefined, body: Uint8Array | number[], metadata: Uint8Array | number[]): SealedMail;

export function sealMailForSelf(private_bundle: Uint8Array | number[], body: Uint8Array | number[], metadata: Uint8Array | number[]): SealedMail;

export function sealRecord(private_bundle: Uint8Array | number[], kind: string, plaintext: Uint8Array | number[]): Uint8Array;

export function start(): void;

export function threadingKeyFromBundle(private_bundle: Uint8Array | number[]): Uint8Array;

export function unwrapAccountKey(wrap_key: Uint8Array | number[], wrapped: Uint8Array | number[], purpose: string): Uint8Array;

export function verifyMailSignature(signature: Uint8Array | number[], ed25519_public: Uint8Array | number[], mldsa65_public: Uint8Array | number[], sender_address: string, recipient_key_hash: Uint8Array | number[], binding_id: Uint8Array | number[], body: Uint8Array | number[], metadata: Uint8Array | number[]): boolean;

export function wrapAccountKey(wrap_key: Uint8Array | number[], account_key: Uint8Array | number[], purpose: string): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_identitykeys_free: (a: number, b: number) => void;
    readonly __wbg_openedmail_free: (a: number, b: number) => void;
    readonly __wbg_pgpdecryptresult_free: (a: number, b: number) => void;
    readonly __wbg_pgpgeneratedkey_free: (a: number, b: number) => void;
    readonly __wbg_pgpimportedkey_free: (a: number, b: number) => void;
    readonly __wbg_pgppublickeyinfo_free: (a: number, b: number) => void;
    readonly __wbg_recoveryresult_free: (a: number, b: number) => void;
    readonly __wbg_sealedmail_free: (a: number, b: number) => void;
    readonly __wbg_splitkeys_free: (a: number, b: number) => void;
    readonly computeSubjectHash: (a: number, b: number, c: number, d: number) => [number, number];
    readonly decryptPrivateBundle: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly derivePasswordKeys: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly generateAccountKey: () => [number, number];
    readonly generateIdentityKeys: (a: number, b: number) => [number, number, number];
    readonly generateRecoveryPhrase: () => [number, number, number];
    readonly generateSalt: () => [number, number];
    readonly hashRecoveryAuthKey: (a: number, b: number) => [number, number];
    readonly identitykeys_ed25519Public: (a: number) => [number, number];
    readonly identitykeys_encryptedPrivateBundle: (a: number) => [number, number];
    readonly identitykeys_keyVersion: (a: number) => number;
    readonly identitykeys_mldsa65Public: (a: number) => [number, number];
    readonly identitykeys_mlkem768Public: (a: number) => [number, number];
    readonly identitykeys_x25519Public: (a: number) => [number, number];
    readonly mailSignatureKeyVersion: (a: number, b: number) => [number, number, number];
    readonly openMail: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly openRecord: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly openedmail_bindingId: (a: number) => [number, number];
    readonly openedmail_plaintext: (a: number) => [number, number];
    readonly openedmail_recipientKeyHash: (a: number) => [number, number];
    readonly openedmail_selfSealed: (a: number) => number;
    readonly openedmail_signature: (a: number) => [number, number];
    readonly pgpDecryptMessage: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpDecryptMessageVerified: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly pgpEncryptToRecipients: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pgpExportKey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pgpGenerateKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpImportKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly pgpKeyInfo: (a: number, b: number) => [number, number, number];
    readonly pgpdecryptresult_fingerprintUsed: (a: number) => [number, number];
    readonly pgpdecryptresult_plaintext: (a: number) => [number, number];
    readonly pgpdecryptresult_signatureVerified: (a: number) => number;
    readonly pgpdecryptresult_signerFingerprint: (a: number) => [number, number];
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
    readonly pgppublickeyinfo_createdAt: (a: number) => bigint;
    readonly pgppublickeyinfo_expiresAt: (a: number) => [number, bigint];
    readonly pgppublickeyinfo_fingerprint: (a: number) => [number, number];
    readonly pgppublickeyinfo_isExpired: (a: number) => number;
    readonly pgppublickeyinfo_isRevoked: (a: number) => number;
    readonly pgppublickeyinfo_uids: (a: number) => [number, number];
    readonly recoveryKeysFromPhrase: (a: number, b: number) => [number, number, number];
    readonly recoveryresult_authKey: (a: number) => [number, number];
    readonly recoveryresult_phrase: (a: number) => [number, number];
    readonly recoveryresult_wrapKey: (a: number) => [number, number];
    readonly rotateIdentityKeys: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly sealMailForRecipient: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number];
    readonly sealMailForSelf: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly sealRecord: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly sealedmail_body: (a: number) => [number, number];
    readonly sealedmail_metadata: (a: number) => [number, number];
    readonly splitkeys_authKey: (a: number) => [number, number];
    readonly splitkeys_wrapKey: (a: number) => [number, number];
    readonly start: () => void;
    readonly threadingKeyFromBundle: (a: number, b: number) => [number, number, number, number];
    readonly unwrapAccountKey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verifyMailSignature: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number) => number;
    readonly wrapAccountKey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
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

export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
